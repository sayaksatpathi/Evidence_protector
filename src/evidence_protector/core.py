from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

import click
from dateutil import parser as dateutil_parser
from dateutil.parser import ParserError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

if TYPE_CHECKING:
    import argparse


console = Console()


def _public_console() -> Console:
    """Return the console instance to use for output.

    Tests and some callers monkeypatch `evidence_protector.console` to capture output.
    Use that when available.
    """

    mod = sys.modules.get("evidence_protector")
    patched = getattr(mod, "console", None) if mod is not None else None
    return patched if isinstance(patched, Console) else console


# --- Versioning / schemes ---

MANIFEST_VERSION = 3
HASH_ALGORITHM = "sha256"

SIGNATURE_SCHEME = "ed25519"
LEGACY_HMAC_SIGNATURE_SCHEME = "hmac-sha256"

CHAIN_SCHEME_V1 = "v1-line+prev"  # legacy: sha256(utf8(line + prev_chain_hex))
CHAIN_SCHEME_V2 = "v2-prev+lineno+line"  # sha256(prev_hash_bytes || lineno || line_bytes)


# --- Environment / configuration ---

ENV_SIGNATURE_SCHEME = "EVIDENCE_PROTECTOR_SIGNATURE_SCHEME"  # ed25519 | hmac-sha256

ENV_PRIVATE_KEY_PATH = "EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH"
ENV_PUBLIC_KEY_PATH = "EVIDENCE_PROTECTOR_PUBLIC_KEY_PATH"
ENV_ACTIVE_KEY_ID = "EVIDENCE_PROTECTOR_ACTIVE_KEY_ID"
ENV_KEY_DIR = "EVIDENCE_PROTECTOR_KEY_DIR"
ENV_REVOKED_KEYS_PATH = "EVIDENCE_PROTECTOR_REVOKED_KEYS_PATH"

ENV_ALLOW_LEGACY_HMAC_VERIFY = "EVIDENCE_PROTECTOR_ALLOW_LEGACY_HMAC_VERIFY"

ENV_HMAC_SIGNING_KEY_B64 = "EVIDENCE_PROTECTOR_SIGNING_KEY_B64"
ENV_HMAC_SIGNING_KEY_PATH = "EVIDENCE_PROTECTOR_SIGNING_KEY_PATH"

ENV_CHAIN_SCHEME = "EVIDENCE_PROTECTOR_CHAIN_SCHEME"

ENV_MANIFEST_MODE = "EVIDENCE_PROTECTOR_MANIFEST_MODE"  # full | compact
ENV_CHECKPOINT_EVERY = "EVIDENCE_PROTECTOR_CHECKPOINT_EVERY"  # int

ENV_CREATED_BY = "EVIDENCE_PROTECTOR_CREATED_BY"


# Deterministic "fingerprint phrase" derived from a hash.
# This intentionally matches the algorithm used by the Web UI's ForensicFingerprint
# component (Evidence Protector Web UI/src/app/components/ForensicFingerprint.tsx).
FINGERPRINT_ADJECTIVES: list[str] = [
    "absurd",
    "ancient",
    "ashen",
    "atomic",
    "bitten",
    "blazing",
    "brass",
    "cobalt",
    "cosmic",
    "cryptic",
    "delta",
    "drift",
    "electric",
    "etched",
    "feral",
    "frozen",
    "ghost",
    "glitch",
    "hollow",
    "hyper",
    "infra",
    "ivory",
    "jagged",
    "kinetic",
    "lunar",
    "mossy",
    "neon",
    "nimbus",
    "noisy",
    "obsidian",
    "omega",
    "orbital",
    "paper",
    "plasma",
    "polar",
    "quiet",
    "radial",
    "raven",
    "rusty",
    "signal",
    "silent",
    "solar",
    "spectral",
    "static",
    "storm",
    "sudden",
    "synthetic",
    "tidal",
    "ultra",
    "velvet",
    "vivid",
    "void",
    "wild",
    "winter",
    "wired",
    "withered",
    "xeno",
    "young",
    "zen",
    "zigzag",
    "hushed",
    "arcane",
    "volatile",
]

FINGERPRINT_NOUNS: list[str] = [
    "artifact",
    "asteroid",
    "atlas",
    "beacon",
    "circuit",
    "cipher",
    "codex",
    "comet",
    "constellation",
    "crystal",
    "drone",
    "engine",
    "echo",
    "flare",
    "forgery",
    "fractal",
    "garden",
    "glyph",
    "hammer",
    "helix",
    "horizon",
    "labyrinth",
    "lantern",
    "ledger",
    "meteor",
    "mirror",
    "monolith",
    "nebula",
    "needle",
    "node",
    "oracle",
    "orbit",
    "owl",
    "payload",
    "phantom",
    "prism",
    "protocol",
    "quartz",
    "relay",
    "riddle",
    "rift",
    "router",
    "satellite",
    "scan",
    "signal",
    "siren",
    "spectrum",
    "spiral",
    "stencil",
    "talisman",
    "thread",
    "threshold",
    "timeline",
    "token",
    "torch",
    "vault",
    "vector",
    "verdict",
    "witness",
    "wrench",
    "zenith",
    "ziggurat",
    "checksum",
]


def _fingerprint_bytes_from_hash(value: str) -> list[int]:
    clean = value.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]

    if len(clean) >= 2 and re.fullmatch(r"[0-9a-f]+", clean):
        even_len = len(clean) - (len(clean) % 2)
        out: list[int] = []
        for i in range(0, even_len, 2):
            out.append(int(clean[i : i + 2], 16))
        if out:
            return out

    # Fallback that matches JS String.charCodeAt(i) & 0xff: iterate UTF-16 code units.
    utf16le = value.encode("utf-16-le", errors="surrogatepass")
    return [utf16le[i] for i in range(0, len(utf16le), 2)]


def fingerprint_phrase(hash_value: str) -> str:
    """Return a short, human-readable phrase derived from a hash."""

    b = _fingerprint_bytes_from_hash(hash_value)
    b0 = b[0] if len(b) > 0 else 0
    b1 = b[1] if len(b) > 1 else 0
    b2 = b[2] if len(b) > 2 else 0
    b3 = b[3] if len(b) > 3 else 0

    a1 = FINGERPRINT_ADJECTIVES[b0 % len(FINGERPRINT_ADJECTIVES)]
    a2 = FINGERPRINT_ADJECTIVES[(b1 + b3) % len(FINGERPRINT_ADJECTIVES)]
    n1 = FINGERPRINT_NOUNS[b2 % len(FINGERPRINT_NOUNS)]
    suffix = ((b0 << 8) | b1) & 0xFFFF
    return f"{a1}-{a2}-{n1}-{suffix:04x}"


def _canonical_json_bytes(value: Any) -> bytes:
    """Serialize as canonical JSON bytes for signing."""

    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def _default_key_dir() -> Path:
    base = Path(os.getenv(ENV_KEY_DIR, "")).expanduser() if os.getenv(ENV_KEY_DIR) else (Path.home() / ".evidence_protector")
    return base / "keys"


def _active_key_id_path() -> Path:
    return _default_key_dir().parent / "active_key_id"


def _revoked_keys_path() -> Path:
    env = os.getenv(ENV_REVOKED_KEYS_PATH)
    if env:
        return Path(env).expanduser()
    return _default_key_dir().parent / "revoked_keys.json"


def _key_paths(key_id: str) -> tuple[Path, Path]:
    key_dir = _default_key_dir()
    return key_dir / f"{key_id}.ed25519.private.pem", key_dir / f"{key_id}.ed25519.public.pem"


def _compute_key_id(public_key: Ed25519PublicKey) -> str:
    pub = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return hashlib.sha256(pub).hexdigest()[:16]


def _load_active_key_id() -> Optional[str]:
    env = os.getenv(ENV_ACTIVE_KEY_ID)
    if env:
        return env.strip()

    path = _active_key_id_path()
    if path.exists():
        try:
            return path.read_text(encoding="utf-8").strip() or None
        except Exception:
            return None
    return None


def _set_active_key_id(key_id: str) -> None:
    path = _active_key_id_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key_id + "\n", encoding="utf-8")


def _load_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    return key


def _load_ed25519_public_key(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519")
    return key


def _write_ed25519_keypair(private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey, *, key_id: str) -> tuple[Path, Path]:
    priv_path, pub_path = _key_paths(key_id)
    priv_path.parent.mkdir(parents=True, exist_ok=True)

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)
    return priv_path, pub_path


def load_or_create_signing_keypair() -> tuple[str, Ed25519PrivateKey, Ed25519PublicKey]:
    """Load the active Ed25519 keypair, or create it if missing."""

    env_priv = os.getenv(ENV_PRIVATE_KEY_PATH)
    env_pub = os.getenv(ENV_PUBLIC_KEY_PATH)
    if env_priv and env_pub:
        priv_path = Path(env_priv).expanduser()
        pub_path = Path(env_pub).expanduser()
        priv = _load_ed25519_private_key(priv_path)
        pub = _load_ed25519_public_key(pub_path)
        key_id = _compute_key_id(pub)
        return key_id, priv, pub

    key_id = _load_active_key_id()
    if key_id:
        priv_path, pub_path = _key_paths(key_id)
        if priv_path.exists() and pub_path.exists():
            priv = _load_ed25519_private_key(priv_path)
            pub = _load_ed25519_public_key(pub_path)
            return key_id, priv, pub

    # First run (or missing files): create a new keypair and make it active.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    key_id = _compute_key_id(pub)
    _write_ed25519_keypair(priv, pub, key_id=key_id)
    _set_active_key_id(key_id)
    return key_id, priv, pub


def rotate_signing_keypair() -> tuple[str, Path, Path]:
    """Generate a new Ed25519 keypair and set it as active."""

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    key_id = _compute_key_id(pub)
    priv_path, pub_path = _write_ed25519_keypair(priv, pub, key_id=key_id)
    _set_active_key_id(key_id)
    return key_id, priv_path, pub_path


def _load_revoked_keys_data() -> Dict[str, Any]:
    path = _revoked_keys_path()
    if not path.exists():
        return {"version": 1, "updated_at": datetime.now(timezone.utc).isoformat(), "revoked": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "updated_at": datetime.now(timezone.utc).isoformat(), "revoked": []}

    if not isinstance(raw, dict):
        return {"version": 1, "updated_at": datetime.now(timezone.utc).isoformat(), "revoked": []}
    revoked = raw.get("revoked")
    if not isinstance(revoked, list):
        raw["revoked"] = []
    return raw


def _save_revoked_keys_data(data: Dict[str, Any]) -> None:
    path = _revoked_keys_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def list_revoked_key_ids() -> list[str]:
    data = _load_revoked_keys_data()
    out: list[str] = []
    for item in data.get("revoked", []):
        if not isinstance(item, dict):
            continue
        kid = str(item.get("key_id", "")).strip()
        if kid:
            out.append(kid)
    return out


def revoke_key_id(key_id: str, *, reason: str = "") -> None:
    kid = key_id.strip()
    if not kid:
        raise ValueError("key_id is required")

    data = _load_revoked_keys_data()
    revoked = data.get("revoked", [])
    if not isinstance(revoked, list):
        revoked = []

    for item in revoked:
        if isinstance(item, dict) and str(item.get("key_id", "")).strip() == kid:
            # Already revoked; keep the first record and return.
            return

    revoked.append(
        {
            "key_id": kid,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }
    )
    data["version"] = int(data.get("version", 1) or 1)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    data["revoked"] = revoked
    _save_revoked_keys_data(data)


def is_key_id_revoked(key_id: str) -> bool:
    kid = key_id.strip()
    if not kid:
        return False
    return kid in set(list_revoked_key_ids())


def load_public_key_for_key_id(key_id: str) -> Optional[Ed25519PublicKey]:
    env_pub = os.getenv(ENV_PUBLIC_KEY_PATH)
    if env_pub:
        try:
            return _load_ed25519_public_key(Path(env_pub).expanduser())
        except Exception:
            return None

    _priv_path, pub_path = _key_paths(key_id)
    if pub_path.exists():
        try:
            return _load_ed25519_public_key(pub_path)
        except Exception:
            return None

    return None


def _default_hmac_signing_key_path() -> Path:
    base = Path.home() / ".evidence_protector"
    return base / "hmac_signing_key.b64"


def _load_hmac_signing_key_for_verify() -> Optional[bytes]:
    """Load an HMAC key for legacy verification.

    Important: we do NOT auto-create during verification, because that would create
    a new secret unrelated to the signer.
    """

    key_b64 = os.getenv(ENV_HMAC_SIGNING_KEY_B64)
    if key_b64:
        try:
            return base64.b64decode(key_b64.encode("utf-8"), validate=True)
        except Exception:
            return None

    path = Path(os.getenv(ENV_HMAC_SIGNING_KEY_PATH, "")).expanduser() if os.getenv(ENV_HMAC_SIGNING_KEY_PATH) else None
    key_path = path if path else _default_hmac_signing_key_path()
    if not key_path.exists():
        return None

    raw = key_path.read_text(encoding="utf-8").strip()
    try:
        return base64.b64decode(raw.encode("utf-8"), validate=True)
    except Exception:
        return None


def _load_or_create_hmac_signing_key_for_sign() -> bytes:
    key_b64 = os.getenv(ENV_HMAC_SIGNING_KEY_B64)
    if key_b64:
        return base64.b64decode(key_b64.encode("utf-8"), validate=True)

    path = Path(os.getenv(ENV_HMAC_SIGNING_KEY_PATH, "")).expanduser() if os.getenv(ENV_HMAC_SIGNING_KEY_PATH) else None
    key_path = path if path else _default_hmac_signing_key_path()

    if key_path.exists():
        raw = key_path.read_text(encoding="utf-8").strip()
        return base64.b64decode(raw.encode("utf-8"), validate=True)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    key_path.write_text(base64.b64encode(key).decode("utf-8") + "\n", encoding="utf-8")
    return key


def _manifest_payload_for_signature(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(manifest)
    payload.pop("signature", None)
    return payload


def compute_manifest_signature(manifest: Dict[str, Any]) -> Dict[str, str]:
    """Compute a manifest signature object.

    Default scheme is Ed25519. Legacy HMAC signing is supported only if
    `EVIDENCE_PROTECTOR_SIGNATURE_SCHEME=hmac-sha256`.

    Returns:
      {"scheme": "ed25519", "key_id": "...", "value": "<base64>"}
    """

    scheme = (os.getenv(ENV_SIGNATURE_SCHEME, SIGNATURE_SCHEME) or SIGNATURE_SCHEME).strip().lower()
    payload = _manifest_payload_for_signature(manifest)

    if scheme == SIGNATURE_SCHEME:
        key_id, priv, _pub = load_or_create_signing_keypair()
        sig = priv.sign(_canonical_json_bytes(payload))
        return {"scheme": SIGNATURE_SCHEME, "key_id": key_id, "value": base64.b64encode(sig).decode("utf-8")}

    if scheme == LEGACY_HMAC_SIGNATURE_SCHEME:
        key = _load_or_create_hmac_signing_key_for_sign()
        mac = hmac.new(key, _canonical_json_bytes(payload), hashlib.sha256).digest()
        return {"scheme": LEGACY_HMAC_SIGNATURE_SCHEME, "value": base64.b64encode(mac).decode("utf-8")}

    raise ValueError(f"Unsupported signature scheme: {scheme}")


def verify_manifest_signature(manifest: Dict[str, Any]) -> tuple[bool, str]:
    """Verify the signature on a manifest.

    Returns (ok, reason):
      - (True, "ok")
      - (False, "missing")
      - (False, "invalid")
      - (False, "unsupported-scheme")
      - (False, "missing-public-key")
    - (False, "revoked-key-id")
      - (False, "legacy-hmac-not-allowed")
      - (False, "legacy-hmac-key-missing")
      - (False, "error")
    """

    sig = manifest.get("signature")
    if not sig:
        return False, "missing"

    if isinstance(sig, str):
        # Very old manifests: treat as legacy HMAC value.
        scheme = LEGACY_HMAC_SIGNATURE_SCHEME
        sig_value = sig
        key_id = ""
    elif isinstance(sig, dict):
        scheme = str(sig.get("scheme", "")).strip()
        sig_value = str(sig.get("value", "")).strip()
        key_id = str(sig.get("key_id", "")).strip()
    else:
        return False, "invalid"

    payload = _manifest_payload_for_signature(manifest)

    if scheme == SIGNATURE_SCHEME:
        if not key_id:
            return False, "invalid"

        if is_key_id_revoked(key_id):
            return False, "revoked-key-id"

        pub = load_public_key_for_key_id(key_id)
        if pub is None:
            return False, "missing-public-key"

        try:
            sig_bytes = base64.b64decode(sig_value.encode("utf-8"), validate=True)
        except Exception:
            return False, "invalid"

        try:
            pub.verify(sig_bytes, _canonical_json_bytes(payload))
            return True, "ok"
        except Exception:
            return False, "invalid"

    if scheme == LEGACY_HMAC_SIGNATURE_SCHEME:
        allow = os.getenv(ENV_ALLOW_LEGACY_HMAC_VERIFY, "0") not in {"0", "false", "False"}
        if not allow:
            return False, "legacy-hmac-not-allowed"

        key = _load_hmac_signing_key_for_verify()
        if key is None:
            return False, "legacy-hmac-key-missing"

        try:
            expected = hmac.new(key, _canonical_json_bytes(payload), hashlib.sha256).digest()
            provided = base64.b64decode(sig_value.encode("utf-8"), validate=True)
            ok = hmac.compare_digest(expected, provided)
            return ok, "ok" if ok else "invalid"
        except Exception:
            return False, "error"

    return False, "unsupported-scheme"


@dataclass
class SuspiciousGap:
    gap_index: int
    gap_start: datetime
    gap_end: datetime
    duration_seconds: int
    line_start: int
    line_end: int
    note: Optional[str] = None


@dataclass
class HashEntry:
    line_number: int
    line_hash: str
    chain_hash: str


@dataclass
class CheckpointEntry:
    line_number: int
    chain_hash: str


@dataclass
class TamperResult:
    line_number: int
    expected_chain_hash: str
    actual_chain_hash: str
    status: str
    note: Optional[str] = None


def _default_manifest_path(filepath: str) -> str:
    return str(Path(filepath).with_suffix(".manifest.json"))


def _normalize_chain_scheme(value: Optional[str]) -> str:
    v = (value or "").strip()
    if v in {"", "legacy", "v1", CHAIN_SCHEME_V1}:
        return CHAIN_SCHEME_V1
    if v in {"v2", CHAIN_SCHEME_V2}:
        return CHAIN_SCHEME_V2
    raise ValueError(f"Unsupported chain scheme: {value}")


def normalize_chain_scheme(value: Optional[str]) -> str:
    """Public wrapper for chain scheme normalization.

    This intentionally delegates to the internal normalizer to preserve
    backwards-compatible behavior, while giving other modules (API/UI helpers)
    a non-private import surface.
    """

    return _normalize_chain_scheme(value)


def _iter_hash_chain(
    filepath: str,
    *,
    chain_scheme: str,
) -> Iterable[HashEntry]:
    scheme = _normalize_chain_scheme(chain_scheme)

    # v1 uses the previous chain hash *hex string* (legacy behavior).
    prev_chain_hex = ""
    # v2 uses the previous chain hash *bytes*.
    prev_hash_bytes = b""

    with open(filepath, "r", encoding="utf-8", errors="surrogateescape", newline=None) as f:
        for line_number, line in enumerate(f, start=1):
            line_bytes = line.encode("utf-8", errors="surrogateescape")
            line_hash = hashlib.sha256(line_bytes).hexdigest()

            if scheme == CHAIN_SCHEME_V1:
                chain_hash = hashlib.sha256((line + prev_chain_hex).encode("utf-8", errors="surrogateescape")).hexdigest()
                yield HashEntry(line_number=line_number, line_hash=line_hash, chain_hash=chain_hash)
                prev_chain_hex = chain_hash
                continue
            else:
                # v2: sha256(prev_hash || lineno || line_bytes)
                lineno_bytes = int(line_number).to_bytes(8, "big", signed=False)
                chain_hash_bytes = hashlib.sha256(prev_hash_bytes + lineno_bytes + line_bytes).digest()

            chain_hash = chain_hash_bytes.hex()
            yield HashEntry(line_number=line_number, line_hash=line_hash, chain_hash=chain_hash)
            prev_hash_bytes = chain_hash_bytes


def iter_hash_chain(filepath: str, *, chain_scheme: str) -> Iterable[HashEntry]:
    """Public wrapper around the streaming hash-chain iterator."""

    return _iter_hash_chain(filepath, chain_scheme=chain_scheme)


def build_hash_chain(filepath: str, *, chain_scheme: Optional[str] = None) -> list[HashEntry]:
    scheme = _normalize_chain_scheme(chain_scheme or os.getenv(ENV_CHAIN_SCHEME) or CHAIN_SCHEME_V1)
    return list(_iter_hash_chain(filepath, chain_scheme=scheme))


def sign_log(
    filepath: str,
    out_path: str | None,
    *,
    manifest_mode: Optional[str] = None,
    checkpoint_every: Optional[int] = None,
    chain_scheme: Optional[str] = None,
) -> None:
    manifest_path = out_path or _default_manifest_path(filepath)

    mode = (manifest_mode or os.getenv(ENV_MANIFEST_MODE, "full") or "full").strip().lower()
    if mode not in {"full", "compact"}:
        raise click.ClickException("Invalid manifest mode (expected full|compact)")

    checkpoints_n = checkpoint_every
    if checkpoints_n is None:
        raw = os.getenv(ENV_CHECKPOINT_EVERY, "")
        checkpoints_n = int(raw) if raw.isdigit() else 1000

    scheme = _normalize_chain_scheme(chain_scheme or os.getenv(ENV_CHAIN_SCHEME) or CHAIN_SCHEME_V1)

    file_path = Path(filepath)
    file_size_bytes = file_path.stat().st_size if file_path.exists() else None

    created_by = os.getenv(ENV_CREATED_BY, "").strip() or None

    entries: list[HashEntry] = []
    checkpoints: list[CheckpointEntry] = []
    last_entry: Optional[HashEntry] = None

    for entry in _iter_hash_chain(filepath, chain_scheme=scheme):
        last_entry = entry
        if mode == "full":
            entries.append(entry)
        else:
            if checkpoints_n > 0 and (entry.line_number % checkpoints_n == 0):
                checkpoints.append(CheckpointEntry(line_number=entry.line_number, chain_hash=entry.chain_hash))

    total_lines = last_entry.line_number if last_entry else 0
    root_hash = last_entry.chain_hash if last_entry else ""
    phrase = fingerprint_phrase(root_hash)

    payload: Dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "file": filepath,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": HASH_ALGORITHM,
        "chain_scheme": scheme,
        "encoding": "utf-8+surrogateescape",
        "newline_policy": "universal",
        "file_size_bytes": file_size_bytes,
        "created_by": created_by,
        "manifest_mode": mode,
        "total_lines": total_lines,
        "root_hash": root_hash,
        "fingerprint_phrase": phrase,
    }

    if mode == "full":
        payload["entries"] = [asdict(e) for e in entries]
    else:
        payload["checkpoints"] = [asdict(c) for c in checkpoints]
        payload["checkpoint_every"] = checkpoints_n

    try:
        payload["signature"] = compute_manifest_signature(payload)
    except Exception as e:
        raise click.ClickException(f"Unable to sign manifest: {e}") from e

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    root_short = root_hash[:16] if root_hash else "(empty)"
    sig_obj = payload.get("signature")
    sig_val = str(sig_obj.get("value", ""))[:16] if isinstance(sig_obj, dict) else ""
    key_id = str(sig_obj.get("key_id", "")) if isinstance(sig_obj, dict) else ""

    _public_console().print(
        Panel(
            "\n".join(
                [
                    f"[bold]File:[/bold] {filepath}",
                    f"[bold]Manifest:[/bold] {manifest_path}",
                    f"[bold]Mode:[/bold] {mode}",
                    f"[bold]Lines signed:[/bold] {total_lines}",
                    f"[bold]Root hash:[/bold] {root_short}",
                    f"[bold]Fingerprint:[/bold] {phrase}",
                    f"[bold]Signature:[/bold] {sig_val}",
                    f"[bold]Key ID:[/bold] {key_id}" if key_id else "",
                ]
            ).strip(),
            title="Log Signed",
        )
    )


def verify_log(
    filepath: str,
    manifest_path: str | None,
    out_path: str | None,
) -> None:
    resolved_manifest_path = manifest_path or _default_manifest_path(filepath)

    try:
        with open(resolved_manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError as e:
        raise click.ClickException(f"Manifest not found: {resolved_manifest_path}") from e
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid manifest JSON: {resolved_manifest_path}") from e

    mode = str(manifest.get("manifest_mode", "full") or "full").strip().lower()
    scheme = _normalize_chain_scheme(str(manifest.get("chain_scheme", CHAIN_SCHEME_V1)))

    sig_ok, sig_reason = verify_manifest_signature(manifest)
    sig_present = bool(manifest.get("signature"))

    sig_scheme = ""
    sig_key_id = ""
    if isinstance(manifest.get("signature"), dict):
        sig_scheme = str(manifest["signature"].get("scheme", ""))
        sig_key_id = str(manifest["signature"].get("key_id", ""))
    elif isinstance(manifest.get("signature"), str):
        sig_scheme = LEGACY_HMAC_SIGNATURE_SCHEME

    if not sig_present:
        _public_console().print(
            Panel(
                "[yellow]Warning: manifest is NOT signed. Integrity check can still run, but the manifest itself can be edited undetected.[/yellow]",
                title="Manifest Signature",
            )
        )

    if sig_present and not sig_ok:
        _public_console().print(
            Panel(
                f"[red]Manifest signature is INVALID ({sig_reason}). The manifest cannot be trusted.[/red]",
                title="Manifest Signature",
            )
        )
        raise SystemExit(2)

    current_chain_iter = _iter_hash_chain(filepath, chain_scheme=scheme)

    mismatches: list[TamperResult] = []

    if mode == "full":
        manifest_entries = manifest.get("entries", [])
        if not isinstance(manifest_entries, list):
            raise click.ClickException("Invalid manifest: entries must be a list")

        current_chain = list(current_chain_iter)

        manifest_len = len(manifest_entries)
        current_len = len(current_chain)
        overlap = min(manifest_len, current_len)

        for idx in range(overlap):
            expected_chain_hash = str(manifest_entries[idx].get("chain_hash", ""))
            actual_chain_hash = current_chain[idx].chain_hash
            line_number = idx + 1
            if expected_chain_hash != actual_chain_hash:
                mismatches.append(
                    TamperResult(
                        line_number=line_number,
                        expected_chain_hash=expected_chain_hash,
                        actual_chain_hash=actual_chain_hash,
                        status="TAMPERED",
                    )
                )

        if manifest_len > current_len:
            for idx in range(current_len, manifest_len):
                expected_chain_hash = str(manifest_entries[idx].get("chain_hash", ""))
                mismatches.append(
                    TamperResult(
                        line_number=idx + 1,
                        expected_chain_hash=expected_chain_hash,
                        actual_chain_hash="",
                        status="DELETED",
                    )
                )

        if current_len > manifest_len:
            for idx in range(manifest_len, current_len):
                mismatches.append(
                    TamperResult(
                        line_number=idx + 1,
                        expected_chain_hash="",
                        actual_chain_hash=current_chain[idx].chain_hash,
                        status="INSERTED",
                    )
                )

        current_root_hash = current_chain[-1].chain_hash if current_chain else ""
        current_total_lines = current_len

    else:
        checkpoints_raw = manifest.get("checkpoints", [])
        if not isinstance(checkpoints_raw, list):
            raise click.ClickException("Invalid manifest: checkpoints must be a list")

        checkpoints: list[CheckpointEntry] = []
        for item in checkpoints_raw:
            if not isinstance(item, dict):
                continue
            try:
                checkpoints.append(
                    CheckpointEntry(
                        line_number=int(item.get("line_number", 0)),
                        chain_hash=str(item.get("chain_hash", "")),
                    )
                )
            except Exception:
                continue

        checkpoints.sort(key=lambda c: c.line_number)

        expected_root_hash = str(manifest.get("root_hash", ""))
        expected_total_lines = int(manifest.get("total_lines", 0) or 0)

        # Stream the file and compare at checkpoint line numbers.
        checkpoint_map = {c.line_number: c.chain_hash for c in checkpoints if c.line_number > 0}
        last_entry: Optional[HashEntry] = None
        last_good_checkpoint = 0

        for entry in current_chain_iter:
            last_entry = entry
            expected = checkpoint_map.get(entry.line_number)
            if expected is not None and expected != entry.chain_hash:
                mismatches.append(
                    TamperResult(
                        line_number=entry.line_number,
                        expected_chain_hash=expected,
                        actual_chain_hash=entry.chain_hash,
                        status="CHECKPOINT_MISMATCH",
                        note=f"Mismatch detected; suspected tampering between lines {last_good_checkpoint + 1} and {entry.line_number}.",
                    )
                )
            if expected is not None and expected == entry.chain_hash:
                last_good_checkpoint = entry.line_number

        current_root_hash = last_entry.chain_hash if last_entry else ""
        current_total_lines = last_entry.line_number if last_entry else 0

        if expected_total_lines and expected_total_lines != current_total_lines:
            mismatches.append(
                TamperResult(
                    line_number=min(expected_total_lines, current_total_lines) + 1,
                    expected_chain_hash=str(expected_total_lines),
                    actual_chain_hash=str(current_total_lines),
                    status="LINECOUNT_MISMATCH",
                    note="File line count differs from manifest; insertions/deletions likely.",
                )
            )

        if expected_root_hash and expected_root_hash != current_root_hash:
            mismatches.append(
                TamperResult(
                    line_number=current_total_lines,
                    expected_chain_hash=expected_root_hash,
                    actual_chain_hash=current_root_hash,
                    status="ROOT_MISMATCH",
                    note="Root hash mismatch; file content differs from signed state.",
                )
            )

    report: Dict[str, Any] = {
        "file": filepath,
        "manifest": resolved_manifest_path,
        "signed_at": manifest.get("signed_at"),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "clean": len(mismatches) == 0,
        "issues_found": len(mismatches),
        "issues": [asdict(m) for m in mismatches],
        "manifest_total_lines": int(manifest.get("total_lines", 0) or 0),
        "current_total_lines": current_total_lines,
        "manifest_root_hash": manifest.get("root_hash", ""),
        "current_root_hash": current_root_hash,
        "manifest_fingerprint_phrase": fingerprint_phrase(str(manifest.get("root_hash", ""))),
        "current_fingerprint_phrase": fingerprint_phrase(current_root_hash),
        "manifest_signature": {
            "present": sig_present,
            "scheme": sig_scheme,
            "key_id": sig_key_id,
            "valid": sig_ok,
            "reason": sig_reason,
        },
        "manifest_mode": mode,
        "chain_scheme": scheme,
        "hash_algorithm": manifest.get("hash_algorithm", HASH_ALGORITHM),
    }

    if out_path is not None:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.write("\n")
        except OSError as e:
            raise click.ClickException(f"Unable to write report to: {out_path}") from e

    if not mismatches:
        manifest_phrase = report.get("manifest_fingerprint_phrase", "")
        current_phrase = report.get("current_fingerprint_phrase", "")
        fingerprint_lines = [f"[bold]Fingerprint:[/bold] {manifest_phrase}"]
        if manifest_phrase != current_phrase:
            fingerprint_lines = [
                f"[bold]Manifest fingerprint:[/bold] {manifest_phrase}",
                f"[bold]Current fingerprint:[/bold] {current_phrase}",
            ]

        _public_console().print(
            Panel(
                "\n".join(
                    [
                        "[green]Integrity verified. No tampering detected.[/green]",
                        *fingerprint_lines,
                    ]
                ),
                title="Integrity Check",
            )
        )
        return

    _public_console().print(
        Panel(
            f"[red]Tampering detected: {len(mismatches)} issue(s).[/red]",
            title="Integrity Check",
        )
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Line", justify="right")
    table.add_column("Status")
    table.add_column("Expected", justify="left")
    table.add_column("Actual", justify="left")

    for item in mismatches[:200]:
        if item.status in {"TAMPERED", "ROOT_MISMATCH", "CHECKPOINT_MISMATCH"}:
            style = "bold red"
        elif item.status in {"DELETED", "LINECOUNT_MISMATCH"}:
            style = "bold yellow"
        else:
            style = "bold cyan"

        expected_short = item.expected_chain_hash[:12] if item.expected_chain_hash else "-"
        actual_short = item.actual_chain_hash[:12] if item.actual_chain_hash else "-"
        table.add_row(str(item.line_number), item.status, expected_short, actual_short, style=style)

    _public_console().print(table)
    raise SystemExit(2)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract the first valid timestamp from a log line."""

    for match in re.finditer(r"\[([^\]]+)\]", line):
        bracket = match.group(1)
        if ":" not in bracket:
            continue
        if not any(ch.isdigit() for ch in bracket):
            continue

        normalized = bracket.strip().rstrip(",;")
        normalized = re.sub(r"(\d{2}/[A-Za-z]{3}/\d{4}):", r"\1 ", normalized, count=1)
        try:
            dt = dateutil_parser.parse(normalized, fuzzy=False)
            return _ensure_utc(dt)
        except (ParserError, ValueError):
            continue

    token_pattern = re.compile(r"[\w/:\[\]+\-\.,]+")
    tokens = token_pattern.findall(line)

    for i in range(len(tokens)):
        candidates: List[str] = [tokens[i]]

        if i + 1 < len(tokens):
            candidates.append(f"{tokens[i]} {tokens[i + 1]}")

        if i + 2 < len(tokens):
            candidates.append(f"{tokens[i]} {tokens[i + 1]} {tokens[i + 2]}")

        for candidate in candidates:
            if ":" not in candidate:
                continue
            if not any(ch.isdigit() for ch in candidate):
                continue
            if re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", candidate):
                continue

            normalized = candidate.strip("[]()").rstrip(",;")
            normalized = re.sub(r"(\d{2}/[A-Za-z]{3}/\d{4}):", r"\1 ", normalized, count=1)
            try:
                dt = dateutil_parser.parse(normalized, fuzzy=False)
                return _ensure_utc(dt)
            except (ParserError, ValueError):
                continue

    return None


def scan_log(filepath: str, gap_threshold: int) -> Tuple[List[SuspiciousGap], Dict[str, Any]]:
    gaps: List[SuspiciousGap] = []
    stats: Dict[str, Any] = {
        "file": filepath,
        "threshold_seconds": gap_threshold,
        "total_lines": 0,
        "malformed_lines": 0,
        "gaps_found": 0,
        "timestamps_found": 0,
        "timestamp_anomalies": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "max_gap_seconds": 0,
        "max_anomaly_seconds": 0,
    }

    prev_time: Optional[datetime] = None
    prev_line_num: Optional[int] = None
    gap_index = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            stats["total_lines"] += 1

            ts = extract_timestamp(line)
            if ts is None:
                stats["malformed_lines"] += 1
                continue

            stats["timestamps_found"] += 1
            if stats["first_timestamp"] is None:
                stats["first_timestamp"] = ts.isoformat()
            stats["last_timestamp"] = ts.isoformat()

            if prev_time is not None and prev_line_num is not None:
                if ts < prev_time:
                    gap_index += 1
                    duration = int(abs((ts - prev_time).total_seconds()))
                    stats["timestamp_anomalies"] += 1
                    if duration > int(stats.get("max_anomaly_seconds") or 0):
                        stats["max_anomaly_seconds"] = duration
                    gaps.append(
                        SuspiciousGap(
                            gap_index=gap_index,
                            gap_start=prev_time,
                            gap_end=ts,
                            duration_seconds=duration,
                            line_start=prev_line_num,
                            line_end=line_num,
                            note="TIMESTAMP_ANOMALY",
                        )
                    )
                else:
                    delta = (ts - prev_time).total_seconds()
                    if delta > gap_threshold:
                        gap_index += 1
                        if int(delta) > int(stats.get("max_gap_seconds") or 0):
                            stats["max_gap_seconds"] = int(delta)
                        gaps.append(
                            SuspiciousGap(
                                gap_index=gap_index,
                                gap_start=prev_time,
                                gap_end=ts,
                                duration_seconds=int(delta),
                                line_start=prev_line_num,
                                line_end=line_num,
                                note=None,
                            )
                        )

            prev_time = ts
            prev_line_num = line_num

    stats["gaps_found"] = len(gaps)
    return gaps, stats


def format_duration(seconds: int) -> str:
    if seconds < 0:
        seconds = -seconds

    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: List[str] = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def _open_output(path: Optional[str]):
    if path is None:
        return click.get_text_stream("stdout")
    return click.open_file(path, mode="w", encoding="utf-8")


def report_terminal(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    summary_lines = [
        f"[bold]File:[/bold] {stats['file']}",
        f"[bold]Total lines:[/bold] {stats['total_lines']}",
        f"[bold]Malformed lines:[/bold] {stats['malformed_lines']}",
        f"[bold]Gap threshold:[/bold] {stats['threshold_seconds']} seconds",
        f"[bold]Suspicious gaps found:[/bold] {stats['gaps_found']}",
    ]
    header_panel = Panel("\n".join(summary_lines), title="Evidence Protector Report")

    def _render(target_console: Console) -> None:
        target_console.print(header_panel)

        if not gaps:
            target_console.print("[green]No suspicious gaps found.[/green]")
            return

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("#", justify="right")
        table.add_column("Gap Start")
        table.add_column("Gap End")
        table.add_column("Duration")
        table.add_column("Start Line", justify="right")
        table.add_column("End Line", justify="right")
        table.add_column("Note")

        for gap in gaps:
            is_anomaly = gap.note == "TIMESTAMP_ANOMALY"
            duration_style = "yellow" if gap.duration_seconds > 3600 else "cyan"
            duration_text = f"[{duration_style}]{format_duration(gap.duration_seconds)}[/{duration_style}]"
            note_text = "[bold red]TIMESTAMP_ANOMALY[/bold red]" if is_anomaly else ""
            row_style = "bold red" if is_anomaly else None

            table.add_row(
                str(gap.gap_index),
                gap.gap_start.isoformat(),
                gap.gap_end.isoformat(),
                duration_text,
                str(gap.line_start),
                str(gap.line_end),
                note_text,
                style=row_style,
            )

        target_console.print(table)

    _render(_public_console())

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            file_console = Console(file=f, no_color=True, force_terminal=False)
            _render(file_console)


def report_csv(gaps: List[SuspiciousGap], _stats: Dict[str, Any], args: argparse.Namespace) -> None:
    fieldnames = [
        "gap_index",
        "gap_start",
        "gap_end",
        "duration_seconds",
        "line_start",
        "line_end",
        "note",
    ]

    with _open_output(args.out) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for gap in gaps:
            writer.writerow(
                {
                    "gap_index": gap.gap_index,
                    "gap_start": gap.gap_start.isoformat(),
                    "gap_end": gap.gap_end.isoformat(),
                    "duration_seconds": gap.duration_seconds,
                    "line_start": gap.line_start,
                    "line_end": gap.line_end,
                    "note": gap.note or "",
                }
            )


def report_json(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    data: Dict[str, Any] = {
        "file": stats["file"],
        "threshold_seconds": stats["threshold_seconds"],
        "total_lines": stats["total_lines"],
        "malformed_lines": stats["malformed_lines"],
        "gaps_found": stats["gaps_found"],
        "suspicious_gaps": [],
    }

    for gap in gaps:
        gap_dict = asdict(gap)
        gap_dict["gap_start"] = gap.gap_start.isoformat()
        gap_dict["gap_end"] = gap.gap_end.isoformat()
        data["suspicious_gaps"].append(gap_dict)

    if args.out is None:
        click.echo(json.dumps(data, indent=2))
        return

    with _open_output(args.out) as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _run_scan(file: str, gap: int, output_format: str, out: Optional[str]) -> None:
    args = SimpleNamespace(file=file, gap=gap, format=output_format, out=out)

    gaps, stats = scan_log(args.file, args.gap)

    if stats.get("timestamps_found", 0) == 0:
        click.echo(f"Warning: no parseable timestamps found in file: {args.file}", err=True)
        return

    if args.format == "terminal":
        report_terminal(gaps, stats, args)
    elif args.format == "csv":
        report_csv(gaps, stats, args)
    elif args.format == "json":
        report_json(gaps, stats, args)
    else:
        raise click.BadParameter(f"Unknown format: {args.format}")
