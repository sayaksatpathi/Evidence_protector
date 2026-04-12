"""Evidence Protector: Automated Log Integrity Monitor.

This tool scans log files for suspicious time gaps between entries and produces
forensic-style reports.

Integrity workflow examples:

# Sign a log (creates system.manifest.json)
python evidence_protector.py --file system.log --mode sign

# Verify integrity against saved manifest
python evidence_protector.py --file system.log --mode verify

# Verify integrity against a specific manifest file
python evidence_protector.py --file system.log --mode verify --manifest system.manifest.json

# Verify integrity and write a JSON tamper report
python evidence_protector.py --file system.log --mode verify --out verify_report.json

# Full forensic workflow: sign first, then gap-scan
python evidence_protector.py --file system.log --mode sign
python evidence_protector.py --file system.log --mode scan --format terminal
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from types import SimpleNamespace
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import click
from dateutil import parser as dateutil_parser
from dateutil.parser import ParserError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    import argparse


console = Console()


SIGNATURE_SCHEME = "hmac-sha256"
ENV_SIGNING_KEY_B64 = "EVIDENCE_PROTECTOR_SIGNING_KEY_B64"
ENV_SIGNING_KEY_PATH = "EVIDENCE_PROTECTOR_SIGNING_KEY_PATH"


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
    """Return a short, human-readable phrase derived from a hash.

    This is meant for quick verbal / eyeball checks: if the hash matches,
    the phrase will match (deterministically).
    """

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
    """Serialize as canonical JSON bytes for signing.

    Important properties:
    - Stable key ordering via sort_keys
    - No whitespace via separators
    - UTF-8 bytes output (not ASCII-escaped) for deterministic signing
    """

    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def _default_signing_key_path() -> Path:
    base = Path.home() / ".evidence_protector"
    return base / "signing_key.b64"


def _load_or_create_signing_key() -> bytes:
    """Return the server-side signing key used to authenticate manifests.

    Priority:
    1) `EVIDENCE_PROTECTOR_SIGNING_KEY_B64` (base64)
    2) `EVIDENCE_PROTECTOR_SIGNING_KEY_PATH` (base64 in file)
    3) `~/.evidence_protector/signing_key.b64` (auto-created if missing)

    Note: this is an HMAC key (symmetric). Keep it private.
    """

    key_b64 = os.getenv(ENV_SIGNING_KEY_B64)
    if key_b64:
        try:
            return base64.b64decode(key_b64.encode("utf-8"), validate=True)
        except Exception as e:
            raise ValueError(f"Invalid {ENV_SIGNING_KEY_B64} (must be base64): {e}") from e

    path = Path(os.getenv(ENV_SIGNING_KEY_PATH, "")).expanduser() if os.getenv(ENV_SIGNING_KEY_PATH) else None
    key_path = path if path else _default_signing_key_path()

    if key_path.exists():
        raw = key_path.read_text(encoding="utf-8").strip()
        try:
            return base64.b64decode(raw.encode("utf-8"), validate=True)
        except Exception as e:
            raise ValueError(f"Invalid signing key file (expected base64): {key_path}") from e

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

    Returns:
      {"scheme": "hmac-sha256", "value": "<base64>"}
    """

    key = _load_or_create_signing_key()
    payload = _manifest_payload_for_signature(manifest)
    mac = hmac.new(key, _canonical_json_bytes(payload), hashlib.sha256).digest()
    return {"scheme": SIGNATURE_SCHEME, "value": base64.b64encode(mac).decode("utf-8")}


def verify_manifest_signature(manifest: Dict[str, Any]) -> tuple[bool, str]:
    """Verify the signature on a manifest.

    Returns (ok, reason):
      - (True, "ok")
      - (False, "missing")
      - (False, "invalid")
      - (False, "unsupported-scheme")
      - (False, "error")
    """

    sig = manifest.get("signature")
    if not sig:
        return False, "missing"

    if isinstance(sig, str):
        scheme = SIGNATURE_SCHEME
        sig_value = sig
    elif isinstance(sig, dict):
        scheme = str(sig.get("scheme", ""))
        sig_value = str(sig.get("value", ""))
    else:
        return False, "invalid"

    if scheme != SIGNATURE_SCHEME:
        return False, "unsupported-scheme"

    try:
        expected = compute_manifest_signature(manifest)["value"]
        ok = hmac.compare_digest(expected, sig_value)
        return ok, "ok" if ok else "invalid"
    except Exception:
        return False, "error"


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
class TamperResult:
    line_number: int
    expected_chain_hash: str
    actual_chain_hash: str
    status: str


def _default_manifest_path(filepath: str) -> str:
    """Return the default manifest path for a given log file."""

    return str(Path(filepath).with_suffix(".manifest.json"))


def build_hash_chain(filepath: str) -> list[HashEntry]:
    """Read file line by line, build and return the full hash chain.

    Algorithm:
      prev_hash = "" (empty string for the genesis/first line)
      for each line:
          line_hash  = sha256(line.encode()).hexdigest()
          chain_hash = sha256((line + prev_hash).encode()).hexdigest()
          prev_hash  = chain_hash
    """

    entries: list[HashEntry] = []
    prev_hash = ""

    # Use surrogateescape so non-UTF8 bytes are preserved (no lossy "?" replacement).
    # Keep universal newlines to reduce cross-platform surprises for CRLF vs LF.
    with open(filepath, "r", encoding="utf-8", errors="surrogateescape", newline=None) as f:
        for line_number, line in enumerate(f, start=1):
            line_bytes = line.encode("utf-8", errors="surrogateescape")
            prev_bytes = prev_hash.encode("utf-8")
            line_hash = hashlib.sha256(line_bytes).hexdigest()
            chain_hash = hashlib.sha256(line_bytes + prev_bytes).hexdigest()
            entries.append(HashEntry(line_number=line_number, line_hash=line_hash, chain_hash=chain_hash))
            prev_hash = chain_hash

    return entries


def sign_log(filepath: str, out_path: str | None) -> None:
    """Build hash chain and write manifest JSON.

    Manifest structure:
    {
      "file": str,
      "signed_at": ISO UTC timestamp,
      "total_lines": int,
      "root_hash": str,
      "entries": [
        { "line_number": int, "line_hash": str, "chain_hash": str },
        ...
      ]
    }

    Output path: if --out is given use it, else write to <file>.manifest.json.
    Prints a rich Panel summary: file, lines signed, root hash (first 16 chars).
    """

    manifest_path = out_path or _default_manifest_path(filepath)
    entries = build_hash_chain(filepath)
    root_hash = entries[-1].chain_hash if entries else ""
    phrase = fingerprint_phrase(root_hash)

    payload: Dict[str, Any] = {
        "manifest_version": 2,
        "file": filepath,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "total_lines": len(entries),
        "root_hash": root_hash,
        "fingerprint_phrase": phrase,
        "entries": [asdict(e) for e in entries],
    }

    # Cryptographically authenticate the manifest so it cannot be modified undetected.
    try:
        payload["signature"] = compute_manifest_signature(payload)
    except Exception as e:
        raise click.ClickException(f"Unable to sign manifest: {e}") from e

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    root_short = root_hash[:16] if root_hash else "(empty)"
    signature_short = str(payload.get("signature", {}).get("value", ""))[:16] or "(missing)"
    console.print(
        Panel(
            "\n".join(
                [
                    f"[bold]File:[/bold] {filepath}",
                    f"[bold]Manifest:[/bold] {manifest_path}",
                    f"[bold]Lines signed:[/bold] {len(entries)}",
                    f"[bold]Root hash:[/bold] {root_short}",
                    f"[bold]Fingerprint:[/bold] {phrase}",
                    f"[bold]Signature:[/bold] {signature_short}",
                ]
            ),
            title="Log Signed",
        )
    )


def verify_log(filepath: str, manifest_path: str | None, out_path: str | None) -> None:
    """Recompute hash chain and compare against saved manifest.

    Steps:
    1. Load manifest from <file>.manifest.json (or --manifest path).
    2. Recompute build_hash_chain(filepath).
    3. Compare entry by entry:
         - chain_hash mismatch on existing line  → TAMPERED
         - manifest has entry but file line gone  → DELETED
         - file has extra lines not in manifest   → INSERTED
    4. Collect all mismatches into list[TamperResult].
    5. Print results with rich:
         - If clean: green Panel "Integrity verified. No tampering detected."
         - If issues: red Panel with count, then Table of TamperResult rows.
           Table columns: Line | Status | Expected Hash (first 12) | Actual Hash (first 12)
           TAMPERED rows → bold red, DELETED rows → bold yellow, INSERTED → bold cyan
    6. If --out is provided, write a JSON tamper report.
    7. Exit code 0 if clean, exit code 2 if any tampering found.
    """

    resolved_manifest_path = manifest_path or _default_manifest_path(filepath)

    try:
        with open(resolved_manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError as e:
        raise click.ClickException(f"Manifest not found: {resolved_manifest_path}") from e
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid manifest JSON: {resolved_manifest_path}") from e

    manifest_entries = manifest.get("entries", [])
    if not isinstance(manifest_entries, list):
        raise click.ClickException("Invalid manifest: entries must be a list")

    sig_ok, sig_reason = verify_manifest_signature(manifest)
    sig_present = bool(manifest.get("signature"))
    sig_scheme = str(manifest.get("signature", {}).get("scheme", "")) if isinstance(manifest.get("signature"), dict) else SIGNATURE_SCHEME

    current_chain = build_hash_chain(filepath)

    mismatches: list[TamperResult] = []
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

    report: Dict[str, Any] = {
        "file": filepath,
        "manifest": resolved_manifest_path,
        "signed_at": manifest.get("signed_at"),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "clean": len(mismatches) == 0,
        "issues_found": len(mismatches),
        "issues": [asdict(m) for m in mismatches],
        "manifest_total_lines": manifest_len,
        "current_total_lines": current_len,
        "manifest_root_hash": manifest.get("root_hash", ""),
        "current_root_hash": current_chain[-1].chain_hash if current_chain else "",
        "manifest_fingerprint_phrase": fingerprint_phrase(str(manifest.get("root_hash", ""))),
        "current_fingerprint_phrase": fingerprint_phrase(current_chain[-1].chain_hash if current_chain else ""),
        "manifest_signature": {
            "present": sig_present,
            "scheme": sig_scheme,
            "valid": sig_ok,
            "reason": sig_reason,
        },
    }

    if out_path is not None:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.write("\n")
        except OSError as e:
            raise click.ClickException(f"Unable to write report to: {out_path}") from e

    if not sig_present:
        console.print(
            Panel(
                "[yellow]Warning: manifest is NOT signed. Integrity check can still run, but the manifest itself can be edited undetected.[/yellow]",
                title="Manifest Signature",
            )
        )
    elif not sig_ok:
        # Signature invalid: treat as tampering (manifest cannot be trusted).
        report["clean"] = False
        if out_path is not None:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
                    f.write("\n")
            except OSError as e:
                raise click.ClickException(f"Unable to write report to: {out_path}") from e

        console.print(
            Panel(
                "[red]Manifest signature is INVALID. The manifest cannot be trusted.[/red]",
                title="Manifest Signature",
            )
        )
        raise SystemExit(2)

    if not mismatches:
        manifest_phrase = report.get("manifest_fingerprint_phrase", "")
        current_phrase = report.get("current_fingerprint_phrase", "")
        fingerprint_lines = [f"[bold]Fingerprint:[/bold] {manifest_phrase}"]
        if manifest_phrase != current_phrase:
            fingerprint_lines = [
                f"[bold]Manifest fingerprint:[/bold] {manifest_phrase}",
                f"[bold]Current fingerprint:[/bold] {current_phrase}",
            ]

        console.print(
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

    console.print(
        Panel(
            f"[red]Tampering detected: {len(mismatches)} issue(s).[/red]",
            title="Integrity Check",
        )
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Line", justify="right")
    table.add_column("Status")
    table.add_column("Expected Hash", justify="left")
    table.add_column("Actual Hash", justify="left")

    for item in mismatches:
        if item.status == "TAMPERED":
            style = "bold red"
        elif item.status == "DELETED":
            style = "bold yellow"
        else:
            style = "bold cyan"

        expected_short = item.expected_chain_hash[:12] if item.expected_chain_hash else "-"
        actual_short = item.actual_chain_hash[:12] if item.actual_chain_hash else "-"
        table.add_row(str(item.line_number), item.status, expected_short, actual_short, style=style)

    console.print(table)
    raise SystemExit(2)


def _ensure_utc(dt: datetime) -> datetime:
    """Return a timezone-aware datetime in UTC."""

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract the first valid timestamp from a log line.

    Supported formats (checked in order):
      - ISO 8601: 2024-01-15T14:23:01 or 2024-01-15 14:23:01 (with optional offset)
      - Apache/Nginx: [15/Jan/2024:14:23:01 +0000]
      - Apache error log: [Sun Dec 04 04:47:44 2005]
      - Syslog: Jan 15 14:23:01 (assumes current UTC year)
    """

    # Fast-path: many log formats wrap the timestamp in [brackets].
    # Examples:
    #   Apache access: [27/Dec/2037:12:00:00 +0530]
    #   Apache error : [Sun Dec 04 04:47:44 2005]
    for match in re.finditer(r"\[([^\]]+)\]", line):
        bracket = match.group(1)
        if ":" not in bracket:
            continue
        if " " not in bracket:
            continue
        if not any(ch.isdigit() for ch in bracket):
            continue

        normalized = bracket
        # Normalize common Apache/Nginx format: 15/Jan/2024:14:23:01 +0000
        normalized = re.sub(
            r"(\d{2}/[A-Za-z]{3}/\d{4}):",
            r"\1 ",
            normalized,
            count=1,
        )
        try:
            dt = dateutil_parser.parse(normalized, fuzzy=False)
            return _ensure_utc(dt)
        except (ParserError, ValueError):
            continue

    token_pattern = re.compile(r"[\w/:\[\]+\-]+")
    tokens = token_pattern.findall(line)

    for i in range(len(tokens)):
        candidates: List[str] = [tokens[i]]

        if i + 1 < len(tokens):
            candidates.append(f"{tokens[i]} {tokens[i + 1]}")

        # Practical extension: allow 3-token candidates so common syslog formats
        # like "Jan 15 14:23:01" remain parseable with fuzzy=False.
        if i + 2 < len(tokens):
            candidates.append(f"{tokens[i]} {tokens[i + 1]} {tokens[i + 2]}")

        for candidate in candidates:
            # Avoid accepting overly-short parses (e.g., "Jan") that dateutil
            # will interpret using today's day/time.
            if ":" not in candidate:
                continue
            if not any(ch.isdigit() for ch in candidate):
                continue
            if re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", candidate):
                continue

            normalized = candidate.strip("[]")
            # Normalize common Apache/Nginx format: 15/Jan/2024:14:23:01 +0000
            normalized = re.sub(
                r"(\d{2}/[A-Za-z]{3}/\d{4}):",
                r"\1 ",
                normalized,
                count=1,
            )
            try:
                dt = dateutil_parser.parse(normalized, fuzzy=False)
                return _ensure_utc(dt)
            except (ParserError, ValueError):
                continue

    return None


def scan_log(filepath: str, gap_threshold: int) -> Tuple[List[SuspiciousGap], Dict[str, Any]]:
    """Scan the log file for suspicious gaps.

    Returns a list of `SuspiciousGap` objects and a stats dictionary.
    """

    gaps: List[SuspiciousGap] = []
    stats: Dict[str, Any] = {
        "file": filepath,
        "threshold_seconds": gap_threshold,
        "total_lines": 0,
        "malformed_lines": 0,
        "gaps_found": 0,
        "timestamps_found": 0,
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

            if prev_time is not None and prev_line_num is not None:
                if ts < prev_time:
                    # Timestamp anomaly: backwards in time
                    gap_index += 1
                    duration = int(abs((ts - prev_time).total_seconds()))
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
    """Format a duration in seconds into a human-readable string."""

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
    """Return a file-like object for output (stdout if path is None)."""

    if path is None:
        return click.get_text_stream("stdout")
    return click.open_file(path, mode="w", encoding="utf-8")


def report_terminal(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    """Print a formatted summary report to stdout and optionally to a file."""

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

    _render(console)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            file_console = Console(file=f, no_color=True, force_terminal=False)
            _render(file_console)


def report_csv(gaps: List[SuspiciousGap], _stats: Dict[str, Any], args: argparse.Namespace) -> None:
    """Write suspicious gaps to CSV (stdout or file)."""

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
    """Write a JSON report with overall stats and suspicious gaps."""

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
        # Should not happen because click restricts choices
        raise click.BadParameter(f"Unknown format: {args.format}")

@click.group(invoke_without_command=True)
@click.option(
    "--file",
    required=False,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "csv", "json"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output file path (scan report | sign manifest | verify JSON report)",
)
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Manifest JSON path (verify mode)",
)
@click.option(
    "--mode",
    type=click.Choice(["scan", "sign", "verify"]),
    default="scan",
    show_default=True,
    help="scan=gap detection only | sign=build manifest | verify=check manifest",
)
def main(file: Optional[str], gap: int, output_format: str, out: Optional[str], manifest: Optional[str], mode: str) -> None:
    """Evidence Protector CLI.

    Preferred (subcommands):
      - evidence_protector scan --file app.log
      - evidence_protector sign --file app.log
      - evidence_protector verify --file app.log

    Legacy (still supported):
      - evidence_protector --file app.log --mode scan|sign|verify
    """

    # If a subcommand is provided, let it handle its own options.
    ctx = click.get_current_context(silent=True)
    if ctx is not None and ctx.invoked_subcommand is not None:
        return

    if not file:
        raise click.UsageError("Missing option '--file'.")

    if mode == "sign":
        sign_log(file, out)
        return
    if mode == "verify":
        verify_log(file, manifest, out)
        return

    _run_scan(file, gap, output_format, out)


@main.command("scan")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "csv", "json"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output file path (scan report)",
)
def scan_cmd(file: str, gap: int, output_format: str, out: Optional[str]) -> None:
    """Scan a log for suspicious time gaps."""

    _run_scan(file, gap, output_format, out)


@main.command("sign")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output manifest path (defaults to <file>.manifest.json)",
)
def sign_cmd(file: str, out: Optional[str]) -> None:
    """Create a signed manifest for a log."""

    sign_log(file, out)


@main.command("verify")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Manifest JSON path (defaults to <file>.manifest.json)",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output JSON report path (optional)",
)
def verify_cmd(file: str, manifest: Optional[str], out: Optional[str]) -> None:
    """Verify a log against a saved manifest."""

    verify_log(file, manifest, out)


if __name__ == "__main__":
    main()
