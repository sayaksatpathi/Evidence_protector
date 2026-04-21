from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple


COMMITMENTS_VERSION = 1

ANCHOR_STATEMENT_VERSION = 1


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json_bytes(value: Any) -> bytes:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def default_register_path() -> str:
    base = Path.home() / ".evidence_protector"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "commitments.jsonl")


@dataclass(frozen=True)
class CommitmentEntry:
    version: int
    committed_at: str
    file: str
    size_bytes: int
    mtime_epoch: float
    file_sha256: str
    note: str
    prev_entry_hash: str
    entry_hash: str


def _entry_hash(payload: Dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json_bytes(payload))


def iter_commitments(register_path: str) -> Iterator[Dict[str, Any]]:
    p = Path(register_path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def append_commitment(
    *,
    file_path: str,
    register_path: Optional[str] = None,
    note: str = "",
) -> CommitmentEntry:
    reg = register_path or default_register_path()
    p = Path(file_path)
    st = p.stat()

    prev_hash = ""
    last = None
    for item in iter_commitments(reg):
        last = item
    if isinstance(last, dict):
        prev_hash = str(last.get("entry_hash", ""))

    payload: Dict[str, Any] = {
        "version": COMMITMENTS_VERSION,
        "committed_at": _now_utc_iso(),
        "file": str(p),
        "size_bytes": int(st.st_size),
        "mtime_epoch": float(st.st_mtime),
        "file_sha256": compute_file_sha256(str(p)),
        "note": note,
        "prev_entry_hash": prev_hash,
    }
    entry_hash = _entry_hash(payload)
    payload["entry_hash"] = entry_hash

    Path(reg).parent.mkdir(parents=True, exist_ok=True)
    with open(reg, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")

    return CommitmentEntry(**payload)  # type: ignore[arg-type]


def verify_commitments(register_path: str) -> Tuple[bool, str]:
    prev_hash = ""
    idx = 0
    for item in iter_commitments(register_path):
        idx += 1
        if not isinstance(item, dict):
            return False, f"Invalid entry at line {idx}"

        expected_prev = str(item.get("prev_entry_hash", ""))
        if expected_prev != prev_hash:
            return False, f"Broken chain at line {idx} (prev hash mismatch)"

        entry_hash = str(item.get("entry_hash", ""))
        payload = dict(item)
        payload.pop("entry_hash", None)
        expected_hash = _entry_hash(payload)
        if expected_hash != entry_hash:
            return False, f"Entry hash mismatch at line {idx}"

        prev_hash = entry_hash

    return True, "ok"


def export_anchor(register_path: str, out_path: str) -> Dict[str, Any]:
    last_hash = ""
    count = 0
    for item in iter_commitments(register_path):
        count += 1
        last_hash = str(item.get("entry_hash", last_hash))

    anchor = {
        "version": 1,
        "created_at": _now_utc_iso(),
        "method": "export-v1",
        "register": str(register_path),
        "commitment_count": count,
        "anchor_hash": last_hash,
    }

    Path(out_path).write_text(json.dumps(anchor, indent=2) + "\n", encoding="utf-8")
    return anchor


def build_anchor_statement(register_path: str) -> Dict[str, Any]:
    """Build a portable anchor statement for external witnessing.

    This is meant to be copy/pasted or posted to an external medium (email, chat,
    ticket, etc.) so that the current commitment chain tip is independently
    timestamped/witnessed.
    """

    last_hash = ""
    count = 0
    for item in iter_commitments(register_path):
        count += 1
        last_hash = str(item.get("entry_hash", last_hash))

    register_sha256 = ""
    try:
        if Path(register_path).exists():
            register_sha256 = compute_file_sha256(register_path)
    except Exception:
        register_sha256 = ""

    return {
        "version": ANCHOR_STATEMENT_VERSION,
        "created_at": _now_utc_iso(),
        "method": "statement-v1",
        "register": str(register_path),
        "register_sha256": register_sha256,
        "commitment_count": count,
        "anchor_hash": last_hash,
    }


def render_anchor_statement_text(statement: Dict[str, Any]) -> str:
    """Render a one-line statement designed for external posting."""

    created_at = str(statement.get("created_at", ""))
    anchor_hash = str(statement.get("anchor_hash", ""))
    count = int(statement.get("commitment_count", 0) or 0)
    reg_sha = str(statement.get("register_sha256", ""))
    return f"GHOST-ANCHOR v1 created_at={created_at} count={count} anchor={anchor_hash} register_sha256={reg_sha}".strip() + "\n"


def export_anchor_statement(register_path: str, out_path: str) -> Dict[str, Any]:
    statement = build_anchor_statement(register_path)
    out = dict(statement)
    out["statement_text"] = render_anchor_statement_text(statement)
    Path(out_path).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def append_witness(
    *,
    register_path: str,
    witness_log_path: str,
    channel: str = "manual",
    note: str = "",
) -> Dict[str, Any]:
    """Append a witness record (JSONL) for the current anchor tip."""

    statement = build_anchor_statement(register_path)
    witness: Dict[str, Any] = {
        "version": 1,
        "witnessed_at": _now_utc_iso(),
        "channel": channel,
        "note": note,
        "statement": statement,
        "statement_text": render_anchor_statement_text(statement),
    }

    p = Path(witness_log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(witness, sort_keys=True) + "\n")

    return witness


def verify_witnesses(register_path: str, witness_log_path: str) -> Tuple[bool, str]:
    """Verify at least one witness matches the current anchor tip."""

    current = build_anchor_statement(register_path)
    current_hash = str(current.get("anchor_hash", ""))
    current_count = int(current.get("commitment_count", 0) or 0)
    current_reg_sha = str(current.get("register_sha256", ""))

    p = Path(witness_log_path)
    if not p.exists():
        return False, "witness log not found"

    matches = 0
    total = 0
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                item = json.loads(line)
            except Exception:
                continue
            st = item.get("statement")
            if not isinstance(st, dict):
                continue
            if str(st.get("anchor_hash", "")) != current_hash:
                continue
            if int(st.get("commitment_count", 0) or 0) != current_count:
                continue
            reg_sha = str(st.get("register_sha256", ""))
            # If we were able to compute the register hash now, require it to match.
            if current_reg_sha and reg_sha and reg_sha != current_reg_sha:
                continue
            matches += 1

    if matches > 0:
        return True, f"ok ({matches} matching witness record(s) out of {total})"
    return False, f"no witness matches current anchor (checked {total} record(s))"


def build_anchor_statement(register_path: str) -> Dict[str, Any]:
    """Build a portable anchor statement for external witnessing.

    This is meant to be copy/pasted or posted to an external medium (email, chat,
    ticket, etc.) so that the current commitment chain tip is independently
    timestamped/witnessed.
    """

    last_hash = ""
    count = 0
    for item in iter_commitments(register_path):
        count += 1
        last_hash = str(item.get("entry_hash", last_hash))

    register_sha256 = ""
    try:
        if Path(register_path).exists():
            register_sha256 = compute_file_sha256(register_path)
    except Exception:
        register_sha256 = ""

    return {
        "version": ANCHOR_STATEMENT_VERSION,
        "created_at": _now_utc_iso(),
        "method": "statement-v1",
        "register": str(register_path),
        "register_sha256": register_sha256,
        "commitment_count": count,
        "anchor_hash": last_hash,
    }


def render_anchor_statement_text(statement: Dict[str, Any]) -> str:
    """Render a one-line statement designed for external posting."""

    created_at = str(statement.get("created_at", ""))
    anchor_hash = str(statement.get("anchor_hash", ""))
    count = int(statement.get("commitment_count", 0) or 0)
    reg_sha = str(statement.get("register_sha256", ""))
    return f"GHOST-ANCHOR v1 created_at={created_at} count={count} anchor={anchor_hash} register_sha256={reg_sha}".strip() + "\n"


def export_anchor_statement(register_path: str, out_path: str) -> Dict[str, Any]:
    statement = build_anchor_statement(register_path)
    out = dict(statement)
    out["statement_text"] = render_anchor_statement_text(statement)
    Path(out_path).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def append_witness(
    *,
    register_path: str,
    witness_log_path: str,
    channel: str = "manual",
    note: str = "",
) -> Dict[str, Any]:
    """Append a witness record (JSONL) for the current anchor tip."""

    statement = build_anchor_statement(register_path)
    witness: Dict[str, Any] = {
        "version": 1,
        "witnessed_at": _now_utc_iso(),
        "channel": channel,
        "note": note,
        "statement": statement,
        "statement_text": render_anchor_statement_text(statement),
    }

    p = Path(witness_log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(witness, sort_keys=True) + "\n")

    return witness


def verify_witnesses(register_path: str, witness_log_path: str) -> Tuple[bool, str]:
    """Verify at least one witness matches the current anchor tip."""

    current = build_anchor_statement(register_path)
    current_hash = str(current.get("anchor_hash", ""))
    current_count = int(current.get("commitment_count", 0) or 0)
    current_reg_sha = str(current.get("register_sha256", ""))

    p = Path(witness_log_path)
    if not p.exists():
        return False, "witness log not found"

    matches = 0
    total = 0
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                item = json.loads(line)
            except Exception:
                continue
            st = item.get("statement")
            if not isinstance(st, dict):
                continue
            if str(st.get("anchor_hash", "")) != current_hash:
                continue
            if int(st.get("commitment_count", 0) or 0) != current_count:
                continue
            reg_sha = str(st.get("register_sha256", ""))
            # If we were able to compute the register hash now, require it to match.
            if current_reg_sha and reg_sha and reg_sha != current_reg_sha:
                continue
            matches += 1

    if matches > 0:
        return True, f"ok ({matches} matching witness record(s) out of {total})"
    return False, f"no witness matches current anchor (checked {total} record(s))"


def verify_anchor(register_path: str, anchor_path: str) -> Tuple[bool, str]:
    raw = json.loads(Path(anchor_path).read_text(encoding="utf-8"))
    expected = str(raw.get("anchor_hash", ""))

    last_hash = ""
    for item in iter_commitments(register_path):
        last_hash = str(item.get("entry_hash", last_hash))

    if expected and expected == last_hash:
        return True, "ok"
    return False, "anchor mismatch"
