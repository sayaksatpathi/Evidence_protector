from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


RECEIPTS_VERSION = 1


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class HostReceipt:
    hostname: str
    user: str
    platform: str
    platform_release: str
    platform_version: str
    python_version: str
    pid: int


@dataclass(frozen=True)
class FileReceipt:
    path: str
    size_bytes: int
    mtime_epoch: float
    ctime_epoch: float
    inode: Optional[int]

    # Optional digests (cheap sampling)
    head_sha256: Optional[str] = None
    tail_sha256: Optional[str] = None


@dataclass(frozen=True)
class ReceiptEnvelope:
    version: int
    created_at: str
    kind: str
    host: HostReceipt
    data: Dict[str, Any]


def collect_host_receipt() -> HostReceipt:
    try:
        user = os.getlogin()
    except Exception:
        user = os.getenv("USERNAME") or os.getenv("USER") or "unknown"

    return HostReceipt(
        hostname=socket.gethostname(),
        user=user,
        platform=platform.system(),
        platform_release=platform.release(),
        platform_version=platform.version(),
        python_version=platform.python_version(),
        pid=os.getpid(),
    )


def _sha256_of_bytes(data: bytes) -> str:
    import hashlib

    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _sample_head_tail_sha256(path: str, *, sample_bytes: int = 64 * 1024) -> tuple[Optional[str], Optional[str]]:
    try:
        p = Path(path)
        size = p.stat().st_size
        with p.open("rb") as f:
            head = f.read(min(sample_bytes, size))
            tail = b""
            if size > 0:
                f.seek(max(0, size - sample_bytes))
                tail = f.read(min(sample_bytes, size))
        return _sha256_of_bytes(head) if head else None, _sha256_of_bytes(tail) if tail else None
    except Exception:
        return None, None


def collect_file_receipt(path: str, *, include_samples: bool = True) -> FileReceipt:
    p = Path(path)
    st = p.stat()
    inode: Optional[int]
    try:
        inode = int(getattr(st, "st_ino", 0)) or None
    except Exception:
        inode = None

    head, tail = (None, None)
    if include_samples:
        head, tail = _sample_head_tail_sha256(str(p))

    return FileReceipt(
        path=str(p),
        size_bytes=int(st.st_size),
        mtime_epoch=float(st.st_mtime),
        ctime_epoch=float(getattr(st, "st_ctime", st.st_mtime)),
        inode=inode,
        head_sha256=head,
        tail_sha256=tail,
    )


def _run_cmd_best_effort(cmd: list[str], *, timeout_seconds: int = 4) -> Optional[str]:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout_seconds)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None


def collect_process_snapshot(*, max_chars: int = 60_000) -> Optional[str]:
    """Return a best-effort process list snapshot.

    Uses stdlib only; output is kept as a raw string to avoid OS-specific parsers.
    """

    system = platform.system().lower()
    if system.startswith("win"):
        out = _run_cmd_best_effort(["tasklist", "/fo", "csv"])
    else:
        out = _run_cmd_best_effort(["ps", "-eo", "pid,ppid,comm,args"])

    if out is None:
        return None
    return out[:max_chars]


def collect_netstat_snapshot(*, max_chars: int = 60_000) -> Optional[str]:
    system = platform.system().lower()
    if system.startswith("win"):
        out = _run_cmd_best_effort(["netstat", "-ano"])
    else:
        out = _run_cmd_best_effort(["netstat", "-an"])

    if out is None:
        return None
    return out[:max_chars]


def collect_receipts(
    *,
    file_path: str,
    include_processes: bool = False,
    include_netstat: bool = False,
    include_samples: bool = True,
) -> list[ReceiptEnvelope]:
    host = collect_host_receipt()
    created_at = _now_utc_iso()

    file_receipt = collect_file_receipt(file_path, include_samples=include_samples)
    envs: list[ReceiptEnvelope] = [
        ReceiptEnvelope(
            version=RECEIPTS_VERSION,
            created_at=created_at,
            kind="FILE",
            host=host,
            data=asdict(file_receipt),
        )
    ]

    if include_processes:
        snap = collect_process_snapshot()
        if snap is not None:
            envs.append(
                ReceiptEnvelope(
                    version=RECEIPTS_VERSION,
                    created_at=created_at,
                    kind="PROCESSES",
                    host=host,
                    data={"snapshot": snap},
                )
            )

    if include_netstat:
        snap = collect_netstat_snapshot()
        if snap is not None:
            envs.append(
                ReceiptEnvelope(
                    version=RECEIPTS_VERSION,
                    created_at=created_at,
                    kind="NETSTAT",
                    host=host,
                    data={"snapshot": snap},
                )
            )

    return envs


def write_receipts_jsonl(receipts: Iterable[ReceiptEnvelope], out_path: str, *, append: bool = True) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with p.open(mode, encoding="utf-8") as f:
        for r in receipts:
            f.write(json.dumps(asdict(r), sort_keys=True) + "\n")
