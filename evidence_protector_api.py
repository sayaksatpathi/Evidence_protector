r"""Minimal HTTP API wrapper for Evidence Protector.

This lets the React UI (Evidence Protector Web UI) call the same backend logic
used by the CLI without shelling out to subprocesses.

Run locally:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python -m uvicorn evidence_protector_api:app --reload --host 127.0.0.1 --port 8000

Or use the helper script (Linux/macOS):
    bash start-backend.sh
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
from collections import deque
import csv
import hashlib
import io
import json
import logging
import os
import tempfile
import time
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import secrets
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, Literal, Optional, cast
import uuid

from fastapi import FastAPI, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response
from cryptography.fernet import Fernet, InvalidToken

import evidence_protector as ep
from evidence_protector.core import CHAIN_SCHEME_V1, iter_hash_chain, normalize_chain_scheme
from evidence_protector.ghost_correlate import correlate_report_with_receipts, load_receipts_jsonl
from evidence_protector.ghost_protocol import load_report as load_ghost_report
from evidence_protector.ghost_receipts import collect_receipts


app = FastAPI(title="Evidence Protector API", version="1.0")

logger = logging.getLogger("evidence_protector_api")


class ErrorResponse(BaseModel):
    ok: Literal[False] = False
    error: str
    error_code: str = "error"
    request_id: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    request_id: str


class ScanOutput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    text: str
    json_data: Optional[Dict[str, Any]] = Field(default=None, alias="json")
    csv: Optional[str] = None


class ScanResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["scan"]
    file_name: str
    gap_threshold: int
    output_format: Literal["terminal", "csv", "json"]
    status: Literal["NO_TIMESTAMPS", "GAPS_FOUND", "CLEAN"]
    stats: Dict[str, Any]
    gaps: list[Dict[str, Any]]
    output: ScanOutput


class SignResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["sign"]
    file_name: str
    root_hash: str
    fingerprint_phrase: str
    manifest: Dict[str, Any]
    output: Dict[str, Any]


class VerifyResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["verify"]
    file_name: str
    status: Literal["CLEAN", "TAMPERED"]
    fingerprint_phrase: str
    report: Dict[str, Any]
    output: Dict[str, Any]


class GhostBaselineResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["ghost-baseline"]
    file_name: str
    baseline: Dict[str, Any]


class GhostAnalyzeResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["ghost-analyze"]
    file_name: str
    report: Dict[str, Any]


class GhostReceiptsResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["ghost-receipts"]
    file_name: str
    receipts: list[Dict[str, Any]]


class GhostCorrelateResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["ghost-correlate"]
    file_name: str
    report: Dict[str, Any]


class CasePackageMetadata(BaseModel):
    """Metadata about the exported case package."""
    case_id: str
    exported_at: str
    file_name: str
    root_hash: str
    fingerprint_phrase: str
    manifest_version: int
    signature_scheme: str
    signature_key_id: str
    tampering_detected: bool


class CasePackageResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["case-package"]
    package_metadata: CasePackageMetadata
    package_size_bytes: int


class JobCreateResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["jobs-scan"]
    job_id: str
    status: Literal["queued", "running", "succeeded", "failed"]


class JobStatusResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["jobs-status"]
    job_id: str
    job_mode: str
    status: Literal["queued", "running", "succeeded", "failed"]
    created_at: str
    updated_at: str
    file_name: str
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class AuditEvent(BaseModel):
    timestamp: str
    request_id: str
    trace_id: str
    method: str
    path: str
    status_code: int
    client: str
    duration_ms: int
    api_role: str


class AuditListResponse(BaseModel):
    ok: Literal[True] = True
    request_id: str
    mode: Literal["audit-list"]
    events: list[AuditEvent]


MAX_LOG_BYTES = int(os.getenv("EVIDENCE_PROTECTOR_MAX_LOG_BYTES", str(50 * 1024 * 1024)))
MAX_MANIFEST_BYTES = int(os.getenv("EVIDENCE_PROTECTOR_MAX_MANIFEST_BYTES", str(5 * 1024 * 1024)))
MAX_GHOST_BYTES = int(os.getenv("EVIDENCE_PROTECTOR_MAX_GHOST_BYTES", str(5 * 1024 * 1024)))

API_KEY = os.getenv("EVIDENCE_PROTECTOR_API_KEY", "")
ALLOW_LOCALHOST_WITHOUT_KEY = os.getenv("EVIDENCE_PROTECTOR_ALLOW_LOCALHOST_WITHOUT_KEY", "1") not in {"0", "false", "False"}
LOCALHOSTS = {"127.0.0.1", "::1", "localhost"}

RATE_WINDOW_SECONDS = int(os.getenv("EVIDENCE_PROTECTOR_RATE_WINDOW_SECONDS", "60"))
RATE_MAX_HEALTH = int(os.getenv("EVIDENCE_PROTECTOR_RATE_MAX_HEALTH", "240"))
RATE_MAX_DEFAULT = int(os.getenv("EVIDENCE_PROTECTOR_RATE_MAX_DEFAULT", "30"))

TEMP_ENCRYPTION_KEY_B64 = os.getenv("EVIDENCE_PROTECTOR_TEMP_ENCRYPTION_KEY_B64", "").strip()
SECURE_WIPE_PASSES = max(1, int(os.getenv("EVIDENCE_PROTECTOR_SECURE_WIPE_PASSES", "1")))
SECURE_DELETE_ENABLED = os.getenv("EVIDENCE_PROTECTOR_SECURE_DELETE_ENABLED", "1") not in {"0", "false", "False"}
JOB_RECORD_RETENTION_SECONDS = max(1, int(os.getenv("EVIDENCE_PROTECTOR_JOB_RECORD_RETENTION_SECONDS", "900")))
AUDIT_TRAIL_MAX_EVENTS = max(100, int(os.getenv("EVIDENCE_PROTECTOR_AUDIT_MAX_EVENTS", "5000")))
AUDIT_TRAIL_FILE = os.getenv("EVIDENCE_PROTECTOR_AUDIT_FILE", "").strip()
TRACE_LOGGING_ENABLED = os.getenv("EVIDENCE_PROTECTOR_TRACE_LOGGING", "1") not in {"0", "false", "False"}
API_KEYS_JSON = os.getenv("EVIDENCE_PROTECTOR_API_KEYS_JSON", "").strip()

GHOST_DRIFT_PROFILES: dict[str, dict[str, float | int]] = {
    "strict": {
        "gap": 180,
        "window_lines": 150,
        "min_window_chars": 600,
        "dna_jsd_threshold": 0.08,
        "entropy_z_threshold": 2.5,
    },
    "balanced": {
        "gap": 300,
        "window_lines": 200,
        "min_window_chars": 800,
        "dna_jsd_threshold": 0.12,
        "entropy_z_threshold": 3.5,
    },
    "lenient": {
        "gap": 600,
        "window_lines": 300,
        "min_window_chars": 1200,
        "dna_jsd_threshold": 0.18,
        "entropy_z_threshold": 4.5,
    },
}

_rate_lock = Lock()
_rate_buckets: dict[tuple[str, str], deque[float]] = {}

_idempotency_lock = Lock()
_idempotency_cache: dict[tuple[str, str], dict[str, Any]] = {}

_MULTIPART_POST_PATHS = {
    "/api/scan",
    "/api/sign",
    "/api/verify",
    "/api/ghost/baseline",
    "/api/ghost/analyze",
    "/api/ghost/receipts",
    "/api/ghost/correlate",
    "/api/jobs/scan",
    "/api/case-package",
}

_job_lock = Lock()
_jobs: dict[str, dict[str, Any]] = {}
_job_executor = ThreadPoolExecutor(max_workers=max(1, int(os.getenv("EVIDENCE_PROTECTOR_JOB_WORKERS", "2"))))
_fernet: Fernet | None = None
_audit_lock = Lock()
_audit_events: deque[dict[str, Any]] = deque(maxlen=AUDIT_TRAIL_MAX_EVENTS)


def _load_api_role_map() -> dict[str, str]:
    if not API_KEYS_JSON:
        return {}
    try:
        payload = json.loads(API_KEYS_JSON)
        if not isinstance(payload, dict):
            return {}
        return {str(k): str(v).strip().lower() for k, v in payload.items() if str(k).strip() and str(v).strip()}
    except Exception:
        logger.warning("Invalid EVIDENCE_PROTECTOR_API_KEYS_JSON; RBAC map disabled")
        return {}


API_ROLE_BY_KEY = _load_api_role_map()

RBAC_RULES: dict[str, set[str]] = {
    "viewer": {"health", "audit-read"},
    "analyst": {"health", "audit-read", "scan", "sign", "verify", "ghost", "jobs", "case-package"},
    "admin": {"*"},
}


def _required_permission(path: str) -> str:
    if path in {"/api/health", "/api/health/live", "/api/health/ready"}:
        return "health"
    if path.startswith("/api/audit"):
        return "audit-read"
    if path.startswith("/api/scan"):
        return "scan"
    if path.startswith("/api/sign"):
        return "sign"
    if path.startswith("/api/verify"):
        return "verify"
    if path.startswith("/api/ghost/"):
        return "ghost"
    if path.startswith("/api/jobs"):
        return "jobs"
    if path.startswith("/api/case-package"):
        return "case-package"
    return "health"


def _role_allows(role: str, permission: str) -> bool:
    perms = RBAC_RULES.get(role, set())
    return "*" in perms or permission in perms


def _append_audit_event(event: dict[str, Any]) -> None:
    with _audit_lock:
        _audit_events.appendleft(event)

    if AUDIT_TRAIL_FILE:
        try:
            p = Path(AUDIT_TRAIL_FILE)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
        except Exception:
            logger.exception("Unable to persist audit event")


def _get_fernet() -> Fernet | None:
    global _fernet
    if _fernet is not None:
        return _fernet
    if not TEMP_ENCRYPTION_KEY_B64:
        return None
    try:
        _fernet = Fernet(TEMP_ENCRYPTION_KEY_B64.encode("utf-8"))
    except Exception:
        logger.warning("Invalid EVIDENCE_PROTECTOR_TEMP_ENCRYPTION_KEY_B64; temp encryption disabled.")
        _fernet = None
    return _fernet


def _temp_encryption_enabled() -> bool:
    return _get_fernet() is not None


def _secure_wipe_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        return
    if not SECURE_DELETE_ENABLED:
        with contextlib.suppress(Exception):
            path.unlink(missing_ok=True)
        return

    try:
        size = path.stat().st_size
    except Exception:
        size = 0

    with contextlib.suppress(Exception):
        if size > 0:
            with path.open("r+b") as f:
                for _ in range(SECURE_WIPE_PASSES):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
        path.unlink(missing_ok=True)


@contextlib.contextmanager
def _materialize_for_processing(stored_path: Path, tmp_dir: Path):
    """Yield a plaintext path. If at-rest encryption is enabled, decrypt into a temp file and securely wipe it after use."""

    if not _temp_encryption_enabled():
        yield stored_path
        return

    fernet = _get_fernet()
    if fernet is None:
        yield stored_path
        return

    dec_path = tmp_dir / f"{uuid.uuid4().hex}.dec"
    try:
        enc = stored_path.read_bytes()
        plain = fernet.decrypt(enc)
    except InvalidToken as e:
        raise RuntimeError("Unable to decrypt temp artifact") from e

    dec_path.write_bytes(plain)
    try:
        yield dec_path
    finally:
        _secure_wipe_file(dec_path)


def _prune_finished_jobs(now_epoch: float | None = None) -> None:
    now = now_epoch if now_epoch is not None else time.time()
    cutoff = now - JOB_RECORD_RETENTION_SECONDS

    with _job_lock:
        remove_ids: list[str] = []
        for job_id, job in _jobs.items():
            status = str(job.get("status", ""))
            if status not in {"succeeded", "failed"}:
                continue
            finished_at = float(job.get("finished_at_epoch", 0) or 0)
            if finished_at and finished_at < cutoff:
                remove_ids.append(job_id)

        for job_id in remove_ids:
            _jobs.pop(job_id, None)


def _request_id(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if isinstance(rid, str) and rid:
        return rid
    return "unknown"


def _resolve_ghost_profile(profile: str) -> dict[str, float | int] | None:
    key = profile.strip().lower()
    return dict(GHOST_DRIFT_PROFILES.get(key, {})) if key in GHOST_DRIFT_PROFILES else None


def _error(request: Request, status_code: int, message: str, *, code: str = "error") -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"ok": False, "error": message, "error_code": code, "request_id": _request_id(request)},
        headers={"X-Request-ID": _request_id(request)},
    )


def _client_host(request: Request) -> str:
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


def _check_rate_limit(client: str, group: str, limit: int) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds)."""

    now = time.monotonic()
    window = max(1, RATE_WINDOW_SECONDS)
    key = (client, group)

    with _rate_lock:
        bucket = _rate_buckets.get(key)
        if bucket is None:
            bucket = deque[float]()
            _rate_buckets[key] = bucket

        while bucket and (now - bucket[0]) > window:
            bucket.popleft()

        if len(bucket) >= limit:
            oldest = bucket[0]
            retry_after = max(1, int(window - (now - oldest)))
            return False, retry_after

        bucket.append(now)
        return True, 0


def _content_type_is_multipart(value: str) -> bool:
    return value.lower().startswith("multipart/form-data")


def _get_idempotency_entry(path: str, key: str) -> Optional[dict[str, Any]]:
    with _idempotency_lock:
        value = _idempotency_cache.get((path, key))
        return dict(value) if isinstance(value, dict) else None


def _set_idempotency_entry(path: str, key: str, *, request_hash: str, payload: dict[str, Any]) -> None:
    with _idempotency_lock:
        _idempotency_cache[(path, key)] = {"request_hash": request_hash, "payload": dict(payload)}


def _request_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _job_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_set_status(job_id: str, *, status: str, error: Optional[str] = None, result: Optional[dict[str, Any]] = None) -> None:
    with _job_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["status"] = status
        job["updated_at"] = _job_now_iso()
        if error is not None:
            job["error"] = error
        if result is not None:
            job["result"] = result
        if status in {"succeeded", "failed"}:
            job["finished_at_epoch"] = time.time()


def _scan_job_worker(job_id: str, *, file_path: str, file_name: str, gap: int, output_format: str) -> None:
    _job_set_status(job_id, status="running")
    raw_path = Path(file_path)
    tmp_dir = raw_path.parent
    try:
        with _materialize_for_processing(raw_path, tmp_dir) as proc_path:
            gaps, stats = ep.scan_log(str(proc_path), gap_threshold=gap)

        stats_out = dict(stats)
        stats_out["file"] = file_name
        gaps_out = [_serialize_gap(g) for g in gaps]

        if stats_out.get("timestamps_found", 0) == 0:
            status = "NO_TIMESTAMPS"
        elif gaps_out:
            status = "GAPS_FOUND"
        else:
            status = "CLEAN"

        output: Dict[str, Any] = {"text": "", "json": None, "csv": None}
        if output_format == "terminal":
            output["text"] = _scan_report_terminal_text(file_name, gaps, stats_out)
        elif output_format == "csv":
            csv_text = _scan_report_csv(gaps)
            output["text"] = csv_text
            output["csv"] = csv_text
        else:
            report = _scan_report_json(file_name, gaps, stats_out)
            output["json"] = report
            output["text"] = json.dumps(report, indent=2)

        result = ScanResponse(
            request_id="job",
            mode="scan",
            file_name=file_name,
            gap_threshold=gap,
            output_format=output_format,  # type: ignore[arg-type]
            status=status,  # type: ignore[arg-type]
            stats=stats_out,
            gaps=gaps_out,
            output=ScanOutput(**output),
        ).model_dump(by_alias=True)

        _job_set_status(job_id, status="succeeded", result=result)
    except Exception as e:
        _job_set_status(job_id, status="failed", error=str(e))
    finally:
        _secure_delete(raw_path)
        try:
            raw_path.parent.rmdir()
        except Exception:
            pass


@app.middleware("http")
async def security_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    request.state.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.trace_id = request.headers.get("X-Trace-ID") or uuid.uuid4().hex
    request.state.api_role = "anonymous"

    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)

    client = _client_host(request)
    start = time.monotonic()

    # Enforce content-type contract for upload-style POST endpoints.
    if request.method.upper() == "POST" and path in _MULTIPART_POST_PATHS:
        content_type = request.headers.get("content-type", "")
        if not _content_type_is_multipart(content_type):
            return _error(
                request,
                415,
                "Unsupported content type. Expected multipart/form-data.",
                code="unsupported_content_type",
            )

    provided = request.headers.get("X-API-Key", "")
    if API_ROLE_BY_KEY or API_KEY:
        if not (ALLOW_LOCALHOST_WITHOUT_KEY and client in LOCALHOSTS):
            role = ""
            if API_ROLE_BY_KEY:
                role = API_ROLE_BY_KEY.get(provided, "")
            elif API_KEY and secrets.compare_digest(provided, API_KEY):
                role = "admin"

            if not role:
                return _error(request, 401, "Unauthorized. Missing or invalid X-API-Key.", code="unauthorized")

            permission = _required_permission(path)
            if not _role_allows(role, permission):
                return _error(request, 403, f"Forbidden for role '{role}'.", code="forbidden")

            request.state.api_role = role

    # Rate limiting (simple in-memory sliding window).
    group = "health" if path in {"/api/health", "/api/health/live", "/api/health/ready"} else "default"
    limit = RATE_MAX_HEALTH if group == "health" else RATE_MAX_DEFAULT
    allowed, retry_after = _check_rate_limit(client, group, limit)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "ok": False,
                "error": "Rate limit exceeded. Please retry in a moment.",
                "error_code": "rate_limited",
                "request_id": _request_id(request),
            },
            headers={"Retry-After": str(retry_after), "X-Request-ID": _request_id(request)},
        )

    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "Unhandled API error",
            extra={"request_id": _request_id(request), "path": path, "client": client},
        )
        return _error(request, 500, "Internal server error.", code="internal")

    response.headers.setdefault("X-Request-ID", _request_id(request))
    response.headers.setdefault("X-Trace-ID", str(getattr(request.state, "trace_id", "")))
    duration_ms = int((time.monotonic() - start) * 1000)
    status_code = int(getattr(response, "status_code", 0) or 0)
    api_role = str(getattr(request.state, "api_role", "anonymous"))
    trace_id = str(getattr(request.state, "trace_id", ""))

    audit_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": _request_id(request),
        "trace_id": trace_id,
        "method": request.method,
        "path": path,
        "status_code": status_code,
        "client": client,
        "duration_ms": duration_ms,
        "api_role": api_role,
    }
    _append_audit_event(audit_event)

    if TRACE_LOGGING_ENABLED:
        logger.info(json.dumps({"event": "api_trace", **audit_event}, separators=(",", ":")))
    else:
        logger.info(
            "API request",
            extra={
                "request_id": _request_id(request),
                "path": path,
                "method": request.method,
                "status_code": status_code,
                "client": client,
                "duration_ms": duration_ms,
            },
        )

    return response


def _safe_name(filename: Optional[str], fallback: str) -> str:
    if not filename:
        return fallback
    # Strip any directory components from the client-provided filename.
    return Path(filename).name


class UploadTooLarge(Exception):
    def __init__(self, *, max_bytes: int, received_bytes: int) -> None:
        super().__init__(f"Upload exceeds limit ({received_bytes} > {max_bytes})")
        self.max_bytes = max_bytes
        self.received_bytes = received_bytes


def _save_upload(upload: UploadFile, destination: Path, *, max_bytes: int) -> int:
    received, _sha256 = _save_upload_with_sha256(upload, destination, max_bytes=max_bytes)
    return received


def _save_upload_with_sha256(upload: UploadFile, destination: Path, *, max_bytes: int) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    received = 0
    digest = hashlib.sha256()
    encrypt = _temp_encryption_enabled()
    fernet = _get_fernet()
    plain_buf = bytearray() if encrypt else None
    try:
        with destination.open("wb") as out:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > max_bytes:
                    raise UploadTooLarge(max_bytes=max_bytes, received_bytes=received)
                if plain_buf is not None:
                    plain_buf.extend(chunk)
                else:
                    out.write(chunk)
                digest.update(chunk)

            if plain_buf is not None:
                if fernet is None:
                    raise RuntimeError("Temp encryption was requested but encryption key is unavailable")
                encrypted = fernet.encrypt(bytes(plain_buf))
                out.write(encrypted)
    finally:
        try:
            upload.file.close()
        except Exception:
            pass

    return received, digest.hexdigest()


def _serialize_gap(gap: ep.SuspiciousGap) -> Dict[str, Any]:
    data = asdict(gap)
    data["gap_start"] = gap.gap_start.isoformat()
    data["gap_end"] = gap.gap_end.isoformat()
    return data


def _scan_report_json(file_name: str, gaps: list[ep.SuspiciousGap], stats: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "file": file_name,
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

    return data


def _scan_report_csv(gaps: list[ep.SuspiciousGap]) -> str:
    fieldnames = [
        "gap_index",
        "gap_start",
        "gap_end",
        "duration_seconds",
        "line_start",
        "line_end",
        "note",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
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

    return buf.getvalue()


def _scan_report_terminal_text(file_name: str, gaps: list[ep.SuspiciousGap], stats: Dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("Evidence Protector Report")
    lines.append("=" * 80)
    lines.append(f"File: {file_name}")
    lines.append(f"Total lines: {stats['total_lines']}")
    lines.append(f"Malformed lines: {stats['malformed_lines']}")
    lines.append(f"Timestamps found: {stats.get('timestamps_found', 0)}")
    lines.append(f"Gap threshold: {stats['threshold_seconds']} seconds")
    lines.append(f"Suspicious gaps found: {stats['gaps_found']}")
    lines.append("")

    if not gaps:
        lines.append("No suspicious gaps found.")
        return "\n".join(lines) + "\n"

    header = f"{'#':>3}  {'Gap Start':<25}  {'Gap End':<25}  {'Duration':<10}  {'StartLn':>7}  {'EndLn':>7}  Note"
    lines.append(header)
    lines.append("-" * len(header))
    for gap in gaps:
        note = gap.note or ""
        duration = ep.format_duration(gap.duration_seconds)
        lines.append(
            f"{gap.gap_index:>3}  "
            f"{gap.gap_start.isoformat():<25}  "
            f"{gap.gap_end.isoformat():<25}  "
            f"{duration:<10}  "
            f"{gap.line_start:>7}  "
            f"{gap.line_end:>7}  "
            f"{note}"
        )

    return "\n".join(lines) + "\n"


@app.get("/api/health", response_model=HealthResponse)
def health(request: Request) -> Dict[str, str]:
    return {"status": "ok", "request_id": _request_id(request)}


@app.get("/api/health/live", response_model=HealthResponse)
def health_live(request: Request) -> Dict[str, str]:
    return {"status": "ok", "request_id": _request_id(request)}


@app.get("/api/health/ready", response_model=HealthResponse)
def health_ready(request: Request) -> Dict[str, str]:
    return {"status": "ok", "request_id": _request_id(request)}


@app.get(
    "/api/audit",
    response_model=AuditListResponse,
    responses={400: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def audit_list(request: Request, limit: int = 100) -> AuditListResponse | JSONResponse:
    if limit < 1 or limit > 2000:
        return _error(request, 400, "Invalid limit: expected 1..2000.", code="invalid_limit")

    with _audit_lock:
        rows = list(_audit_events)[:limit]

    events = [AuditEvent(**row) for row in rows]
    return AuditListResponse(
        request_id=_request_id(request),
        mode="audit-list",
        events=events,
    )


@app.post(
    "/api/scan",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def scan(
    request: Request,
    file: UploadFile = File(...),
    gap: int = Form(300),
    output_format: str = Form("terminal"),
) -> ScanResponse | JSONResponse:
    output_format = output_format.lower().strip()
    if output_format not in {"terminal", "csv", "json"}:
        return _error(request, 400, f"Invalid output_format: {output_format}", code="invalid_output_format")

    if gap < 0 or gap > 24 * 60 * 60:
        return _error(request, 400, "Invalid gap: must be between 0 and 86400 seconds.", code="invalid_gap")

    original_name = _safe_name(file.filename, "uploaded.log")

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        try:
            _save_upload(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
            gaps, stats = ep.scan_log(str(proc_log_path), gap_threshold=gap)

    # Replace temp path with the original filename for UI display.
    stats_out = dict(stats)
    stats_out["file"] = original_name

    gaps_out = [_serialize_gap(g) for g in gaps]

    if stats_out.get("timestamps_found", 0) == 0:
        status = "NO_TIMESTAMPS"
    elif gaps_out:
        status = "GAPS_FOUND"
    else:
        status = "CLEAN"

    output: Dict[str, Any] = {"text": "", "json": None, "csv": None}

    if output_format == "terminal":
        output["text"] = _scan_report_terminal_text(original_name, gaps, stats_out)
    elif output_format == "csv":
        csv_text = _scan_report_csv(gaps)
        output["text"] = csv_text
        output["csv"] = csv_text
    else:
        report = _scan_report_json(original_name, gaps, stats_out)
        output["json"] = report
        output["text"] = json.dumps(report, indent=2)

    return ScanResponse(
        request_id=_request_id(request),
        mode="scan",
        file_name=original_name,
        gap_threshold=gap,
        output_format=output_format,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        stats=stats_out,
        gaps=gaps_out,
        output=ScanOutput(**output),
    )


@app.post(
    "/api/sign",
    response_model=SignResponse,
    responses={413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def sign(
    request: Request,
    file: UploadFile = File(...),
    manifest_mode: str | None = Form(None),
    checkpoint_every: int | None = Form(None),
    chain_scheme: str | None = Form(None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> SignResponse | JSONResponse:
    original_name = _safe_name(file.filename, "uploaded.log")

    mode = (manifest_mode or "full").strip().lower()
    if mode not in {"full", "compact"}:
        return _error(request, 400, "Invalid manifest_mode (expected full|compact).", code="invalid_manifest_mode")

    checkpoints_n = checkpoint_every
    if checkpoints_n is None:
        checkpoints_n = 1000
    if checkpoints_n < 0:
        return _error(request, 400, "Invalid checkpoint_every (expected non-negative integer).", code="invalid_checkpoint_every")

    try:
        scheme = normalize_chain_scheme(chain_scheme or CHAIN_SCHEME_V1)
    except Exception:
        scheme = CHAIN_SCHEME_V1

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        try:
            file_size_bytes, file_sha256 = _save_upload_with_sha256(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        request_hash = _request_hash(
            {
                "op": "sign",
                "file_name": original_name,
                "file_sha256": file_sha256,
                "manifest_mode": mode,
                "checkpoint_every": checkpoints_n,
                "chain_scheme": scheme,
            }
        )

        if idempotency_key:
            cached = _get_idempotency_entry(request.url.path, idempotency_key)
            if cached is not None:
                cached_hash = str(cached.get("request_hash", ""))
                if cached_hash != request_hash:
                    return _error(
                        request,
                        409,
                        "Idempotency key was already used with a different request payload.",
                        code="idempotency_conflict",
                    )
                payload = cached.get("payload")
                if isinstance(payload, dict):
                    return SignResponse(**payload)

        try:
            file_size_bytes = int(file_size_bytes)
        except Exception:
            file_size_bytes = None

        entries_out: list[Dict[str, Any]] = []
        checkpoints_out: list[Dict[str, Any]] = []
        last_entry: ep.HashEntry | None = None

        try:
            with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
                for entry in iter_hash_chain(str(proc_log_path), chain_scheme=scheme):
                    last_entry = entry
                    if mode == "full":
                        entries_out.append(asdict(entry))
                    else:
                        if checkpoints_n > 0 and (entry.line_number % checkpoints_n == 0):
                            checkpoints_out.append({"line_number": entry.line_number, "chain_hash": entry.chain_hash})
        except Exception as e:
            return _error(request, 500, f"Unable to hash log: {e}", code="hash_failed")

    total_lines = int(last_entry.line_number) if last_entry else 0
    root_hash = last_entry.chain_hash if last_entry else ""
    phrase = ep.fingerprint_phrase(root_hash)

    # Keep the signed payload stable and user-facing for downloads:
    # - file is the original filename (not a temp path)
    manifest: Dict[str, Any] = {
        "manifest_version": 3,
        "file": original_name,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "sha256",
        "chain_scheme": scheme,
        "encoding": "utf-8+surrogateescape",
        "newline_policy": "universal",
        "file_size_bytes": file_size_bytes,
        "manifest_mode": mode,
        "total_lines": total_lines,
        "root_hash": root_hash,
        "fingerprint_phrase": phrase,
    }

    if mode == "full":
        manifest["entries"] = entries_out
    else:
        manifest["checkpoints"] = checkpoints_out
        manifest["checkpoint_every"] = checkpoints_n

    try:
        manifest["signature"] = ep.compute_manifest_signature(manifest)
    except Exception as e:
        return _error(request, 500, f"Unable to sign manifest: {e}", code="sign_failed")

    signature_value = ""
    signature_scheme = ep.SIGNATURE_SCHEME
    signature_key_id = ""
    if isinstance(manifest.get("signature"), dict):
        signature_value = str(manifest["signature"].get("value", ""))
        signature_scheme = str(manifest["signature"].get("scheme", signature_scheme) or signature_scheme)
        signature_key_id = str(manifest["signature"].get("key_id", ""))

    text_lines = [
        "Log Signed",
        "=" * 80,
        f"File: {original_name}",
        f"Mode: {mode}",
        f"Chain scheme: {scheme}",
        f"Checkpoint every: {checkpoints_n}" if mode == "compact" else "",
        f"Lines signed: {total_lines}",
        f"Root hash: {root_hash}",
        f"Fingerprint: {phrase}",
        f"Signature ({signature_scheme}): {signature_value}",
        f"Key ID: {signature_key_id}" if signature_key_id else "",
    ]

    text_lines = [line for line in text_lines if line]

    response = SignResponse(
        request_id=_request_id(request),
        mode="sign",
        file_name=original_name,
        root_hash=root_hash,
        fingerprint_phrase=phrase,
        manifest=manifest,
        output={"text": "\n".join(text_lines) + "\n", "json": manifest},
    )

    if idempotency_key:
        _set_idempotency_entry(
            request.url.path,
            idempotency_key,
            request_hash=request_hash,
            payload=response.model_dump(by_alias=True),
        )

    return response


@app.post(
    "/api/verify",
    response_model=VerifyResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def verify(
    request: Request,
    file: UploadFile = File(...),
    manifest: UploadFile | None = File(None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> VerifyResponse | JSONResponse:
    original_name = _safe_name(file.filename, "uploaded.log")

    if manifest is None:
        return _error(request, 400, "Manifest file is required for verify in the Web UI.", code="missing_manifest")

    manifest_name = _safe_name(manifest.filename, "manifest.json")

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        manifest_path = tmp_dir / manifest_name

        try:
            _, file_sha256 = _save_upload_with_sha256(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        try:
            _, manifest_sha256 = _save_upload_with_sha256(manifest, manifest_path, max_bytes=MAX_MANIFEST_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Manifest file too large. Max allowed is {e.max_bytes} bytes.", code="manifest_too_large")

        request_hash = _request_hash(
            {
                "op": "verify",
                "file_name": original_name,
                "file_sha256": file_sha256,
                "manifest_name": manifest_name,
                "manifest_sha256": manifest_sha256,
            }
        )

        if idempotency_key:
            cached = _get_idempotency_entry(request.url.path, idempotency_key)
            if cached is not None:
                cached_hash = str(cached.get("request_hash", ""))
                if cached_hash != request_hash:
                    return _error(
                        request,
                        409,
                        "Idempotency key was already used with a different request payload.",
                        code="idempotency_conflict",
                    )
                payload = cached.get("payload")
                if isinstance(payload, dict):
                    return VerifyResponse(**payload)

        try:
            with _materialize_for_processing(manifest_path, tmp_dir) as proc_manifest_path:
                manifest_data = json.loads(proc_manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return _error(request, 400, "Invalid manifest JSON.", code="invalid_manifest_json")

        sig_ok, sig_reason = ep.verify_manifest_signature(manifest_data)
        if not sig_ok:
            if sig_reason == "missing":
                return _error(request, 400, "Manifest is not signed. Please re-sign the log to generate a signed manifest.", code="manifest_not_signed")
            if sig_reason == "unsupported-scheme":
                return _error(request, 400, "Unsupported manifest signature scheme.", code="unsupported_signature")
            if sig_reason == "revoked-key-id":
                return _error(request, 400, "Manifest signature key has been revoked.", code="revoked_key")
            return _error(request, 400, "Manifest signature is invalid. The manifest cannot be trusted.", code="invalid_signature")

        mode = str(manifest_data.get("manifest_mode", "full") or "full").strip().lower()
        chain_scheme = manifest_data.get("chain_scheme")
        with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
            current_chain = ep.build_hash_chain(str(proc_log_path), chain_scheme=chain_scheme)

    mismatches: list[ep.TamperResult] = []

    if mode == "full":
        manifest_entries_any = manifest_data.get("entries", [])
        if not isinstance(manifest_entries_any, list):
            return _error(request, 400, "Invalid manifest: entries must be a list.", code="invalid_manifest")

        manifest_entries_any = cast(list[Any], manifest_entries_any)

        if any(not isinstance(e, dict) for e in manifest_entries_any):
            return _error(request, 400, "Invalid manifest: entries must be objects.", code="invalid_manifest")

        manifest_entries = cast(list[dict[str, Any]], manifest_entries_any)

        manifest_len = len(manifest_entries)
        current_len = len(current_chain)
        overlap = min(manifest_len, current_len)

        for idx in range(overlap):
            expected_chain_hash = str(manifest_entries[idx].get("chain_hash", ""))
            actual_chain_hash = current_chain[idx].chain_hash
            if expected_chain_hash != actual_chain_hash:
                mismatches.append(
                    ep.TamperResult(
                        line_number=idx + 1,
                        expected_chain_hash=expected_chain_hash,
                        actual_chain_hash=actual_chain_hash,
                        status="TAMPERED",
                    )
                )

        if manifest_len > current_len:
            for idx in range(current_len, manifest_len):
                expected_chain_hash = str(manifest_entries[idx].get("chain_hash", ""))
                mismatches.append(
                    ep.TamperResult(
                        line_number=idx + 1,
                        expected_chain_hash=expected_chain_hash,
                        actual_chain_hash="",
                        status="DELETED",
                    )
                )

        if current_len > manifest_len:
            for idx in range(manifest_len, current_len):
                mismatches.append(
                    ep.TamperResult(
                        line_number=idx + 1,
                        expected_chain_hash="",
                        actual_chain_hash=current_chain[idx].chain_hash,
                        status="INSERTED",
                    )
                )

        manifest_len_out = manifest_len
        current_len_out = current_len

    elif mode == "compact":
        checkpoints_raw_any = manifest_data.get("checkpoints", [])
        if not isinstance(checkpoints_raw_any, list):
            return _error(request, 400, "Invalid manifest: checkpoints must be a list.", code="invalid_manifest")

        checkpoints_raw_any = cast(list[Any], checkpoints_raw_any)

        checkpoint_map: dict[int, str] = {}
        for item in checkpoints_raw_any:
            if not isinstance(item, dict):
                continue
            item = cast(dict[str, Any], item)
            try:
                ln = int(item.get("line_number", 0))
                ch = str(item.get("chain_hash", ""))
            except Exception:
                continue
            if ln > 0 and ch:
                checkpoint_map[ln] = ch

        for entry in current_chain:
            expected = checkpoint_map.get(entry.line_number)
            if expected is not None and expected != entry.chain_hash:
                mismatches.append(
                    ep.TamperResult(
                        line_number=entry.line_number,
                        expected_chain_hash=expected,
                        actual_chain_hash=entry.chain_hash,
                        status="CHECKPOINT_MISMATCH",
                    )
                )

        expected_total_lines = int(manifest_data.get("total_lines", 0) or 0)
        current_total_lines = len(current_chain)
        if expected_total_lines and expected_total_lines != current_total_lines:
            mismatches.append(
                ep.TamperResult(
                    line_number=min(expected_total_lines, current_total_lines) + 1,
                    expected_chain_hash=str(expected_total_lines),
                    actual_chain_hash=str(current_total_lines),
                    status="LINECOUNT_MISMATCH",
                )
            )

        expected_root_hash = str(manifest_data.get("root_hash", ""))
        current_root_hash = current_chain[-1].chain_hash if current_chain else ""
        if expected_root_hash and expected_root_hash != current_root_hash:
            mismatches.append(
                ep.TamperResult(
                    line_number=current_total_lines,
                    expected_chain_hash=expected_root_hash,
                    actual_chain_hash=current_root_hash,
                    status="ROOT_MISMATCH",
                )
            )

        manifest_len_out = expected_total_lines
        current_len_out = current_total_lines
    else:
        return _error(request, 400, "Invalid manifest: unknown manifest_mode.", code="invalid_manifest")

    report: Dict[str, Any] = {
        "file": original_name,
        "manifest": manifest_name,
        "signed_at": manifest_data.get("signed_at"),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "clean": len(mismatches) == 0,
        "issues_found": len(mismatches),
        "issues": [asdict(m) for m in mismatches],
        "manifest_total_lines": manifest_len_out,
        "current_total_lines": current_len_out,
        "manifest_root_hash": manifest_data.get("root_hash", ""),
        "current_root_hash": current_chain[-1].chain_hash if current_chain else "",
        "manifest_fingerprint_phrase": ep.fingerprint_phrase(str(manifest_data.get("root_hash", ""))),
        "current_fingerprint_phrase": ep.fingerprint_phrase(current_chain[-1].chain_hash if current_chain else ""),
        "manifest_signature": {
            "present": True,
            "scheme": (
                str(manifest_data.get("signature", {}).get("scheme", ep.SIGNATURE_SCHEME))
                if isinstance(manifest_data.get("signature"), dict)
                else ep.SIGNATURE_SCHEME
            ),
            "key_id": (
                str(manifest_data.get("signature", {}).get("key_id", ""))
                if isinstance(manifest_data.get("signature"), dict)
                else ""
            ),
            "valid": True,
            "reason": "ok",
        },
    }

    if report["clean"]:
        text = "Integrity verified. No tampering detected."
        status = "CLEAN"
    else:
        text_lines = [f"Tampering detected: {report['issues_found']} issue(s)."]
        for issue in mismatches[:50]:
            expected_short = issue.expected_chain_hash[:12] if issue.expected_chain_hash else "-"
            actual_short = issue.actual_chain_hash[:12] if issue.actual_chain_hash else "-"
            text_lines.append(f"Line {issue.line_number}: {issue.status} expected={expected_short} actual={actual_short}")
        if len(mismatches) > 50:
            text_lines.append(f"... ({len(mismatches) - 50} more)")
        text = "\n".join(text_lines)
        status = "TAMPERED"

    # Always include the phrases in the human-readable output.
    text += f"\nManifest fingerprint: {report['manifest_fingerprint_phrase']}\nCurrent fingerprint: {report['current_fingerprint_phrase']}"

    response = VerifyResponse(
        request_id=_request_id(request),
        mode="verify",
        file_name=original_name,
        status=status,  # type: ignore[arg-type]
        fingerprint_phrase=str(report["current_fingerprint_phrase"]),
        report=report,
        output={"text": text + "\n", "json": report},
    )

    if idempotency_key:
        _set_idempotency_entry(
            request.url.path,
            idempotency_key,
            request_hash=request_hash,
            payload=response.model_dump(by_alias=True),
        )

    return response


@app.post(
    "/api/case-package",
    response_model=None,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def case_package(
    request: Request,
    file: UploadFile = File(...),
    manifest: UploadFile = File(...),
    tamper_report: UploadFile | None = File(None),
    ghost_report: UploadFile | None = File(None),
) -> Response:
    """Export signed case evidence as a ZIP package.
    
    Creates a case package containing:
    - Original log file
    - Signed manifest
    - Optional tamper report
    - Optional ghost analysis report
    - Metadata file (case_metadata.json)
    
    Returns a ZIP file as binary stream.
    """
    original_name = _safe_name(file.filename, "uploaded.log")
    manifest_name = _safe_name(manifest.filename, "manifest.json")
    
    case_id = uuid.uuid4().hex[:12].upper()
    package_name = f"case_{case_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.zip"
    
    try:
        with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
            tmp_dir = Path(tmp)
            log_path = tmp_dir / original_name
            manifest_path = tmp_dir / manifest_name
            
            # Save uploaded files
            try:
                _ = _save_upload_with_sha256(file, log_path, max_bytes=MAX_LOG_BYTES)
            except UploadTooLarge as e:
                return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")
            
            try:
                _ = _save_upload_with_sha256(manifest, manifest_path, max_bytes=MAX_MANIFEST_BYTES)
            except UploadTooLarge as e:
                return _error(request, 413, f"Manifest file too large. Max allowed is {e.max_bytes} bytes.", code="manifest_too_large")
            
            # Optional report files
            tamper_report_path: Path | None = None
            ghost_report_path: Path | None = None
            
            if tamper_report is not None:
                tamper_report_name = _safe_name(tamper_report.filename, "tamper_report.json")
                tamper_report_path = tmp_dir / tamper_report_name
                try:
                    _ = _save_upload_with_sha256(tamper_report, tamper_report_path, max_bytes=MAX_MANIFEST_BYTES)
                except UploadTooLarge:
                    pass  # Optional; skip on size error
            
            if ghost_report is not None:
                ghost_report_name = _safe_name(ghost_report.filename, "ghost_report.json")
                ghost_report_path = tmp_dir / ghost_report_name
                try:
                    _ = _save_upload_with_sha256(ghost_report, ghost_report_path, max_bytes=MAX_GHOST_BYTES)
                except UploadTooLarge:
                    pass  # Optional; skip on size error
            
            # Read manifest to extract metadata
            manifest_data: dict[str, Any] = {}
            try:
                manifest_text = manifest_path.read_text(encoding="utf-8")
                manifest_data = json.loads(manifest_text)
            except Exception as e:
                logger.warning(f"Could not parse manifest: {e}")
            
            # Check if tampering was detected (from presence of tamper_report)
            tampering_detected = tamper_report_path is not None and tamper_report_path.exists()
            
            # Extract key metadata
            root_hash = str(manifest_data.get("root_hash", ""))
            fingerprint_phrase = str(manifest_data.get("fingerprint_phrase", ""))
            manifest_version = int(manifest_data.get("manifest_version", 3))
            
            signature_dict = manifest_data.get("signature", {})
            signature_scheme = str(signature_dict.get("scheme", ep.SIGNATURE_SCHEME)) if isinstance(signature_dict, dict) else ep.SIGNATURE_SCHEME
            signature_key_id = str(signature_dict.get("key_id", "")) if isinstance(signature_dict, dict) else ""
            
            # Create ZIP package
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                # Add original log
                zf.write(log_path, arcname=f"evidence/{original_name}")
                
                # Add signed manifest
                zf.write(manifest_path, arcname="evidence/manifest.json")
                
                # Add optional reports
                if tamper_report_path is not None and tamper_report_path.exists():
                    zf.write(tamper_report_path, arcname="evidence/tamper_report.json")
                
                if ghost_report_path is not None and ghost_report_path.exists():
                    zf.write(ghost_report_path, arcname="evidence/ghost_report.json")
                
                # Create case metadata file
                case_metadata = {
                    "case_id": case_id,
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "file_name": original_name,
                    "root_hash": root_hash,
                    "fingerprint_phrase": fingerprint_phrase,
                    "manifest_version": manifest_version,
                    "signature_scheme": signature_scheme,
                    "signature_key_id": signature_key_id,
                    "tampering_detected": tampering_detected,
                    "evidence_files": [
                        {
                            "path": f"evidence/{original_name}",
                            "type": "log",
                            "sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
                        },
                        {
                            "path": "evidence/manifest.json",
                            "type": "manifest",
                            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        },
                    ],
                }
                
                if tamper_report_path is not None and tamper_report_path.exists():
                    case_metadata["evidence_files"].append({
                        "path": "evidence/tamper_report.json",
                        "type": "tamper_report",
                        "sha256": hashlib.sha256(tamper_report_path.read_bytes()).hexdigest(),
                    })
                
                if ghost_report_path is not None and ghost_report_path.exists():
                    case_metadata["evidence_files"].append({
                        "path": "evidence/ghost_report.json",
                        "type": "ghost_report",
                        "sha256": hashlib.sha256(ghost_report_path.read_bytes()).hexdigest(),
                    })
                
                # Write metadata file
                metadata_json = json.dumps(case_metadata, indent=2)
                zf.writestr("case_metadata.json", metadata_json)
                
                # Write README for context
                readme = f"""Evidence Protector Case Package
==============================

Case ID: {case_id}
Exported: {case_metadata['exported_at']}
Status: {'TAMPERING DETECTED' if tampering_detected else 'CLEAN'}

Files:
- evidence/{original_name} - Original log file
- evidence/manifest.json - Signed cryptographic manifest
- case_metadata.json - Case metadata and file hashes

Evidence Summary:
- Root Hash: {root_hash}
- Fingerprint: {fingerprint_phrase}
- Manifest Version: {manifest_version}
- Signature Scheme: {signature_scheme}
- Signature Key ID: {signature_key_id}

For verification:
1. Extract the ZIP archive
2. Use Evidence Protector to verify: evidence_protector verify --log evidence/{original_name} --manifest evidence/manifest.json
3. Review case_metadata.json for package integrity details
"""
                zf.writestr("README.txt", readme)
            
            zip_buffer.seek(0)
            package_size = len(zip_buffer.getvalue())
            
            # Log the case package creation
            logger.info(f"Case package created: case_id={case_id}, size={package_size}, tampering={tampering_detected}")
            
            # Return as StreamingResponse
            return StreamingResponse(
                iter([zip_buffer.getvalue()]),
                media_type="application/zip",
                headers={"Content-Disposition": f"attachment; filename={package_name}"},
            )
    
    except Exception as e:
        logger.exception(f"Error creating case package: {e}")
        return _error(request, 500, f"Error creating case package: {str(e)}", code="case_package_error")


@app.post(
    "/api/ghost/baseline",
    response_model=GhostBaselineResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def ghost_baseline(
    request: Request,
    file: UploadFile = File(...),
    max_lines: int = Form(250_000),
    source_hint: str = Form(""),
) -> GhostBaselineResponse | JSONResponse:
    original_name = _safe_name(file.filename, "uploaded.log")

    if max_lines < 1 or max_lines > 5_000_000:
        return _error(request, 400, "Invalid max_lines.", code="invalid_max_lines")

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        try:
            _save_upload(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
            baseline = ep.build_baseline(
                str(proc_log_path),
                config=ep.GhostConfig(max_lines=max_lines),
                source_hint=source_hint,
            )

    baseline_out = asdict(baseline)
    baseline_out["source_file_name"] = original_name
    return GhostBaselineResponse(
        request_id=_request_id(request),
        mode="ghost-baseline",
        file_name=original_name,
        baseline=baseline_out,
    )


@app.post(
    "/api/ghost/analyze",
    response_model=GhostAnalyzeResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def ghost_analyze(
    request: Request,
    file: UploadFile = File(...),
    baseline: UploadFile | None = File(None),
    drift_profile: str = Form("balanced"),
    gap: int | None = Form(None),
    drift_window_lines: int | None = Form(None),
    drift_min_window_chars: int | None = Form(None),
    window_lines: int | None = Form(None),
    dna_jsd_threshold: float | None = Form(None),
    entropy_z_threshold: float | None = Form(None),
    max_lines: int = Form(250_000),
) -> GhostAnalyzeResponse | JSONResponse:
    original_name = _safe_name(file.filename, "uploaded.log")

    profile = _resolve_ghost_profile(drift_profile)
    if profile is None:
        valid = ", ".join(sorted(GHOST_DRIFT_PROFILES.keys()))
        return _error(request, 400, f"Invalid drift_profile. Valid values: {valid}.", code="invalid_drift_profile")

    resolved_gap = int(profile["gap"] if gap is None else gap)
    requested_window_lines = drift_window_lines if drift_window_lines is not None else window_lines
    resolved_window_lines = int(profile["window_lines"] if requested_window_lines is None else requested_window_lines)
    resolved_min_window_chars = int(
        profile["min_window_chars"] if drift_min_window_chars is None else drift_min_window_chars
    )
    resolved_dna_jsd_threshold = float(
        profile["dna_jsd_threshold"] if dna_jsd_threshold is None else dna_jsd_threshold
    )
    resolved_entropy_z_threshold = float(
        profile["entropy_z_threshold"] if entropy_z_threshold is None else entropy_z_threshold
    )

    if resolved_gap < 0 or resolved_gap > 24 * 60 * 60:
        return _error(request, 400, "Invalid gap.", code="invalid_gap")
    if resolved_window_lines < 10 or resolved_window_lines > 50_000:
        return _error(request, 400, "Invalid window_lines.", code="invalid_window_lines")
    if resolved_min_window_chars < 64 or resolved_min_window_chars > 2_000_000:
        return _error(request, 400, "Invalid drift_min_window_chars.", code="invalid_drift_min_window_chars")
    if max_lines < 1 or max_lines > 5_000_000:
        return _error(request, 400, "Invalid max_lines.", code="invalid_max_lines")

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        baseline_path = tmp_dir / "baseline.json"

        try:
            _save_upload(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        baseline_obj = None
        if baseline is not None:
            try:
                _save_upload(baseline, baseline_path, max_bytes=MAX_GHOST_BYTES)
                with _materialize_for_processing(baseline_path, tmp_dir) as proc_baseline_path:
                    baseline_obj = ep.load_baseline(str(proc_baseline_path))
            except UploadTooLarge as e:
                return _error(request, 413, f"Baseline too large. Max allowed is {e.max_bytes} bytes.", code="baseline_too_large")
            except Exception:
                return _error(request, 400, "Invalid baseline JSON.", code="invalid_baseline")

        cfg = ep.GhostConfig(
            gap_threshold_seconds=resolved_gap,
            window_lines=resolved_window_lines,
            dna_jsd_threshold=resolved_dna_jsd_threshold,
            dna_min_window_chars=resolved_min_window_chars,
            entropy_z_threshold=resolved_entropy_z_threshold,
            entropy_min_window_chars=resolved_min_window_chars,
            max_lines=max_lines,
        )
        with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
            report = ep.analyze_log(str(proc_log_path), baseline=baseline_obj, config=cfg, display_file=original_name)

    report_out = asdict(report)
    report_out.setdefault("config", {})
    if isinstance(report_out.get("config"), dict):
        report_out["config"]["drift_profile"] = drift_profile.strip().lower()
    return GhostAnalyzeResponse(
        request_id=_request_id(request),
        mode="ghost-analyze",
        file_name=original_name,
        report=report_out,
    )


@app.post(
    "/api/ghost/receipts",
    response_model=GhostReceiptsResponse,
    responses={413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def ghost_receipts(
    request: Request,
    file: UploadFile = File(...),
    processes: bool = Form(False),
    netstat: bool = Form(False),
    samples: bool = Form(True),
) -> GhostReceiptsResponse | JSONResponse:
    original_name = _safe_name(file.filename, "uploaded.log")
    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / original_name
        try:
            _save_upload(file, log_path, max_bytes=MAX_LOG_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

        with _materialize_for_processing(log_path, tmp_dir) as proc_log_path:
            receipts = collect_receipts(
                file_path=str(proc_log_path),
                include_processes=bool(processes),
                include_netstat=bool(netstat),
                include_samples=bool(samples),
            )

    return GhostReceiptsResponse(
        request_id=_request_id(request),
        mode="ghost-receipts",
        file_name=original_name,
        receipts=[asdict(r) for r in receipts],
    )


@app.post(
    "/api/ghost/correlate",
    response_model=GhostCorrelateResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def ghost_correlate(
    request: Request,
    report: UploadFile = File(...),
    receipts: UploadFile = File(...),
) -> GhostCorrelateResponse | JSONResponse:
    report_name = _safe_name(report.filename, "report.json")
    receipts_name = _safe_name(receipts.filename, "receipts.jsonl")

    with tempfile.TemporaryDirectory(prefix="evidence_protector_") as tmp:
        tmp_dir = Path(tmp)
        report_path = tmp_dir / report_name
        receipts_path = tmp_dir / receipts_name
        try:
            _save_upload(report, report_path, max_bytes=MAX_GHOST_BYTES)
            _save_upload(receipts, receipts_path, max_bytes=MAX_GHOST_BYTES)
        except UploadTooLarge as e:
            return _error(request, 413, f"Payload too large. Max allowed is {e.max_bytes} bytes.", code="payload_too_large")

        try:
            with _materialize_for_processing(report_path, tmp_dir) as proc_report_path:
                ghost_report = load_ghost_report(str(proc_report_path))
        except Exception:
            return _error(request, 400, "Invalid report JSON.", code="invalid_report")

        with _materialize_for_processing(receipts_path, tmp_dir) as proc_receipts_path:
            receipt_items = load_receipts_jsonl(str(proc_receipts_path))
        correlated = correlate_report_with_receipts(ghost_report, receipt_items)

    return GhostCorrelateResponse(
        request_id=_request_id(request),
        mode="ghost-correlate",
        file_name=str(correlated.file),
        report=asdict(correlated),
    )


@app.post(
    "/api/jobs/scan",
    response_model=JobCreateResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    status_code=202,
)
async def enqueue_scan_job(
    request: Request,
    file: UploadFile = File(...),
    gap: int = Form(300),
    output_format: str = Form("terminal"),
) -> JobCreateResponse | JSONResponse:
    _prune_finished_jobs()

    output_format = output_format.lower().strip()
    if output_format not in {"terminal", "csv", "json"}:
        return _error(request, 400, f"Invalid output_format: {output_format}", code="invalid_output_format")

    if gap < 0 or gap > 24 * 60 * 60:
        return _error(request, 400, "Invalid gap: must be between 0 and 86400 seconds.", code="invalid_gap")

    original_name = _safe_name(file.filename, "uploaded.log")
    job_id = uuid.uuid4().hex
    job_dir = Path(tempfile.gettempdir()) / "evidence_protector_jobs" / job_id
    log_path = job_dir / original_name

    try:
        _save_upload(file, log_path, max_bytes=MAX_LOG_BYTES)
    except UploadTooLarge as e:
        return _error(request, 413, f"Log file too large. Max allowed is {e.max_bytes} bytes.", code="log_too_large")

    now = _job_now_iso()
    with _job_lock:
        _jobs[job_id] = {
            "job_id": job_id,
            "job_mode": "scan",
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "file_name": original_name,
            "error": None,
            "result": None,
        }

    _job_executor.submit(
        _scan_job_worker,
        job_id,
        file_path=str(log_path),
        file_name=original_name,
        gap=gap,
        output_format=output_format,
    )

    return JobCreateResponse(
        request_id=_request_id(request),
        mode="jobs-scan",
        job_id=job_id,
        status="queued",
    )


@app.get(
    "/api/jobs/{job_id}",
    response_model=JobStatusResponse,
    responses={404: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def get_job_status(request: Request, job_id: str) -> JobStatusResponse | JSONResponse:
    _prune_finished_jobs()

    with _job_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _error(request, 404, "Job not found.", code="job_not_found")

    return JobStatusResponse(
        request_id=_request_id(request),
        mode="jobs-status",
        job_id=job_id,
        job_mode=str(job.get("job_mode", "scan")),
        status=str(job.get("status", "failed")),  # type: ignore[arg-type]
        created_at=str(job.get("created_at", "")),
        updated_at=str(job.get("updated_at", "")),
        file_name=str(job.get("file_name", "uploaded.log")),
        error=cast(Optional[str], job.get("error")),
        result=cast(Optional[Dict[str, Any]], job.get("result")),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("evidence_protector_api:app", host="127.0.0.1", port=8000)
