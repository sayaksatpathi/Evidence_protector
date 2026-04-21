"""Evidence Protector package.

This package contains the core log integrity and scanning logic, a CLI entrypoint,
and (optionally) a FastAPI backend.

The repository also contains a top-level `evidence_protector.py` compatibility
shim for local runs; the canonical implementation lives under `src/`.
"""

from __future__ import annotations

from .cli import main
from .core import (
    SIGNATURE_SCHEME,
    CheckpointEntry,
    HashEntry,
    SuspiciousGap,
    TamperResult,
    _default_manifest_path,
    build_hash_chain,
    compute_manifest_signature,
    console,
    extract_timestamp,
    fingerprint_phrase,
    format_duration,
    report_csv,
    report_json,
    report_terminal,
    revoke_key_id,
    rotate_signing_keypair,
    scan_log,
    sign_log,
    list_revoked_key_ids,
    verify_log,
    verify_manifest_signature,
)

from .ghost_protocol import (  # noqa: E402
    GhostBaseline,
    GhostConfig,
    GhostEvent,
    GhostReport,
    analyze_log,
    build_baseline,
    load_baseline,
    save_baseline,
    save_report,
)

# Re-export Rich Console class for backward compatibility (tests patch it).
from rich.console import Console  # noqa: E402

__all__ = [
    "CheckpointEntry",
    "Console",
    "SIGNATURE_SCHEME",
    "HashEntry",
    "SuspiciousGap",
    "TamperResult",
    "_default_manifest_path",
    "build_hash_chain",
    "compute_manifest_signature",
    "console",
    "extract_timestamp",
    "fingerprint_phrase",
    "format_duration",
    "main",
    "report_csv",
    "report_json",
    "report_terminal",
    "revoke_key_id",
    "rotate_signing_keypair",
    "scan_log",
    "sign_log",
    "list_revoked_key_ids",
    "verify_log",
    "verify_manifest_signature",

    # Ghost Protocol (offline-first) API
    "GhostBaseline",
    "GhostConfig",
    "GhostEvent",
    "GhostReport",
    "analyze_log",
    "build_baseline",
    "load_baseline",
    "save_baseline",
    "save_report",
]
