#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import evidence_protector as ep


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(source_dir: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for p in sorted(source_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(source_dir).as_posix()
        items.append(
            {
                "path": rel,
                "bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        )
    return items


def create_bundle(source_dir: Path, out_dir: Path, bundle_name: str = "release-evidence-bundle.zip") -> tuple[Path, Path]:
    if not source_dir.exists() or not source_dir.is_dir():
        raise RuntimeError(f"Source dir does not exist: {source_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / bundle_name
    manifest_path = out_dir / "release-evidence-bundle.manifest.json"

    file_items = collect_files(source_dir)
    if not file_items:
        raise RuntimeError(f"No files found in source dir: {source_dir}")

    with zipfile.ZipFile(bundle_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in file_items:
            rel = str(item["path"])
            zf.write(source_dir / rel, arcname=rel)

    payload: Dict[str, Any] = {
        "manifest_version": 1,
        "created_at": now_iso(),
        "source_dir": str(source_dir),
        "bundle_file": bundle_path.name,
        "bundle_sha256": sha256_file(bundle_path),
        "files": file_items,
    }

    payload["signature"] = ep.compute_manifest_signature(payload)
    sig_ok, sig_reason = ep.verify_manifest_signature(payload)
    if not sig_ok:
        raise RuntimeError(f"Generated bundle signature is invalid: {sig_reason}")

    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return bundle_path, manifest_path


def verify_bundle(bundle_path: Path, manifest_path: Path) -> None:
    if not bundle_path.exists():
        raise RuntimeError(f"Bundle not found: {bundle_path}")
    if not manifest_path.exists():
        raise RuntimeError(f"Manifest not found: {manifest_path}")

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))

    expected_bundle_sha = str(raw.get("bundle_sha256", ""))
    actual_bundle_sha = sha256_file(bundle_path)
    if not expected_bundle_sha or expected_bundle_sha != actual_bundle_sha:
        raise RuntimeError(
            f"Bundle SHA mismatch: expected={expected_bundle_sha[:16]} actual={actual_bundle_sha[:16]}"
        )

    sig_ok, sig_reason = ep.verify_manifest_signature(raw)
    if not sig_ok:
        raise RuntimeError(f"Bundle manifest signature invalid: {sig_reason}")



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create/verify signed release evidence bundle")
    sub = parser.add_subparsers(dest="cmd", required=True)

    create = sub.add_parser("create", help="Create signed bundle")
    create.add_argument("--source-dir", required=True)
    create.add_argument("--out-dir", required=True)
    create.add_argument("--bundle-name", default="release-evidence-bundle.zip")

    verify = sub.add_parser("verify", help="Verify signed bundle")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--manifest", required=True)

    return parser.parse_args()



def main() -> int:
    args = parse_args()

    try:
        if args.cmd == "create":
            bundle_path, manifest_path = create_bundle(
                source_dir=Path(args.source_dir),
                out_dir=Path(args.out_dir),
                bundle_name=args.bundle_name,
            )
            print(f"Created bundle: {bundle_path}")
            print(f"Created manifest: {manifest_path}")
            return 0

        if args.cmd == "verify":
            verify_bundle(bundle_path=Path(args.bundle), manifest_path=Path(args.manifest))
            print("Bundle verification OK")
            return 0

        raise RuntimeError(f"Unsupported command: {args.cmd}")
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
