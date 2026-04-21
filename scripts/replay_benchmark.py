#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import evidence_protector as ep


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stats(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {
            "count": 0,
            "avg_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
        }

    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))
    return {
        "count": len(ordered),
        "avg_ms": round(float(statistics.fmean(ordered)), 3),
        "min_ms": round(float(ordered[0]), 3),
        "max_ms": round(float(ordered[-1]), 3),
        "p50_ms": round(float(statistics.median(ordered)), 3),
        "p95_ms": round(float(ordered[p95_index]), 3),
    }


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return (end_ns - start_ns) / 1_000_000.0


def _one_run(file_path: Path, gap: int) -> dict[str, float]:
    run_ms: dict[str, float] = {}

    t0 = time.perf_counter_ns()
    ep.scan_log(str(file_path), gap_threshold=gap)
    t1 = time.perf_counter_ns()
    run_ms["scan_ms"] = _elapsed_ms(t0, t1)

    with tempfile.TemporaryDirectory(prefix="replay_bench_") as tmp:
        tmp_dir = Path(tmp)
        manifest_path = tmp_dir / "bench.manifest.json"
        verify_report_path = tmp_dir / "verify.json"

        t2 = time.perf_counter_ns()
        ep.sign_log(str(file_path), str(manifest_path))
        t3 = time.perf_counter_ns()
        run_ms["sign_ms"] = _elapsed_ms(t2, t3)

        t4 = time.perf_counter_ns()
        ep.verify_log(str(file_path), str(manifest_path), str(verify_report_path))
        t5 = time.perf_counter_ns()
        run_ms["verify_ms"] = _elapsed_ms(t4, t5)

    t6 = time.perf_counter_ns()
    ep.analyze_log(str(file_path), config=ep.GhostConfig(max_lines=250_000, gap_threshold_seconds=gap))
    t7 = time.perf_counter_ns()
    run_ms["ghost_analyze_ms"] = _elapsed_ms(t6, t7)

    run_ms["pipeline_total_ms"] = round(
        run_ms["scan_ms"] + run_ms["sign_ms"] + run_ms["verify_ms"] + run_ms["ghost_analyze_ms"],
        3,
    )
    return run_ms


def run_benchmark(file_path: Path, *, iterations: int, warmup: int, gap: int) -> dict[str, Any]:
    if not file_path.exists() or not file_path.is_file():
        raise RuntimeError(f"Input file not found: {file_path}")

    for _ in range(max(0, warmup)):
        _one_run(file_path, gap=gap)

    runs: list[dict[str, float]] = []
    for index in range(1, iterations + 1):
        run = _one_run(file_path, gap=gap)
        run["iteration"] = float(index)
        runs.append(run)

    metric_names = ["scan_ms", "sign_ms", "verify_ms", "ghost_analyze_ms", "pipeline_total_ms"]
    summary = {
        metric: _stats([float(run[metric]) for run in runs])
        for metric in metric_names
    }

    return {
        "version": 1,
        "generated_at": _now_iso(),
        "file": str(file_path),
        "config": {
            "iterations": iterations,
            "warmup": warmup,
            "gap": gap,
        },
        "runs": runs,
        "summary": summary,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay benchmark harness for Evidence Protector pipeline")
    parser.add_argument("--file", required=True, help="Input log file path")
    parser.add_argument("--iterations", type=int, default=5, help="Measured benchmark iterations")
    parser.add_argument("--warmup", type=int, default=1, help="Warmup iterations before measurement")
    parser.add_argument("--gap", type=int, default=300, help="Gap threshold used by scan/ghost")
    parser.add_argument("--out", required=True, help="Output JSON file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.iterations < 1:
        print("--iterations must be >= 1", file=sys.stderr)
        return 2
    if args.warmup < 0:
        print("--warmup must be >= 0", file=sys.stderr)
        return 2

    try:
        result = run_benchmark(
            Path(args.file),
            iterations=int(args.iterations),
            warmup=int(args.warmup),
            gap=int(args.gap),
        )
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote benchmark report: {out_path}")
        return 0
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
