#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate replay benchmark metrics against budget thresholds")
    parser.add_argument("--report", required=True, help="Path to replay benchmark JSON report")
    parser.add_argument("--budget", required=True, help="Path to performance budget JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)
    budget_path = Path(args.budget)

    if not report_path.exists():
        raise SystemExit(f"Report not found: {report_path}")
    if not budget_path.exists():
        raise SystemExit(f"Budget file not found: {budget_path}")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    budget = json.loads(budget_path.read_text(encoding="utf-8"))

    summary = report.get("summary", {})
    budgets = budget.get("budgets_ms", {})
    if not isinstance(summary, dict) or not isinstance(budgets, dict):
        raise SystemExit("Invalid report or budget format")

    failures: list[str] = []
    for metric, threshold in budgets.items():
        metric_summary = summary.get(metric, {}) if isinstance(summary.get(metric), dict) else {}
        p95 = float(metric_summary.get("p95_ms", 0.0) or 0.0)
        threshold_value = float(threshold)
        print(f"{metric}: p95={p95:.3f}ms threshold={threshold_value:.3f}ms")
        if p95 > threshold_value:
            failures.append(f"{metric} p95 {p95:.3f}ms exceeds {threshold_value:.3f}ms")

    if failures:
        print("\nPerformance budget violations:")
        for row in failures:
            print(f"- {row}")
        return 1

    print("\nPerformance budgets passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
