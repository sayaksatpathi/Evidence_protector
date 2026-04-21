from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ghost_protocol import GhostEvidence, GhostEvent, GhostReport


def load_receipts_jsonl(path: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


def correlate_report_with_receipts(report: GhostReport, receipts: List[Dict[str, Any]]) -> GhostReport:
    file_receipts = [r for r in receipts if str(r.get("kind")) == "FILE" and isinstance(r.get("data"), dict)]
    if len(file_receipts) < 2:
        return report

    # sort by created_at if present
    def key(r: Dict[str, Any]) -> str:
        return str(r.get("created_at", ""))

    file_receipts.sort(key=key)

    added: List[GhostEvent] = []

    prev = file_receipts[0]["data"]
    for r in file_receipts[1:]:
        cur = r["data"]
        prev_size = int(prev.get("size_bytes", 0) or 0)
        cur_size = int(cur.get("size_bytes", 0) or 0)

        prev_m = float(prev.get("mtime_epoch", 0.0) or 0.0)
        cur_m = float(cur.get("mtime_epoch", 0.0) or 0.0)

        if cur_size < prev_size:
            added.append(
                GhostEvent(
                    signal_type="FS_TRUNCATION",
                    severity="HIGH",
                    confidence=0.85,
                    time_range=None,
                    line_range=None,
                    evidence=[
                        GhostEvidence(kind="sizes", detail={"before": prev_size, "after": cur_size}),
                        GhostEvidence(kind="mtimes", detail={"before": prev_m, "after": cur_m}),
                    ],
                )
            )

        if cur_m < prev_m:
            added.append(
                GhostEvent(
                    signal_type="FS_MTIME_BACKWARDS",
                    severity="MEDIUM",
                    confidence=0.65,
                    time_range=None,
                    line_range=None,
                    evidence=[GhostEvidence(kind="mtimes", detail={"before": prev_m, "after": cur_m})],
                )
            )

        # Detect rewrite by sample hash changes with stable size.
        if cur_size == prev_size:
            prev_head = prev.get("head_sha256")
            cur_head = cur.get("head_sha256")
            prev_tail = prev.get("tail_sha256")
            cur_tail = cur.get("tail_sha256")
            if prev_head and cur_head and prev_head != cur_head:
                added.append(
                    GhostEvent(
                        signal_type="FS_REWRITE",
                        severity="HIGH",
                        confidence=0.8,
                        time_range=None,
                        line_range=None,
                        evidence=[GhostEvidence(kind="head_sha256", detail={"before": prev_head, "after": cur_head})],
                    )
                )
            elif prev_tail and cur_tail and prev_tail != cur_tail:
                added.append(
                    GhostEvent(
                        signal_type="FS_REWRITE",
                        severity="HIGH",
                        confidence=0.8,
                        time_range=None,
                        line_range=None,
                        evidence=[GhostEvidence(kind="tail_sha256", detail={"before": prev_tail, "after": cur_tail})],
                    )
                )

        prev = cur

    if not added:
        return report

    # Update summary counts/risk
    events = list(report.events) + added
    risk = int(report.summary.get("risk_score", 0) or 0)
    for ev in added:
        if ev.severity == "CRITICAL":
            risk += 100
        elif ev.severity == "HIGH":
            risk += 60
        elif ev.severity == "MEDIUM":
            risk += 25
        else:
            risk += 10

    summary = dict(report.summary)
    counts = dict(summary.get("event_counts", {}) or {})
    counts["total"] = int(counts.get("total", 0) or 0) + len(added)
    counts["high"] = int(counts.get("high", 0) or 0) + sum(1 for e in added if e.severity == "HIGH")
    counts["medium"] = int(counts.get("medium", 0) or 0) + sum(1 for e in added if e.severity == "MEDIUM")
    counts["critical"] = int(counts.get("critical", 0) or 0) + sum(1 for e in added if e.severity == "CRITICAL")
    counts["low"] = int(counts.get("low", 0) or 0) + sum(1 for e in added if e.severity == "LOW")
    summary["event_counts"] = counts
    summary["risk_score"] = risk

    return GhostReport(
        version=report.version,
        generated_at=report.generated_at,
        file=report.file,
        config=report.config,
        summary=summary,
        events=events,
    )


def save_report(report: GhostReport, path: str) -> None:
    Path(path).write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
