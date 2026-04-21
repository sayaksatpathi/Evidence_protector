from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from .ghost_protocol import GhostReport


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _md_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("`", "\\`")


def render_narrative_md(report: GhostReport) -> str:
    s = report.summary
    lines: List[str] = []
    lines.append(f"# Ghost Protocol Narrative\n")
    lines.append(f"- Generated at: `{report.generated_at}`")
    lines.append(f"- File: `{report.file}`")
    lines.append(f"- Total lines: `{s.get('total_lines')}`")
    lines.append(f"- Timestamps found: `{s.get('timestamps_found')}`")
    lines.append(f"- Risk score: `{s.get('risk_score')}`")
    lines.append("")

    lines.append("## Signals")
    events = list(report.events)
    events.sort(key=lambda e: (_SEVERITY_ORDER.get(e.severity, 99), e.signal_type))

    if not events:
        lines.append("No events emitted.")
        return "\n".join(lines) + "\n"

    for ev in events:
        lr = "?"
        if ev.line_range:
            lr = f"{ev.line_range[0]}-{ev.line_range[1]}"
        tr = ""
        if ev.time_range and ev.time_range[0] and ev.time_range[1]:
            tr = f" | time `{ev.time_range[0]}` → `{ev.time_range[1]}`"
        lines.append(f"- **{ev.severity}** `{ev.signal_type}` (lines `{lr}`){tr}")
        if ev.evidence:
            # keep it compact
            for evi in ev.evidence[:3]:
                lines.append(f"  - `{evi.kind}`: {_md_escape(str(evi.detail))}")

    lines.append("")
    lines.append("## Raw Summary")
    lines.append("```json")
    lines.append(str(asdict(report)["summary"]))
    lines.append("```")
    return "\n".join(lines) + "\n"
