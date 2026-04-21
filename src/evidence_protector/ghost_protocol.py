from __future__ import annotations

import json
import re
import math
import os
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from .core import extract_timestamp


GHOST_PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class GhostConfig:
    window_lines: int = 200
    max_lines: int = 250_000
    gap_threshold_seconds: int = 300

    # Jensen-Shannon divergence (0..1). Higher means “different voice”.
    dna_jsd_threshold: float = 0.12
    dna_min_window_chars: int = 800

    # Entropy spike detection (z-score relative to baseline)
    entropy_z_threshold: float = 3.5
    entropy_min_window_chars: int = 800

    # Time-based rhythm heuristics
    regularity_cv_threshold: float = 0.01  # stdev/mean
    min_intervals_for_regularity: int = 40

    # Filesystem timestamp sanity
    fs_mtime_vs_last_log_seconds: int = 3600


@dataclass(frozen=True)
class GhostBaseline:
    version: int
    created_at: str
    source_hint: str

    total_lines: int
    timestamps_found: int
    malformed_lines: int

    # Character “DNA” distribution.
    char_prob: List[float]  # length 257 (0..255 plus 'other')

    # Entropy baseline across parsed windows/lines.
    entropy_mean: float
    entropy_stdev: float

    # Inter-arrival baseline.
    interval_mean: float
    interval_stdev: float


@dataclass(frozen=True)
class GhostEvidence:
    kind: str
    detail: Dict[str, Any]


@dataclass(frozen=True)
class GhostEvent:
    signal_type: str
    severity: str  # LOW|MEDIUM|HIGH|CRITICAL
    confidence: float  # 0..1
    time_range: Optional[Tuple[str, str]]
    line_range: Optional[Tuple[int, int]]
    evidence: List[GhostEvidence]


@dataclass(frozen=True)
class GhostReport:
    version: int
    generated_at: str
    file: str
    config: Dict[str, Any]
    summary: Dict[str, Any]
    events: List[GhostEvent]


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_SYSLOG_RE = re.compile(
    r"\b(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\b"
)


def _parse_syslog_with_year(text: str, year: int) -> Optional[datetime]:
    try:
        dt = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def extract_timestamp_consensus(line: str, prev_ts: Optional[datetime]) -> Optional[datetime]:
    """Timestamp parsing with a small "consensus" layer.

    Rationale: many syslog-style timestamps omit the year. When watching or analyzing
    logs that span year boundaries, assuming the current year can create false
    TIME_REVERSAL signals. Here we detect syslog-style timestamps and choose a
    plausible year near the previous timestamp.
    """

    m = _SYSLOG_RE.search(line)
    if m:
        candidate = f"{m.group('mon')} {m.group('day')} {m.group('time')}"
        years: list[int] = []
        now_year = datetime.now(timezone.utc).year
        years.append(now_year)
        if prev_ts is not None:
            years.extend([prev_ts.year - 1, prev_ts.year, prev_ts.year + 1])

        best: Optional[datetime] = None
        best_score: float = 1e30
        for y in sorted(set(years)):
            dt = _parse_syslog_with_year(candidate, y)
            if dt is None:
                continue
            if prev_ts is None:
                return dt
            delta = (dt - prev_ts).total_seconds()
            # Prefer non-negative deltas; otherwise choose closest.
            score = abs(delta) + (10_000_000 if delta < 0 else 0)
            if score < best_score:
                best = dt
                best_score = score

        if best is not None:
            return best

    return extract_timestamp(line)


def load_report(path: str) -> GhostReport:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    events = []
    for ev in raw.get("events", []) or []:
        evidence = [GhostEvidence(**e) for e in (ev.get("evidence", []) or [])]
        events.append(
            GhostEvent(
                signal_type=ev.get("signal_type"),
                severity=ev.get("severity"),
                confidence=float(ev.get("confidence", 0.0) or 0.0),
                time_range=tuple(ev.get("time_range")) if ev.get("time_range") else None,
                line_range=tuple(ev.get("line_range")) if ev.get("line_range") else None,
                evidence=evidence,
            )
        )

    return GhostReport(
        version=int(raw.get("version", GHOST_PROTOCOL_VERSION)),
        generated_at=str(raw.get("generated_at", "")),
        file=str(raw.get("file", "")),
        config=dict(raw.get("config", {}) or {}),
        summary=dict(raw.get("summary", {}) or {}),
        events=events,
    )


def _char_counts(line: str) -> List[int]:
    counts = [0] * 257
    for ch in line:
        o = ord(ch)
        if 0 <= o <= 255:
            counts[o] += 1
        else:
            counts[256] += 1
    return counts


def _counts_to_prob(counts: List[int]) -> List[float]:
    total = float(sum(counts))
    if total <= 0:
        return [0.0] * len(counts)
    return [c / total for c in counts]


def _shannon_entropy_from_counts(counts: List[int]) -> float:
    total = float(sum(counts))
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


def _js_divergence(p: List[float], q: List[float]) -> float:
    # Jensen–Shannon divergence (base-2). Bounded: 0..1 for distributions.
    # We add a tiny epsilon to avoid log(0) without biasing results meaningfully.
    eps = 1e-12
    m = [(pi + qi) * 0.5 for pi, qi in zip(p, q)]

    def kl(a: List[float], b: List[float]) -> float:
        s = 0.0
        for ai, bi in zip(a, b):
            ai2 = ai if ai > 0 else eps
            bi2 = bi if bi > 0 else eps
            s += ai2 * math.log2(ai2 / bi2)
        return s

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


def save_baseline(baseline: GhostBaseline, path: str) -> None:
    Path(path).write_text(json.dumps(asdict(baseline), indent=2) + "\n", encoding="utf-8")


def load_baseline(path: str) -> GhostBaseline:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return GhostBaseline(**raw)


def build_baseline(file_path: str, *, config: Optional[GhostConfig] = None, source_hint: str = "") -> GhostBaseline:
    cfg = config or GhostConfig()
    total_lines = 0
    ts_found = 0
    malformed = 0

    global_counts = [0] * 257
    entropies: List[float] = []
    intervals: List[float] = []
    prev_ts: Optional[datetime] = None

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            if total_lines > cfg.max_lines:
                break

            counts = _char_counts(line)
            for i in range(257):
                global_counts[i] += counts[i]
            entropies.append(_shannon_entropy_from_counts(counts))

            ts = extract_timestamp_consensus(line, prev_ts)
            if ts is None:
                malformed += 1
                continue
            ts_found += 1
            if prev_ts is not None:
                delta = (ts - prev_ts).total_seconds()
                if delta >= 0:
                    intervals.append(delta)
            prev_ts = ts

    char_prob = _counts_to_prob(global_counts)
    entropy_mean = float(sum(entropies) / max(1, len(entropies)))
    entropy_var = 0.0
    if len(entropies) > 1:
        entropy_var = sum((x - entropy_mean) ** 2 for x in entropies) / (len(entropies) - 1)
    entropy_stdev = math.sqrt(entropy_var) if entropy_var > 0 else 0.0

    interval_mean = float(sum(intervals) / max(1, len(intervals)))
    interval_var = 0.0
    if len(intervals) > 1:
        interval_var = sum((x - interval_mean) ** 2 for x in intervals) / (len(intervals) - 1)
    interval_stdev = math.sqrt(interval_var) if interval_var > 0 else 0.0

    return GhostBaseline(
        version=GHOST_PROTOCOL_VERSION,
        created_at=_now_utc_iso(),
        source_hint=source_hint,
        total_lines=total_lines,
        timestamps_found=ts_found,
        malformed_lines=malformed,
        char_prob=char_prob,
        entropy_mean=entropy_mean,
        entropy_stdev=entropy_stdev,
        interval_mean=interval_mean,
        interval_stdev=interval_stdev,
    )


def analyze_log(
    file_path: str,
    *,
    baseline: Optional[GhostBaseline] = None,
    config: Optional[GhostConfig] = None,
    display_file: Optional[str] = None,
) -> GhostReport:
    cfg = config or GhostConfig()
    events: List[GhostEvent] = []

    total_lines = 0
    ts_found = 0
    malformed = 0
    negative_jumps = 0
    big_gaps = 0
    max_gap = 0

    # For rhythm stats
    intervals: List[float] = []
    prev_ts: Optional[datetime] = None
    prev_ts_iso: Optional[str] = None
    first_ts_iso: Optional[str] = None
    last_ts_iso: Optional[str] = None

    # Sliding window for DNA/entropy
    window: Deque[Tuple[int, str, List[int], float, Optional[str]]] = deque()
    window_counts = [0] * 257
    window_char_total = 0
    window_entropy_sum = 0.0

    def emit_dna_if_needed(current_line: int):
        nonlocal window_counts, window_char_total
        if not baseline:
            return
        if window_char_total < cfg.dna_min_window_chars:
            return
        wp = _counts_to_prob(window_counts)
        jsd = _js_divergence(wp, baseline.char_prob)
        if jsd >= cfg.dna_jsd_threshold:
            start_line = window[0][0]
            end_line = window[-1][0]
            events.append(
                GhostEvent(
                    signal_type="LOG_DNA_SHIFT",
                    severity="HIGH" if jsd >= (cfg.dna_jsd_threshold * 1.6) else "MEDIUM",
                    confidence=min(0.99, 0.55 + (jsd / max(1e-6, cfg.dna_jsd_threshold)) * 0.15),
                    time_range=None,
                    line_range=(start_line, end_line),
                    evidence=[
                        GhostEvidence(kind="js_divergence", detail={"jsd": jsd, "threshold": cfg.dna_jsd_threshold}),
                        GhostEvidence(kind="window", detail={"window_lines": len(window), "chars": window_char_total, "at_line": current_line}),
                    ],
                )
            )

    def emit_entropy_if_needed(current_line: int):
        if not baseline:
            return
        if window_char_total < cfg.entropy_min_window_chars:
            return
        mean = baseline.entropy_mean
        sd = baseline.entropy_stdev
        if sd <= 1e-9:
            return
        avg_entropy = window_entropy_sum / max(1, len(window))
        z = (avg_entropy - mean) / sd
        if z >= cfg.entropy_z_threshold:
            start_line = window[0][0]
            end_line = window[-1][0]
            events.append(
                GhostEvent(
                    signal_type="ENTROPY_SPIKE",
                    severity="HIGH" if z >= (cfg.entropy_z_threshold * 1.3) else "MEDIUM",
                    confidence=min(0.99, 0.5 + (z / max(1e-6, cfg.entropy_z_threshold)) * 0.2),
                    time_range=None,
                    line_range=(start_line, end_line),
                    evidence=[
                        GhostEvidence(kind="entropy", detail={"avg_entropy": avg_entropy, "z": z, "baseline_mean": mean, "baseline_stdev": sd}),
                        GhostEvidence(kind="window", detail={"window_lines": len(window), "chars": window_char_total, "at_line": current_line}),
                    ],
                )
            )

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            if total_lines > cfg.max_lines:
                break

            # Injection primitives
            if "\x00" in line:
                events.append(
                    GhostEvent(
                        signal_type="INJECTION_PRIMITIVE",
                        severity="HIGH",
                        confidence=0.9,
                        time_range=None,
                        line_range=(total_lines, total_lines),
                        evidence=[GhostEvidence(kind="null_byte", detail={"line": total_lines})],
                    )
                )
            if "\r" in line and not line.endswith("\r\n") and not line.endswith("\r"):
                events.append(
                    GhostEvent(
                        signal_type="INJECTION_PRIMITIVE",
                        severity="MEDIUM",
                        confidence=0.7,
                        time_range=None,
                        line_range=(total_lines, total_lines),
                        evidence=[GhostEvidence(kind="carriage_return", detail={"line": total_lines})],
                    )
                )

            counts = _char_counts(line)
            ent = _shannon_entropy_from_counts(counts)

            ts = extract_timestamp_consensus(line, prev_ts)
            ts_iso: Optional[str] = None
            if ts is None:
                malformed += 1
            else:
                ts_found += 1
                ts_iso = ts.isoformat()
                if first_ts_iso is None:
                    first_ts_iso = ts_iso
                last_ts_iso = ts_iso

                if prev_ts is not None:
                    delta = (ts - prev_ts).total_seconds()
                    if delta < 0:
                        negative_jumps += 1
                        events.append(
                            GhostEvent(
                                signal_type="TIME_REVERSAL",
                                severity="HIGH",
                                confidence=0.85,
                                time_range=(prev_ts_iso or prev_ts.isoformat(), ts_iso),
                                line_range=(max(1, total_lines - 1), total_lines),
                                evidence=[GhostEvidence(kind="delta_seconds", detail={"delta": delta})],
                            )
                        )
                    else:
                        intervals.append(delta)
                        if delta > cfg.gap_threshold_seconds:
                            big_gaps += 1
                            if int(delta) > max_gap:
                                max_gap = int(delta)

                            severity = "MEDIUM" if delta <= (cfg.gap_threshold_seconds * 5) else "HIGH"
                            events.append(
                                GhostEvent(
                                    signal_type="TIME_GAP",
                                    severity=severity,
                                    confidence=0.65,
                                    time_range=(prev_ts_iso or prev_ts.isoformat(), ts_iso),
                                    line_range=(max(1, total_lines - 1), total_lines),
                                    evidence=[
                                        GhostEvidence(
                                            kind="delta_seconds",
                                            detail={"delta": delta, "threshold": cfg.gap_threshold_seconds},
                                        )
                                    ],
                                )
                            )

                        # Drift vs baseline interval (if available)
                        if baseline and baseline.interval_stdev and baseline.interval_stdev > 1e-9:
                            z = (delta - baseline.interval_mean) / baseline.interval_stdev
                            if z >= 6.0:
                                events.append(
                                    GhostEvent(
                                        signal_type="RHYTHM_DRIFT",
                                        severity="MEDIUM",
                                        confidence=0.6,
                                        time_range=(prev_ts_iso or prev_ts.isoformat(), ts_iso),
                                        line_range=(max(1, total_lines - 1), total_lines),
                                        evidence=[
                                            GhostEvidence(
                                                kind="interval_z",
                                                detail={
                                                    "delta": delta,
                                                    "z": z,
                                                    "baseline_mean": baseline.interval_mean,
                                                    "baseline_stdev": baseline.interval_stdev,
                                                },
                                            )
                                        ],
                                    )
                                )
                prev_ts = ts
                prev_ts_iso = ts_iso

            # Slide window
            window.append((total_lines, line, counts, ent, ts_iso))
            for i in range(257):
                window_counts[i] += counts[i]
            line_chars = int(sum(counts))
            window_char_total += line_chars
            window_entropy_sum += ent

            while len(window) > cfg.window_lines:
                old_line_no, _old_line, old_counts, old_ent, _old_ts = window.popleft()
                for i in range(257):
                    window_counts[i] -= old_counts[i]
                window_char_total -= int(sum(old_counts))
                window_entropy_sum -= old_ent

            if len(window) == cfg.window_lines:
                emit_dna_if_needed(total_lines)
                emit_entropy_if_needed(total_lines)

    # Rhythm: synthetic regularity
    if intervals and len(intervals) >= cfg.min_intervals_for_regularity:
        mean = sum(intervals) / len(intervals)
        if mean > 0:
            var = sum((x - mean) ** 2 for x in intervals) / max(1, (len(intervals) - 1))
            sd = math.sqrt(var) if var > 0 else 0.0
            cv = (sd / mean) if mean else 0.0
            if cv <= cfg.regularity_cv_threshold:
                events.append(
                    GhostEvent(
                        signal_type="SYNTHETIC_REGULARITY",
                        severity="MEDIUM",
                        confidence=0.65,
                        time_range=(first_ts_iso, last_ts_iso) if first_ts_iso and last_ts_iso else None,
                        line_range=None,
                        evidence=[GhostEvidence(kind="interval_stats", detail={"mean": mean, "stdev": sd, "cv": cv})],
                    )
                )

    # Filesystem vs last log timestamp
    try:
        if last_ts_iso:
            mtime = os.path.getmtime(file_path)
            last_dt = datetime.fromisoformat(last_ts_iso.replace("Z", "+00:00"))
            last_epoch = last_dt.timestamp()
            drift = abs(mtime - last_epoch)
            if drift >= cfg.fs_mtime_vs_last_log_seconds:
                events.append(
                    GhostEvent(
                        signal_type="FS_TIME_MISMATCH",
                        severity="MEDIUM",
                        confidence=0.6,
                        time_range=None,
                        line_range=None,
                        evidence=[
                            GhostEvidence(
                                kind="mtime_vs_last_log",
                                detail={
                                    "file_mtime_epoch": mtime,
                                    "last_log_epoch": last_epoch,
                                    "delta_seconds": drift,
                                    "threshold_seconds": cfg.fs_mtime_vs_last_log_seconds,
                                },
                            )
                        ],
                    )
                )
    except Exception:
        pass

    # Summary + naive risk score
    risk = 0
    for ev in events:
        if ev.severity == "CRITICAL":
            risk += 100
        elif ev.severity == "HIGH":
            risk += 60
        elif ev.severity == "MEDIUM":
            risk += 25
        else:
            risk += 10

    summary: Dict[str, Any] = {
        "total_lines": total_lines,
        "timestamps_found": ts_found,
        "malformed_lines": malformed,
        "big_gaps": big_gaps,
        "max_gap_seconds": max_gap,
        "time_reversals": negative_jumps,
        "first_timestamp": first_ts_iso,
        "last_timestamp": last_ts_iso,
        "event_counts": {
            "total": len(events),
            "critical": sum(1 for e in events if e.severity == "CRITICAL"),
            "high": sum(1 for e in events if e.severity == "HIGH"),
            "medium": sum(1 for e in events if e.severity == "MEDIUM"),
            "low": sum(1 for e in events if e.severity == "LOW"),
        },
        "risk_score": risk,
    }

    return GhostReport(
        version=GHOST_PROTOCOL_VERSION,
        generated_at=_now_utc_iso(),
        file=str(display_file or file_path),
        config=asdict(cfg),
        summary=summary,
        events=events,
    )


def save_report(report: GhostReport, path: str) -> None:
    Path(path).write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
