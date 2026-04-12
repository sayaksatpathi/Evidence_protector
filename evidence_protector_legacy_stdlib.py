"""Evidence Protector: Automated Log Integrity Monitor.

This tool scans log files for suspicious time gaps between entries and produces
forensic-style reports.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


ISO_TIMESTAMP_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)"
)
APACHE_TIMESTAMP_PATTERN = re.compile(
    r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})]"
)
SYSLOG_TIMESTAMP_PATTERN = re.compile(r"\b([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})\b")


@dataclass
class SuspiciousGap:
    gap_index: int
    gap_start: datetime
    gap_end: datetime
    duration_seconds: int
    line_start: int
    line_end: int
    note: Optional[str] = None


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the Evidence Protector tool."""

    parser = argparse.ArgumentParser(
        description=(
            "Scan a log file for suspicious time gaps between entries and "
            "produce a forensic report."
        )
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the .log file to analyze",
    )
    parser.add_argument(
        "--gap",
        type=int,
        default=300,
        help="Minimum gap in seconds to flag (default: 300)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "csv", "json"],
        default="terminal",
        help="Output format: terminal | csv | json (default: terminal)",
    )
    parser.add_argument(
        "--out",
        help=(
            "Optional output file path (if omitted, print to stdout). "
            "For terminal format, the same text is written to the file if provided."
        ),
    )

    return parser.parse_args()


def _ensure_utc(dt: datetime) -> datetime:
    """Return a timezone-aware datetime in UTC."""

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract the first valid timestamp from a log line.

    Supported formats (checked in order):
      - ISO 8601: 2024-01-15T14:23:01 or 2024-01-15 14:23:01 (with optional offset)
      - Apache/Nginx: [15/Jan/2024:14:23:01 +0000]
      - Syslog: Jan 15 14:23:01 (assumes current UTC year)
    """

    # ISO 8601
    match = ISO_TIMESTAMP_PATTERN.search(line)
    if match:
        text = match.group(1)
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return _ensure_utc(dt)
        except ValueError:
            pass

    # Apache/Nginx style
    match = APACHE_TIMESTAMP_PATTERN.search(line)
    if match:
        text = match.group(1)
        try:
            dt = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    # Syslog style (no year, no timezone)
    match = SYSLOG_TIMESTAMP_PATTERN.search(line)
    if match:
        text = match.group(1)
        current_year = datetime.now(timezone.utc).year
        composed = f"{current_year} {text}"
        try:
            dt = datetime.strptime(composed, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return None


def scan_log(filepath: str, gap_threshold: int) -> Tuple[List[SuspiciousGap], Dict[str, Any]]:
    """Scan the log file for suspicious gaps.

    Returns a list of SuspiciousGap objects and a stats dictionary.
    """

    gaps: List[SuspiciousGap] = []
    stats: Dict[str, Any] = {
        "file": filepath,
        "threshold_seconds": gap_threshold,
        "total_lines": 0,
        "malformed_lines": 0,
        "gaps_found": 0,
        "timestamps_found": 0,
    }

    prev_time: Optional[datetime] = None
    prev_line_num: Optional[int] = None
    gap_index = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            stats["total_lines"] += 1

            ts = extract_timestamp(line)
            if ts is None:
                stats["malformed_lines"] += 1
                continue

            stats["timestamps_found"] += 1

            if prev_time is not None and prev_line_num is not None:
                if ts < prev_time:
                    # Timestamp anomaly: backwards in time
                    gap_index += 1
                    duration = int(abs((ts - prev_time).total_seconds()))
                    gaps.append(
                        SuspiciousGap(
                            gap_index=gap_index,
                            gap_start=prev_time,
                            gap_end=ts,
                            duration_seconds=duration,
                            line_start=prev_line_num,
                            line_end=line_num,
                            note="TIMESTAMP_ANOMALY",
                        )
                    )
                else:
                    delta = (ts - prev_time).total_seconds()
                    if delta > gap_threshold:
                        gap_index += 1
                        gaps.append(
                            SuspiciousGap(
                                gap_index=gap_index,
                                gap_start=prev_time,
                                gap_end=ts,
                                duration_seconds=int(delta),
                                line_start=prev_line_num,
                                line_end=line_num,
                                note=None,
                            )
                        )

            prev_time = ts
            prev_line_num = line_num

    stats["gaps_found"] = len(gaps)
    return gaps, stats


def format_duration(seconds: int) -> str:
    """Format a duration in seconds into a human-readable string."""

    if seconds < 0:
        seconds = -seconds

    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _open_output(path: Optional[str]):
    """Return a file-like object for output (stdout if path is None)."""

    if path is None:
        return sys.stdout
    return open(path, "w", encoding="utf-8", newline="")


def report_terminal(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    """Print a formatted summary table to stdout or to the specified file."""

    output = []
    output.append("Evidence Protector Report")
    output.append("=" * 80)
    output.append(f"File: {stats['file']}")
    output.append(f"Total lines: {stats['total_lines']}")
    output.append(f"Malformed lines (no valid timestamp): {stats['malformed_lines']}")
    output.append(f"Timestamps found: {stats['timestamps_found']}")
    output.append(f"Gap threshold: {stats['threshold_seconds']} seconds")
    output.append(f"Suspicious gaps found: {stats['gaps_found']}")
    output.append("")

    if not gaps:
        output.append("No suspicious gaps found.")
    else:
        header = (
            f"{'#':>3}  {'Gap Start':<25}  {'Gap End':<25}  {'Duration':<12}  "
            f"{'StartLn':>7}  {'EndLn':>7}  Note"
        )
        output.append(header)
        output.append("-" * len(header))
        for gap in gaps:
            duration_hr = format_duration(gap.duration_seconds)
            note = gap.note or ""
            output.append(
                f"{gap.gap_index:>3}  "
                f"{gap.gap_start.isoformat():<25}  "
                f"{gap.gap_end.isoformat():<25}  "
                f"{duration_hr:<12}  "
                f"{gap.line_start:>7}  "
                f"{gap.line_end:>7}  "
                f"{note}"
            )

    text = "\n".join(output) + "\n"
    if args.out:
        with _open_output(args.out) as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def report_csv(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    """Write suspicious gaps to CSV (stdout or file)."""

    fieldnames = [
        "gap_index",
        "gap_start",
        "gap_end",
        "duration_seconds",
        "line_start",
        "line_end",
        "note",
    ]

    with _open_output(args.out) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
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


def report_json(gaps: List[SuspiciousGap], stats: Dict[str, Any], args: argparse.Namespace) -> None:
    """Write a JSON report with overall stats and suspicious gaps."""

    data: Dict[str, Any] = {
        "file": stats["file"],
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

    with _open_output(args.out) as f:
        json.dump(data, f, indent=2)
        if f is sys.stdout:
            f.write("\n")


def main() -> None:
    """Entry point for the CLI tool."""

    args = parse_args()

    if not os.path.isfile(args.file):
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        sys.exit(1)

    gaps, stats = scan_log(args.file, args.gap)

    if stats.get("timestamps_found", 0) == 0:
        sys.stderr.write(f"Warning: no parseable timestamps found in file: {args.file}\n")
        sys.exit(0)

    if args.format == "terminal":
        report_terminal(gaps, stats, args)
    elif args.format == "csv":
        report_csv(gaps, stats, args)
    elif args.format == "json":
        report_json(gaps, stats, args)
    else:
        # Should not happen because argparse restricts choices
        sys.stderr.write(f"Error: unknown format: {args.format}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
