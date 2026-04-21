from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

import base64
import os
from .ghost_protocol import GhostBaseline, GhostConfig, analyze_log, build_baseline


def generate_attack_fixtures(out_dir: str) -> Dict[str, str]:
    """Create synthetic logs that trigger key detectors.

    Returns a mapping fixture_name -> file_path.
    """

    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)

    fixtures: Dict[str, str] = {}

    # Baseline corpus (moderate entropy, varied lines) used by baseline-relative detectors.
    baseline = p / "fixture_baseline_normal.log"
    base_lines = []
    for i in range(240):
        # Ensure timestamps advance with small jitter to create non-zero stdev.
        sec = i + (1 if (i % 17 == 0) else 0)
        base_lines.append(f"2024-01-15T14:{sec // 60:02d}:{sec % 60:02d}Z user=alice action=ok id={i} msg=hello-{i % 7}\n")
    baseline.write_text("".join(base_lines), encoding="utf-8")
    fixtures["baseline_normal"] = str(baseline)

    # Time reversal
    tr = p / "fixture_time_reversal.log"
    tr.write_text(
        "2024-01-15T14:00:10Z ok\n2024-01-15T14:00:05Z backwards\n",
        encoding="utf-8",
    )
    fixtures["time_reversal"] = str(tr)

    # Big gap
    gap = p / "fixture_big_gap.log"
    gap.write_text(
        "2024-01-15T14:00:00Z a\n2024-01-15T14:20:00Z b\n",
        encoding="utf-8",
    )
    fixtures["big_gap"] = str(gap)

    # Null byte injection
    nb = p / "fixture_null_byte.log"
    with nb.open("wb") as f:
        f.write(b"2024-01-15T14:00:00Z ok\n")
        f.write(b"2024-01-15T14:00:01Z bad\x00stuff\n")
    fixtures["null_byte"] = str(nb)

    # Synthetic regularity: constant 1-second intervals.
    reg = p / "fixture_synthetic_regularity.log"
    reg_lines = [f"2024-01-15T15:00:{i:02d}Z ok\n" for i in range(60)]
    reg.write_text("".join(reg_lines), encoding="utf-8")
    fixtures["synthetic_regularity"] = str(reg)

    # Log DNA shift: content distribution changes vs baseline.
    dna = p / "fixture_dna_shift.log"
    dna_lines = []
    for i in range(260):
        # Uppercase + digits bias
        dna_lines.append(f"2024-01-15T16:{i // 60:02d}:{i % 60:02d}Z USER=BOB EVENT=LOGIN_OK CODE={i:06d} ######\n")
    dna.write_text("".join(dna_lines), encoding="utf-8")
    fixtures["dna_shift"] = str(dna)

    # Entropy spike: embed high-entropy base64 payload in the middle of otherwise normal lines.
    ent = p / "fixture_entropy_spike.log"
    payload = base64.b64encode(b"".join(bytes([(x * 73 + 19) % 256]) for x in range(4096))).decode("ascii")
    ent_lines = []
    for i in range(140):
        ent_lines.append(f"2024-01-15T17:{i // 60:02d}:{i % 60:02d}Z ok id={i}\n")
        if i == 70:
            ent_lines.append(f"2024-01-15T17:01:11Z blob={payload}\n")
    ent.write_text("".join(ent_lines), encoding="utf-8")
    fixtures["entropy_spike"] = str(ent)

    return fixtures


def run_selftest(fixtures: Dict[str, str]) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}

    baseline_obj: GhostBaseline | None = None
    baseline_path = fixtures.get("baseline_normal")
    if baseline_path:
        baseline_obj = build_baseline(
            baseline_path,
            config=GhostConfig(max_lines=250_000),
            source_hint="selftest",
        )

    expected: Dict[str, List[str]] = {
        "time_reversal": ["TIME_REVERSAL"],
        "big_gap": ["TIME_GAP"],
        "null_byte": ["INJECTION_PRIMITIVE"],
        "synthetic_regularity": ["SYNTHETIC_REGULARITY"],
        "dna_shift": ["LOG_DNA_SHIFT"],
        "entropy_spike": ["ENTROPY_SPIKE"],
    }
    for name, path in fixtures.items():
        if name == "baseline_normal":
            continue
        report = analyze_log(
            path,
            baseline=baseline_obj,
            config=GhostConfig(
                max_lines=50_000,
                window_lines=20,
                gap_threshold_seconds=300,
                dna_min_window_chars=200,
                entropy_min_window_chars=200,
                min_intervals_for_regularity=40,
            ),
        )
        kinds = [e.signal_type for e in report.events]
        exp = expected.get(name, [])
        missing = [k for k in exp if k not in kinds]
        ok = len(missing) == 0

        results[name] = {
            "ok": ok,
            "expected": exp,
            "missing": missing,
            "events": kinds,
            "summary": report.summary,
        }

    return results
