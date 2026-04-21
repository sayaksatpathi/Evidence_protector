from __future__ import annotations

import json
import os
import time
import hashlib
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import tempfile

import click

from .core import (
    _run_scan,
    list_revoked_key_ids,
    revoke_key_id,
    rotate_signing_keypair,
    sign_log,
    verify_log,
)
from .ghost_protocol import (
    GhostBaseline,
    GhostConfig,
    analyze_log,
    build_baseline,
    load_baseline,
    load_report,
    save_baseline,
    save_report,
)
from .ghost_watch import tail_lines as tail_file_lines
from .ghost_receipts import collect_receipts, write_receipts_jsonl
from .ghost_correlate import correlate_report_with_receipts, load_receipts_jsonl, save_report as save_correlated_report
from .ghost_commitments import (
    append_commitment,
    default_register_path,
    export_anchor_statement,
    append_witness,
    verify_witnesses,
    export_anchor,
    verify_anchor,
    verify_commitments,
)
from .ghost_canary import generate_canary, load_canary, save_canary, scan_for_canary
from .ghost_narrative import render_narrative_md
from .ghost_selftest import generate_attack_fixtures, run_selftest


@click.group(invoke_without_command=True)
@click.option(
    "--file",
    required=False,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "csv", "json"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output file path (scan report | sign manifest | verify JSON report)",
)
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Manifest JSON path (verify mode)",
)
@click.option(
    "--mode",
    type=click.Choice(["scan", "sign", "verify"]),
    default="scan",
    show_default=True,
    help="scan=gap detection only | sign=build manifest | verify=check manifest",
)
# Newer signing options (also exposed on the `sign` subcommand)
@click.option(
    "--manifest-mode",
    type=click.Choice(["full", "compact"]),
    default=None,
    help="Manifest mode for sign: full stores per-line entries, compact stores checkpoints only",
)
@click.option(
    "--checkpoint-every",
    type=int,
    default=None,
    help="For compact manifests: store a checkpoint every N lines",
)
@click.option(
    "--chain-scheme",
    type=click.Choice(["v1-line+prev", "v2-prev+lineno+line", "v1", "v2", "legacy"]),
    default=None,
    help="Hash chain construction scheme to use for signing",
)
def main(
    file: Optional[str],
    gap: int,
    output_format: str,
    out: Optional[str],
    manifest: Optional[str],
    mode: str,
    manifest_mode: Optional[str] = None,
    checkpoint_every: Optional[int] = None,
    chain_scheme: Optional[str] = None,
) -> None:
    """Evidence Protector CLI.

    Preferred:
      - evidence_protector scan --file app.log
      - evidence_protector sign --file app.log
      - evidence_protector verify --file app.log

    Legacy (still supported):
      - evidence_protector --file app.log --mode scan|sign|verify
    """

    ctx = click.get_current_context(silent=True)
    if ctx is not None and ctx.invoked_subcommand is not None:
        return

    if not file:
        raise click.UsageError("Missing option '--file'.")

    if mode == "sign":
        sign_log(
            file,
            out,
            manifest_mode=manifest_mode,
            checkpoint_every=checkpoint_every,
            chain_scheme=chain_scheme,
        )
        return

    if mode == "verify":
        verify_log(file, manifest, out)
        return

    _run_scan(file, gap, output_format, out)


@main.command("scan")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "csv", "json"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output file path (scan report)",
)
def scan_cmd(file: str, gap: int, output_format: str, out: Optional[str]) -> None:
    """Scan a log for suspicious time gaps."""

    _run_scan(file, gap, output_format, out)


@main.command("sign")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output manifest path (defaults to <file>.manifest.json)",
)
@click.option(
    "--manifest-mode",
    type=click.Choice(["full", "compact"]),
    default=None,
    help="full stores per-line entries, compact stores checkpoints only",
)
@click.option(
    "--checkpoint-every",
    type=int,
    default=None,
    help="For compact manifests: store a checkpoint every N lines",
)
@click.option(
    "--chain-scheme",
    type=click.Choice(["v1-line+prev", "v2-prev+lineno+line", "v1", "v2", "legacy"]),
    default=None,
    help="Hash chain construction scheme",
)
def sign_cmd(file: str, out: Optional[str], manifest_mode: Optional[str], checkpoint_every: Optional[int], chain_scheme: Optional[str]) -> None:
    """Create a signed manifest for a log."""

    sign_log(
        file,
        out,
        manifest_mode=manifest_mode,
        checkpoint_every=checkpoint_every,
        chain_scheme=chain_scheme,
    )


@main.command("verify")
@click.option(
    "--file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .log file",
)
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Manifest JSON path (defaults to <file>.manifest.json)",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output JSON report path (optional)",
)
def verify_cmd(file: str, manifest: Optional[str], out: Optional[str]) -> None:
    """Verify a log against a saved manifest."""

    verify_log(file, manifest, out)


@main.group("ghost")
def ghost_group() -> None:
    """Ghost Protocol detectors (offline-first).

    This mode is cross-platform (Windows/Linux) and does not require an agent/daemon.
    """


@ghost_group.command("baseline")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Log file to baseline",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Baseline output path (defaults to <file>.ghost-baseline.json)",
)
@click.option(
    "--max-lines",
    type=int,
    default=250_000,
    show_default=True,
    help="Max lines to read for baseline",
)
@click.option(
    "--source-hint",
    default="",
    help="Optional label describing the log source (e.g. 'prod/nginx')",
)
def ghost_baseline_cmd(file_path: str, out: Optional[str], max_lines: int, source_hint: str) -> None:
    """Build a baseline profile (Log DNA + rhythm + entropy)."""

    out_path = out or f"{file_path}.ghost-baseline.json"
    cfg = GhostConfig(max_lines=max_lines)
    baseline = build_baseline(file_path, config=cfg, source_hint=source_hint)
    save_baseline(baseline, out_path)
    click.echo(f"Wrote baseline: {out_path}")


@ghost_group.command("analyze")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Log file to analyze",
)
@click.option(
    "--baseline",
    "baseline_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Optional baseline JSON path",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Report output path (defaults to <file>.ghost-report.json)",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--window-lines",
    type=int,
    default=200,
    show_default=True,
    help="Sliding window size (lines) for Log DNA / entropy detectors",
)
@click.option(
    "--dna-jsd-threshold",
    type=float,
    default=0.12,
    show_default=True,
    help="Jensen-Shannon divergence threshold for Log DNA shift",
)
@click.option(
    "--entropy-z-threshold",
    type=float,
    default=3.5,
    show_default=True,
    help="Z-score threshold (vs baseline) for entropy spikes",
)
@click.option(
    "--max-lines",
    type=int,
    default=250_000,
    show_default=True,
    help="Max lines to read for analysis",
)
def ghost_analyze_cmd(
    file_path: str,
    baseline_path: Optional[str],
    out: Optional[str],
    gap: int,
    window_lines: int,
    dna_jsd_threshold: float,
    entropy_z_threshold: float,
    max_lines: int,
) -> None:
    """Run Ghost Protocol heuristics and emit a JSON report."""

    out_path = out or f"{file_path}.ghost-report.json"
    baseline: Optional[GhostBaseline] = load_baseline(baseline_path) if baseline_path else None
    cfg = GhostConfig(
        window_lines=window_lines,
        max_lines=max_lines,
        gap_threshold_seconds=gap,
        dna_jsd_threshold=dna_jsd_threshold,
        entropy_z_threshold=entropy_z_threshold,
    )
    report = analyze_log(file_path, baseline=baseline, config=cfg)
    save_report(report, out_path)
    click.echo(f"Wrote report: {out_path}")
    click.echo(
        f"Events: {report.summary.get('event_counts', {}).get('total', 0)} | Risk score: {report.summary.get('risk_score', 0)}"
    )


@ghost_group.command("watch")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Log file to watch (tail + analyze)",
)
@click.option(
    "--baseline",
    "baseline_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Optional baseline JSON path",
)
@click.option(
    "--interval",
    type=float,
    default=2.0,
    show_default=True,
    help="Poll interval in seconds",
)
@click.option(
    "--tail-lines",
    "tail_lines_count",
    type=int,
    default=5000,
    show_default=True,
    help="Analyze only the last N lines each time",
)
@click.option(
    "--window-lines",
    type=int,
    default=200,
    show_default=True,
    help="Sliding window size (lines) for detectors",
)
@click.option("--gap", default=300, show_default=True, help="Min gap seconds to flag")
@click.option(
    "--dna-jsd-threshold",
    type=float,
    default=0.12,
    show_default=True,
    help="Jensen-Shannon divergence threshold for Log DNA shift",
)
@click.option(
    "--entropy-z-threshold",
    type=float,
    default=3.5,
    show_default=True,
    help="Z-score threshold (vs baseline) for entropy spikes",
)
def ghost_watch_cmd(
    file_path: str,
    baseline_path: Optional[str],
    interval: float,
    tail_lines_count: int,
    window_lines: int,
    gap: int,
    dna_jsd_threshold: float,
    entropy_z_threshold: float,
) -> None:
    """Continuously tail a growing log and emit new Ghost Protocol events.

    This is a portable "agent" mode that runs in your terminal on Windows/Linux.
    """

    baseline: Optional[GhostBaseline] = load_baseline(baseline_path) if baseline_path else None
    cfg = GhostConfig(
        window_lines=window_lines,
        gap_threshold_seconds=gap,
        dna_jsd_threshold=dna_jsd_threshold,
        entropy_z_threshold=entropy_z_threshold,
    )

    last_mtime: Optional[float] = None
    last_emitted_keys: set[str] = set()

    click.echo("Watching for changes (Ctrl+C to stop)...")
    try:
        while True:
            try:
                mtime = os.path.getmtime(file_path)
            except OSError:
                mtime = None

            if mtime is not None and (last_mtime is None or mtime > last_mtime):
                last_mtime = mtime

                buf = tail_file_lines(file_path, max_lines=tail_lines_count)
                tmp_path: Optional[Path] = None
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        delete=False,
                        prefix="ghost_watch_",
                        suffix=".log",
                    ) as tmp:
                        tmp.write("".join(buf))
                        tmp_path = Path(tmp.name)

                    report = analyze_log(
                        str(tmp_path),
                        baseline=baseline,
                        config=cfg,
                        display_file=file_path,
                    )
                finally:
                    if tmp_path is not None:
                        try:
                            tmp_path.unlink(missing_ok=True)  # py3.8+
                        except TypeError:
                            if tmp_path.exists():
                                tmp_path.unlink()

                # Print only newly-seen events to avoid noisy repeats.
                new_events = []
                for ev in report.events:
                    key = json.dumps(
                        {
                            "signal_type": ev.signal_type,
                            "severity": ev.severity,
                            "line_range": ev.line_range,
                            "time_range": ev.time_range,
                        },
                        sort_keys=True,
                    )
                    if key in last_emitted_keys:
                        continue
                    last_emitted_keys.add(key)
                    new_events.append(ev)

                if new_events:
                    click.echo(
                        f"+{len(new_events)} new event(s) | total={report.summary.get('event_counts', {}).get('total', 0)} | risk={report.summary.get('risk_score', 0)}"
                    )
                    for ev in new_events[:40]:
                        lr = f"lines {ev.line_range[0]}-{ev.line_range[1]}" if ev.line_range else "lines ?"
                        click.echo(f"  - {ev.severity} {ev.signal_type} ({lr})")

            time.sleep(max(0.2, interval))
    except KeyboardInterrupt:
        click.echo("Stopped.")


@ghost_group.group("receipts")
def ghost_receipts_group() -> None:
    """Collect platform receipts (filesystem + optional process/net snapshots)."""


@ghost_receipts_group.command("collect")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Log file to collect receipts for",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Receipts output JSONL path (defaults to <file>.ghost-receipts.jsonl)",
)
@click.option("--append/--no-append", default=True, show_default=True)
@click.option("--processes/--no-processes", default=False, show_default=True)
@click.option("--netstat/--no-netstat", default=False, show_default=True)
@click.option("--samples/--no-samples", default=True, show_default=True)
def ghost_receipts_collect_cmd(
    file_path: str,
    out: Optional[str],
    append: bool,
    processes: bool,
    netstat: bool,
    samples: bool,
) -> None:
    out_path = out or f"{file_path}.ghost-receipts.jsonl"
    receipts = collect_receipts(
        file_path=file_path,
        include_processes=processes,
        include_netstat=netstat,
        include_samples=samples,
    )
    write_receipts_jsonl(receipts, out_path, append=append)
    click.echo(f"Wrote receipts: {out_path} (+{len(receipts)} record(s))")


@ghost_group.command("correlate")
@click.option(
    "--report",
    "report_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Ghost Protocol report JSON path",
)
@click.option(
    "--receipts",
    "receipts_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Receipts JSONL path",
)
@click.option(
    "--out",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output correlated report path (defaults to <report>.correlated.json)",
)
def ghost_correlate_cmd(report_path: str, receipts_path: str, out: Optional[str]) -> None:
    out_path = out or f"{report_path}.correlated.json"
    report = load_report(report_path)
    receipts = load_receipts_jsonl(receipts_path)
    out_report = correlate_report_with_receipts(report, receipts)
    save_correlated_report(out_report, out_path)
    click.echo(f"Wrote correlated report: {out_path}")


@ghost_group.group("commit")
def ghost_commit_group() -> None:
    """Write-time commitment register (local append-only JSONL chain)."""


@ghost_commit_group.command("add")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="File to commit",
)
@click.option(
    "--register",
    default=None,
    type=click.Path(dir_okay=False),
    help="Register JSONL path (defaults to ~/.evidence_protector/commitments.jsonl)",
)
@click.option("--note", default="", help="Optional note")
def ghost_commit_add_cmd(file_path: str, register: Optional[str], note: str) -> None:
    entry = append_commitment(file_path=file_path, register_path=register, note=note)
    click.echo(f"Committed: {entry.entry_hash}")


@ghost_commit_group.command("verify")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Register JSONL path (defaults to ~/.evidence_protector/commitments.jsonl)",
)
def ghost_commit_verify_cmd(register: Optional[str]) -> None:
    reg = register or default_register_path()
    ok, reason = verify_commitments(reg)
    if ok:
        click.echo("Commitments OK")
        return
    raise click.ClickException(reason)


@ghost_group.group("anchor")
def ghost_anchor_group() -> None:
    """Distributed anchoring outputs (export hash for external posting)."""


@ghost_anchor_group.command("export")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Commitment register path",
)
@click.option(
    "--out",
    required=True,
    type=click.Path(dir_okay=False),
    help="Anchor JSON output path",
)
def ghost_anchor_export_cmd(register: Optional[str], out: str) -> None:
    reg = register or default_register_path()
    export_anchor(reg, out)
    click.echo(f"Wrote anchor: {out}")


@ghost_anchor_group.command("statement")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Commitment register path",
)
@click.option(
    "--out",
    required=True,
    type=click.Path(dir_okay=False),
    help="Anchor statement JSON output path",
)
def ghost_anchor_statement_cmd(register: Optional[str], out: str) -> None:
    reg = register or default_register_path()
    export_anchor_statement(reg, out)
    click.echo(f"Wrote anchor statement: {out}")


@ghost_anchor_group.group("witness")
def ghost_anchor_witness_group() -> None:
    """Witness log helpers (append + verify)."""


@ghost_anchor_witness_group.command("add")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Commitment register path",
)
@click.option(
    "--out",
    "witness_log_path",
    required=True,
    type=click.Path(dir_okay=False),
    help="Witness JSONL output path",
)
@click.option("--channel", default="manual", show_default=True)
@click.option("--note", default="", show_default=False)
def ghost_anchor_witness_add_cmd(register: Optional[str], witness_log_path: str, channel: str, note: str) -> None:
    reg = register or default_register_path()
    w = append_witness(register_path=reg, witness_log_path=witness_log_path, channel=channel, note=note)
    click.echo(f"Witnessed: {w.get('statement', {}).get('anchor_hash', '')}")
    click.echo(f"Wrote witness log entry: {witness_log_path}")


@ghost_anchor_witness_group.command("verify")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Commitment register path",
)
@click.option(
    "--witness-log",
    "witness_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Witness JSONL path",
)
def ghost_anchor_witness_verify_cmd(register: Optional[str], witness_log_path: str) -> None:
    reg = register or default_register_path()
    ok, reason = verify_witnesses(reg, witness_log_path)
    if ok:
        click.echo(f"Witness OK: {reason}")
        return
    raise click.ClickException(reason)


@ghost_anchor_group.command("verify")
@click.option(
    "--register",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Commitment register path",
)
@click.option(
    "--anchor",
    "anchor_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Anchor JSON path",
)
def ghost_anchor_verify_cmd(register: Optional[str], anchor_path: str) -> None:
    reg = register or default_register_path()
    ok, reason = verify_anchor(reg, anchor_path)
    if ok:
        click.echo("Anchor OK")
        return
    raise click.ClickException(reason)


@ghost_group.group("canary")
def ghost_canary_group() -> None:
    """Canary token generator + scanner."""


@ghost_canary_group.command("generate")
@click.option("--out", required=True, type=click.Path(dir_okay=False), help="Output canary JSON path")
@click.option("--hint", default="", help="Optional hint (where you planted it)")
def ghost_canary_generate_cmd(out: str, hint: str) -> None:
    canary = generate_canary(hint=hint)
    save_canary(canary, out)
    click.echo(f"Wrote canary: {out}")
    click.echo(f"Token: {canary.token}")


@ghost_canary_group.command("scan")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Log file to scan",
)
@click.option(
    "--canary",
    "canary_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Canary JSON path",
)
def ghost_canary_scan_cmd(file_path: str, canary_path: str) -> None:
    canary = load_canary(canary_path)
    matches = scan_for_canary(file_path, canary.token)
    if not matches:
        click.echo("No canary hits")
        return
    click.echo(f"Canary hits: {len(matches)}")
    for line_no, line in matches[:20]:
        click.echo(f"  - line {line_no}: {line}")


@ghost_group.command("narrative")
@click.option(
    "--report",
    "report_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Ghost Protocol report JSON",
)
@click.option(
    "--out",
    required=True,
    type=click.Path(dir_okay=False),
    help="Narrative markdown output path",
)
def ghost_narrative_cmd(report_path: str, out: str) -> None:
    report = load_report(report_path)
    md = render_narrative_md(report)
    Path(out).write_text(md, encoding="utf-8")
    click.echo(f"Wrote narrative: {out}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@ghost_group.command("bundle")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False), help="Output ZIP path")
@click.option("--report", "report_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Ghost report JSON")
@click.option("--baseline", "baseline_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Ghost baseline JSON")
@click.option("--receipts", "receipts_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Ghost receipts JSONL")
@click.option("--correlated", "correlated_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Correlated report JSON")
@click.option("--narrative", "narrative_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Narrative markdown")
@click.option("--include", "include_paths", multiple=True, type=click.Path(exists=True, dir_okay=False), help="Additional files to include")
def ghost_bundle_cmd(
    out_path: str,
    report_path: Optional[str],
    baseline_path: Optional[str],
    receipts_path: Optional[str],
    correlated_path: Optional[str],
    narrative_path: Optional[str],
    include_paths: tuple[str, ...],
) -> None:
    """Create a self-contained ZIP bundle for incident handoff."""

    inputs: list[tuple[str, Path]] = []
    if report_path:
        inputs.append(("ghost-report", Path(report_path)))
    if baseline_path:
        inputs.append(("ghost-baseline", Path(baseline_path)))
    if receipts_path:
        inputs.append(("ghost-receipts", Path(receipts_path)))
    if correlated_path:
        inputs.append(("ghost-correlated", Path(correlated_path)))
    if narrative_path:
        inputs.append(("ghost-narrative", Path(narrative_path)))
    for p in include_paths:
        inputs.append(("additional", Path(p)))

    if not inputs:
        raise click.ClickException("Nothing to bundle. Provide at least one artifact path.")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    artifacts: list[dict[str, object]] = []
    manifest: dict[str, object] = {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool": "evidence_protector ghost bundle",
        "artifacts": artifacts,
    }

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for idx, (kind, path) in enumerate(inputs, start=1):
            arcname = f"{idx:02d}_{path.name}"
            zf.write(path, arcname=arcname)

            artifact = {
                "kind": kind,
                "source_path": str(path),
                "archive_path": arcname,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
            artifacts.append(artifact)

        zf.writestr("bundle_manifest.json", json.dumps(manifest, indent=2) + "\n")

    click.echo(f"Wrote bundle: {out}")
    click.echo(f"Artifacts: {len(inputs)}")


@ghost_group.group("selftest")
def ghost_selftest_group() -> None:
    """Generate and run adversarial fixtures."""


@ghost_selftest_group.command("generate")
@click.option("--out-dir", required=True, type=click.Path(file_okay=False), help="Directory to write fixtures")
def ghost_selftest_generate_cmd(out_dir: str) -> None:
    fixtures = generate_attack_fixtures(out_dir)
    click.echo(f"Wrote {len(fixtures)} fixture(s) into: {out_dir}")


@ghost_selftest_group.command("run")
@click.option("--dir", "fixtures_dir", required=True, type=click.Path(exists=True, file_okay=False), help="Fixtures directory")
def ghost_selftest_run_cmd(fixtures_dir: str) -> None:
    # Discover fixtures by re-generating map from filenames.
    p = Path(fixtures_dir)
    fixtures = {
        "time_reversal": str(p / "fixture_time_reversal.log"),
        "big_gap": str(p / "fixture_big_gap.log"),
        "null_byte": str(p / "fixture_null_byte.log"),
    }
    results = run_selftest(fixtures)
    bad = [k for k, v in results.items() if not v.get("ok")]
    if bad:
        raise click.ClickException(f"Selftest failed: {bad}")
    click.echo("Selftest OK")


@main.group("key")
def key_group() -> None:
    """Signing key lifecycle commands."""


@key_group.command("rotate")
def key_rotate_cmd() -> None:
    """Generate a new Ed25519 keypair and mark it active."""

    key_id, priv_path, pub_path = rotate_signing_keypair()
    click.echo(f"Rotated active key: {key_id}")
    click.echo(f"Private key: {priv_path}")
    click.echo(f"Public key:  {pub_path}")


@key_group.command("revoke")
@click.option("--key-id", required=True, help="Key ID to revoke")
@click.option("--reason", default="", help="Optional revocation reason")
def key_revoke_cmd(key_id: str, reason: str) -> None:
    """Revoke a key ID so future verification fails for manifests signed by it."""

    revoke_key_id(key_id, reason=reason)
    click.echo(f"Revoked key ID: {key_id}")


@key_group.command("revoked")
def key_revoked_cmd() -> None:
    """List revoked key IDs."""

    keys = list_revoked_key_ids()
    if not keys:
        click.echo("No revoked keys")
        return
    for kid in keys:
        click.echo(kid)
