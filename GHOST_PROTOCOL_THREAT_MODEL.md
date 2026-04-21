# Ghost Protocol — Threat Model (practical)

## Assets
- Logs under investigation
- Ghost reports (signals + evidence)
- Receipt streams (`*.ghost-receipts.jsonl`)
- Commitment register (`commitments.jsonl`) and anchors/witness logs

## Adversary capabilities (assumed possible)
- Edit/insert/delete/reorder log lines
- Truncate or rewrite the log file contents
- Adjust filesystem timestamps (within OS limitations)
- Inject control characters (e.g., `\x00`, stray `\r`) to break parsers/terminals
- Generate synthetic logs with plausible timestamps

## Out of scope adversary capabilities
- Kernel/root compromise that can falsify *all* local measurements and tools
- Hardware/firmware compromise
- Coercing external witnesses (social channel compromise)

## Detection goals (what we try to catch)
- Timeline anomalies
  - `TIME_REVERSAL`: timestamps decreasing between adjacent events
  - `TIME_GAP`: unusually large gaps
  - `SYNTHETIC_REGULARITY`: unrealistically perfect timing
  - `RHYTHM_DRIFT`: intervals far from baseline distribution
- Content anomalies
  - `LOG_DNA_SHIFT`: character distribution changes vs baseline
  - `ENTROPY_SPIKE`: window entropy increases vs baseline
  - `INJECTION_PRIMITIVE`: null bytes / carriage-return anomalies
- Environment contradictions
  - `FS_TIME_MISMATCH`: filesystem mtime far from last log timestamp
  - Receipt correlation: `FS_TRUNCATION`, `FS_REWRITE`, `FS_MTIME_BACKWARDS`

## Known limitations / failure modes
- A smart adversary can *mimic* baseline statistics; heuristics reduce but do not eliminate this.
- Baseline mismatch (wrong environment/source) increases false positives.
- Timestamp parsing is best-effort; heterogeneous formats reduce coverage.
- Receipts are only as trustworthy as the host collecting them.

## Mitigations (implemented)
- Size limits on API uploads
- Best-effort safe temp file handling in watch mode
- Append-only commitment chain + portable anchor statements for external witnessing

## Recommended operational mitigations (user process)
- Collect receipts immediately at acquisition time, not after analysis.
- Export anchor statements and post them to at least one external channel you control (ticket/email/chat) to create an independent timestamp trail.
- Keep baselines per-source; rotate them intentionally.
