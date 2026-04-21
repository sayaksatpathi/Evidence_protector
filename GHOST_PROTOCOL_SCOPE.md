# Ghost Protocol — Scope (offline-first)

## Goal
Ghost Protocol adds *forensic heuristics* and *receipt/correlation artifacts* on top of Evidence Protector’s integrity features.

It is designed to answer:
- “Does this log’s *timeline* look physically plausible?”
- “Does the log’s *voice* (character distribution) shift unexpectedly vs a baseline?”
- “Do filesystem receipts contradict the narrative (truncation/rewrites/mtime regressions)?”
- “Can we create portable ‘witnessable’ commitments and anchors for later verification?”

## In scope (current implementation)
- Offline baseline + analysis (`ghost baseline`, `ghost analyze`)
- Portable watch mode (terminal polling) (`ghost watch`)
- Detectors/signals:
  - `TIME_REVERSAL`, `TIME_GAP`
  - `SYNTHETIC_REGULARITY`, `RHYTHM_DRIFT`
  - `LOG_DNA_SHIFT`, `ENTROPY_SPIKE`
  - `INJECTION_PRIMITIVE`
  - `FS_TIME_MISMATCH`
- Receipts:
  - FILE receipt (size/mtime/ctime + optional head/tail SHA-256 sampling)
  - Optional best-effort process and netstat snapshots (raw text)
- Correlation:
  - `FS_TRUNCATION`, `FS_REWRITE`, `FS_MTIME_BACKWARDS`
- Commitment register (append-only JSONL hash chain) + anchoring outputs
  - Anchor export/verify (hash tip)
  - Anchor statement + witness log (portable posting format)
- Narrative output (Markdown)
- Adversarial fixtures + evaluation harness (`ghost selftest generate|run`)
- FastAPI endpoints for Ghost operations (`/api/ghost/*`)

## Explicit non-goals (for now)
- “Proving truth” or guaranteeing non-tampering (this is heuristic + evidence collection)
- OS-level daemon/service installation (systemd/Windows Service)
- External network posting of anchors (the tool generates statements; you post them)
- Cryptographic attestation hardware integration (TPM/HSM/SGX)
- Multi-host distributed consensus or byzantine agreement

## Operational guidance
- Use baselines per *source* (e.g., per app/service/environment). Mixing sources increases false positives.
- Treat all signals as *investigative leads*, not verdicts.
- Preserve originals; store receipts and reports alongside the log to support later re-verification.
