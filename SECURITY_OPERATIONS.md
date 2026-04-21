# Security Operations Runbook

## Purpose

This runbook covers day-2 security operations for Evidence Protector deployments:
- API key role management (RBAC)
- signing key rotation and revocation
- audit trail review and incident triage
- performance budget monitoring for abuse or regression detection

## 1) API Key RBAC

The API supports role-based key mapping via `EVIDENCE_PROTECTOR_API_KEYS_JSON`.

Example:

```bash
export EVIDENCE_PROTECTOR_API_KEYS_JSON='{"viewer-key":"viewer","analyst-key":"analyst","admin-key":"admin"}'
```

Roles:
- `viewer`: health + audit read
- `analyst`: viewer + scan/sign/verify/ghost/jobs/case package
- `admin`: full access

Legacy single key mode (`EVIDENCE_PROTECTOR_API_KEY`) remains supported.

## 2) Key Rotation and Revocation

Use CLI key lifecycle commands to rotate active signing keys and revoke old key IDs.

Recommended cadence:
- rotate at least every 90 days
- rotate immediately after any suspected credential leakage

Minimum process:
1. Generate new key pair and set as active key.
2. Verify new signatures on staging logs.
3. Revoke the previous key ID.
4. Publish the change window and key ID in incident/change notes.

## 3) Audit Trail Monitoring

The API emits in-memory audit events and can optionally persist JSONL:

```bash
export EVIDENCE_PROTECTOR_AUDIT_FILE=./artifacts/audit/audit.jsonl
```

Review methods:
- API: `GET /api/audit?limit=200`
- Web UI: `/audit`
- Optional persisted JSONL: tail + SIEM ingestion

Operational checks:
- repeated `401/403` from same client
- unusual spikes in `duration_ms`
- access to sensitive paths outside expected windows

## 4) Trace Logging

Enable structured trace logs (default enabled):

```bash
export EVIDENCE_PROTECTOR_TRACE_LOGGING=1
```

Each API request includes:
- `request_id`
- `trace_id`
- method/path/status
- client
- duration
- role

Pass `X-Trace-ID` from upstream gateway to preserve end-to-end correlation.

## 5) Performance Budgets and Alarms

Budgets are stored in:
- `artifacts/performance/budgets.json`

CI enforcement:
1. Runs `scripts/replay_benchmark.py`
2. Validates p95 metrics with `scripts/check_performance_budget.py`
3. Fails workflow if any metric exceeds threshold

Tune thresholds when:
- workload shape intentionally changes
- hardware baseline changes
- optimization/feature rollout materially shifts latency

## 6) Incident Response Quick Steps

1. Capture affected log, manifest, and ghost report.
2. Export signed case package (`/api/case-package`).
3. Pull recent audit events around the request window.
4. Verify signature validity and key ID lineage.
5. Revoke compromised keys, rotate active keys, redeploy.
6. Re-run benchmark + CI to validate post-fix stability.

## 7) Post-Incident Checklist

- [ ] Key rotation completed and previous key revoked
- [ ] Audit anomalies reviewed and archived
- [ ] Case package attached to incident ticket
- [ ] Performance budgets pass in CI
- [ ] Runbook updates captured
