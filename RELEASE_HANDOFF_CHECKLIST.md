# Release Handoff Checklist

## Scope Completion

- [x] Backend hardening backlog complete (RBAC, audit trail, health split, trace IDs/logging)
- [x] Frontend backlog complete (Ghost explainability cards, compare timeline overlays, audit page)
- [x] Case package export implemented (`/api/case-package`)
- [x] Performance budgets defined and CI alarm gating added
- [x] Security operations runbook added (`SECURITY_OPERATIONS.md`)

## Validation Evidence

- [x] Python test suite green (`56 passed`)
- [x] API contract tests green (`16 passed`)
- [x] UI production build green (`npm run build`)
- [x] Compose smoke checks green (`/api/health`, `/api/health/live`, `/api/health/ready`, `/api/audit` on backend+proxy)
- [x] UI E2E flow tests green (`scan/sign/verify/ghost`)
- [x] Accuracy/parity validation green (`17/17`, 100%)
- [x] Performance budget validation green

## Security / Ops Readiness

- [x] API key role mapping available via `EVIDENCE_PROTECTOR_API_KEYS_JSON`
- [x] Audit endpoint available (`GET /api/audit?limit=...`)
- [x] Optional audit JSONL persistence configurable (`EVIDENCE_PROTECTOR_AUDIT_FILE`)
- [x] Trace correlation header supported (`X-Trace-ID`)
- [x] Liveness/readiness endpoints available

## Artifacts to Share

- [ ] Source snapshot / branch containing final code
- [ ] CI run URLs for latest green runs
- [ ] Performance report artifact (`artifacts/performance/replay-benchmark.final.json`)
- [ ] Security runbook (`SECURITY_OPERATIONS.md`)
- [ ] Signed case-package demo output (optional)

## Manual Sign-off

- [ ] Product owner acceptance
- [ ] Security review acceptance
- [ ] Ops/deployment approval
- [ ] Release tag/version decided

## Post-Release Monitoring (recommended)

- [ ] Monitor `/api/audit` for abnormal 401/403 spikes
- [ ] Monitor p95 performance drift against budgets
- [ ] Confirm trace IDs are propagated from ingress/gateway
