# Evidence Protector: Automated Log Integrity Monitor

This tool scans log files for suspicious time gaps between entries and produces a forensic-style report.
It supports multiple timestamp formats, handles large files in a streaming fashion, and can output results
in terminal, CSV, or JSON formats.

## Ubuntu Terminal Quickstart (CLI-only)

1) Install prerequisites:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

2) Create a venv + install the CLI:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Optional: install test tooling (pytest/coverage/hypothesis)
pip install -r requirements.txt
```

3) Run:

```bash
evidence_protector scan --file ./sample.log --gap 300 --format terminal
```

## Standalone executable (no Python required on target machine)

If you want this to behave like a "real" terminal tool, ship a standalone binary.
Users only download and run the executable.

### Build Linux binary

```bash
./scripts/build-standalone.sh
```

Output:

- `dist/standalone/evidence-protector`

### Build Windows binary

```powershell
./scripts/build-standalone.ps1
```

Output:

- `dist/standalone/evidence-protector.exe`

### Run the binary

```bash
./dist/standalone/evidence-protector --help
./dist/standalone/evidence-protector scan --file ./sample.log --gap 300 --format terminal
```

### Offline use

- The built executable runs locally and offline.
- No internet is required for scan/sign/verify/ghost operations.
- Build binaries per target OS (Linux binary on Linux, Windows binary on Windows).

## Example Usage

Install the CLI so `evidence_protector` is available on your PATH:

```bash
pip install -e .

# Optional: install test tooling
pip install -r requirements.txt
```

From this folder:

```bash
evidence_protector scan --file sample.log --gap 300 --format terminal
evidence_protector scan --file sample.log --gap 60 --format json --out report.json
evidence_protector scan --file sample.log --format csv --out gaps.csv

# Legacy form (still supported)
python3 evidence_protector.py --file sample.log --gap 300 --format terminal
python3 evidence_protector.py --file sample.log --gap 60 --format json --out report.json
python3 evidence_protector.py --file sample.log --format csv --out gaps.csv
```

## Ghost Protocol (Offline-First)

Ghost Protocol mode adds additional heuristics (Log DNA shift, entropy spikes, synthetic regularity, injection primitives, filesystem time mismatch). It is offline-first and runs on both Windows and Linux.

Build a baseline profile:

```bash
evidence_protector ghost baseline --file sample.log --out sample.ghost-baseline.json
```
### Scope & threat model
- [GHOST_PROTOCOL_SCOPE.md](GHOST_PROTOCOL_SCOPE.md)
- [GHOST_PROTOCOL_THREAT_MODEL.md](GHOST_PROTOCOL_THREAT_MODEL.md)
- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)

Analyze a log (optionally using a baseline):

```bash
evidence_protector ghost analyze --file sample.log --baseline sample.ghost-baseline.json --out sample.ghost-report.json
```

Watch a growing log (portable terminal agent mode):

```bash
evidence_protector ghost watch --file sample.log --baseline sample.ghost-baseline.json --interval 2 --tail-lines 5000
```

Commit + anchor (portable distributed witnessing):

```bash
# Append the current log hash into an append-only commitment register
evidence_protector ghost commit add --file sample.log --register ./commitments.jsonl --note "acquired"

# Export a one-line anchor statement suitable for posting to an external channel
evidence_protector ghost anchor statement --register ./commitments.jsonl --out ./anchor_statement.json

# Append a witness entry (JSONL) and verify that at least one witness matches the current anchor
evidence_protector ghost anchor witness add --register ./commitments.jsonl --out ./witness.jsonl --channel "ticket" --note "INC-1234"
evidence_protector ghost anchor witness verify --register ./commitments.jsonl --witness-log ./witness.jsonl
```

Evaluation harness (adversarial fixtures):

```bash
evidence_protector ghost selftest generate --out-dir ./ghost-fixtures
evidence_protector ghost selftest run --dir ./ghost-fixtures
```

Bundle a case handoff ZIP (report + receipts + narrative + extras):

```bash
evidence_protector ghost bundle \
	--out ./case-bundle.zip \
	--report ./sample.ghost-report.json \
	--receipts ./sample.ghost-receipts.jsonl \
	--narrative ./ghost_narrative.md
```

The bundle includes a `bundle_manifest.json` with per-file SHA-256 hashes.

## Web UI + Backend API

### Run locally (dev)

1) Start the backend API:

```bash
pip install -r requirements.txt
python -m uvicorn evidence_protector_api:app --reload --host 127.0.0.1 --port 8000
```

2) Start the Web UI:

```bash
cd "Evidence Protector Web UI"
corepack enable
pnpm install
pnpm dev
```

If you don't have `corepack`/`pnpm` available, `npm` works too:

```bash
cd "Evidence Protector Web UI"
npm install
npm run dev
```

Note: the Web UI includes a committed `package-lock.json`. For deterministic installs, prefer `npm ci` over `npm install`.

### Run with Docker Compose (production-style)

```bash
docker compose up --build
```

Windows smoke test (recommended):

```powershell
./scripts/docker-smoke-test.ps1 -OpenBrowser
```

Linux/macOS smoke test (recommended):

```bash
./scripts/docker-smoke-test.sh --open-browser
```

Stop stack (either script):

```bash
./scripts/docker-smoke-test.sh --down
```

This script runs `docker compose up --build` (detached), waits for:
- `http://localhost:8000/api/health` (backend)
- `http://localhost:8080/api/health` (nginx proxy -> backend)

- Web UI: http://localhost:8080
- Backend API: http://localhost:8000

The Web UI container proxies `/api/*` requests to the backend service.

Results view supports downloading Ghost artifacts:

- report JSON
- receipts JSONL
- correlated report JSON (when available)
- narrative markdown

### Automated release evidence capture

Generate the release screenshot pack + manifest/checklist with one command:

```bash
./scripts/capture-release-evidence.sh
```

Windows PowerShell:

```powershell
./scripts/capture-release-evidence.ps1
```

What this script does automatically:
- verifies stack health at `/api/health`
- starts `docker compose up --build -d` if services are not up
- ensures Playwright Chromium is installed
- captures screenshots and writes artifacts to `artifacts/release-evidence/`

Optional environment variables:
- `EVIDENCE_PROTECTOR_BASE_URL` (default `http://127.0.0.1:8080`)
- `EVIDENCE_PROTECTOR_HEALTH_URL` (default `<base>/api/health`)
- `EVIDENCE_PROTECTOR_CAPTURE_TIMEOUT_SECONDS` (default `180`)

### Nginx proxy image/config pinning

- Web runtime image is pinned in `Evidence Protector Web UI/Dockerfile` as `nginx:1.27-alpine`.
- Proxy behavior is defined in `Evidence Protector Web UI/nginx.conf`.
- If you upgrade nginx, update both files together and re-run the compose smoke test.

### Minimum supported versions (validated path)

| Component | Baseline |
|---|---|
| Python | 3.13 |
| Node.js | 20.x |
| Docker Engine | Any modern engine with BuildKit and Compose V2 support |
| Docker Compose | `docker compose` (Compose V2 plugin) |

Notes:
- CI uses Python 3.13 and Node 20.
- Docker commands in docs/workflows assume Compose V2 (`docker compose`, not legacy `docker-compose`).

### Dependency vulnerability checks

CI runs dependency audits for both stacks:

- Python: `pip-audit -r requirements.txt`
- Web UI: `npm audit --audit-level=high`

If either audit fails, address or triage vulnerabilities before release.

### Signature key lifecycle

See `KEY_MANAGEMENT.md` for rotation, backup, and verification policy.

Key lifecycle CLI helpers:

```bash
# Rotate to a new active Ed25519 keypair
evidence_protector key rotate

# Revoke a compromised/retired key ID (future verify fails for that key)
evidence_protector key revoke --key-id <key_id> --reason "compromised"

# List revoked key IDs
evidence_protector key revoked
```

Manifest verification now returns a revocation failure when `key_id` is revoked.

## Tamper Demo (Hash Chain Integrity)

1) Sign the log (creates `sample.manifest.json`):

```bash
evidence_protector sign --file ./sample.log

# Legacy form (still supported)
python3 evidence_protector.py --file ./sample.log --mode sign
```

This manifest now includes a cryptographic signature (Ed25519) so the manifest itself cannot be edited undetected.

Legacy HMAC-SHA256 signing and verification can be enabled via environment variables.

2) Edit `sample.log` and change any character on any line (or delete a line).

3) Verify integrity (should report tampering and exit code 2):

```bash
evidence_protector verify --file ./sample.log
echo $?

# Legacy form (still supported)
python3 evidence_protector.py --file ./sample.log --mode verify
echo $?
```

Optional: write a JSON tamper report while verifying:

```bash
evidence_protector verify --file ./sample.log --out ./verify_report.json

# Legacy form
python3 evidence_protector.py --file ./sample.log --mode verify --out ./verify_report.json
```

Note:
- CLI verification will still run against older *unsigned* manifests, but it will print a warning.

## Sample Log

A small sample log file is provided as `sample.log`. It includes:

- ISO 8601 timestamps
- Apache/Nginx-style timestamps
- Syslog-style timestamps
- Lines without timestamps (treated as malformed)
- A large time gap that should be flagged
- A timestamp anomaly where time goes backwards (TIMESTAMP_ANOMALY)

## Running Tests

Basic unit tests are (or will be) available in `test_evidence_protector.py`.
Run them with:

```bash
python -m unittest test_evidence_protector.py
```

Or run the full suite (recommended):

```bash
python -m pytest -q
```

## Coverage

Install the testing tools:

```bash
pip install hypothesis coverage pytest
```

Run with coverage (works reliably even when the venv is not activated):

```bash
python -m coverage run -m pytest test_evidence_protector.py -v
python -m coverage report
```

On Windows, if `python` points to your system Python (not the project venv), use the venv interpreter explicitly:

```bash
.\.venv\Scripts\python.exe -m coverage run -m pytest test_evidence_protector.py -v
.\.venv\Scripts\python.exe -m coverage report
```

If you *have activated your venv* and `coverage` is on your PATH, this shorter form is equivalent:

```bash
coverage run -m pytest test_evidence_protector.py -v
coverage report
```
