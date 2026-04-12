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

## Tamper Demo (Hash Chain Integrity)

1) Sign the log (creates `sample.manifest.json`):

```bash
evidence_protector sign --file ./sample.log

# Legacy form (still supported)
python3 evidence_protector.py --file ./sample.log --mode sign
```

This manifest now includes a cryptographic signature (HMAC-SHA256) so the manifest itself cannot be edited undetected.

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
