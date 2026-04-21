#!/usr/bin/env bash
set -euo pipefail

# Evidence Protector - Start Backend (FastAPI)
# Linux/macOS helper script.
#
# Defaults:
# - Creates .venv if missing
# - Skips pip install if deps look present
#
# Options:
#   ./start-backend.sh --install   (force pip install -r requirements.txt)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

FORCE_INSTALL=0
if [[ "${1:-}" == "--install" ]]; then
  FORCE_INSTALL=1
fi

PY_EXE="$ROOT_DIR/.venv/bin/python"
NEW_VENV=0

if [[ ! -x "$PY_EXE" ]]; then
  echo "Creating virtual environment .venv..."
  python3 -m venv .venv
  NEW_VENV=1
fi

if [[ ! -x "$PY_EXE" ]]; then
  echo "ERROR: Could not find $PY_EXE"
  echo "Install Python 3.10+ and try again."
  exit 1
fi

# If something is already listening on 8000, don't block the user.
if "$PY_EXE" - <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(0.2)
rc = s.connect_ex(("127.0.0.1", 8000))
s.close()
sys.exit(0 if rc == 0 else 1)
PY
then
  echo "Backend already running or port 8000 is in use."
  echo "Try: http://127.0.0.1:8000/api/health"
  exit 0
fi

NEED_INSTALL=$FORCE_INSTALL
if [[ "$NEED_INSTALL" -eq 0 ]]; then
  if [[ "$NEW_VENV" -eq 1 ]]; then
    NEED_INSTALL=1
  else
    if ! "$PY_EXE" -c 'import fastapi, uvicorn, click, rich; import dateutil; import multipart' >/dev/null 2>&1; then
      NEED_INSTALL=1
    fi
  fi
fi

if [[ "$NEED_INSTALL" -eq 1 ]]; then
  echo "Installing Python dependencies..."
  "$PY_EXE" -m pip install --upgrade pip
  "$PY_EXE" -m pip install -r requirements.txt
else
  echo "Dependencies already installed. Skipping pip install."
fi

# Optional security knobs (uncomment if you want them)
# export EVIDENCE_PROTECTOR_API_KEY="change-me"
# export EVIDENCE_PROTECTOR_ALLOW_LOCALHOST_WITHOUT_KEY=1
# export EVIDENCE_PROTECTOR_MAX_LOG_BYTES=52428800
# export EVIDENCE_PROTECTOR_MAX_MANIFEST_BYTES=5242880

echo "Starting backend on http://127.0.0.1:8000 ..."
echo "Press CTRL+C to stop."
echo
"$PY_EXE" -m uvicorn evidence_protector_api:app --reload --host 127.0.0.1 --port 8000
