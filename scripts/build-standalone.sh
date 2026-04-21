#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_VENV="${ROOT_DIR}/.venv-build"
DIST_DIR="${ROOT_DIR}/dist/standalone"

python3 -m venv "${BUILD_VENV}"
source "${BUILD_VENV}/bin/activate"

python -m pip install --upgrade pip
pip install "${ROOT_DIR}[packaging]"

mkdir -p "${DIST_DIR}"
pyinstaller \
  --onefile \
  --clean \
  --name evidence-protector \
  --distpath "${DIST_DIR}" \
  --workpath "${ROOT_DIR}/build/pyinstaller" \
  --specpath "${ROOT_DIR}/build/pyinstaller" \
  "${ROOT_DIR}/scripts/ep_launcher.py"

echo "Standalone binary generated: ${DIST_DIR}/evidence-protector"
