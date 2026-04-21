#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_BIN="${TARGET_DIR}/evidence-protector"

printf '\n[1/3] Building standalone binary...\n'
"${ROOT_DIR}/scripts/build-standalone.sh"

printf '\n[2/3] Installing to %s...\n' "${TARGET_BIN}"
mkdir -p "${TARGET_DIR}"
install -m 755 "${ROOT_DIR}/dist/standalone/evidence-protector" "${TARGET_BIN}"

printf '\n[3/3] Verifying install...\n'
"${TARGET_BIN}" --help >/dev/null

if [[ ":$PATH:" != *":${TARGET_DIR}:"* ]]; then
  printf '\nAdd this to your shell profile (if command not found):\n'
  printf '  export PATH="$HOME/.local/bin:$PATH"\n'
fi

printf '\nDone. Run:\n'
printf '  evidence-protector --help\n'
printf '  evidence-protector scan --file ./sample.log --gap 300 --format terminal\n\n'
