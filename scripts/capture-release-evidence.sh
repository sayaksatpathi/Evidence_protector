#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_URL="${EVIDENCE_PROTECTOR_BASE_URL:-http://127.0.0.1:8080}"
HEALTH_URL="${EVIDENCE_PROTECTOR_HEALTH_URL:-${BASE_URL%/}/api/health}"
TIMEOUT_SECONDS="${EVIDENCE_PROTECTOR_CAPTURE_TIMEOUT_SECONDS:-180}"

is_healthy() {
	local body
	if ! body="$(curl -fsS "$HEALTH_URL" 2>/dev/null)"; then
		return 1
	fi

	printf '%s' "$body" | python3 -c 'import json,sys; print(0 if json.load(sys.stdin).get("status") == "ok" else 1)' | grep -qx '0'
}

wait_for_health() {
	local start
	start="$(date +%s)"
	while true; do
		if is_healthy; then
			return 0
		fi

		if (( $(date +%s) - start >= TIMEOUT_SECONDS )); then
			echo "Timed out waiting for health endpoint: $HEALTH_URL" >&2
			return 1
		fi

		sleep 2
	done
}

ensure_stack() {
	if is_healthy; then
		return 0
	fi

	echo "Release capture preflight: stack is not healthy at $HEALTH_URL, starting docker compose..."
	(
		cd "$REPO_ROOT"
		docker compose up --build -d
	)
	wait_for_health
}

cd "$REPO_ROOT/Evidence Protector Web UI"

ensure_stack

echo "Release capture preflight: ensuring Playwright Chromium is installed..."
npx playwright install chromium

npm run capture:evidence
