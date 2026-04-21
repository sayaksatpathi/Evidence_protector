#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SECONDS=180
DETACH=1
DO_DOWN=0
OPEN_BROWSER=0

usage() {
  cat <<'EOF'
Usage: ./scripts/docker-smoke-test.sh [options]

Options:
  --timeout <seconds>   Health-check timeout per endpoint (default: 180)
  --no-detach           Run compose in foreground
  --down                Run compose down and exit
  --open-browser        Open http://localhost:8080 after successful checks
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    --no-detach)
      DETACH=0
      shift
      ;;
    --down)
      DO_DOWN=1
      shift
      ;;
    --open-browser)
      OPEN_BROWSER=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI not found on PATH." >&2
  exit 1
fi

docker version >/dev/null

docker compose version >/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

wait_health() {
  local url="$1"
  local timeout="$2"
  local start
  local body
  start="$(date +%s)"

  while true; do
    if body="$(curl -fsS "$url" 2>/dev/null)"; then
      if printf '%s' "$body" | python3 -c 'import json,sys; print(0 if json.load(sys.stdin).get("status") == "ok" else 1)' | grep -qx '0'; then
        return 0
      fi
    fi

    if (( $(date +%s) - start >= timeout )); then
      echo "Timed out waiting for: $url" >&2
      return 1
    fi

    sleep 2
  done
}

if [[ "$DO_DOWN" -eq 1 ]]; then
  docker compose down
  exit 0
fi

if [[ "$DETACH" -eq 1 ]]; then
  docker compose up --build -d
else
  docker compose up --build
fi

echo "Waiting for backend health..."
if ! wait_health "http://localhost:8000/api/health" "$TIMEOUT_SECONDS"; then
  echo
  echo "Compose status:" >&2
  docker compose ps >&2 || true
  echo
  echo "Recent logs (backend/web):" >&2
  docker compose logs --tail 200 backend web >&2 || true
  exit 1
fi

echo "Waiting for web proxy health..."
if ! wait_health "http://localhost:8080/api/health" "$TIMEOUT_SECONDS"; then
  echo
  echo "Compose status:" >&2
  docker compose ps >&2 || true
  echo
  echo "Recent logs (backend/web):" >&2
  docker compose logs --tail 200 backend web >&2 || true
  exit 1
fi

echo
echo "OK: backend and proxy health checks passed."
echo "Next manual check (UI): open http://localhost:8080 and run a Ghost Baseline or Ghost Analyze action."

if [[ "$OPEN_BROWSER" -eq 1 ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:8080" >/dev/null 2>&1 || true
  fi
fi
