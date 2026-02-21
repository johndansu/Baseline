#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="${1:-.artifacts/api-smoke}"
ADDR="${2:-127.0.0.1:18080}"
STARTUP_TIMEOUT_SECONDS="${STARTUP_TIMEOUT_SECONDS:-30}"

TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"

STDOUT_LOG="${RUN_DIR}/api-server.out.log"
STDERR_LOG="${RUN_DIR}/api-server.err.log"
SUMMARY_LOG="${RUN_DIR}/summary.log"
DB_PATH="${RUN_DIR}/baseline-api-smoke.db"

if [[ "${ADDR}" == :* ]]; then
  BASE_URL="http://127.0.0.1${ADDR}"
else
  BASE_URL="http://${ADDR}"
fi

ADMIN_KEY="$(go run ./cmd/baseline api keygen | tr -d '\r\n')"
if [[ -z "${ADMIN_KEY}" ]]; then
  echo "Failed to generate API key" >&2
  exit 1
fi

BASELINE_API_KEY="${ADMIN_KEY}" \
BASELINE_API_DB_PATH="${DB_PATH}" \
BASELINE_API_SELF_SERVICE_ENABLED=false \
BASELINE_API_DASHBOARD_SESSION_ENABLED=false \
BASELINE_API_REQUIRE_HTTPS=false \
go run ./cmd/baseline api serve --addr "${ADDR}" >"${STDOUT_LOG}" 2>"${STDERR_LOG}" &
SERVER_PID=$!

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_health() {
  local attempts=$((STARTUP_TIMEOUT_SECONDS * 2))
  local i
  for ((i = 0; i < attempts; i++)); do
    local status
    status="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/healthz" || true)"
    if [[ "${status}" == "200" ]]; then
      return
    fi
    sleep 0.5
  done
  echo "API server did not become healthy within ${STARTUP_TIMEOUT_SECONDS}s" >&2
  exit 1
}

run_step() {
  local step="$1"
  local method="$2"
  local path="$3"
  local expected_status="$4"
  local request_body="$5"
  local expected_body_text="$6"
  local expected_header_text="$7"
  shift 7

  local body_file="${RUN_DIR}/${step}.body"
  local header_file="${RUN_DIR}/${step}.headers"

  local -a cmd=(curl -sS -D "${header_file}" -o "${body_file}" -w "%{http_code}" -X "${method}")
  while (($#)); do
    cmd+=(-H "$1")
    shift
  done
  if [[ -n "${request_body}" ]]; then
    local request_file="${RUN_DIR}/${step}.request.json"
    printf "%s" "${request_body}" > "${request_file}"
    cmd+=(--data-binary "@${request_file}")
  fi
  cmd+=("${BASE_URL}${path}")

  local status
  status="$("${cmd[@]}")"

  if [[ "${status}" != "${expected_status}" ]]; then
    echo "[${step}] expected ${expected_status}, got ${status}" >&2
    echo "Body:" >&2
    cat "${body_file}" >&2 || true
    exit 1
  fi

  if [[ -n "${expected_body_text}" ]] && ! grep -Fqi "${expected_body_text}" "${body_file}"; then
    echo "[${step}] response body missing expected text: ${expected_body_text}" >&2
    exit 1
  fi

  if [[ -n "${expected_header_text}" ]] && ! grep -Fqi "${expected_header_text}" "${header_file}"; then
    echo "[${step}] response headers missing expected text: ${expected_header_text}" >&2
    exit 1
  fi

  echo "${step}: PASS (HTTP ${status})" >> "${SUMMARY_LOG}"
  echo "${step} ok (HTTP ${status})"
}

wait_for_health

{
  echo "base_url=${BASE_URL}"
  echo "db_path=${DB_PATH}"
} >> "${SUMMARY_LOG}"

AUTH_HEADER="Authorization: Bearer ${ADMIN_KEY}"
PROJECT_PAYLOAD='{"id":"smoke-project","name":"Smoke Project","default_branch":"main","policy_set":"baseline:prod"}'
SCAN_PAYLOAD='{"id":"smoke-scan-1","project_id":"smoke-project","commit_sha":"abc123","status":"fail","violations":[{"policy_id":"A1","severity":"block","message":"smoke violation"}]}'

run_step "01-healthz" "GET" "/healthz" "200" "" '"status":"ok"' ""
run_step "02-readyz" "GET" "/readyz" "200" "" '"status":"ready"' ""
run_step "03-dashboard-unauthorized" "GET" "/v1/dashboard" "401" "" '"code":"unauthorized"' "www-authenticate"
run_step "04-project-create" "POST" "/v1/projects" "201" "${PROJECT_PAYLOAD}" '"id":"smoke-project"' "" \
  "${AUTH_HEADER}" "Content-Type: application/json"

run_step "05-scan-create" "POST" "/v1/scans" "201" "${SCAN_PAYLOAD}" '"id":"smoke-scan-1"' "" \
  "${AUTH_HEADER}" "Content-Type: application/json" "Idempotency-Key: smoke-idempotency-1"

run_step "06-scan-idempotent-replay" "POST" "/v1/scans" "201" "${SCAN_PAYLOAD}" '"id":"smoke-scan-1"' "x-idempotency-replayed: true" \
  "${AUTH_HEADER}" "Content-Type: application/json" "Idempotency-Key: smoke-idempotency-1"

run_step "07-scan-sarif" "GET" "/v1/scans/smoke-scan-1/report?format=sarif" "200" "" '"runs"' "" \
  "${AUTH_HEADER}"

run_step "08-dashboard-summary" "GET" "/v1/dashboard" "200" "" '"metrics"' "" \
  "${AUTH_HEADER}"

run_step "09-audit-events" "GET" "/v1/audit/events?limit=5" "200" "" '"events"' "" \
  "${AUTH_HEADER}"

run_step "10-api-keys" "GET" "/v1/api-keys" "200" "" '"api_keys"' "" \
  "${AUTH_HEADER}"

run_step "11-metrics" "GET" "/metrics" "200" "" "baseline_projects_total" ""

echo
echo "API smoke passed. Artifacts written to: ${RUN_DIR}"
