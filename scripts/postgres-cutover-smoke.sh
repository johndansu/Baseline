#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8080}"
ADMIN_KEY="${2:-}"
PROJECT_ID="${3:-}"
SCAN_ID="${4:-}"
OUTPUT_ROOT="${OUTPUT_ROOT:-.artifacts/postgres-cutover-smoke}"

normalize_base_url() {
  local raw="${1:-}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  if [[ -z "${raw}" ]]; then
    echo "http://127.0.0.1:8080"
    return
  fi
  if [[ "${raw}" =~ ^https?:// ]]; then
    echo "${raw%/}"
    return
  fi
  if [[ "${raw}" == :* ]]; then
    echo "http://127.0.0.1${raw}"
    return
  fi
  echo "http://${raw%/}"
}

TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"
SUMMARY_LOG="${RUN_DIR}/summary.log"
NORMALIZED_BASE_URL="$(normalize_base_url "${BASE_URL}")"

{
  echo "base_url=${NORMALIZED_BASE_URL}"
  if [[ -n "${ADMIN_KEY}" ]]; then
    echo "authenticated=true"
  else
    echo "authenticated=false"
  fi
} >> "${SUMMARY_LOG}"

invoke_step() {
  local step="$1"
  local path="$2"
  local expected_status="$3"
  local expected_body_text="$4"
  shift 4

  local body_file="${RUN_DIR}/${step}.body"
  local header_file="${RUN_DIR}/${step}.headers"

  local -a cmd=(curl -sS -D "${header_file}" -o "${body_file}" -w "%{http_code}")
  while (($#)); do
    cmd+=(-H "$1")
    shift
  done
  cmd+=("${NORMALIZED_BASE_URL}${path}")

  local status
  status="$("${cmd[@]}")"
  if [[ "${status}" != "${expected_status}" ]]; then
    echo "[${step}] expected ${expected_status}, got ${status}" >&2
    echo "Body:" >&2
    cat "${body_file}" >&2 || true
    exit 1
  fi

  if [[ -n "${expected_body_text}" ]] && ! grep -Fq "${expected_body_text}" "${body_file}"; then
    echo "[${step}] response body missing expected text: ${expected_body_text}" >&2
    exit 1
  fi

  echo "${step}: PASS (HTTP ${status})" >> "${SUMMARY_LOG}"
  echo "${step} ok (HTTP ${status})"
}

invoke_step "01-healthz" "/healthz" "200" '"status":"ok"'
invoke_step "02-signin-page" "/signin.html" "200" 'Sign In'
invoke_step "03-dashboard-page" "/dashboard" "200" 'Baseline Dashboard'

if [[ -n "${ADMIN_KEY}" ]]; then
  AUTH_HEADER="Authorization: Bearer ${ADMIN_KEY}"
  invoke_step "04-auth-me" "/v1/auth/me" "200" '"auth_source":"api_key"' "${AUTH_HEADER}"
  invoke_step "05-dashboard-summary" "/v1/dashboard" "200" '"metrics"' "${AUTH_HEADER}"
  invoke_step "06-dashboard-capabilities" "/v1/dashboard/capabilities" "200" '"capabilities"' "${AUTH_HEADER}"
  invoke_step "07-project-list" "/v1/projects" "200" '"projects"' "${AUTH_HEADER}"

  SCAN_PATH="/v1/scans?limit=10"
  if [[ -n "${PROJECT_ID}" ]]; then
    SCAN_PATH="/v1/scans?project_id=${PROJECT_ID}"
  fi
  invoke_step "08-scan-list" "${SCAN_PATH}" "200" '"scans"' "${AUTH_HEADER}"

  if [[ -n "${PROJECT_ID}" ]] && ! grep -Fq "${PROJECT_ID}" "${RUN_DIR}/07-project-list.body"; then
    echo "[07-project-list] expected project id '${PROJECT_ID}' in response body" >&2
    exit 1
  fi
  if [[ -n "${PROJECT_ID}" ]]; then
    echo "project_id_check=PASS (${PROJECT_ID})" >> "${SUMMARY_LOG}"
    echo "project id check ok (${PROJECT_ID})"
  fi

  if [[ -n "${SCAN_ID}" ]] && ! grep -Fq "${SCAN_ID}" "${RUN_DIR}/08-scan-list.body"; then
    echo "[08-scan-list] expected scan id '${SCAN_ID}' in response body" >&2
    exit 1
  fi
  if [[ -n "${SCAN_ID}" ]]; then
    echo "scan_id_check=PASS (${SCAN_ID})" >> "${SUMMARY_LOG}"
    echo "scan id check ok (${SCAN_ID})"
  fi
else
  echo "authenticated_checks=SKIPPED" >> "${SUMMARY_LOG}"
  echo "Admin key not provided; skipping authenticated cutover checks."
fi

echo
echo "Postgres cutover smoke passed. Artifacts written to: ${RUN_DIR}"
