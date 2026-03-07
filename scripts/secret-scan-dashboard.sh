#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST_FILE="${ROOT_DIR}/security/secret-scan-allowlist.regex"

TARGETS=(
  "${ROOT_DIR}/internal/api"
  "${ROOT_DIR}/frontend-nodejs/public"
  "${ROOT_DIR}/frontend-nodejs/src"
)

PATTERNS=(
  "(?i)(^|[\\{\\[,[:space:]])[\"']?(api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}[\"']"
  "\\b(ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,})\\b"
  "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"
  "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)

TMP_RAW="$(mktemp)"
TMP_FILTERED="$(mktemp)"
TMP_FINAL="$(mktemp)"
cleanup() {
  rm -f "${TMP_RAW}" "${TMP_FILTERED}" "${TMP_FINAL}"
}
trap cleanup EXIT

for pattern in "${PATTERNS[@]}"; do
  if command -v rg >/dev/null 2>&1; then
    rg \
      --line-number \
      --no-heading \
      --color never \
      --pcre2 \
      --glob '!**/*_test.go' \
      --glob '!**/*.md' \
      --glob '!**/*.txt' \
      --glob '!**/node_modules/**' \
      --glob '!**/.next/**' \
      --glob '!**/dist/**' \
      --glob '!**/build/**' \
      --glob '!**/*.map' \
      --glob '!**/*.min.js' \
      -e "${pattern}" \
      "${TARGETS[@]}" \
      >> "${TMP_RAW}" || true
  else
    # Fallback for local environments without ripgrep.
    # Convert simple word boundaries and case-insensitive marker for grep -E.
    grep_pattern="${pattern}"
    grep_pattern="${grep_pattern//\\b/}"
    grep_pattern="${grep_pattern//(?i)/}"

    while IFS= read -r file; do
      grep -niE -- "${grep_pattern}" "${file}" >> "${TMP_RAW}" || true
    done < <(
      find "${TARGETS[@]}" -type f \
        ! -name '*_test.go' \
        ! -name '*.md' \
        ! -name '*.txt' \
        ! -name '*.map' \
        ! -name '*.min.js' \
        ! -path '*/node_modules/*' \
        ! -path '*/.next/*' \
        ! -path '*/dist/*' \
        ! -path '*/build/*'
    )
  fi
done

if [[ ! -s "${TMP_RAW}" ]]; then
  echo "[secret-scan] PASS: no potential hardcoded secrets detected."
  exit 0
fi

sort -u "${TMP_RAW}" > "${TMP_FILTERED}"

if [[ -f "${ALLOWLIST_FILE}" ]]; then
  cp "${TMP_FILTERED}" "${TMP_FINAL}"
  while IFS= read -r allow_pattern; do
    allow_pattern="$(echo "${allow_pattern}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    if [[ -z "${allow_pattern}" || "${allow_pattern}" == \#* ]]; then
      continue
    fi
    grep -E -v "${allow_pattern}" "${TMP_FINAL}" > "${TMP_FINAL}.next" || true
    mv "${TMP_FINAL}.next" "${TMP_FINAL}"
  done < "${ALLOWLIST_FILE}"
else
  cp "${TMP_FILTERED}" "${TMP_FINAL}"
fi

if [[ -s "${TMP_FINAL}" ]]; then
  echo "[secret-scan] FAIL: potential hardcoded secrets detected."
  echo "[secret-scan] Review findings below and remediate or explicitly allowlist."
  echo "[secret-scan] Allowlist file: security/secret-scan-allowlist.regex"
  echo
  cat "${TMP_FINAL}"
  exit 1
fi

echo "[secret-scan] PASS: findings matched allowlist only."
