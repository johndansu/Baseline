#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="${1:-.artifacts/release-gate}"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/${TIMESTAMP}"

mkdir -p "${RUN_DIR}"

{
  echo "timestamp=${TIMESTAMP}"
  echo "workspace=$(pwd)"
  echo "go_version=$(go version)"
} > "${RUN_DIR}/metadata.txt"

echo "Release gate artifacts: ${RUN_DIR}"

echo
echo "==> go test ./..."
go test ./... 2>&1 | tee "${RUN_DIR}/go-test.log"

echo
echo "==> go run ./cmd/baseline check"
go run ./cmd/baseline check 2>&1 | tee "${RUN_DIR}/baseline-check.log"

echo
echo "==> go run ./cmd/baseline report --json"
go run ./cmd/baseline report --json > "${RUN_DIR}/baseline-report.json"

echo
echo "==> go run ./cmd/baseline report --sarif"
go run ./cmd/baseline report --sarif > "${RUN_DIR}/baseline-report.sarif"

echo
echo "Release gate passed."
echo "Artifacts written to: ${RUN_DIR}"
