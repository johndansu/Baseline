#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="${1:-.artifacts/release}"
VERSION="${VERSION:-}"

TARGETS=(
  "windows/amd64"
  "windows/arm64"
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

resolve_git_value() {
  local command="$1"
  local fallback="$2"
  local value
  if value="$(eval "${command}" 2>/dev/null)" && [[ -n "${value}" ]]; then
    printf '%s' "${value}"
  else
    printf '%s' "${fallback}"
  fi
}

TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"

if [[ -z "${VERSION}" ]]; then
  VERSION="$(resolve_git_value "git describe --tags --always --dirty" "dev")"
fi
GIT_COMMIT="$(resolve_git_value "git rev-parse --short HEAD" "unknown")"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  echo "timestamp=${TIMESTAMP}"
  echo "version=${VERSION}"
  echo "commit=${GIT_COMMIT}"
  echo "build_date=${BUILD_DATE}"
  echo "workspace=$(pwd)"
  echo "go_version=$(go version)"
} > "${RUN_DIR}/metadata.txt"

checksum_file="${RUN_DIR}/SHA256SUMS"
: > "${checksum_file}"

for target in "${TARGETS[@]}"; do
  IFS=/ read -r goos goarch <<< "${target}"
  suffix=""
  if [[ "${goos}" == "windows" ]]; then
    suffix=".exe"
  fi
  binary_name="baseline_${VERSION}_${goos}_${goarch}${suffix}"
  destination="${RUN_DIR}/${binary_name}"

  echo
  echo "==> Building ${target}"
  GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath \
      -ldflags "-s -w -X github.com/baseline/baseline/internal/version.Version=${VERSION} -X github.com/baseline/baseline/internal/version.GitCommit=${GIT_COMMIT} -X github.com/baseline/baseline/internal/version.BuildDate=${BUILD_DATE}" \
      -o "${destination}" ./cmd/baseline

  sha256sum "${destination}" | awk -v name="${binary_name}" '{print $1 "  " name}' >> "${checksum_file}"
done

echo
echo "Release artifacts written to: ${RUN_DIR}"
echo "Checksums written to: ${checksum_file}"
