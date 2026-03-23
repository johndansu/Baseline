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
RUN_DIR_ABS="$(cd "${RUN_DIR}" && pwd)"
BINARIES_DIR="${RUN_DIR_ABS}/binaries"
ARCHIVES_DIR="${RUN_DIR_ABS}/archives"
mkdir -p "${BINARIES_DIR}" "${ARCHIVES_DIR}"

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
{
  echo "Baseline release artifacts"
  echo "version=${VERSION}"
  echo "commit=${GIT_COMMIT}"
  echo "build_date=${BUILD_DATE}"
} > "${RUN_DIR}/RELEASE_INFO.txt"

binary_checksum_file="${RUN_DIR_ABS}/SHA256SUMS.binaries"
archive_checksum_file="${RUN_DIR_ABS}/SHA256SUMS.archives"
: > "${binary_checksum_file}"
: > "${archive_checksum_file}"

for target in "${TARGETS[@]}"; do
  IFS=/ read -r goos goarch <<< "${target}"
  suffix=""
  if [[ "${goos}" == "windows" ]]; then
    suffix=".exe"
  fi
  binary_name="baseline_${VERSION}_${goos}_${goarch}${suffix}"
  destination="${BINARIES_DIR}/${binary_name}"
  stage_dir="${RUN_DIR_ABS}/stage_${goos}_${goarch}"

  echo
  echo "==> Building ${target}"
  GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath \
      -ldflags "-s -w -X github.com/baseline/baseline/internal/version.Version=${VERSION} -X github.com/baseline/baseline/internal/version.GitCommit=${GIT_COMMIT} -X github.com/baseline/baseline/internal/version.BuildDate=${BUILD_DATE}" \
      -o "${destination}" ./cmd/baseline

  sha256sum "${destination}" | awk -v name="${binary_name}" '{print $1 "  " name}' >> "${binary_checksum_file}"

  rm -rf "${stage_dir}"
  mkdir -p "${stage_dir}"
  cp "${destination}" "${stage_dir}/${binary_name}"
  cp "${RUN_DIR_ABS}/RELEASE_INFO.txt" "${stage_dir}/RELEASE_INFO.txt"

  if [[ "${goos}" == "windows" ]]; then
    archive_name="baseline_${VERSION}_${goos}_${goarch}.zip"
    archive_path="${ARCHIVES_DIR}/${archive_name}"
    (
      cd "${stage_dir}"
      zip -q -r "${archive_path}" .
    )
  else
    archive_name="baseline_${VERSION}_${goos}_${goarch}.tar.gz"
    archive_path="${ARCHIVES_DIR}/${archive_name}"
    tar -C "${stage_dir}" -czf "${archive_path}" .
  fi

  sha256sum "${archive_path}" | awk -v name="${archive_name}" '{print $1 "  " name}' >> "${archive_checksum_file}"
  rm -rf "${stage_dir}"
done

echo
echo "Release artifacts written to: ${RUN_DIR_ABS}"
echo "Binary checksums written to: ${binary_checksum_file}"
echo "Archive checksums written to: ${archive_checksum_file}"
