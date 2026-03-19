#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:-}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_CERT_IDENTITY_REGEXP="${COSIGN_CERT_IDENTITY_REGEXP:-https://github.com/johndansu/Baseline/.github/workflows/ci.yml@refs/(heads/.+|tags/.+)}"

resolve_latest_run_dir() {
  local root="$1"
  find "$root" -mindepth 1 -maxdepth 1 -type d | sort | tail -n1
}

verify_checksum_file() {
  local checksum_file="$1"
  local base_dir="$2"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    if [[ ! "$line" =~ ^([0-9a-fA-F]{64})[[:space:]]{2}(.+)$ ]]; then
      echo "invalid checksum line in ${checksum_file}: ${line}" >&2
      exit 1
    fi
    local expected="${BASH_REMATCH[1],,}"
    local name="${BASH_REMATCH[2]}"
    local target="${base_dir}/${name}"
    if [[ ! -f "$target" ]]; then
      echo "checksum target missing: $target" >&2
      exit 1
    fi
    local actual
    actual="$(sha256sum "$target" | awk '{print tolower($1)}')"
    if [[ "$actual" != "$expected" ]]; then
      echo "checksum mismatch for ${name}" >&2
      exit 1
    fi
    echo "${name} OK"
  done < "$checksum_file"
}

if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$(resolve_latest_run_dir ".artifacts/release")"
fi

if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
  echo "release directory not found. Pass a run directory explicitly, for example:"
  echo "  bash ./scripts/verify-release.sh .artifacts/release/20260318_120000"
  exit 1
fi

pushd "$RUN_DIR" >/dev/null

if [[ ! -f "SHA256SUMS.binaries" || ! -f "SHA256SUMS.archives" ]]; then
  echo "missing checksum files in $RUN_DIR"
  exit 1
fi

echo "==> Verifying binary checksums"
verify_checksum_file "SHA256SUMS.binaries" "binaries"

echo
echo "==> Verifying archive checksums"
verify_checksum_file "SHA256SUMS.archives" "archives"

if ! command -v cosign >/dev/null 2>&1; then
  echo
  echo "cosign not found; skipping signature verification"
  popd >/dev/null
  exit 0
fi

signature_targets=()
for file in archives/* SHA256SUMS.binaries SHA256SUMS.archives; do
  [[ -f "$file" ]] || continue
  [[ -f "${file}.sig" && -f "${file}.pem" ]] || continue
  signature_targets+=("$file")
done

if [[ ${#signature_targets[@]} -eq 0 ]]; then
  echo
  echo "no signatures found in $RUN_DIR; checksum verification completed"
  popd >/dev/null
  exit 0
fi

echo
echo "==> Verifying keyless cosign signatures"
for file in "${signature_targets[@]}"; do
  echo "verifying $file"
  cosign verify-blob \
    --certificate "${file}.pem" \
    --signature "${file}.sig" \
    --certificate-identity-regexp "${COSIGN_CERT_IDENTITY_REGEXP}" \
    --certificate-oidc-issuer "${COSIGN_OIDC_ISSUER}" \
    "$file" >/dev/null
done

echo
echo "release verification completed for: $RUN_DIR"
popd >/dev/null
