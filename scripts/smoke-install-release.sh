#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:-}"
ARCHIVE_NAME="${2:-}"
KEEP_DIR="${KEEP_DIR:-0}"

resolve_latest_run_dir() {
  local root="$1"
  find "$root" -mindepth 1 -maxdepth 1 -type d | sort | tail -n1
}

normalize_platform() {
  local uname_value
  uname_value="$(uname -s)"
  case "$uname_value" in
    Linux*) printf 'linux' ;;
    Darwin*) printf 'darwin' ;;
    CYGWIN*|MINGW*|MSYS*) printf 'windows' ;;
    *) printf 'linux' ;;
  esac
}

normalize_arch() {
  local arch_value
  arch_value="$(uname -m)"
  case "$arch_value" in
    x86_64|amd64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *) printf 'amd64' ;;
  esac
}

if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$(resolve_latest_run_dir ".artifacts/release")"
fi

if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
  echo "release directory not found. Pass a run directory explicitly." >&2
  exit 1
fi

bash ./scripts/verify-release.sh "$RUN_DIR"

if [[ -z "$ARCHIVE_NAME" ]]; then
  platform="$(normalize_platform)"
  arch="$(normalize_arch)"
  extension=".tar.gz"
  if [[ "$platform" == "windows" ]]; then
    extension=".zip"
  fi
  match="$(find "$RUN_DIR/archives" -maxdepth 1 -type f -name "*_${platform}_${arch}${extension}" | sort | tail -n1)"
  if [[ -z "$match" ]]; then
    echo "no matching archive found for ${platform}/${arch} in $RUN_DIR/archives" >&2
    exit 1
  fi
  ARCHIVE_PATH="$match"
else
  ARCHIVE_PATH="$ARCHIVE_NAME"
  if [[ ! -f "$ARCHIVE_PATH" ]]; then
    ARCHIVE_PATH="$RUN_DIR/archives/$ARCHIVE_NAME"
  fi
fi

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/baseline-install-smoke.XXXXXX")"
cleanup() {
  if [[ "$KEEP_DIR" != "1" ]]; then
    rm -rf "$temp_dir"
  fi
}
trap cleanup EXIT

echo "==> Extracting $ARCHIVE_PATH"
case "$ARCHIVE_PATH" in
  *.zip)
    if ! command -v unzip >/dev/null 2>&1; then
      echo "unzip not found; install unzip or run the matching platform smoke script" >&2
      exit 1
    fi
    unzip -q "$ARCHIVE_PATH" -d "$temp_dir"
    ;;
  *.tar.gz)
    if ! command -v tar >/dev/null 2>&1; then
      echo "tar not found; install tar to extract release archives" >&2
      exit 1
    fi
    tar -C "$temp_dir" -xzf "$ARCHIVE_PATH"
    ;;
  *)
    echo "unsupported archive format: $ARCHIVE_PATH" >&2
    exit 1
    ;;
esac

binary_path="$(find "$temp_dir" -maxdepth 2 -type f \( -name 'baseline*' -o -name 'baseline*.exe' \) | sort | head -n1)"
if [[ -z "$binary_path" ]]; then
  echo "baseline binary not found after extraction" >&2
  exit 1
fi

if [[ "$binary_path" != *.exe ]]; then
  chmod +x "$binary_path"
fi

echo
echo "==> Smoke-checking installed binary"
"$binary_path" version
"$binary_path" --help >/dev/null
"$binary_path" ci setup --help >/dev/null

echo
echo "clean install smoke passed for: $ARCHIVE_PATH"
echo "extracted binary: $binary_path"
if [[ "$KEEP_DIR" == "1" ]]; then
  echo "kept extraction directory: $temp_dir"
fi
