#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-postgres:16-alpine}"
CONTAINER_NAME="${CONTAINER_NAME:-baseline-postgres-test}"
PORT="${PORT:-55432}"
DATABASE="${DATABASE:-baseline_test}"
USERNAME="${USERNAME:-baseline}"
PASSWORD="${PASSWORD:-baseline}"
TEST_PATTERN="${TEST_PATTERN:-^TestPostgresStore}"
KEEP_CONTAINER="${KEEP_CONTAINER:-0}"

assert_docker_available() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed or not on PATH" >&2
    exit 1
  fi
  if ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
    echo "docker daemon is not available. Start Docker Desktop (or your daemon) first." >&2
    exit 1
  fi
}

remove_container_if_exists() {
  local name="$1"
  if docker ps -aq -f "name=^${name}$" | grep -q .; then
    docker rm -f "$name" >/dev/null
  fi
}

wait_for_postgres() {
  local name="$1"
  local user="$2"
  local db="$3"
  for _ in $(seq 1 30); do
    if docker exec "$name" pg_isready -U "$user" -d "$db" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Postgres container did not become ready in time" >&2
  exit 1
}

assert_docker_available
remove_container_if_exists "$CONTAINER_NAME"

cleanup() {
  unset BASELINE_TEST_POSTGRES_URL || true
  if [[ "$KEEP_CONTAINER" != "1" ]]; then
    echo "==> Cleaning up container"
    remove_container_if_exists "$CONTAINER_NAME"
  fi
}
trap cleanup EXIT

echo "==> Starting disposable Postgres container"
docker run -d \
  --name "$CONTAINER_NAME" \
  -e "POSTGRES_DB=$DATABASE" \
  -e "POSTGRES_USER=$USERNAME" \
  -e "POSTGRES_PASSWORD=$PASSWORD" \
  -p "${PORT}:5432" \
  "$IMAGE" >/dev/null

echo "==> Waiting for Postgres readiness"
wait_for_postgres "$CONTAINER_NAME" "$USERNAME" "$DATABASE"

export BASELINE_TEST_POSTGRES_URL="postgres://${USERNAME}:${PASSWORD}@127.0.0.1:${PORT}/${DATABASE}?sslmode=disable"

echo "==> Running focused Postgres store tests"
go test ./internal/api -run "$TEST_PATTERN" -count=1

echo
echo "Postgres store tests passed."
echo "DSN: $BASELINE_TEST_POSTGRES_URL"
