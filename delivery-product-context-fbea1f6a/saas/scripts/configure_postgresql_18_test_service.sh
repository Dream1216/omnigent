#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

postgres_container_id=${POSTGRES_SERVICE_CONTAINER_ID:-}
[[ "$postgres_container_id" =~ ^[0-9a-f]{12,64}$ ]] ||
  fail "POSTGRES_SERVICE_CONTAINER_ID must be the exact GitHub service container ID"

postgres_image='postgres:18.6-trixie@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
container_contract=$(
  docker inspect --format '{{.Config.Image}}|{{.State.Running}}' "$postgres_container_id"
)
[[ "$container_contract" == "$postgres_image|true" ]] ||
  fail "PostgreSQL service container does not match the exact PostgreSQL 18.6 image"

export PGCONNECT_TIMEOUT=${PGCONNECT_TIMEOUT:-3}
psql_args=(
  -X
  --host localhost
  --username postgres
  --dbname postgres
)

psql "${psql_args[@]}" \
  --set ON_ERROR_STOP=1 \
  --command "ALTER SYSTEM SET max_notify_queue_pages = '64'" \
  --command "ALTER SYSTEM SET max_prepared_transactions = '0'"

docker restart --time 10 "$postgres_container_id" >/dev/null
readiness_deadline=$((SECONDS + 60))
until pg_isready \
  --host localhost \
  --username postgres \
  --dbname postgres \
  --timeout=1 \
  --quiet; do
  ((SECONDS < readiness_deadline)) ||
    fail "PostgreSQL service did not become ready within 60 seconds"
  sleep 1
done

settings=$(
  psql "${psql_args[@]}" \
    --tuples-only \
    --no-align \
    --field-separator='|' \
    --command "SELECT name, setting, context, pending_restart, source
      FROM pg_settings
      WHERE name IN ('max_notify_queue_pages', 'max_prepared_transactions')
      ORDER BY name"
)
expected_settings=$'max_notify_queue_pages|64|postmaster|f|configuration file\nmax_prepared_transactions|0|postmaster|f|configuration file'
[[ "$settings" == "$expected_settings" ]] ||
  fail "PostgreSQL 18 postmaster settings do not match the runner contract"

server_version_num=$(
  psql "${psql_args[@]}" \
    --tuples-only \
    --no-align \
    --command "SELECT current_setting('server_version_num')::integer"
)
[[ "$server_version_num" == "180006" ]] ||
  fail "PostgreSQL service version is not exactly 18.6"

prepared_xacts=$(
  psql "${psql_args[@]}" \
    --tuples-only \
    --no-align \
    --command "SELECT count(*) FROM pg_prepared_xacts"
)
[[ "$prepared_xacts" == "0" ]] ||
  fail "PostgreSQL service has prepared transactions"
