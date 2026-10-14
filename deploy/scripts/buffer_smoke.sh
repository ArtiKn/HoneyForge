#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"
COMPOSE=(docker compose --env-file .env -f deploy/docker-compose.yml)
DEMO=(docker run --rm --network host --user "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace python:3.12-slim python deploy/scripts/demo.py)

queue_depth() {
  docker exec hf-agent-low python -c \
    'import sqlite3; print(sqlite3.connect("/var/lib/honeyforge/events.sqlite3").execute("select count(*) from pending_events").fetchone()[0])'
}

queue_ids() {
  docker exec hf-agent-low python -c \
    'import sqlite3; print("\n".join(row[0] for row in sqlite3.connect("/var/lib/honeyforge/events.sqlite3").execute("select event_id from pending_events order by event_id")))'
}

before_ids="$(mktemp)"
after_ids="$(mktemp)"
new_ids="$(mktemp)"
trap 'rm -f "${before_ids}" "${after_ids}" "${new_ids}"' EXIT

"${COMPOSE[@]}" stop nginx api >/dev/null
before="$(queue_depth)"
queue_ids >"${before_ids}"
"${DEMO[@]}" attack >/dev/null
for _ in {1..20}; do
  after="$(queue_depth)"
  [[ "${after}" -gt "${before}" ]] && break
  sleep 0.25
done
if [[ "${after}" -le "${before}" ]]; then
  echo "Agent SQLite queue did not grow while Control Center was unavailable" >&2
  exit 1
fi
queue_ids >"${after_ids}"
comm -13 "${before_ids}" "${after_ids}" >"${new_ids}"
if [[ ! -s "${new_ids}" ]]; then
  echo "No new buffered Security Event UUIDs were captured" >&2
  exit 1
fi

"${COMPOSE[@]}" up -d >/dev/null
center_https_port="$("${COMPOSE[@]}" port nginx 443 | awk -F: 'NR == 1 { print $NF }')"
if [[ -z "${center_https_port}" ]]; then
  echo "Could not resolve the published Control Center HTTPS port" >&2
  exit 1
fi
for _ in {1..60}; do
  if curl --silent --fail --cacert deploy/nginx/certs/ca.crt "https://localhost:${center_https_port}/ready" >/dev/null; then
    break
  fi
  sleep 2
done
mapfile -t expected_ids <"${new_ids}"
for _ in {1..60}; do
  current_ids="$(queue_ids)"
  delivered=true
  for event_id in "${expected_ids[@]}"; do
    if grep -Fxq "${event_id}" <<<"${current_ids}"; then
      delivered=false
      break
    fi
  done
  [[ "${delivered}" == true ]] && break
  sleep 1
done
if [[ "${delivered}" != true ]]; then
  echo "Buffered Security Events did not drain after Control Center recovery" >&2
  exit 1
fi

smoke_args=(smoke)
for event_id in "${expected_ids[@]}"; do
  smoke_args+=(--expected-event-id "${event_id}")
done
"${DEMO[@]}" "${smoke_args[@]}"
