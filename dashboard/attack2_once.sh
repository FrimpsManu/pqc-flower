#!/usr/bin/env bash
# One Attack 2 run for the dashboard: start a SuperLink in the given mode with farm 0 registered
# but offline, then let the simulated quantum attacker try to log in as farm 0.
# Usage: dashboard/attack2_once.sh classical|pqc
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-classical}"
LOG="$ROOT/logs/dashboard_attack2_$MODE.log"
mkdir -p "$ROOT/logs"
if [[ "$MODE" == pqc ]]; then
  PUB="$ROOT/credentials/farm-keys-mldsa/farm0.pub.pem" PRIV="$ROOT/credentials/farm-keys-mldsa/farm0.pem"
else
  PUB="$ROOT/credentials/farm-keys/farm0.pub" PRIV="$ROOT/credentials/farm-keys/farm0"
fi

echo "Starting the server ($MODE farm login), farm 0 registered but offline ..."
SERVER_ONLY=1 "$ROOT/scripts/run_local.sh" "$MODE" 3 1 > "$LOG" 2>&1 &
server=$!
disown "$server"
for _ in $(seq 60); do grep -qE "SERVER READY|failed|in use" "$LOG" && break; sleep 1; done
if ! grep -q "SERVER READY" "$LOG"; then cat "$LOG"; "$ROOT/scripts/stop_all.sh" --quiet; exit 1; fi
echo "Server ready."
"$ROOT/.venv/bin/python" -m pqcflower.attack2_quantum "$PUB" "$PRIV" "$ROOT/credentials/certs/ca.crt" 2>/dev/null
status=$?
kill "$server" 2>/dev/null
"$ROOT/scripts/stop_all.sh" --quiet
echo "ATTACK2_EXIT=$status"
