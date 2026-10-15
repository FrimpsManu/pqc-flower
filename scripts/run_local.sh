#!/usr/bin/env bash
# Run the system in Flower deployment mode: one SuperLink (server) and N SuperNodes (farms)
# talking over real gRPC on localhost.
#
# Usage: scripts/run_local.sh [mode] [num_farms] [num_rounds]
#   mode = insecure   no TLS, no farm login
#          classical  TLS 1.3 + ECDSA P-384 farm login (Flower's built-in security)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.venv/bin"
MODE="${1:-classical}"
FARMS="${2:-3}"
ROUNDS="${3:-15}"
LOGS="$ROOT/logs/$MODE"
CERTS="$ROOT/credentials/certs"
KEYS="$ROOT/credentials/farm-keys"
export FLWR_HOME="$ROOT/.flwr"
export PQC_DATA_DIR="$ROOT/data"
export PATH="$BIN:$PATH"  # SuperLink/SuperNode spawn flower-superexec by name

rm -rf "$LOGS" "$FLWR_HOME"
mkdir -p "$LOGS" "$FLWR_HOME"

case "$MODE" in
  insecure)
    LINK_SEC=(--insecure)
    conn_sec='insecure = true'
    farm_sec() { echo --insecure; }
    ;;
  classical)
    [[ -f "$CERTS/server.pem" && -f "$KEYS/farm$((FARMS - 1))" ]] \
      || "$ROOT/scripts/gen_credentials.sh" "$FARMS"
    LINK_SEC=(--ssl-ca-certfile "$CERTS/ca.crt" --ssl-certfile "$CERTS/server.pem"
              --ssl-keyfile "$CERTS/server.key" --enable-supernode-auth)
    conn_sec="root-certificates = \"$CERTS/ca.crt\""
    farm_sec() {
      echo --root-certificates "$CERTS/ca.crt" \
        --auth-supernode-private-key "$KEYS/farm$1" --auth-supernode-public-key "$KEYS/farm$1.pub"
    }
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 1 ;;
esac

cat > "$FLWR_HOME/config.toml" <<EOF
[superlink]
default = "local"

[superlink.local]
address = "127.0.0.1:8000"
$conn_sec
EOF

# Fail early if another run (or a leftover process) holds our ports; otherwise the SuperLink
# crashes on startup and the run fails with no clear reason. Checked before the cleanup trap
# is set, so we never kill processes this script didn't start.
PORTS=(8000 9092)
for ((i = 0; i < FARMS; i++)); do PORTS+=($((9100 + i))); done
busy=0
for port in "${PORTS[@]}"; do
  if holder=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1) && [[ -n "$holder" ]]; then
    echo "port $port is already in use by PID $holder: $(ps -o command= -p "$holder" | cut -c1-120)" >&2
    busy=1
  fi
done
if ((busy)); then
  echo "Stop it first (scripts/stop_all.sh stops leftover Flower processes from this repo)." >&2
  exit 1
fi

pids=()
cleanup() {
  # SuperNodes keep retrying after the SuperLink goes away, and helper processes outlive their parents.
  kill ${pids[@]+"${pids[@]}"} 2>/dev/null || true  # bash 3.2-safe when empty
  "$ROOT/scripts/stop_all.sh" --quiet
}
trap cleanup EXIT

# Wait until a port is listening; give up if the process that should open it has died.
wait_for_port() {
  local port=$1 pid=$2 log=$3
  for _ in $(seq 60); do
    lsof -nP -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1 && return 0
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "process $pid exited before opening port $port. Last lines of $log:" >&2
      grep -vE "^\s*$" "$log" | tail -15 >&2
      exit 1
    fi
    sleep 0.5
  done
  echo "timed out waiting for port $port (see $log)" >&2
  exit 1
}

"$BIN/flower-superlink" "${LINK_SEC[@]}" --database "$LOGS/state.db" > "$LOGS/superlink.log" 2>&1 &
link_pid=$!
pids+=($link_pid)
wait_for_port 8000 "$link_pid" "$LOGS/superlink.log"
wait_for_port 9092 "$link_pid" "$LOGS/superlink.log"

if [[ "$MODE" == classical ]]; then
  # Flower's direct-trust model: the SuperLink only accepts farms whose public key was registered.
  for ((i = 0; i < FARMS; i++)); do
    if ! "$BIN/flwr" supernode register "$KEYS/farm$i.pub" local --name "farm$i" > "$LOGS/register$i.log" 2>&1; then
      echo "registering farm$i failed:" >&2; cat "$LOGS/register$i.log" >&2; exit 1
    fi
  done
fi

for ((i = 0; i < FARMS; i++)); do
  # shellcheck disable=SC2046
  "$BIN/flower-supernode" $(farm_sec "$i") --superlink 127.0.0.1:9092 --port $((9100 + i)) \
    --node-config "partition-id=$i num-partitions=$FARMS" > "$LOGS/farm$i.log" 2>&1 &
  farm_pids[i]=$!
  pids+=($!)
done
for ((i = 0; i < FARMS; i++)); do
  wait_for_port $((9100 + i)) "${farm_pids[i]}" "$LOGS/farm$i.log"
done

cd "$ROOT"
"$BIN/flwr" run . local --stream --run-config "num-farms=$FARMS num-server-rounds=$ROUNDS" \
  > "$LOGS/run.log" 2>&1 &
pids+=($!)

# The log stream never closes on its own; stop once the ServerApp reports it is done.
until grep -qE "PQCFLOWER_DONE|ERROR|Error" "$LOGS/run.log"; do sleep 1; done
grep -E "^\[round" "$LOGS/run.log" | tee "$LOGS/rounds.txt"
if grep -qE "ERROR|Error" "$LOGS/run.log"; then grep -A20 -E "ERROR|Error" "$LOGS/run.log" | head -40; exit 1; fi
echo "mode=$MODE farms=$FARMS rounds=$ROUNDS  logs: $LOGS"
