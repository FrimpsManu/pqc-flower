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

pids=()
cleanup() {
  # SuperNodes keep retrying after the SuperLink goes away, and helper processes outlive their parents.
  kill "${pids[@]}" 2>/dev/null || true
  pkill -f "$BIN/flower-" 2>/dev/null || true
  sleep 2
  pkill -9 -f "$BIN/flower-" 2>/dev/null || true
}
trap cleanup EXIT

"$BIN/flower-superlink" "${LINK_SEC[@]}" --database "$LOGS/state.db" > "$LOGS/superlink.log" 2>&1 &
pids+=($!)
sleep 3

if [[ "$MODE" == classical ]]; then
  # Flower's direct-trust model: the SuperLink only accepts farms whose public key was registered.
  for ((i = 0; i < FARMS; i++)); do
    "$BIN/flwr" supernode register "$KEYS/farm$i.pub" local --name "farm$i" > "$LOGS/register$i.log" 2>&1
  done
fi

for ((i = 0; i < FARMS; i++)); do
  # shellcheck disable=SC2046
  "$BIN/flower-supernode" $(farm_sec "$i") --superlink 127.0.0.1:9092 --port $((9100 + i)) \
    --node-config "partition-id=$i num-partitions=$FARMS" > "$LOGS/farm$i.log" 2>&1 &
  pids+=($!)
done
sleep 3

cd "$ROOT"
"$BIN/flwr" run . local --stream --run-config "num-farms=$FARMS num-server-rounds=$ROUNDS" \
  > "$LOGS/run.log" 2>&1 &
pids+=($!)

# The log stream never closes on its own; stop once the ServerApp reports it is done.
until grep -qE "PQCFLOWER_DONE|ERROR|Error" "$LOGS/run.log"; do sleep 1; done
grep -E "^\[round" "$LOGS/run.log" | tee "$LOGS/rounds.txt"
if grep -qE "ERROR|Error" "$LOGS/run.log"; then grep -A20 -E "ERROR|Error" "$LOGS/run.log" | head -40; exit 1; fi
echo "mode=$MODE farms=$FARMS rounds=$ROUNDS  logs: $LOGS"
