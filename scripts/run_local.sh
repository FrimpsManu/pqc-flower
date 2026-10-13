#!/usr/bin/env bash
# Run the classical baseline in deployment mode: one SuperLink (server) and N SuperNodes (farms)
# talking over real gRPC on localhost. Usage: scripts/run_local.sh [num_farms] [num_rounds]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.venv/bin"
FARMS="${1:-3}"
ROUNDS="${2:-15}"
LOGS="$ROOT/logs"
export FLWR_HOME="$ROOT/.flwr"
export PQC_DATA_DIR="$ROOT/data"
export PATH="$BIN:$PATH"  # SuperLink/SuperNode spawn flower-superexec by name

mkdir -p "$LOGS" "$FLWR_HOME"
cat > "$FLWR_HOME/config.toml" <<EOF
[superlink]
default = "local"

[superlink.local]
address = "127.0.0.1:8000"
insecure = true
EOF

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

"$BIN/flower-superlink" --insecure --database "$LOGS/state.db" > "$LOGS/superlink.log" 2>&1 &
pids+=($!)
sleep 3

for ((i = 0; i < FARMS; i++)); do
  "$BIN/flower-supernode" --insecure --superlink 127.0.0.1:9092 --port $((9100 + i)) \
    --node-config "partition-id=$i num-partitions=$FARMS" > "$LOGS/farm$i.log" 2>&1 &
  pids+=($!)
done
sleep 3

cd "$ROOT"
"$BIN/flwr" run . local --stream \
  --run-config "num-farms=$FARMS num-server-rounds=$ROUNDS"
