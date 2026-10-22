#!/usr/bin/env bash
# Run the system in Flower deployment mode: one SuperLink (server) and N SuperNodes (farms)
# talking over real gRPC on localhost.
#
# Usage: scripts/run_local.sh [mode] [num_farms] [num_rounds] ["extra run-config"]
#   mode = insecure   no TLS, no farm login
#          classical  TLS 1.3 + ECDSA P-384 farm login (Flower's built-in security)
#          pqc        TLS 1.3 + ML-DSA-65 farm login (pqcflower/pqc_login.py)
#          pqc-session  as pqc, but one ML-DSA login per session, then session MACs (session_login.py)
#   SERVER_ONLY=1 (env): start the SuperLink and register farms, but start no farms
#   extra run-config, e.g. "sign-updates=true attack-farm=0" (see [tool.flwr.app.config] in pyproject.toml)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.venv/bin"
MODE="${1:-classical}"
FARMS="${2:-3}"
ROUNDS="${3:-15}"
EXTRA_CONFIG="${4:-}"
LOGS="$ROOT/logs/$MODE${EXTRA_CONFIG:+_$(echo "$EXTRA_CONFIG" | tr " =" "_-")}"
CERTS="$ROOT/credentials/certs"
KEYS="$ROOT/credentials/farm-keys"
MLDSA_KEYS="$ROOT/credentials/farm-keys-mldsa"
# Flower's commands; pqc mode swaps in the pqc-* wrappers that enable ML-DSA farm login.
LINK_CMD=flower-superlink NODE_CMD=flower-supernode FLWR_CMD=flwr
export FLWR_HOME="$ROOT/.flwr"
export PQC_DATA_DIR="$ROOT/data"
export PYTHONUNBUFFERED=1  # ServerApp output reaches the log line by line, so progress shows live
export PQC_KEY_DIR="$ROOT/credentials/pqc-keys"  # ML-DSA-65 keys for signed model updates
export PATH="$BIN:$PATH"  # SuperLink/SuperNode spawn flower-superexec by name

rm -rf "$LOGS" "$FLWR_HOME"
mkdir -p "$LOGS" "$FLWR_HOME"
"$BIN/python" -m pqcflower.signing "$FARMS" > /dev/null

case "$MODE" in
  insecure)
    LINK_SEC=(--insecure)
    conn_sec='insecure = true'
    farm_sec() { echo --insecure; }
    ;;
  classical|pqc|pqc-session)
    [[ -f "$CERTS/server.pem" && -f "$KEYS/farm$((FARMS - 1))" ]] \
      || "$ROOT/scripts/gen_credentials.sh" "$FARMS"
    LINK_SEC=(--ssl-ca-certfile "$CERTS/ca.crt" --ssl-certfile "$CERTS/server.pem"
              --ssl-keyfile "$CERTS/server.key" --enable-supernode-auth)
    conn_sec="root-certificates = \"$CERTS/ca.crt\""
    if [[ "$MODE" == pqc* ]]; then
      [[ "$MODE" == pqc-session ]] && export PQC_SESSION_LOGIN=1
      PQC_LOGIN_KEY_DIR="$MLDSA_KEYS" "$BIN/python" -m pqcflower.pqc_login "$FARMS" > /dev/null
      LINK_CMD=pqc-flower-superlink NODE_CMD=pqc-flower-supernode FLWR_CMD=pqc-flwr
      login_key() { echo "$MLDSA_KEYS/farm$1.pem"; }
      login_pub() { echo "$MLDSA_KEYS/farm$1.pub.pem"; }
    else
      login_key() { echo "$KEYS/farm$1"; }
      login_pub() { echo "$KEYS/farm$1.pub"; }
    fi
    farm_sec() {
      echo --root-certificates "$CERTS/ca.crt" --auth-supernode-private-key "$(login_key "$1")"
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

# Run the apps in this virtualenv: Flower's per-run install would pull cryptography<47 (no ML-DSA).
"$BIN/$LINK_CMD" "${LINK_SEC[@]}" --disable-runtime-dependency-installation --database "$LOGS/state.db" > "$LOGS/superlink.log" 2>&1 &
link_pid=$!
disown "$link_pid"
pids+=($link_pid)
wait_for_port 8000 "$link_pid" "$LOGS/superlink.log"
wait_for_port 9092 "$link_pid" "$LOGS/superlink.log"

if [[ "$MODE" != insecure ]]; then
  # Flower's direct-trust model: the SuperLink only accepts farms whose public key was registered.
  for ((i = 0; i < FARMS; i++)); do
    if ! "$BIN/$FLWR_CMD" supernode register "$(login_pub "$i")" local --name "farm$i" > "$LOGS/register$i.log" 2>&1; then
      echo "registering farm$i failed:" >&2; cat "$LOGS/register$i.log" >&2; exit 1
    fi
  done
fi

# SERVER_ONLY=1: stop here with the SuperLink up and every farm registered but offline
# (used by the Attack 2 demo, which tries to log in as farm 0).
if [[ -n "${SERVER_ONLY:-}" ]]; then
  echo "SERVER READY (mode=$MODE, $FARMS farms registered, none started)"
  while kill -0 "$link_pid" 2>/dev/null; do sleep 1; done
  exit 0
fi

for ((i = 0; i < FARMS; i++)); do
  # shellcheck disable=SC2046
  "$BIN/$NODE_CMD" $(farm_sec "$i") --superlink 127.0.0.1:9092 --port $((9100 + i)) \
    --node-config "partition-id=$i num-partitions=$FARMS" > "$LOGS/farm$i.log" 2>&1 &
  farm_pids[i]=$!
  disown "$!"
  pids+=($!)
done
for ((i = 0; i < FARMS; i++)); do
  wait_for_port $((9100 + i)) "${farm_pids[i]}" "$LOGS/farm$i.log"
done

cd "$ROOT"
: > "$LOGS/run.log"
"$BIN/$FLWR_CMD" run . local --stream --run-config "num-farms=$FARMS num-server-rounds=$ROUNDS $EXTRA_CONFIG" \
  > "$LOGS/run.log" 2>&1 &
disown "$!"
pids+=($!)

# Print progress live, round by round.
tail -n +1 -f "$LOGS/run.log" > >(grep --line-buffered -E "^\[(round|setup)" | tee "$LOGS/rounds.txt") &
tail_pid=$!
disown "$tail_pid"

# The log stream never closes on its own; stop once the ServerApp reports it is done.
until grep -qE "PQCFLOWER_DONE|ERROR|Error" "$LOGS/run.log"; do sleep 1; done
sleep 1
kill "$tail_pid" 2>/dev/null || true
sleep 0.5
if grep -qE "ERROR|Error" "$LOGS/run.log"; then grep -A20 -E "ERROR|Error" "$LOGS/run.log" | head -40; exit 1; fi
echo "mode=$MODE farms=$FARMS rounds=$ROUNDS ${EXTRA_CONFIG:+config: $EXTRA_CONFIG }logs: $LOGS"
