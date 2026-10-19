#!/usr/bin/env bash
# Demo for Attack 2 (simulated quantum attacker): impersonate farm 0 by recovering its login key.
#   1) classical Flower: farms log in with ECDSA P-384, which Shor's algorithm breaks
#   2) our version:      farms log in with ML-DSA-65, which no known quantum algorithm breaks
# Each run starts a real SuperLink (TLS 1.3) with farm 0 registered but offline.
# Usage: scripts/demo_attack2.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.venv/bin"
LOG="$ROOT/logs/demo_attack2"
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'
mkdir -p "$LOG"

attack() {  # mode, public key, private key (the oracle's answer), title
  local mode=$1 pub=$2 priv=$3 title=$4
  echo "${B}$title${N}"
  SERVER_ONLY=1 "$ROOT/scripts/run_local.sh" "$mode" 3 1 > "$LOG/server_$mode.log" 2>&1 &
  local server=$!
  disown "$server"  # no "Terminated" line when it is stopped
  for _ in $(seq 60); do grep -qE "SERVER READY|failed|in use" "$LOG/server_$mode.log" && break; sleep 1; done
  if ! grep -q "SERVER READY" "$LOG/server_$mode.log"; then cat "$LOG/server_$mode.log"; return 1; fi
  "$BIN/python" -m pqcflower.attack2_quantum "$pub" "$priv" "$ROOT/credentials/certs/ca.crt" 2>/dev/null
  kill "$server" 2>/dev/null
  "$ROOT/scripts/stop_all.sh" --quiet
  echo
}

echo "${B}Quantum-Safe Federated Learning for Smart Agriculture: Attack 2 demo${N}"
echo "A (simulated) quantum attacker tries to log in to the server as farm 0."
echo
attack classical "$ROOT/credentials/farm-keys/farm0.pub" "$ROOT/credentials/farm-keys/farm0" \
  "${Y}Run 1: classical Flower (ECDSA P-384 farm login)${N}"
attack pqc "$ROOT/credentials/farm-keys-mldsa/farm0.pub.pem" "$ROOT/credentials/farm-keys-mldsa/farm0.pem" \
  "${G}Run 2: our version (ML-DSA-65 farm login)${N}"
echo "${B}Note:${N} the quantum computer is simulated: for ECDSA the oracle returns the real key,"
echo "as Shor's algorithm would; no such attack is known against ML-DSA."
