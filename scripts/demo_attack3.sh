#!/usr/bin/env bash
# Demo for Attack 3 (replayed model update): an attacker records farm 0's updates and sends an old
# one again in place of the new one.
#   1) classical Flower behaviour: updates are not signed, so the old update is accepted
#   2) our version: the replayed update from the previous round is rejected (signature covers the round)
#   3) our version again: the update recorded in run 2 for the same round is rejected
#      (signature covers the run id; before that, this replay carried a valid signature)
# All runs use TLS 1.3 + ECDSA farm login. Usage: scripts/demo_attack3.sh [num_rounds]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROUNDS="${1:-4}"
CAPTURED="$ROOT/logs/captured"
B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[2m'; N=$'\e[0m'

show() {
  sed -l -nE \
    -e "s/^\[setup\].*//p" \
    -e "s/^(\[round +[0-9]+\] farm [0-9]+: .*REJECTED.*)$/${G}\1${N}/p" \
    -e "s/^(\[round +[0-9]+\] farm [0-9]+: .*REPLAYED.*)$/${R}\1${N}/p" \
    -e "s/^(\[round +[0-9]+\] farm [0-9]+: .*)$/${D}\1${N}/p" \
    -e "s/^(\[round +[0-9]+\]) test_acc=([0-9.]+).*$/${B}\1 shared model accuracy: \2${N}/p" \
    | grep --line-buffered -v '^$'
}

echo "${B}Quantum-Safe Federated Learning for Smart Agriculture: Attack 3 demo${N}"
echo "3 farms train one crop model. An attacker records farm 0's updates and replays old ones."
echo

rm -rf "$CAPTURED"
echo "${Y}${B}Run 1: classical Flower (updates are not signed)${N}"
"$ROOT/scripts/run_local.sh" classical 3 "$ROUNDS" "sign-updates=false replay-farm=0" 2>&1 | show
echo

rm -rf "$CAPTURED"
echo "${G}${B}Run 2: our version (ML-DSA-65 signed updates): replaying last round's update${N}"
"$ROOT/scripts/run_local.sh" classical 3 "$ROUNDS" "sign-updates=true replay-farm=0" 2>&1 | show
echo

echo "${G}${B}Run 3: our version: replaying the update recorded in run 2 for the same round${N}"
"$ROOT/scripts/run_local.sh" classical 3 "$ROUNDS" "sign-updates=true replay-farm=0" 2>&1 | show
