#!/usr/bin/env bash
# Demo for Attack 1 (tampered model update): same attack, run against
#   1) classical Flower behaviour: updates are not signed
#   2) our version: every update is signed with ML-DSA-65 and verified by the server
# Both runs use TLS 1.3 + ECDSA farm login. Usage: scripts/demo_attack.sh [num_rounds]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROUNDS="${1:-5}"
B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[2m'; N=$'\e[0m'

# Show the farm/aggregation lines from a run, colour-coded.
show() {
  sed -l -nE \
    -e "s/^\[setup\].*//p" \
    -e "s/^(\[round +[0-9]+\] farm [0-9]+: .*(TAMPERED|REJECTED).*)$/${R}\1${N}/p" \
    -e "s/^(\[round +[0-9]+\] farm [0-9]+: .*)$/${D}\1${N}/p" \
    -e "s/^(\[round +[0-9]+\]) test_acc=([0-9.]+).*$/${B}\1 shared model accuracy: \2${N}/p" \
    | grep --line-buffered -v '^$'
}
final_acc() { grep -E "^\[round +$ROUNDS\] test_acc" "$1" | sed -E 's/.*test_acc=([0-9.]+).*/\1/'; }

echo "${B}Quantum-Safe Federated Learning for Smart Agriculture: Attack 1 demo${N}"
echo "3 farms train one crop model. An attacker alters farm 0's update in transit."
echo

echo "${Y}${B}Run 1: classical Flower (updates are not signed)${N}"
"$ROOT/scripts/run_local.sh" classical 3 "$ROUNDS" "sign-updates=false attack-farm=0" 2>&1 | show
UNSIGNED="$ROOT/logs/classical_sign-updates-false_attack-farm-0/rounds.txt"
echo

echo "${G}${B}Run 2: our version (every update signed with ML-DSA-65)${N}"
"$ROOT/scripts/run_local.sh" classical 3 "$ROUNDS" "sign-updates=true attack-farm=0" 2>&1 | show
SIGNED="$ROOT/logs/classical_sign-updates-true_attack-farm-0/rounds.txt"
echo

echo "${B}Result after $ROUNDS rounds${N}"
printf "  %-44s accuracy %s\n" "classical Flower: tampered update ACCEPTED" "${R}$(final_acc "$UNSIGNED")${N}"
printf "  %-44s accuracy %s\n" "ML-DSA signed:    tampered update REJECTED" "${G}$(final_acc "$SIGNED")${N}"
