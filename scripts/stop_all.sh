#!/usr/bin/env bash
# Stop every Flower process started from this repo's virtualenv, however it was launched
# (absolute ".venv/bin/flower-..." or relative, which shows up as ".venv/bin/python .venv/bin/flower-...").
# Usage: scripts/stop_all.sh [--quiet]
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATTERN="$ROOT/\.venv/bin/(python[0-9.]* .*)?flower-"

found=$(pgrep -f "$PATTERN" || true)
if [[ -z "$found" ]]; then
  [[ "${1:-}" == --quiet ]] || echo "no Flower processes from $ROOT running"
  exit 0
fi
[[ "${1:-}" == --quiet ]] || ps -o pid=,command= -p "$(echo "$found" | paste -sd, -)" | cut -c1-140
pkill -f "$PATTERN" 2>/dev/null || true
sleep 2
pkill -9 -f "$PATTERN" 2>/dev/null || true
[[ "${1:-}" == --quiet ]] || echo "stopped $(echo "$found" | wc -l | tr -d ' ') process(es)"
exit 0
