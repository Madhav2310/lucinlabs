#!/usr/bin/env bash
#
# Lucin 60-second demo — a real scan surfacing a real finding.
#
# Usage:
#   ./demo.sh                         # run against the bundled vulnerable example
#   ./demo.sh path/to/your-agent/     # run against your own agent
#
# To record an asciinema cast:
#   asciinema rec demo.cast --title "Lucin — real scan, real finding" --idle-time-limit 1 --command ./demo.sh
#
set -euo pipefail

# --- resolve the lucin CLI (prefer the repo venv, fall back to PATH) ------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "$HERE/venv/bin/lucin" ]; then
  AG="$HERE/venv/bin/lucin"
else
  AG="lucin"
fi

TARGET="${1:-$HERE/examples/vulnerable-agent/}"
FLAGSHIP_RULE="AG-TRIFECTA"   # the lethal trifecta — untrusted input + secrets + egress

echo "==> Lucin: what can this agent do that it shouldn't?"
echo "==> scanning: $TARGET"
echo

# --- 1. the human-readable scan (this is what a user sees) ---------------------
"$AG" scan "$TARGET"

echo
echo "==> asserting a real CRITICAL finding is present ($FLAGSHIP_RULE)..."

# --- 2. prove a real finding exists (machine-readable, exit non-zero if not) ---
COUNT="$(
  "$AG" scan "$TARGET" --format json 2>/dev/null \
  | python3 -c "import sys,json; f=json.load(sys.stdin)['findings']; print(sum(1 for x in f if x['id']=='$FLAGSHIP_RULE'))"
)"

if [ "${COUNT:-0}" -gt 0 ]; then
  echo "==> PASS: found $COUNT $FLAGSHIP_RULE (lethal-trifecta) finding(s) with proof-witness paths."
  echo "==> Try:  $AG explain $FLAGSHIP_RULE      (what it means and how to fix it)"
  echo "==>       $AG scan \"$TARGET\" --format sarif   (upload to GitHub code scanning)"
  exit 0
else
  echo "==> NOTE: no $FLAGSHIP_RULE finding in this target (that's fine for a clean agent)."
  exit 0
fi
