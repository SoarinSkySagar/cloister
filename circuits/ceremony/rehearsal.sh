#!/usr/bin/env bash
# A full rehearsal of the ceremony on a small circuit: two Phase 1 and two Phase 2 contributors, the beacon, the keys,
# then a real proof under those keys. NOT yet completed on the 15 GB / 12-thread development laptop: phase 2 initialisation
# ran over 40 minutes on the small circuit below (docs/ceremony.md, "Measured cost"). Expect an hour or more. Run from anywhere:
#
#   circuits/ceremony/rehearsal.sh [log2]       (default 19, enough for the small circuit below)
#
# The real ceremony is the same commands on the real config with -log2 21 (docs/ceremony.md).
set -euo pipefail
cd "$(dirname "$0")/.."
LOG2="${1:-19}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
L="go run ./cmd/ledger"
# time every step, so a slow one is visible: "-> N s"
run() { local t0; t0=$(date +%s); "$@"; echo "   -> $(( $(date +%s) - t0 )) s ($(date +%H:%M:%S))"; }
mkdir -p "$W/setup"
cat > "$W/setup/config.json" <<'JSON'
{ "depth": 4, "txs": 1, "moves": 2, "withdrawals": 1, "parties": 1, "relayer": 1,
  "chain_id": "qorechain-diana", "rollup_id": "cloister-rehearsal",
  "genesis": [ { "index": 0, "pk_commit": "01", "qor": 1000000, "usd": 1000000 }, { "index": 1, "pk_commit": "02" } ] }
JSON
echo "== phase 1 (universal), 2 contributors"
run $L ceremony phase1-init -log2 "$LOG2" -out "$W/p1_0000.bin"
run $L ceremony contribute -phase 1 -in "$W/p1_0000.bin" -out "$W/p1_0001.bin"
run $L ceremony contribute -phase 1 -in "$W/p1_0001.bin" -out "$W/p1_0002.bin"
BEACON="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"   # stands in for a public beacon fetched after the last contribution
run $L ceremony phase1-seal -log2 "$LOG2" -beacon "$BEACON" -out "$W/srs.bin" "$W/p1_0001.bin" "$W/p1_0002.bin"
echo "== phase 2 (this circuit), 2 contributors"
run $L ceremony phase2-init -dir "$W/setup" -srs "$W/srs.bin" -out "$W/p2_0000.bin"
run $L ceremony contribute -phase 2 -in "$W/p2_0000.bin" -out "$W/p2_0001.bin"
run $L ceremony contribute -phase 2 -in "$W/p2_0001.bin" -out "$W/p2_0002.bin"
run $L ceremony phase2-finalize -dir "$W/setup" -srs "$W/srs.bin" -beacon "$BEACON" "$W/p2_0001.bin" "$W/p2_0002.bin"
echo "== a chain with a skipped contributor is refused"
if $L ceremony phase2-finalize -dir "$W/setup" -srs "$W/srs.bin" -beacon "$BEACON" "$W/p2_0002.bin" >/dev/null 2>&1; then
  echo "FAIL: a skipped contribution was accepted"; exit 1
fi
echo "== a real proof under the ceremony's keys"
echo '{"txs":[{"sender":0,"payer":0,"relayer":1,"actions":[{"kind":"transfer","to":2,"amount":5}]}]}' > "$W/batch.json"
run $L prove -dir "$W/setup" -batch "$W/batch.json" -data "$(printf 'ab%.0s' {1..32})" -out "$W/out"
echo "ceremony rehearsal passed"
