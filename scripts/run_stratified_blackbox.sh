#!/usr/bin/env bash
# Stratified BLACK-BOX CTF benchmark — the honest-autonomy measurement for the paper.
#
# Integrity design:
#   * CTF_BLACKBOX=1  → the adapter withholds vuln class / code loc / strategy / example
#     payload / params; the agent gets only the running target + "recover the flag".
#   * --exclude xss   → drop the XSS/HTML-injection cohort (needs a headless browser the
#     HTTP-only agent architecturally cannot drive — a capability, not outcome, exclusion).
#   * Stratified by YEAR, cleanest FIRST (2026 is post-model-cutoff → least contamination;
#     2024 is the contamination cohort). Running cleanest-first means a mid-run API failure
#     (e.g. DeepSeek 402) leaves the headline strata intact and clearly bounded.
#   * Content-discovery tooling is active (ffuf + SecLists via FFUF_WORDLIST; DISCOVERY_SCAN_ROOT
#     default on). Optional harness steering stays OFF here — this is the clean Config-A
#     autonomy number.
#
# Env knobs: YEARS (default "2026 2025 2024"), TIMEOUT (1800), REPEATS (1; set 3 for n=3),
#            FFUF_WORDLIST (SecLists common.txt). Balance must cover ~0.5M tok/challenge.
set -u
cd "$(dirname "$0")/.." || exit 1

export CTF_BLACKBOX=1
export FFUF_WORDLIST="${FFUF_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
PY="${PY:-./.venv/bin/python}"
TIMEOUT="${TIMEOUT:-1800}"
YEARS="${YEARS:-2026 2025 2024}"
REPEATS="${REPEATS:-1}"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOGDIR="reports/bench/stratified_${STAMP}"
mkdir -p "$LOGDIR"
MANIFEST="$LOGDIR/manifest.tsv"
: > "$MANIFEST"
echo -e "year\trepeat\tresults_json" >> "$MANIFEST"

echo "STRATIFIED BLACK-BOX | years=[$YEARS] | repeats=$REPEATS | timeout=${TIMEOUT}s | log=$LOGDIR"
echo "CTF_BLACKBOX=1  --exclude xss  FFUF_WORDLIST=$FFUF_WORDLIST"

for r in $(seq 1 "$REPEATS"); do
  for y in $YEARS; do
    echo "=============== YEAR $y  (repeat $r/$REPEATS, injection-scope, XSS excluded) ==============="
    ylog="$LOGDIR/year_${y}_r${r}.log"
    "$PY" scripts/run_bench.py --suite ctf --only "$y" --exclude xss \
        --stream --timeout "$TIMEOUT" 2>&1 | tee "$ylog"
    # record the results.json this run produced so aggregation can find every stratum
    rj="$(grep -oE 'reports/bench/ctf_[0-9_-]+/results.json' "$ylog" | head -1)"
    echo -e "${y}\t${r}\t${rj}" >> "$MANIFEST"
    echo "===YEAR_${y}_R${r}_DONE==="
  done
done
echo "===ALL_STRATA_DONE=== manifest=$MANIFEST"
