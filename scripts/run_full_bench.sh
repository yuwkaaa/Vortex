#!/usr/bin/env bash
# Full overnight bench: CTF (21) + CVE-Injection (17), PoC reports collected.
#
# Designed to be started in tmux and left alone. It never aborts the batch on a
# single target's failure, writes incremental state so a crash costs one target
# rather than the whole night, and ends with a single summary file to read over
# coffee.
#
#   tmux new -s bench
#   ./scripts/run_full_bench.sh 2>&1 | tee -a bench_driver.log
#   # detach: Ctrl-b d      reattach: tmux attach -t bench
#
# Options (env):
#   SUITES="ctf cve"   which suites to run, in order   (default: both)
#   TIMEOUT=900        per-challenge agent timeout, s
#   MAX_LOOPS=3        dual-loop retry cap for the cve suite
#   RESUME=1           skip suites whose results.json already exists in OUT
#   OUT=...            output directory (default: reports/full_<timestamp>)
set -uo pipefail          # deliberately NOT -e: a failed target must not kill the batch

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE" || exit 1

TS="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-reports/full_${TS}}"
SUITES="${SUITES:-ctf cve}"
TIMEOUT="${TIMEOUT:-900}"
MAX_LOOPS="${MAX_LOOPS:-3}"
RESUME="${RESUME:-0}"
mkdir -p "$OUT"/{logs,poc}

# Fixed start marker for `find -newer`. It must be written ONCE and never touched
# again: driver.log is appended to by every log() call, so using it as the -newer
# reference makes its mtime ~now and silently matches nothing.
STARTED_AT="$OUT/.started"
: > "$STARTED_AT"

log()  { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/driver.log"; }
fail() { log "FATAL: $*"; exit 1; }

# Prefer the project venv over whatever python3 is on PATH. run_bench.py itself
# only needs stdlib, but the agent subprocess it spawns needs langgraph etc., and
# it is launched with sys.executable -- so the interpreter chosen here decides
# whether the agent can import its dependencies at all.
PY=""
for cand in .venv/bin/python3 .venv/Scripts/python.exe python3 python; do
  if [ -x "$cand" ] || command -v "$cand" >/dev/null 2>&1; then
    PY="$cand"
    break
  fi
done
[ -n "$PY" ] || { echo "FATAL: no python interpreter found (tried venv, python3, python)"; exit 1; }

# The 22-target restore set, minus UofTCTF/prepared_2 (byte-identical duplicate of
# prepared_1; see curation/PROVENANCE_2025.md). Substring match on challenge path.
CTF_EXCLUDE="xss,2024,Alice_and_the_Literal_Escape,my_first_website,pickle_soup,\
Non_Functional_Calculator,cppickle,Comments_Only,HeroCTF,Neuroflux,Pragyan,Flyer,\
No_SQLi,BKISC,templateception,supersqli,jinjail,Eval_is_Evil,prepared_2,2026cve"
# 2026cve is the CVE-2026 cohort wired in by curation/wire_2026cve_to_ctf.py. It lives
# under test/ only because discover_ctf() hardcodes that root, and it is graded by a
# DIFFERENT oracle (canary extraction). It must never enter the 21-target denominator;
# run it on its own with --only 2026cve.

# ─── preflight ───────────────────────────────────────────────────────────────
log "=== preflight ==="
[ -f scripts/run_bench.py ] || fail "run from the framework directory (scripts/run_bench.py not found)"

command -v docker >/dev/null 2>&1 || fail "docker not on PATH"
docker info >/dev/null 2>&1       || fail "docker daemon unreachable"
log "docker            OK ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"

"$PY" -c "import sys; sys.exit(0 if sys.version_info>=(3,12) else 1)" \
  || fail "python3 >= 3.12 required"
log "python            OK ($("$PY" -V 2>&1) via $PY)"

# Without ffuf/katana the discovery tools silently degrade to built-in fallbacks,
# which changes the endpoint set the agent sees. README calls results measured
# that way incomparable across machines, so refuse rather than produce them.
for t in ffuf katana; do
  command -v "$t" >/dev/null 2>&1 \
    || fail "$t not on PATH -- content_discovery/crawl_site would silently degrade and the run would not be comparable"
done
log "ffuf, katana      OK"

: "${FFUF_WORDLIST:=/usr/share/seclists/Discovery/Web-Content/common.txt}"
[ -r "$FFUF_WORDLIST" ] || fail "FFUF_WORDLIST unreadable: $FFUF_WORDLIST"
export FFUF_WORDLIST
log "wordlist          OK ($FFUF_WORDLIST)"

[ -f .env ] || fail ".env missing -- copy .env.example and set the provider keys"
# shellcheck disable=SC1091
set -a; . ./.env; set +a
[ -n "${OPENROUTER_API_KEY:-}" ] || fail "OPENROUTER_API_KEY empty in .env"
log "llm               OK (${OPENROUTER_MODEL:-?} @ ${OPENROUTER_BASE_URL:-?})"

# run_bench.py imports only stdlib, so it starts fine with no dependencies at all
# and only fails once it spawns the agent -- i.e. after the first Docker build.
# Import the agent's real stack here instead, so a missing venv costs five seconds
# rather than surfacing mid-batch.
"$PY" - <<'PY' || fail "agent dependencies or source are not importable -- do not start a long run"
import ast, importlib, pathlib, sys

missing = []
for mod in ("langgraph", "langchain_core", "langchain_openai", "dotenv",
            "pydantic", "requests", "yaml"):
    try:
        importlib.import_module(mod)
    except Exception:
        missing.append(mod)
if missing:
    print("  MISSING python modules: " + ", ".join(missing))
    print("  fix: python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt")
    sys.exit(1)

src = pathlib.Path("src/agents/executor.py").read_text(encoding="utf-8")
ast.parse(src)
assert "request_log" in src, "request_log instrumentation missing from executor.py"

# The graph is what main.py actually builds; importing it catches a broken node
# wiring or a bad relative import that a syntax check alone would pass.
sys.path.insert(0, ".")
importlib.import_module("src.graph")

print("deps + agent      OK (graph imports, request_log present)")
PY

# The cve suite drives the UPSTREAM CVE-Bench harness: its `run` script brings
# targets up and its graders decide success. benchmarks/cve_injection_bench_17/ is
# only the challenge list -- it ships no `run`, no compose-include/target/mariadb
# fragments and no grader base class. Without the clone the suite exits immediately,
# which is fine on its own but wastes the whole CTF pass if discovered three hours in.
# Check it now and drop the suite rather than fail the run.
if printf '%s' "$SUITES" | grep -qw cve; then
  : "${CVEBENCH_REPO:=$(cd .. && pwd)/cve-bench}"
  export CVEBENCH_REPO
  if [ -f "$CVEBENCH_REPO/run" ]; then
    log "cve harness       OK ($CVEBENCH_REPO)"
  else
    log "cve harness       MISSING at $CVEBENCH_REPO"
    log "                  -> dropping the cve suite; ctf will still run in full."
    log "                  fix: git clone https://github.com/uiuc-kang-lab/cve-bench.git \\"
    log "                         $CVEBENCH_REPO"
    log "                  or:  export CVEBENCH_REPO=/path/to/cve-bench"
    SUITES="$(printf '%s' "$SUITES" | tr ' ' '\n' | grep -vw cve | tr '\n' ' ')"
    [ -n "${SUITES// /}" ] || fail "no suites left to run"
  fi
fi

df -h . | awk 'NR==2 {print "  disk free: "$4}' | tee -a "$OUT/driver.log"
log "output            $OUT"
log ""

# ─── run one suite ───────────────────────────────────────────────────────────
run_suite() {
  local suite="$1" rc
  local dest="$OUT/$suite"

  if [ "$RESUME" = "1" ] && [ -f "$dest/results.json" ]; then
    log "[$suite] results.json already present -- skipping (RESUME=1)"
    return 0
  fi

  log "[$suite] starting (timeout=${TIMEOUT}s)"
  # run_bench writes live state into reports/bench/<suite>_<ts>/; results are only
  # copied into $OUT/<suite>/ once the suite finishes, so point at the live path now.
  log "[$suite] monitor: ls reports/bench/${suite}_*/states/ | wc -l"
  local before; before=$(date +%s)

  if [ "$suite" = "ctf" ]; then
    CTF_BLACKBOX=1 "$PY" scripts/run_bench.py \
        --suite ctf --stream --timeout "$TIMEOUT" \
        --exclude "$CTF_EXCLUDE" \
        >"$OUT/logs/ctf.log" 2>&1
    rc=$?
  else
    "$PY" scripts/run_bench.py \
        --suite cve --stream --timeout "$TIMEOUT" --max-loops "$MAX_LOOPS" \
        >"$OUT/logs/cve.log" 2>&1
    rc=$?
  fi

  local elapsed=$(( $(date +%s) - before ))
  log "[$suite] finished rc=$rc in $((elapsed/60))m $((elapsed%60))s"

  # run_bench writes reports/bench/<suite>_<ts>/; adopt the newest one
  local latest
  latest=$(ls -1dt reports/bench/${suite}_* 2>/dev/null | head -1)
  if [ -n "$latest" ] && [ -d "$latest" ]; then
    mkdir -p "$dest"
    cp -r "$latest"/. "$dest"/ 2>/dev/null
    log "[$suite] results -> $dest  (from $latest)"
  else
    log "[$suite] WARNING: no reports/bench/${suite}_* directory found"
  fi
  return 0        # never propagate: the next suite must still run
}

for s in $SUITES; do
  run_suite "$s"
done

# ─── collect PoC reports ─────────────────────────────────────────────────────
# Every run terminates at the poc_generator node -- including failures -- so each
# target leaves a reports/report_<ts>.md. Gather the ones written during this run.
log ""
log "=== collecting PoC reports ==="
found=0
while IFS= read -r r; do
  [ -f "$r" ] || continue
  cp "$r" "$OUT/poc/" 2>/dev/null && found=$((found+1))
done < <(find reports -maxdepth 1 -name 'report_*.md' -newer "$STARTED_AT" 2>/dev/null)
log "collected $found PoC report(s) -> $OUT/poc/"

# ─── summary ─────────────────────────────────────────────────────────────────
log ""
log "=== summary ==="
"$PY" scripts/summarize_bench.py "$OUT" | tee -a "$OUT/driver.log"

log ""
log "DONE. Read: $OUT/SUMMARY.md"
