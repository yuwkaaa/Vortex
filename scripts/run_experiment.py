#!/usr/bin/env python3
"""
Experiment orchestrator for the harness-vs-evaluation-vs-model comparison in the
paper. Runs a matrix of

    {agent × model × ablation × cve × repeat}

as subprocesses, is RESUMABLE (skips already-completed cells), and aggregates
Success Rate with mean±std + a pairwise significance test.

Each cell is graded by the SAME neutral end-grader (/evaluator/done.sh) for both
agents — never the agent's self-report.

  our agent's cell -> scripts/run_bench.py --suite cve --only <cve> --max-loops N --no-build
  AXE's cell        -> the AXE baseline's own main.py --cve <cve> --mode blackbox --llm P:M ... then grade

Usage
-----
  # run a slice (resumable) — e.g. base vs full ablation, our agent, n=3, deepseek
  python scripts/run_experiment.py run --exp E2_ablation \
      --agents vortex --models deepseek --ablations base,full \
      --cves injection17 --n 3 --max-loops 3

  # head-to-head (our agent, full config, vs AXE), n=5
  python scripts/run_experiment.py run --exp E1_head2head \
      --agents vortex,axe --models deepseek --ablations full \
      --cves injection17 --n 5 --max-loops 3

  # aggregate + significance
  python scripts/run_experiment.py aggregate --exp E1_head2head

Env
---
  AXE_DIR (default ../_axe_extract, i.e. a separately-obtained checkout of the AXE
  baseline next to this repo), CVEBENCH_REPO (default AXE_DIR/cve-bench),
  CVEBENCH_VERSION (default critical). Model endpoint comes from this repo's own
  .env OPENROUTER_* vars unless a model registry entry overrides them.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent                       # this repo's root


def _find_axe_dir() -> Path:
    """Locate the AXE baseline checkout (_axe_extract), which lives alongside this
    repo rather than inside it, so walk up until we find it."""
    if os.getenv("AXE_DIR"):
        return Path(os.environ["AXE_DIR"])
    d = ROOT
    for _ in range(4):
        cand = d.parent / "_axe_extract"
        if cand.exists():
            return cand
        d = d.parent
    return ROOT.parent.parent / "_axe_extract"


AXE_DIR = _find_axe_dir()
CVEBENCH_REPO = os.getenv("CVEBENCH_REPO", str(AXE_DIR / "cve-bench"))
CVEBENCH_VERSION = os.getenv("CVEBENCH_VERSION", "critical")
EXP_ROOT = ROOT / "reports" / "experiment"

# 17 unauthenticated single-target web-injection CVEs.
# Curation criteria (outcome-independent, applied uniformly to every candidate):
#   (a) single web target  (b) unauthenticated attack surface  (c) injection via an HTTP request.
# Excluded on these grounds: 4701 (broken challenge, target exits 127); 34070/34716 (XSS, need
# headless browser); 5314/5315 (no image); 22120 (multi-host target:8080+server:10051);
# 25641 (requires an authenticated "Import Templates" permission); 34359 (attack surface is a
# loaded .gguf model file, not an HTTP parameter). Backfilled to n=17 with clean unauth
# injection CVEs selected by class + runnability (NOT by outcome): 3495, 32980, 5084.
INJECTION_17 = [
    "CVE-2024-2359", "CVE-2024-2624", "CVE-2024-32167", "CVE-2024-3234", "CVE-2024-32964",
    "CVE-2024-3552", "CVE-2024-36412", "CVE-2024-36675", "CVE-2024-36779", "CVE-2024-37388",
    "CVE-2024-37831", "CVE-2024-37849", "CVE-2024-4320", "CVE-2024-4443",
    "CVE-2024-3495", "CVE-2024-32980", "CVE-2024-5084",   # backfill (SQLi / SSRF / file-upload)
]
CVE_SETS = {"injection17": INJECTION_17}

# Ablation registry (env-flag sets) for our agent. AXE ignores ablations (baseline = its own design).
ABLATIONS = {
    "full": {},
    "base": {  # all upgrades OFF = baseline harness
        "ABLATE_SELF_VERIFY": "1", "ABLATE_CONTEXT_TRIM": "1", "ABLATE_DISCOVERY": "1",
        "ABLATE_IMPACT_GOALS": "1", "ENABLE_PARAM_FUZZ": "0", "ENABLE_CONTENT_DISCOVERY": "0",
    },
    "no_selfverify":  {"ABLATE_SELF_VERIFY": "1"},        # drop impact self-verification
    "no_ctxtrim":     {"ABLATE_CONTEXT_TRIM": "1"},       # drop on-demand context re-read tools
    "no_discovery":   {"ABLATE_DISCOVERY": "1", "ENABLE_PARAM_FUZZ": "0",
                       "ENABLE_CONTENT_DISCOVERY": "0"},  # drop hidden endpoint/param discovery
    "no_impactgoals": {"ABLATE_IMPACT_GOALS": "1"},       # drop impact-goal steering
}

# Model registry: name -> extra env to select the endpoint/model. Empty dict = use this
# repo's own .env as-is (DeepSeek-direct). The override wins over that .env in _base_env(),
# so a 2nd backbone never touches the DeepSeek setup the main ablation depends on — pick it
# with --models <name>.
MODELS = {
    # DeepSeek-direct (V4-flash). This repo's .env already points here (api.deepseek.com /
    # deepseek-chat), so no override needed; AXE gets a bare model id (api.deepseek.com wants
    # no vendor prefix).
    "deepseek": {"_llm": "deepseek:deepseek-chat"},
    # 2nd backbone — GLM-4.7 via Z.ai (OpenAI-compatible). Set ZAI_API_KEY (or GLM_API_KEY)
    # in the shell before running. Base_url per https://docs.z.ai/guides/overview/quick-start.
    # Both agents (our agent reads OPENROUTER_*; AXE's deepseek: branch reads the same vars,
    # bare model id) are pointed at Z.ai by this single override, so endpoints stay consistent
    # across the two agents.
    "glm": {
        "OPENROUTER_BASE_URL": "https://api.z.ai/api/paas/v4",
        # The flash variant (glm-4.7-flash) returned sustained rate-limit errors from Z.ai
        # during tuning; glm-4.7 (non-flash, a reasoning model) is what's actually used for
        # the GLM backbone numbers in the paper — it costs more tokens (reasoning overhead)
        # but was verified working end-to-end for both agents.
        "OPENROUTER_MODEL": "glm-4.7",
        "OPENROUTER_API_KEY": os.environ.get("ZAI_API_KEY") or os.environ.get("GLM_API_KEY", ""),
        "_llm": "deepseek:glm-4.7",
    },
    # Local Ollama (WSL) — OpenAI-compatible at :11434/v1. Free/offline; no key (SDK just needs a
    # non-empty string). Pick the pulled tag with OLLAMA_MODEL (default qwen2.5:7b). Use a
    # tool-capable Qwen (qwen2.5 / qwen3) for the ReAct executor, and raise num_ctx via a
    # Modelfile (Ollama defaults ~4k → ReAct context truncates silently). parse_llm splits on
    # the FIRST ':' so "deepseek:qwen2.5:7b" -> model="qwen2.5:7b" stays intact.
    "qwen": {
        "OPENROUTER_BASE_URL": os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        "OPENROUTER_MODEL": os.environ.get("OLLAMA_MODEL", "qwen2.5:7b"),
        "OPENROUTER_API_KEY": "ollama",
        "_llm": "deepseek:" + os.environ.get("OLLAMA_MODEL", "qwen2.5:7b"),
    },
}


def _load_vortex_env() -> dict:
    """Read this repo's own .env (the DeepSeek-direct OPENROUTER_* vars) into a dict."""
    env = {}
    envf = ROOT / ".env"
    if envf.exists():
        for line in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _cells_path(exp: str) -> Path:
    d = EXP_ROOT / exp
    d.mkdir(parents=True, exist_ok=True)
    return d / "cells.jsonl"


def _load_done(exp: str) -> set:
    p = _cells_path(exp)
    done = set()
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                rec = json.loads(line)
                done.add(rec["cell"])
            except Exception:
                pass
    return done


def _append_cell(exp: str, rec: dict) -> None:
    with _cells_path(exp).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _cell_id(agent, model, ablation, cve, rep) -> str:
    return f"{agent}|{model}|{ablation}|{cve}|r{rep}"


def _base_env(model: str, ablation: str) -> dict:
    env = dict(os.environ)
    env.update(_load_vortex_env())                       # endpoint/model from this repo's .env
    env["CVEBENCH_REPO"] = CVEBENCH_REPO
    env["CVEBENCH_VERSION"] = CVEBENCH_VERSION
    for k, v in MODELS.get(model, {}).items():       # model override (except the _llm marker)
        if not k.startswith("_"):
            env[k] = v
    for k, v in ABLATIONS.get(ablation, {}).items(): # ablation flags (our agent only)
        env[k] = v
    return env


# ---------------------------------------------------------------- our agent's cell
def _run_vortex(cve: str, model: str, ablation: str, max_loops: int, timeout: int) -> dict:
    env = _base_env(model, ablation)
    before = set(glob.glob(str(ROOT / "reports" / "bench" / "cve_*")))
    cmd = [sys.executable, "-u", "scripts/run_bench.py", "--suite", "cve",
           "--only", cve, "--max-loops", str(max_loops), "--no-build",
           "--timeout", str(timeout)]
    t0 = time.time()
    try:
        subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=timeout + 300,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    dur = round(time.time() - t0, 1)
    # find the results.json produced by THIS call
    after = sorted(set(glob.glob(str(ROOT / "reports" / "bench" / "cve_*"))) - before,
                   key=os.path.getmtime)
    r = {}
    for d in reversed(after):
        rj = Path(d) / "results.json"
        if rj.exists():
            try:
                res = json.load(rj.open())["results"]
                for row in res:
                    if row.get("name") == cve:
                        r = row
                        break
            except Exception:
                pass
        if r:
            break
    return {
        "grader": str(r.get("grader_status")) if r else None,
        "calls": r.get("llm_calls"), "tokens": r.get("total_tokens"),
        "loops": r.get("loop_count"), "infra_error": r.get("run_error"),
        "duration": dur,
    }


# ---------------------------------------------------------------- AXE cell
def _run_axe(cve: str, model: str, max_loops: int, timeout: int, no_peek: bool = False) -> dict:
    env = _base_env(model, "full")
    env["AXE_INSTRUCTOR_MODE"] = os.getenv("AXE_INSTRUCTOR_MODE", "JSON")
    env["AXE_NO_DONE_PEEK"] = "1" if no_peek else "0"  # honest end-only grading, no in-band grader peek
    llm = MODELS.get(model, {}).get("_llm", "deepseek:deepseek-chat")
    run = str(Path(CVEBENCH_REPO) / "run")
    # AXE has its own venv (instructor, its own langgraph/langchain pins) — sys.executable
    # here is this repo's interpreter and lacks `instructor`, which made every AXE cell fail
    # instantly (infra failure, <1s) when invoked through this combined vortex,axe runner.
    axe_python = AXE_DIR / ".venv" / "bin" / "python"
    axe_python_str = str(axe_python) if axe_python.exists() else sys.executable
    t0 = time.time()
    try:
        subprocess.run([axe_python_str, "-u", "main.py", "--cve", cve, "--mode", "blackbox",
                        "--llm", llm, "--max-loops", str(max_loops),
                        "--max-exec-steps", "15", "--max-explore-steps", "15"],
                       cwd=str(AXE_DIR), env=env, timeout=timeout + 300,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    dur = round(time.time() - t0, 1)
    # neutral end-grade (same grader our agent uses), then tear down
    grader, infra = None, None
    try:
        g = subprocess.run(["bash", run, "compose", cve, "exec", "-T", "target",
                            "/evaluator/done.sh"], cwd=str(AXE_DIR), env=env,
                           capture_output=True, text=True, timeout=120)
        out = (g.stdout or "") + (g.stderr or "")
        if '"status": true' in out or '"status":true' in out:
            grader = "true"
        elif '"status": false' in out or '"status":false' in out:
            grader = "false"
        else:
            infra = "grade failed: " + out[:200]
    except Exception as exc:
        infra = f"grade error: {exc}"
    try:
        subprocess.run(["bash", run, "compose", cve, "down"], cwd=str(AXE_DIR), env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    except Exception:
        pass
    return {"grader": grader, "calls": None, "tokens": None, "loops": None,
            "infra_error": infra, "duration": dur}


# ---------------------------------------------------------------- run
def cmd_run(args) -> None:
    agents = args.agents.split(",")
    models = args.models.split(",")
    ablations = args.ablations.split(",")
    cves = CVE_SETS.get(args.cves, args.cves.split(","))
    done = _load_done(args.exp)
    total = len(agents) * len(models) * len(ablations) * len(cves) * args.n
    print(f"[exp {args.exp}] matrix cells={total}  already-done={len(done)}  "
          f"agents={agents} models={models} ablations={ablations} cves={len(cves)} n={args.n}")
    i = 0
    for rep in range(args.n):
        for model in models:
            for ablation in ablations:
                for agent in agents:
                    abl = ablation if agent == "vortex" else "full"   # AXE not ablated
                    for cve in cves:
                        i += 1
                        cell = _cell_id(agent, model, abl, cve, rep)
                        if cell in done:
                            continue
                        print(f"  [{i}/{total}] {cell} ... ", end="", flush=True)
                        # clean any stray containers between cells
                        subprocess.run("docker ps -aq | xargs -r docker rm -f",
                                       shell=True, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
                        subprocess.run(["docker", "volume", "prune", "-f"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if agent == "vortex":
                            out = _run_vortex(cve, model, abl, args.max_loops, args.timeout)
                        else:  # "axe" (peeks /done) or "axe_nopeek" (end-grade only, no peek)
                            out = _run_axe(cve, model, args.max_loops, args.timeout,
                                           no_peek=(agent == "axe_nopeek"))
                        rec = {"cell": cell, "agent": agent, "model": model,
                               "ablation": abl, "cve": cve, "rep": rep,
                               "ts": datetime.now(timezone.utc).isoformat(), **out}
                        _append_cell(args.exp, rec)
                        done.add(cell)
                        print(f"grader={out['grader']} calls={out['calls']} "
                              f"infra={'Y' if out['infra_error'] else '-'} {out['duration']}s")
    print(f"[exp {args.exp}] done.")


# ---------------------------------------------------------------- aggregate
def _solved(rec) -> bool:
    return rec.get("grader") == "true"


def _ran(rec) -> bool:
    # a real attempt = graded true/false and no infra error
    return rec.get("grader") in ("true", "false") and not rec.get("infra_error")


def cmd_aggregate(args) -> None:
    p = _cells_path(args.exp)
    if not p.exists():
        print("no cells for", args.exp); return
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    # group by (agent,model,ablation) -> per-rep SR over CVEs that ran
    groups: dict = {}
    for r in rows:
        groups.setdefault((r["agent"], r["model"], r["ablation"]), []).append(r)
    print(f"\n=== {args.exp} — SR (mean±std over repeats, only clean-run CVEs) ===")
    print(f"{'agent/model/ablation':<40}{'SR mean':<10}{'std':<8}{'n_rep':<6}{'infra_fails'}")
    per_rep_sr = {}
    for key, recs in sorted(groups.items()):
        reps = sorted({r["rep"] for r in recs})
        srs = []
        infra = 0
        for rep in reps:
            sub = [r for r in recs if r["rep"] == rep]
            ran = [r for r in sub if _ran(r)]
            infra += sum(1 for r in sub if r.get("infra_error"))
            if ran:
                srs.append(sum(1 for r in ran if _solved(r)) / len(ran))
        per_rep_sr[key] = srs
        mean = statistics.mean(srs) if srs else float("nan")
        std = statistics.pstdev(srs) if len(srs) > 1 else 0.0
        label = "/".join(key)
        print(f"{label:<40}{mean:<10.3f}{std:<8.3f}{len(srs):<6}{infra}")
    # per-CVE solve-rate table (fraction of reps solved), per group
    print(f"\n=== per-CVE solve-rate (fraction of repeats solved) ===")
    for key, recs in sorted(groups.items()):
        by_cve = {}
        for r in recs:
            by_cve.setdefault(r["cve"], []).append(r)
        line = " ".join(
            f"{cve.split('-')[-1]}:{sum(1 for x in rs if _solved(x))}/{len(rs)}"
            for cve, rs in sorted(by_cve.items()))
        print(f"  {'/'.join(key)}: {line}")
    # pairwise significance (Wilcoxon if scipy; else sign test) between the two
    # requested configs on matched per-CVE solve counts
    if args.compare:
        a, b = args.compare.split("::")
        _significance(rows, a, b)


def _significance(rows, a_key: str, b_key: str) -> None:
    def sel(k):
        ag, mo, ab = k.split("/")
        return [r for r in rows if r["agent"] == ag and r["model"] == mo and r["ablation"] == ab]
    A, B = sel(a_key), sel(b_key)
    cves = sorted({r["cve"] for r in A} & {r["cve"] for r in B})
    a_solverate, b_solverate = [], []
    for cve in cves:
        ar = [r for r in A if r["cve"] == cve]
        br = [r for r in B if r["cve"] == cve]
        if ar and br:
            a_solverate.append(sum(_solved(r) for r in ar) / len(ar))
            b_solverate.append(sum(_solved(r) for r in br) / len(br))
    diffs = [x - y for x, y in zip(a_solverate, b_solverate)]
    print(f"\n=== significance: {a_key} vs {b_key} (n_cve={len(cves)}) ===")
    print(f"  mean per-CVE solve-rate: {a_key}={statistics.mean(a_solverate):.3f}  "
          f"{b_key}={statistics.mean(b_solverate):.3f}")
    pos = sum(1 for d in diffs if d > 0); neg = sum(1 for d in diffs if d < 0)
    print(f"  sign test: {pos} CVEs favour {a_key}, {neg} favour {b_key}, "
          f"{len(diffs) - pos - neg} ties")
    try:
        from scipy.stats import wilcoxon
        nz = [d for d in diffs if d != 0]
        if nz:
            stat, p = wilcoxon(nz)
            print(f"  Wilcoxon signed-rank (nonzero diffs n={len(nz)}): stat={stat:.2f} p={p:.4f}")
    except Exception:
        print("  (install scipy for Wilcoxon; sign test above)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--exp", required=True)
    r.add_argument("--agents", default="vortex", help="comma: vortex,axe")
    r.add_argument("--models", default="deepseek")
    r.add_argument("--ablations", default="full", help="comma of: " + ",".join(ABLATIONS))
    r.add_argument("--cves", default="injection17", help="set name or comma list")
    r.add_argument("--n", type=int, default=3, help="repeats per cell")
    r.add_argument("--max-loops", type=int, default=3)
    r.add_argument("--timeout", type=int, default=700)
    r.set_defaults(func=cmd_run)
    a = sub.add_parser("aggregate")
    a.add_argument("--exp", required=True)
    a.add_argument("--compare", default="", help="e.g. 'vortex/deepseek/full::axe/deepseek/full'")
    a.set_defaults(func=cmd_aggregate)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
