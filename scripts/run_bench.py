#!/usr/bin/env python3
"""
Batch runner — run every challenge in a suite through main.py and collect results.

Suites:
  ctf  : CTF_Injection_Bench/test/**/challenge.json   (runnable today)
  cve  : cve-injection-bench/challenges/*/             (needs a CVE-Bench adapter — pending)

Each challenge is run in an isolated subprocess (`python main.py --challenge-json X
--state-out ...`) so a crash/hang in one challenge cannot take down the whole batch.
Per-challenge outcome (exploited?), per-loop attempt_history, tokens and timing are
collected into reports/bench/<suite>_<ts>/results.json for scripts/aggregate_metrics.py.

Examples:
  python scripts/run_bench.py --suite ctf
  python scripts/run_bench.py --suite ctf --types sql,ssti --limit 5
  python scripts/run_bench.py --suite ctf --only AmateursCTF --timeout 600
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Running as `python scripts/run_bench.py` puts scripts/ on sys.path, not the project
# root — make `import src.*` work for the CVE adapter.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Full CVE-Bench clone (has the harness: ./run, scripts/, src/cvebench). The curated
# cve-injection-bench/ subset is only the challenge list; bring-up + grading use this repo.
CVEBENCH_REPO = Path(os.getenv("CVEBENCH_REPO", str(ROOT.parent / "cve-bench")))
# Host ports exposed by `./run up` (see scripts/get_expose_services.py): target:80→9090,
# evaluator/proof→9091.
CVE_WEB_PORT = 9090


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")


def _safe_name(challenge_json: Path) -> str:
    # e.g. .../2024/AmateursCTF/web/one_shot/challenge.json -> 2024_AmateursCTF_one_shot
    parts = challenge_json.parent.parts
    tail = "_".join(parts[-3:]) if len(parts) >= 3 else challenge_json.parent.name
    return re.sub(r"[^A-Za-z0-9_.-]", "_", tail)


def _read_family(challenge_json: Path) -> str:
    """Best-effort injection family from challenge.json (for filtering/grouping)."""
    try:
        d = json.loads(challenge_json.read_text(encoding="utf-8"))
    except Exception:
        return "unknown"
    fam = d.get("injection_family") or d.get("vuln_type") or d.get("category") or "unknown"
    return str(fam).strip().lower().replace(" ", "_").replace("/", "_")


def _rel(p) -> str:
    """Display path, relative to ROOT when possible.

    discover_ctf() already handles both layouts: CTF_Injection_Bench either sits
    inside the framework directory or, as in the release bundle, beside it under
    ../benchmarks/. In the second case a challenge path is NOT under ROOT, so a
    bare Path.relative_to(ROOT) raises ValueError and kills the batch before the
    first target runs. Fall back to the bundle root, then to the absolute path.
    """
    p = Path(p).resolve()
    for base in (ROOT, ROOT.parent):
        try:
            return str(p.relative_to(base))
        except ValueError:
            continue
    return str(p)


def discover_ctf(
    types: list[str] | None,
    only: str | None,
    waf_level: int | None = None,
    exclude: list[str] | None = None,
) -> list[tuple[Path, str]]:
    """Discover CTF challenges.

    By default only the baseline (no-WAF) challenges are returned; the generated
    ``.waf_variants/PL*/challenge.json`` files are skipped so a plain
    ``--suite ctf`` run stays the no-WAF baseline. Pass ``waf_level`` (1-4) to run
    *only* that ModSecurity paranoia-level variant instead, so each WAF level is a
    self-contained suite with its own results.json (for the solve-rate delta).
    """
    base = ROOT / "CTF_Injection_Bench" / "test"
    if not base.exists():
        base = ROOT / "benchmarks" / "CTF_Injection_Bench" / "test"
    if not base.exists():
        base = ROOT.parent / "benchmarks" / "CTF_Injection_Bench" / "test"
    found: list[tuple[Path, str]] = []
    for cj in sorted(base.glob("**/challenge.json")):
        is_variant = ".waf_variants" in cj.parts
        if waf_level is None:
            if is_variant:
                continue
        else:
            if not is_variant or cj.parent.name != f"PL{waf_level}":
                continue
        fam = _read_family(cj)
        if types and not any(t in fam for t in types):
            continue
        if only and only.lower() not in str(cj).lower():
            continue
        # Exclude matches the challenge PATH or its injection FAMILY, so `--exclude xss`
        # drops the XSS/HTML-injection cohort (needs a browser the HTTP agent lacks) and
        # `--exclude BKISC` drops by path — both outcome-independent scoping.
        if exclude and any(x.lower() in str(cj).lower() or x.lower() in fam for x in exclude):
            continue
        found.append((cj, fam))
    return found


def _load_metrics(metrics_path: str | None) -> dict:
    if not metrics_path:
        return {}
    p = Path(metrics_path)
    if not p.is_absolute():
        p = ROOT / metrics_path
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _fallback_summary(by_node: dict) -> dict:
    """Derive an explicit fallback-fired signal from per-node LLM failed_calls.

    planner/navigator/executor substitute canned fallback text (see
    src/agents/{planner,navigator,executor}.py) on EVERY llm.invoke() failure —
    so by_node[node]["failed_calls"] > 0 is an exact proxy for "this node ran
    on fallback text for at least one turn". Nothing previously surfaced this
    alongside solve rate, so a "solved" run that partly ran on fallback text
    looked identical to one that never fell back at all. Report both here so
    the paper can state (and the reviewer can check) how much of a headline
    number depends on the LLM actually reasoning vs. a canned substitute.
    """
    fallback_nodes = {
        node: v.get("failed_calls", 0)
        for node, v in (by_node or {}).items()
        if v.get("failed_calls", 0) > 0
    }
    return {
        "any_fallback_fired": bool(fallback_nodes),
        "fallback_call_count": sum(fallback_nodes.values()),
        "fallback_calls_by_node": fallback_nodes,
    }


def run_one(challenge_json: Path, family: str, states_dir: Path, timeout: int, stream: bool = False) -> dict:
    state_out = states_dir / f"{_safe_name(challenge_json)}.json"
    cmd = [
        sys.executable, "main.py",
        "--challenge-json", str(challenge_json),
        "--state-out", str(state_out),
    ]
    started = time.monotonic()
    run_error = None
    if stream:
        rc, _ = _run_streamed(cmd, timeout, cwd=str(ROOT))
        if rc == 124:
            run_error = f"timeout>{timeout}s"
    else:
        try:
            subprocess.run(
                cmd, cwd=str(ROOT), timeout=timeout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            run_error = f"timeout>{timeout}s"
        except Exception as exc:  # noqa: BLE001 — record any launcher failure, keep batch going
            run_error = f"{type(exc).__name__}: {exc}"
    wall = round(time.monotonic() - started, 1)

    state = {}
    if state_out.exists():
        try:
            state = json.loads(state_out.read_text(encoding="utf-8"))
        except Exception:
            pass

    metrics = _load_metrics(state.get("metrics_path"))
    llm = metrics.get("llm", {})

    return {
        "name": _safe_name(challenge_json),
        "challenge_json": _rel(challenge_json),
        "family": family,
        "vulnerability_type": state.get("vulnerability_type") or family,
        "exploited": bool(state.get("exploited")),
        "final_status": state.get("final_status"),
        "loop_count": state.get("loop_count"),
        "attempt_history": state.get("attempt_history", []),
        "total_tokens": llm.get("total_tokens", 0),
        "input_tokens": llm.get("input_tokens", 0),
        "output_tokens": llm.get("output_tokens", 0),
        "llm_calls": llm.get("calls", 0),
        "duration_seconds": metrics.get("duration_seconds"),
        "wall_seconds": wall,
        "by_node": llm.get("by_node", {}),
        **_fallback_summary(llm.get("by_node", {})),
        "report_path": state.get("report_path"),
        "metrics_path": state.get("metrics_path"),
        "run_error": run_error,
    }


# ── CVE-Bench suite ──────────────────────────────────────────────────────────

def discover_cve(only: str | None) -> list[str]:
    """Injection-CVE list = the curated cve-injection-bench/challenges/ subset."""
    bench_base = ROOT / "benchmarks" / "cve_injection_bench_17" / "challenges"
    if not bench_base.exists():
        bench_base = ROOT.parent / "benchmarks" / "cve_injection_bench_17" / "challenges"
    base = bench_base if bench_base.exists() else (ROOT / "cve-injection-bench" / "challenges")
    cves = sorted(p.name for p in base.glob("CVE-*") if p.is_dir())
    if only:
        cves = [c for c in cves if only.lower() in c.lower()]
    return cves


def _run_cmd(args: list[str], timeout: int, cwd: str | None = None, env: dict | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(
            args, cwd=cwd, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        return 124, out + f"\n[timeout>{timeout}s]"
    except Exception as exc:  # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"


# Per-agent ANSI colors for live streaming (terminal only — captured text stays plain,
# so log files and the markdown report are never polluted with escape codes).
_RESET = "\033[0m"
_BOLD = "\033[1m"
_NODE_COLORS = {
    "infrastructure": "\033[38;5;208m",       # orange
    "planner": "\033[34m",                    # blue
    "navigator": "\033[36m",                  # cyan
    "executor": "\033[32m",                   # green
    "dual_loop": "\033[33m",                  # yellow
    "dual_loop_controller": "\033[33m",       # yellow
    "poc_generator": "\033[35m",              # magenta
}
_NO_COLOR = os.getenv("NO_COLOR") is not None


def _colorize(txt: str, cur: str) -> tuple[str, str]:
    """Return (line_to_print, new_current_node_color). Color whole agent blocks by node."""
    if _NO_COLOR:
        return txt, cur
    if "[NODE]:" in txt:
        name = txt.split("[NODE]:", 1)[1].strip()
        cur = _NODE_COLORS.get(name, "")
        return f"{_BOLD}{cur}{txt}{_RESET}", cur
    if "[SUCCESS]" in txt or "FLAG FOUND" in txt:
        return f"\033[1;32m{txt}{_RESET}", cur          # bold green
    if "RESULT: [FAILED]" in txt or txt.lstrip().startswith("❌"):
        return f"\033[31m{txt}{_RESET}", cur            # red
    return (f"{cur}{txt}{_RESET}" if cur else txt), cur


def _run_streamed(args: list[str], timeout: int, cwd: str | None = None, env: dict | None = None) -> tuple[int, str]:
    """Run a command, echoing its output live (colored by agent) while capturing it PLAIN.

    Timeout is checked per output line, so a process that hangs with NO output may
    exceed it — fine for the agent (it logs frequently). Use _run_cmd for reliable
    timeouts on quiet steps (up/down/grade).
    """
    # Force unbuffered child stdout so each agent node's log appears as soon as the
    # node finishes, instead of being held in the pipe buffer until it fills up.
    env = {**(env or os.environ), "PYTHONUNBUFFERED": "1"}
    try:
        proc = subprocess.Popen(
            args, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
    except Exception as exc:  # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"
    deadline = time.monotonic() + timeout
    out: list[str] = []
    timed_out = False
    cur_color = ""
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            out.append(line)  # capture PLAIN for log file / report
            colored, cur_color = _colorize(line.rstrip("\n"), cur_color)
            print(colored, flush=True)
            if time.monotonic() > deadline:
                proc.kill()
                out.append(f"\n[timeout>{timeout}s]\n")
                timed_out = True
                break
        proc.wait(timeout=10)
    except Exception as exc:  # noqa: BLE001
        proc.kill()
        out.append(f"\n[{type(exc).__name__}: {exc}]\n")
    rc = 124 if timed_out else (proc.returncode or 0)
    return rc, "".join(out)


def run_one_cve(cve: str, states_dir: Path, agent_timeout: int, up_timeout: int, no_build: bool, stream: bool = False, max_loops: int = 1) -> dict:
    """Bring target up via ./run, point the pipeline at the host port, grade via done.sh, tear down."""
    run = str(CVEBENCH_REPO / "run")
    env = {**os.environ, "CVEBENCH_VERSION": "critical"}
    # `./run` needs `uv`, often installed to ~/.local/bin or ~/.cargo/bin which a
    # non-interactive subprocess shell may not have on PATH — prepend them.
    extra_paths = [str(Path.home() / ".local" / "bin"), str(Path.home() / ".cargo" / "bin")]
    env["PATH"] = os.pathsep.join(extra_paths + [env.get("PATH", "")])
    target_url = f"http://localhost:{CVE_WEB_PORT}"
    base = {
        "name": cve, "challenge_json": f"cve-injection-bench/challenges/{cve}",
        "family": "cve-bench", "vulnerability_type": "unknown",
        "exploited": False, "final_status": None, "loop_count": None,
        "attempt_history": [], "total_tokens": 0, "input_tokens": 0, "output_tokens": 0,
        "llm_calls": 0, "duration_seconds": None, "wall_seconds": 0,
        "by_node": {}, "report_path": None, "metrics_path": None,
        "grader_status": None, "run_error": None,
        "any_fallback_fired": False, "fallback_call_count": 0, "fallback_calls_by_node": {},
    }
    started = time.monotonic()
    log_path = states_dir / f"{cve}.log"

    def _log(section: str, text: str) -> None:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"\n===== {section} =====\n{text}\n")

    up_args = ["bash", run, "up", cve] + (["--no-build"] if no_build else [])
    rc, up_log = _run_cmd(up_args, up_timeout, env=env)
    _log(f"up (rc={rc})", up_log)
    if rc != 0:
        tail = "\n".join(up_log.strip().splitlines()[-4:])
        base["run_error"] = f"up failed (rc={rc}): {tail[:300]}"
        rc_d, down_log = _run_cmd(["bash", run, "down", cve], 180, env=env)
        _log(f"down (rc={rc_d})", down_log)
        base["wall_seconds"] = round(time.monotonic() - started, 1)
        return base

    try:
        from src.cve_bench_adapter import load_cve_challenge
        _, config, _ = load_cve_challenge(cve, CVEBENCH_REPO / "src" / "critical" / "challenges")
        cfg_path = states_dir / f"{cve}_config.json"
        cfg_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        state_out = states_dir / f"{cve}.json"

        agent_args = [
            sys.executable, "main.py",
            "--cve-config", str(cfg_path),
            "--target-url", target_url,
            "--state-out", str(state_out),
        ]
        # CVE-Bench has no success signal for the agent → cap dual-loop retries to
        # avoid burning tokens on blind re-attempts. (Env name matches dual_loop_controller.)
        agent_env = {**os.environ, "DUAL_LOOP_MAX_COUNT": str(max_loops)}
        if stream:
            print(f"\n----- agent: {cve} (target {target_url}, max_loops={max_loops}) -----", flush=True)
            arc, alog = _run_streamed(agent_args, agent_timeout, cwd=str(ROOT), env=agent_env)
        else:
            arc, alog = _run_cmd(agent_args, agent_timeout, cwd=str(ROOT), env=agent_env)
        _log(f"agent (rc={arc})", alog)  # full — early discovery output is the useful part

        # Grade with CVE-Bench's own evaluator inside the target container.
        grc, glog = _run_cmd(
            ["bash", run, "compose", cve, "exec", "-T", "target", "/evaluator/done.sh"],
            120, env=env,
        )
        _log(f"grade (rc={grc})", glog)
        m = re.search(r'"status"\s*:\s*(true|false)', glog)
        base["grader_status"] = m.group(1) if m else None
        base["exploited"] = bool(m and m.group(1) == "true")

        if state_out.exists():
            try:
                state = json.loads(state_out.read_text(encoding="utf-8"))
            except Exception:
                state = {}
            base["final_status"] = state.get("final_status")
            base["loop_count"] = state.get("loop_count")
            base["attempt_history"] = state.get("attempt_history", [])
            base["report_path"] = state.get("report_path")
            base["metrics_path"] = state.get("metrics_path")
            metrics = _load_metrics(state.get("metrics_path"))
            llm = metrics.get("llm", {})
            base.update({
                "total_tokens": llm.get("total_tokens", 0),
                "input_tokens": llm.get("input_tokens", 0),
                "output_tokens": llm.get("output_tokens", 0),
                "llm_calls": llm.get("calls", 0),
                "duration_seconds": metrics.get("duration_seconds"),
                "by_node": llm.get("by_node", {}),
                **_fallback_summary(llm.get("by_node", {})),
            })
    finally:
        rc_d, down_log = _run_cmd(["bash", run, "down", cve], 180, env=env)
        _log(f"down (rc={rc_d})", down_log)

    base["wall_seconds"] = round(time.monotonic() - started, 1)
    return base


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", choices=["ctf", "cve"], default="ctf")
    ap.add_argument("--types", default="", help="Comma list to filter injection families, e.g. sql,ssti")
    ap.add_argument("--only", default="", help="Substring filter on challenge path, e.g. AmateursCTF")
    ap.add_argument("--exclude", default="", help="[ctf] comma-separated substrings to EXCLUDE by challenge path OR injection family, e.g. BKISC,mAuth or xss")
    ap.add_argument("--limit", type=int, default=0, help="Run at most N challenges (0 = all)")
    ap.add_argument("--timeout", type=int, default=900, help="Per-challenge agent timeout in seconds")
    ap.add_argument("--up-timeout", type=int, default=1200, help="[cve] timeout for `./run up` (build can be slow)")
    ap.add_argument("--no-build", action="store_true", help="[cve] pass --no-build to ./run up (reuse built images)")
    ap.add_argument("--stream", action="store_true", help="Show agent thoughts/logs live per challenge (tee to log file too)")
    ap.add_argument("--max-loops", type=int, default=1, help="[cve] dual-loop retry cap (DUAL_LOOP_MAX_COUNT); cve has no success signal so default 1")
    ap.add_argument("--waf", type=int, default=None, choices=[1, 2, 3, 4], help="[ctf] run only ModSecurity-CRS paranoia-level PL<N> variants (default: no-WAF baseline). Generate them first with scripts/gen_waf_variant.py --all")
    args = ap.parse_args(argv)

    if args.suite == "cve" and not (CVEBENCH_REPO / "run").is_file():
        print(f"[run_bench] CVE-Bench repo not found at {CVEBENCH_REPO} (set CVEBENCH_REPO env).")
        return 1

    types = [t.strip().lower() for t in args.types.split(",") if t.strip()]
    exclude = [x.strip() for x in args.exclude.split(",") if x.strip()]
    if args.suite == "ctf":
        challenges = discover_ctf(types, args.only or None, waf_level=args.waf, exclude=exclude or None)
    else:
        challenges = discover_cve(args.only or None)  # type filter N/A (zero_day = unknown vuln)
    if args.limit:
        challenges = challenges[: args.limit]
    if not challenges:
        print("[run_bench] no challenges matched the filters.")
        return 1

    suite_tag = args.suite if args.waf is None else f"{args.suite}-waf-pl{args.waf}"
    run_dir = ROOT / "reports" / "bench" / f"{suite_tag}_{_ts()}"
    states_dir = run_dir / "states"
    states_dir.mkdir(parents=True, exist_ok=True)

    print(f"[run_bench] suite={args.suite} challenges={len(challenges)} timeout={args.timeout}s")
    print(f"[run_bench] output dir: {_rel(run_dir)}")

    results = []
    for i, item in enumerate(challenges, 1):
        if args.suite == "ctf":
            cj, fam = item
            label = f"{_safe_name(cj)} ({fam})"
        else:
            label = f"{item} (cve-bench/zero_day)"

        if args.stream:
            # Clear banner so each challenge's live output starts fresh / easy to scan.
            print(f"\n{'='*78}\n[{i}/{len(challenges)}]  {label}\n{'='*78}", flush=True)
        else:
            print(f"[{i}/{len(challenges)}] {label} … ", end="", flush=True)

        if args.suite == "ctf":
            res = run_one(item[0], item[1], states_dir, args.timeout, stream=args.stream)
        else:
            res = run_one_cve(item, states_dir, args.timeout, args.up_timeout, args.no_build, stream=args.stream, max_loops=args.max_loops)

        flag = "✅" if res["exploited"] else ("⏱️" if res["run_error"] else "❌")
        extra = f" grader={res['grader_status']}" if args.suite == "cve" else ""
        line = f"{flag}  tokens={res['total_tokens']} time={res['duration_seconds']}s err={res['run_error'] or '-'}{extra}"
        print(f"  → RESULT [{i}/{len(challenges)}] {label}: {line}" if args.stream else line, flush=True)
        results.append(res)

    payload = {
        "suite": args.suite,
        "waf_paranoia_level": args.waf,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters": {"types": types, "only": args.only, "limit": args.limit, "waf": args.waf},
        "total": len(results),
        "solved": sum(1 for r in results if r["exploited"]),
        "runs_with_fallback_fired": sum(1 for r in results if r.get("any_fallback_fired")),
        "results": results,
    }
    out = run_dir / "results.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    solved = payload["solved"]
    fb = payload["runs_with_fallback_fired"]
    print(f"\n[run_bench] done: {solved}/{len(results)} solved "
          f"({fb}/{len(results)} runs had a fallback-plan/recon fire at least once)")
    print(f"[run_bench] results: {_rel(out)}")
    print(f"[run_bench] aggregate with: python scripts/aggregate_metrics.py {_rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
