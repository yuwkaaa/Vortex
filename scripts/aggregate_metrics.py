#!/usr/bin/env python3
"""
Aggregate a batch result (from scripts/run_bench.py) into a report + charts.

Produces, next to the input results.json:
  summary.md          — overall + per-injection-type table, solved/failed lists,
                        and a per-challenge LOOP-BY-LOOP breakdown (one block per loop)
  summary.csv         — per-challenge row (for spreadsheets / paper tables)
  chart_outcome.png   — solved vs failed (overall)            [needs matplotlib]
  chart_by_type.png   — solved vs failed stacked, per type    [needs matplotlib]

Charts are skipped gracefully if matplotlib is not installed.

Usage:
  python scripts/aggregate_metrics.py reports/bench/ctf_<ts>/results.json
  python scripts/aggregate_metrics.py            # auto-pick the latest run
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _rel(p: Path) -> str:
    """Path relative to ROOT for tidy printing; fall back to the full path."""
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _latest_results() -> Path | None:
    base = ROOT / "reports" / "bench"
    cands = sorted(base.glob("*/results.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


def _avg(nums: list[float]) -> float:
    nums = [n for n in nums if isinstance(n, (int, float))]
    return round(sum(nums) / len(nums), 1) if nums else 0.0


def build_summary(payload: dict) -> tuple[str, list[dict]]:
    results = payload["results"]
    total = len(results)
    solved = sum(1 for r in results if r["exploited"])
    errored = [r for r in results if r.get("run_error")]
    rate = round(100 * solved / total, 1) if total else 0.0

    # Per injection type
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_type[r.get("vulnerability_type") or "unknown"].append(r)

    lines: list[str] = []
    lines.append(f"# Benchmark Summary — suite `{payload.get('suite')}`\n")
    lines.append(f"Generated from `{payload.get('generated_at')}`\n")
    lines.append("## Overall\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Challenges | {total} |")
    lines.append(f"| Solved (exploited) | {solved} |")
    lines.append(f"| Failed | {total - solved} |")
    lines.append(f"| Success rate | {rate}% |")
    lines.append(f"| Errored / timed out | {len(errored)} |")
    lines.append(f"| Total tokens | {sum(r.get('total_tokens', 0) for r in results):,} |")
    lines.append(f"| Avg tokens / challenge | {_avg([r.get('total_tokens', 0) for r in results]):,} |")
    lines.append(f"| Avg time / challenge (s) | {_avg([r.get('duration_seconds') or 0 for r in results])} |")
    lines.append("")

    lines.append("## By injection type\n")
    lines.append("| Type | Total | Solved | Rate | Avg tokens | Avg time (s) |")
    lines.append("|------|-------|--------|------|------------|--------------|")
    for t in sorted(by_type):
        rs = by_type[t]
        s = sum(1 for r in rs if r["exploited"])
        tr = round(100 * s / len(rs), 1) if rs else 0.0
        lines.append(
            f"| {t} | {len(rs)} | {s} | {tr}% | "
            f"{_avg([r.get('total_tokens', 0) for r in rs]):,} | "
            f"{_avg([r.get('duration_seconds') or 0 for r in rs])} |"
        )
    lines.append("")

    # Solved / failed listing
    lines.append("## Solved\n")
    sol = [r for r in results if r["exploited"]]
    lines.append("\n".join(f"- ✅ `{r['name']}` ({r['vulnerability_type']})" for r in sol) or "_(none)_")
    lines.append("\n## Failed\n")
    fail = [r for r in results if not r["exploited"]]
    lines.append(
        "\n".join(
            f"- ❌ `{r['name']}` ({r['vulnerability_type']})"
            + (f" — {r['run_error']}" if r.get("run_error") else "")
            for r in fail
        )
        or "_(none)_"
    )
    lines.append("")

    # Per-challenge loop-by-loop breakdown (one block per loop)
    lines.append("## Loop-by-loop breakdown\n")
    for r in results:
        hist = r.get("attempt_history") or []
        head = "✅" if r["exploited"] else "❌"
        lines.append(f"### {head} {r['name']}  ·  {len(hist)} loop(s)\n")
        if not hist:
            lines.append("_(no attempts recorded — likely infra/setup failure)_\n")
            continue
        for h in hist:
            payloads = ", ".join(f"`{p}`" for p in h.get("payloads_tried", [])) or "—"
            lines.append(
                f"- **Loop {h.get('loop')} [{h.get('loop_type')}]** · type=`{h.get('injection_type')}` "
                f"· error=`{h.get('error_type')}` · verdict: {h.get('verdict')}\n"
                f"    - payloads: {payloads}\n"
                f"    - response hint: {(h.get('response_snippet') or '—')[:160]}"
            )
        lines.append("")

    return "\n".join(lines), results


def write_csv(results: list[dict], path: Path) -> None:
    cols = ["name", "vulnerability_type", "exploited", "grader_status", "loop_count", "final_status",
            "total_tokens", "input_tokens", "output_tokens", "llm_calls",
            "duration_seconds", "wall_seconds", "run_error"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow(r)


def draw_charts(payload: dict, out_dir: Path) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []  # matplotlib not installed — skip charts gracefully

    results = payload["results"]
    made: list[str] = []

    # Chart 1: solved vs failed overall
    solved = sum(1 for r in results if r["exploited"])
    failed = len(results) - solved
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.bar(["Solved", "Failed"], [solved, failed], color=["#2e9e5b", "#c0392b"])
    ax.set_title(f"Outcome ({solved}/{len(results)} solved)")
    for i, v in enumerate([solved, failed]):
        ax.text(i, v, str(v), ha="center", va="bottom")
    fig.tight_layout()
    p1 = out_dir / "chart_outcome.png"
    fig.savefig(p1, dpi=120)
    plt.close(fig)
    made.append(p1.name)

    # Chart 2: solved vs failed stacked, per type
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_type[r.get("vulnerability_type") or "unknown"].append(r)
    types = sorted(by_type)
    sol = [sum(1 for r in by_type[t] if r["exploited"]) for t in types]
    fai = [len(by_type[t]) - s for t, s in zip(types, sol)]
    fig, ax = plt.subplots(figsize=(max(5, len(types) * 0.9), 4))
    ax.bar(types, sol, label="Solved", color="#2e9e5b")
    ax.bar(types, fai, bottom=sol, label="Failed", color="#c0392b")
    ax.set_title("Outcome by injection type")
    ax.set_ylabel("Challenges")
    plt.xticks(rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    p2 = out_dir / "chart_by_type.png"
    fig.savefig(p2, dpi=120)
    plt.close(fig)
    made.append(p2.name)

    return made


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv:
        results_path = Path(argv[0])
        if not results_path.is_absolute():
            results_path = ROOT / results_path
    else:
        results_path = _latest_results()
        if results_path is None:
            print("[aggregate] no results.json found under reports/bench/. Run scripts/run_bench.py first.")
            return 1
        print(f"[aggregate] using latest: {_rel(results_path)}")

    payload = json.loads(results_path.read_text(encoding="utf-8"))
    out_dir = results_path.parent

    summary_md, results = build_summary(payload)
    charts = draw_charts(payload, out_dir)
    if charts:
        summary_md += "\n## Charts\n\n" + "\n".join(f"![{c}]({c})" for c in charts) + "\n"
    else:
        summary_md += "\n_(charts skipped — `pip install matplotlib` to enable)_\n"

    (out_dir / "summary.md").write_text(summary_md, encoding="utf-8")
    write_csv(results, out_dir / "summary.csv")

    print(f"[aggregate] summary : {_rel(out_dir / 'summary.md')}")
    print(f"[aggregate] csv     : {_rel(out_dir / 'summary.csv')}")
    for c in charts:
        print(f"[aggregate] chart   : {_rel(out_dir / c)}")
    if not charts:
        print("[aggregate] charts  : skipped (matplotlib not installed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
