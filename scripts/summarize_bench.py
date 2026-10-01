#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Summarize a run_full_bench.sh output directory into one readable file.

Writes <out>/SUMMARY.md and prints the same to stdout. Built to be the only
thing you have to read after an unattended overnight run: what solved, what
broke, what it cost, and which numbers are safe to quote.

    python3 scripts/summarize_bench.py reports/full_20260930_013000
"""
import io, json, os, sys, glob, collections, pathlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Figures the artifact README forbids citing (pre-audit stub runs).
FORBIDDEN_NOTE = (
    "Do not quote any 2024/2025 solve rate measured against `.benchmark_runtime` "
    "stubs (43/43, 54/57, 94.7%, 12/14, 11/14). See curation/PAPER_NUMBERS_AUDIT.md."
)


def load(out: pathlib.Path, suite: str):
    p = out / suite / "results.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


def fmt_hms(sec):
    sec = int(sec or 0)
    return f"{sec//3600}h {sec%3600//60:02d}m" if sec >= 3600 else f"{sec//60}m {sec%60:02d}s"


def suite_block(name, data):
    L = []
    if data is None:
        L.append(f"## {name.upper()}\n\n**NOT RUN** — no `results.json`.\n")
        return L, None
    if "_error" in data:
        L.append(f"## {name.upper()}\n\n**UNREADABLE** — {data['_error']}\n")
        return L, None

    res = data.get("results", [])
    solved = [r for r in res if r.get("exploited")]
    errored = [r for r in res if r.get("run_error")]
    wall = sum(r.get("wall_seconds") or 0 for r in res)
    toks = sum(r.get("total_tokens") or 0 for r in res)

    L.append(f"## {name.upper()}  —  {len(solved)}/{len(res)} solved")
    L.append("")
    L.append(f"- wall clock: **{fmt_hms(wall)}**")
    L.append(f"- tokens: **{toks/1e6:.1f}M**")
    if errored:
        L.append(f"- **{len(errored)} target(s) errored** (see table)")
    L.append("")

    if solved:
        L.append("**Solved:**")
        L.append("")
        for r in solved:
            L.append(f"- `{r.get('name')}` — {r.get('family') or '?'}, "
                     f"{fmt_hms(r.get('wall_seconds'))}, "
                     f"{(r.get('total_tokens') or 0)/1000:.0f}K tok, "
                     f"{r.get('loop_count')} loop(s)")
        L.append("")

    L.append("| Target | Solved | Status | Loops | Wall | Tokens | Error |")
    L.append("|---|:--:|---|--:|--:|--:|---|")
    for r in sorted(res, key=lambda x: (not x.get("exploited"), x.get("name") or "")):
        err = (r.get("run_error") or "")[:38]
        L.append(
            f"| `{r.get('name')}` | {'YES' if r.get('exploited') else '—'} "
            f"| {r.get('final_status') or '?'} | {r.get('loop_count') or 0} "
            f"| {fmt_hms(r.get('wall_seconds'))} "
            f"| {(r.get('total_tokens') or 0)/1000:.0f}K | {err} |"
        )
    L.append("")
    return L, dict(n=len(res), solved=len(solved), err=len(errored), wall=wall, tok=toks)


def main():
    if len(sys.argv) < 2:
        print("usage: summarize_bench.py <output-dir>")
        return 2
    out = pathlib.Path(sys.argv[1])
    if not out.is_dir():
        print(f"no such directory: {out}")
        return 2

    L = [f"# Bench summary — `{out.name}`", ""]
    stats = {}
    for suite, label in (("ctf", "ctf"), ("cve", "cve")):
        block, st = suite_block(label, load(out, suite))
        L += block
        if st:
            stats[suite] = st

    # headline
    head = ["## Headline", ""]
    if "ctf" in stats:
        s = stats["ctf"]
        head.append(f"- **CTF Injection Bench: {s['solved']}/{s['n']}** "
                    f"({100*s['solved']/max(s['n'],1):.1f}%), black-box, n=1")
        if s["n"] != 21:
            head.append(f"  - NOTE: expected 21 targets, got {s['n']} — check the exclude list")
    if "cve" in stats:
        s = stats["cve"]
        head.append(f"- **CVE-Injection: {s['solved']}/{s['n']}** "
                    f"({100*s['solved']/max(s['n'],1):.1f}%), external grader")
        if s["n"] != 17:
            head.append(f"  - NOTE: expected 17 targets, got {s['n']}")
    if stats:
        tw = sum(v["wall"] for v in stats.values())
        tt = sum(v["tok"] for v in stats.values())
        te = sum(v["err"] for v in stats.values())
        head.append(f"- total: {fmt_hms(tw)}, {tt/1e6:.1f}M tokens"
                    + (f", **{te} infrastructure error(s)**" if te else ""))
    head.append("")
    L = L[:2] + head + L[2:]

    pocs = sorted(glob.glob(str(out / "poc" / "report_*.md")))
    L += ["## PoC reports", "", f"{len(pocs)} collected in `{out / 'poc'}`.", ""]
    if not pocs:
        L.append("None collected — check `logs/` if targets solved but no report appeared.")
        L.append("")

    L += ["## Before quoting any number", "", FORBIDDEN_NOTE, "",
          "Denominator is **21** for CTF (prepared_2 withdrawn) and **17** for CVE.",
          "State **n=1** explicitly; do not report mean±std from a single pass.", ""]

    text = "\n".join(L)
    (out / "SUMMARY.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
