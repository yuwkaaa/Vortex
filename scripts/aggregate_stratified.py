#!/usr/bin/env python3
"""Aggregate a stratified black-box run into a per-year (and per-family) solve-rate table.

Usage: python scripts/aggregate_stratified.py reports/bench/stratified_<stamp>/manifest.tsv
Reads each year's results.json (listed in the manifest), computes solved/total per year and
per injection family, and (for REPEATS>1) mean +/- std across repeats. Writes
stratified_summary.md next to the manifest. Reports YEAR as the contamination axis (2026
post-cutoff = cleanest headline; 2024 = contamination cohort) and keeps XSS out of scope.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def _load(results_json: str) -> list[dict]:
    try:
        d = json.loads(Path(results_json).read_text(encoding="utf-8"))
    except Exception:
        return []
    return d.get("results", d) if isinstance(d, dict) else (d or [])


def main(manifest_path: str) -> int:
    manifest = Path(manifest_path)
    root = Path(__file__).resolve().parent.parent
    rows = [ln.split("\t") for ln in manifest.read_text().splitlines() if ln.strip()]
    rows = [r for r in rows if r and r[0] != "year"]  # drop header

    # year -> list of (solved, total) per repeat ; year -> family -> [solved, total]
    per_repeat: dict[str, list[tuple[int, int]]] = defaultdict(list)
    fam_tally: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    solved_names: dict[str, list[str]] = defaultdict(list)

    for year, _rep, rj in ((r + ["", "", ""])[:3] for r in rows):
        if not rj:
            continue
        res = _load(rj if Path(rj).is_absolute() else str(root / rj))
        s = sum(1 for c in res if c.get("exploited"))
        per_repeat[year].append((s, len(res)))
        for c in res:
            fam = str(c.get("family") or c.get("vulnerability_type") or "unknown")
            fam_tally[year][fam][1] += 1
            if c.get("exploited"):
                fam_tally[year][fam][0] += 1
                solved_names[year].append(str(c.get("name")))

    lines = ["# Stratified black-box benchmark — honest autonomy (CTF_BLACKBOX, XSS excluded)\n"]
    lines.append("| Year | Solved / Total | Rate | n(repeats) | mean±std |")
    lines.append("|------|----------------|------|-----------|----------|")
    grand_s = grand_t = 0
    for year in sorted(per_repeat, reverse=True):  # 2026 first
        reps = per_repeat[year]
        tot = reps[0][1] if reps else 0
        rates = [s / t for s, t in reps if t]
        s0 = reps[0][0] if reps else 0
        grand_s += sum(s for s, _ in reps)
        grand_t += sum(t for _, t in reps)
        mstd = ("%.1f%% ± %.1f" % (100 * statistics.mean(rates),
                                   100 * (statistics.pstdev(rates) if len(rates) > 1 else 0.0))) if rates else "-"
        tag = " (cleanest / headline)" if year == "2026" else (" (contamination cohort)" if year == "2024" else "")
        lines.append(f"| **{year}**{tag} | {s0} / {tot} | {100*s0/tot:.1f}% | {len(reps)} | {mstd} |")
    lines.append(f"| **ALL** | {grand_s} / {grand_t} | {100*grand_s/max(grand_t,1):.1f}% | | |")

    lines.append("\n## By family (per year)\n")
    for year in sorted(fam_tally, reverse=True):
        lines.append(f"### {year}")
        for fam, (s, t) in sorted(fam_tally[year].items()):
            lines.append(f"- {fam}: {s}/{t} ({100*s/max(t,1):.0f}%)")
        if solved_names[year]:
            lines.append(f"- ✅ solved: {sorted(set(solved_names[year]))}")
        lines.append("")

    out = manifest.parent / "stratified_summary.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\n[aggregate_stratified] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "reports/bench/stratified/manifest.tsv"))
