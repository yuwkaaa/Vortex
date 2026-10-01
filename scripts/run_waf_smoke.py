"""WAF smoke ablation: 5 classic-SQLi challenges x {no-WAF, CRS PL4}.

Fast-path is forced OFF so the no-WAF arm is a fair re-baseline (the 2026-05-22
100% run predates this and its fast-path state is unverified). Each run reuses
run_bench.run_one -> isolated `main.py --challenge-json X --state-out` subprocess,
so Docker up/down and metrics are handled exactly like the main CTF batch.
"""
from __future__ import annotations
import csv, json, os, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "scripts"))
import run_bench as RB  # noqa: E402

# Fair-comparison knobs (identical across both arms).
os.environ["CTF_DIRECT_SQL_FALLBACK"] = "0"   # hardcoded fast-path OFF
os.environ["EXECUTOR_MAX_TOOL_CALLS"] = "15"
os.environ["MAX_DUAL_LOOPS"] = "2"

PAIRS = [
    ("TSCCTF-2025-E4SY-SQLI",       "Easy",        "CTF_Injection_Bench/test/2025/TSCCTF/web/E4sy_SQLi/challenge.json"),
    ("DICECTF-2024-FUNNYLOGIN",     "Easy-Medium", "CTF_Injection_Bench/test/2024/DiceCTF/web/funnylogin/challenge.json"),
    ("VUWCTF-2025-FISHSITE",        "Easy-Medium", "CTF_Injection_Bench/test/2025/VuwCTF/web/fishsite/challenge.json"),
    ("UOFTCTF-2025-PREPARED-1",     "Medium",      "CTF_Injection_Bench/test/2025/UofTCTF/web/prepared_1/challenge.json"),
    ("INSOMNIHACK-2024-INSOBANK",   "Hard",        "CTF_Injection_Bench/test/2024/insomnihack/web/InsoBank/challenge.json"),
]

out_dir = ROOT / "reports" / "waf_smoke"
states = out_dir / "states"
states.mkdir(parents=True, exist_ok=True)
TIMEOUT = int(os.environ.get("WAF_SMOKE_TIMEOUT", "900"))
# WAF_SMOKE_ARMS lets a focused re-run skip the known no-WAF baseline (saves tokens).
ARMS = [a.strip() for a in os.environ.get("WAF_SMOKE_ARMS", "noWAF,PL4").split(",") if a.strip()]

rows = []
for cid, diff, base in PAIRS:
    base_cj = (ROOT / base).resolve()
    pl4_cj = base_cj.parent / ".waf_variants" / "PL4" / "challenge.json"
    for arm, cj in (("noWAF", base_cj), ("PL4", pl4_cj)):
        if arm not in ARMS:
            continue
        tag = f"{cid} [{arm}]"
        print(f"\n===== RUN {tag} =====", flush=True)
        if not cj.exists():
            print(f"  MISSING {cj}", flush=True)
            rows.append({"cid": cid, "difficulty": diff, "arm": arm, "exploited": "", "error": "missing_challenge_json"})
            continue
        t0 = time.monotonic()
        r = RB.run_one(cj, "sql", states, timeout=TIMEOUT)
        r.update({"cid": cid, "difficulty": diff, "arm": arm})
        rows.append(r)
        print(f"  exploited={r.get('exploited')} status={r.get('final_status')} "
              f"tokens={r.get('total_tokens')} wall={r.get('wall_seconds')}s err={r.get('run_error')}",
              flush=True)

# write outputs (WAF_SMOKE_TAG keeps a focused re-run from clobbering the prior baseline)
TAG = os.environ.get("WAF_SMOKE_TAG", "").strip()
suffix = f"_{TAG}" if TAG else ""
json.dump(rows, open(out_dir / f"results{suffix}.json", "w", encoding="utf-8"), indent=1, default=str)
cols = ["cid", "difficulty", "arm", "exploited", "final_status", "loop_count",
        "total_tokens", "llm_calls", "wall_seconds", "run_error", "challenge_json"]
with open(out_dir / f"results{suffix}.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)

# quick delta summary
print("\n" + "=" * 55 + "\nSUMMARY (no-WAF -> PL4)\n" + "=" * 55)
bycid = {}
for r in rows:
    bycid.setdefault(r["cid"], {})[r["arm"]] = r.get("exploited")
nwaf = sum(1 for c in bycid.values() if c.get("noWAF") is True)
pl4 = sum(1 for c in bycid.values() if c.get("PL4") is True)
for cid, a in bycid.items():
    print(f"  {cid:32s} noWAF={a.get('noWAF')}  PL4={a.get('PL4')}")
print(f"\n  no-WAF solved: {nwaf}/{len(bycid)}   PL4 solved: {pl4}/{len(bycid)}")
print(f"  WROTE {out_dir/('results'+suffix+'.csv')}")
