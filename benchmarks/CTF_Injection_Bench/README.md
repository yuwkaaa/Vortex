# CTF Injection Bench

A locally runnable CTF injection benchmark built from `sajjadium/ctf-archives` challenges.
Each challenge lives under `test/<year>/<event>/<category>/<challenge>/`, with its own
`challenge.json`, `docker-compose.yaml`, and embedded `source/` (so this folder needs no
external `ctf-archives` checkout to run).

**22 real-application targets** (8 from 2025, 14 from 2026) -- see the root
`README.md` ("CTF Injection Bench — restored evaluation set (22 targets)") for
the audit methodology and exclusion criteria. Each target's `docker-compose.yaml`
builds and serves the original challenge application, not a generated stub.

## Layout

```text
CTF_Injection_Bench/
  README.md
  metadata/ctf_injection_research_2024_2025.csv     # the 8 shipped 2025 targets only (2026 has no CSV)
  metadata/reconstruction_manifest.csv               # ditto
  metadata/runtime_manifest.json
  tools/generate_benchmark_runtime.py             # generates the synthetic-stub app (kept for transparency)
  tools/reconstruct_to_benchmark_runnable.py       # the real-source restore helper (see root README §5)
  test/2025/<event>/<category>/<challenge>/{challenge.json,docker-compose.yaml,source/}
  test/2026/<event>/<challenge>/{challenge.json,docker-compose.yaml,source/}
  ordered/<difficulty>/<ordered_challenge>/README.md        # 2025 targets only, by difficulty
  by_injection_type/<injection_family>/<challenge>/README.md # 2025 targets only, by family
```

`ordered/` and `by_injection_type/` are trimmed to exactly what exists under `test/`.

## Execution status

- Real-application, capability-measurable targets: **22** (8 from 2025, 14 from 2026)

Every shipped challenge has:

```text
challenge.json
docker-compose.yaml
source/
```

## Injection families (the 22 shipped targets)

- SQL Injection: 10
- Command Injection: 6
- Template Injection: 3
- SSTI: 2
- XXE: 1

## Notes

- `challenge.json` contains a flag for local benchmark evaluation; where upstream
  did not provide a usable one, it was normalized to a test flag matching the
  framework's success regex (root `README.md` §5.2).
- Setup commands are relative and intentionally do not include machine-specific
  absolute paths.
- The original `ctf-archives/` checkout is intentionally excluded by the parent
  `.gitignore`; only this curated benchmark folder is meant to be committed.
