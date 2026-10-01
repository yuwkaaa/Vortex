# VORTEX: Multi-Agent Web Injection Exploitation Framework

VORTEX is a multi-agent penetration-testing framework for web injection vulnerabilities. It uses a six-node LangGraph state machine (Infrastructure, Planner, Navigator, Executor, Dual-Loop Controller, PoC Generator) and gates every success verdict on an external grader, not the agent's own claim. We also use it to measure temporal contamination in LLM-agent security benchmarks.

## Key Results

| Benchmark | Targets | Solved | Rate |
|---|---|---|---|
| CVE-Injection Bench (2024) | 17 | 8 | 47.1% |
| 2026 CVE Bench (novel, post-training) | 10 | 0 | 0.0% |
| CTF Injection Bench (black-box) | 22 | 3 | 13.6% |

**Temporal gap:** 47.1% on 2024 CVEs vs. 0% on 2026 CVEs from the same vulnerability families, same harness, same backbone (DeepSeek V4 Flash). The 47 pp drop shows that training-data familiarity, not exploitation skill, drives most of the reported success.

## Project Structure

```
vortex-repo/
├── src/                  # Framework source code
│   ├── agents/           # LangGraph agent nodes (6 nodes)
│   ├── tools/            # Executor tool implementations
│   ├── knowledge/        # Injection family definitions
│   ├── graph.py          # State machine definition
│   ├── state.py          # Shared state schema
│   ├── memory.py         # Attempt history & context pruning
│   └── llm.py            # LLM provider abstraction
├── scripts/              # Benchmark runners & analysis
├── benchmarks/           # Benchmark datasets (self-contained)
│   ├── CTF_Injection_Bench/   # 22 CTF challenges + 10 CVE-2026 challenge configs
│   ├── cve_injection_bench_17/ # 17 CVE-2024 challenge configs + Docker
│   └── 2026_cve/              # 10 CVE-2026 Docker targets (plugins, DB, compose)
├── reports/              # Experimental results & metrics
├── main.py               # Entry point
├── requirements.txt
└── .env.example
```

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure LLM provider
cp .env.example .env
# Edit .env — set LLM_PROVIDER, API key, model name, and base URL.
# Example for DeepSeek:
#   LLM_PROVIDER=openrouter
#   OPENROUTER_API_KEY=sk-your-key
#   OPENROUTER_MODEL=deepseek-flash
#   OPENROUTER_BASE_URL=https://api.deepseek.com
```

## Reproducing Benchmarks

### Prerequisites

- Python 3.10+
- Docker (for CVE-Bench and CTF targets)
- An OpenAI-compatible LLM API key (DeepSeek V4 Flash used in paper)

All benchmark datasets are included in `benchmarks/`.

### Benchmark 1: CVE-Injection Bench 2024 (17 targets)

Tests the agent against 17 known 2024 CVEs with Docker-containerized vulnerable applications. Requires the [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench) harness for Docker target management and grading.

```bash
# Clone CVE-Bench harness (provides ./run up/down and evaluator)
git clone https://github.com/uiuc-kang-lab/cve-bench ../cve-bench

# Option A: Run via run_bench.py (uses cve_bench_adapter.py, zero-day mode)
export CVEBENCH_REPO=../cve-bench
python scripts/run_bench.py --suite cve --timeout 900

# Option B: Run via run_cvebench_injection.py (uses xlsx task sheet, one-day mode)
python scripts/run_cvebench_injection.py \
  --cve-bench-dir ../cve-bench \
  --llm-provider openrouter \
  --agent-timeout 900

# Run a single CVE target
python main.py \
  --cve-config benchmarks/cve_injection_bench_17/challenges/CVE-2024-2359/eval.yml \
  --target-url http://localhost:9090
```

**Challenge configs**: `benchmarks/cve_injection_bench_17/challenges/CVE-2024-*/eval.yml`
**Results**: `reports/cve2024_bench/`

### Benchmark 2: CTF Injection Bench (22 targets)

Tests the agent against 22 CTF web injection challenges in black-box mode (no vulnerability hints given to the agent).

```bash
# Run all 22 challenges (black-box mode)
CTF_BLACKBOX=1 python scripts/run_bench.py --suite ctf --timeout 900

# Filter by injection type
CTF_BLACKBOX=1 python scripts/run_bench.py --suite ctf --types sql --timeout 900

# Run a single challenge
python main.py \
  --challenge-json benchmarks/CTF_Injection_Bench/test/2025/UofTCTF/web/prepared_1/challenge.json
```

Each challenge directory contains a `challenge.json` with metadata and a Docker Compose setup for the target.

**Challenge configs**: `benchmarks/CTF_Injection_Bench/test/{2025,2026}/*/challenge.json`
**Results**: `reports/ctf_bench/`

### Benchmark 3: 2026 CVE Bench (10 novel targets)

Tests the agent against 10 CVEs disclosed after the LLM training cutoff. Same vulnerability families (SQL injection on WordPress plugins) as the 2024 bench, but not in training data — measures temporal contamination.

All Docker infrastructure is fully self-contained in `benchmarks/2026_cve/`: each CVE directory includes a standalone `compose.yml` (MariaDB + WordPress), `Dockerfile`, vulnerable WordPress plugin zip, pre-seeded `db.sql`, and `eval.yml`. No external dependencies required.

```bash
# 1. Bring up a target
cd benchmarks/2026_cve/challenges/CVE-2026-0926
docker compose up -d --build
cd ../../../..

# 2. Run the agent against it
python main.py \
  --challenge-json benchmarks/CTF_Injection_Bench/test/2026cve/CVE-2026-0926/challenge.json

# 3. Run all 10 CVE-2026 targets in batch
CTF_BLACKBOX=1 python scripts/run_bench.py --suite ctf --only 2026cve --timeout 900

# 4. Tear down
cd benchmarks/2026_cve/challenges/CVE-2026-0926 && docker compose down -v && cd ../../../..
```

**Docker targets**: `benchmarks/2026_cve/challenges/CVE-2026-*/` (compose.yml + Dockerfile + plugin + DB)
**Challenge configs**: `benchmarks/CTF_Injection_Bench/test/2026cve/CVE-2026-*/challenge.json`
**Results**: `reports/cve2026_bench/`

### Aggregating Results

```bash
# Generate summary statistics and charts from a benchmark run
python scripts/aggregate_metrics.py reports/bench/<suite>_<timestamp>/results.json

# Stratified analysis
python scripts/aggregate_stratified.py reports/bench/<suite>_<timestamp>/results.json
```

## Single-Target Usage

```bash
# Run against a live target with a known CVE config
python main.py --cve-config path/to/config.json --target-url http://target:port

# Run against a CTF challenge
python main.py --challenge-json path/to/challenge.json

# Run with a local source directory (Case A: has source code)
python main.py --target-path ./vulnerable-app --target-url http://localhost:8080
```

## License

MIT
