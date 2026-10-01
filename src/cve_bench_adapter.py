"""
CVE-Bench adapter.

Converts a CVE-Bench challenge (eval.yml + metadata) into the internal injection
config consumed by the pipeline, for the **zero_day** variant (no vulnerability
disclosed → pipeline runs in black-box discovery mode).

Unlike CTF challenges, CVE-Bench is NOT flag-based: success is decided by an
evaluator inside the target container (`/evaluator/done.sh`), not by a regex.
This adapter therefore sets a never-matching success pattern and relies on the
external grader (see scripts/run_bench.py cve suite). It injects the task
objective into `exploitation_notes`, rewriting the internal docker hostnames
(`target:80`, `target:9091`) to the host-exposed ports created by `./run up`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


# Never-match pattern: CVE-Bench has no flag; grading is external via done.sh.
_NO_FLAG = r"(?!x)x"


def _rewrite_objective(prompt: str, *, host: str, web_port: int, proof_port: int) -> str:
    """Rewrite internal docker hostnames to host-exposed ports the agent can reach."""
    return (
        prompt
        .replace("target:80", f"{host}:{web_port}")
        .replace("target:9091", f"{host}:{proof_port}")
    )


def _host_url(value: str, *, host: str, web_port: int, proof_port: int) -> str:
    """Rewrite an internal docker URL to a host-reachable one and ensure a scheme."""
    s = _rewrite_objective(str(value), host=host, web_port=web_port, proof_port=proof_port)
    if s and not s.startswith(("http://", "https://")):
        s = "http://" + s
    return s


def load_cve_challenge(
    cve_id: str,
    challenges_dir: str | Path,
    *,
    variant: str = "zero_day",
    host: str = "localhost",
    web_port: int = 9090,
    proof_port: int = 9091,
) -> tuple[str, dict[str, Any], str]:
    """
    Load a CVE-Bench challenge and build the internal config.

    Returns: (cve_id, config, target_url)
    """
    base = Path(challenges_dir) / cve_id
    eval_path = base / "eval.yml"
    if not eval_path.is_file():
        raise FileNotFoundError(f"eval.yml not found for {cve_id}: {eval_path}")

    data = yaml.safe_load(eval_path.read_text(encoding="utf-8")) or {}
    variants = data.get("variants", {}) or {}
    chosen = variants.get(variant) or variants.get("zero_day") or {}
    objective = _rewrite_objective(
        str(chosen.get("prompt", "")),
        host=host, web_port=web_port, proof_port=proof_port,
    )
    meta = data.get("metadata", {}) or {}

    target_url = f"http://{host}:{web_port}"

    config: dict[str, Any] = {
        "cve_id": cve_id,
        "ctf_id": cve_id,
        "challenge_name": cve_id,
        "category": "cve-bench",
        # zero_day variant: the vulnerability is NOT disclosed → force black-box discovery.
        "vulnerability_type": "unknown",
        "title": cve_id,
        "description": str(chosen.get("prompt", ""))[:500],
        "target_url_path": "/",
        "http_method": "GET",
        "affected_parameters": [],
        # No flag in CVE-Bench; success is graded externally by /evaluator/done.sh.
        "success_regex_pattern": _NO_FLAG,
        "exploitation_notes": objective,
        "required_authentication": False,
        # Markers so the pipeline / runner know this is a CVE-Bench task.
        "cve_bench": True,
        "cve_bench_variant": variant,
        "cve_bench_metadata": meta,
    }

    # flatten the impact/proof metadata into the FLAT keys the Executor reads
    # (proof_fields + submit_proof). Without this the executor's proof_upload_url and
    # secret paths are empty, so submit_proof fails and the agent can never complete a
    # CVE-Bench impact even after a successful exploit.
    proof_raw = meta.get("proof_uploading_url") or meta.get("proof_upload_url") or "target:9091/upload"
    hosted = dict(host=host, web_port=web_port, proof_port=proof_port)
    config["proof_upload_url"] = _host_url(proof_raw, **hosted)            # agent → evaluator (host-reachable)
    config["internal_proof_upload_url"] = _host_url("target:9091/upload", **hosted)
    # Server-side callback targets: keep the value the *target* server must reach.
    if meta.get("outbound_service_url"):
        config["outbound_service_url"] = str(meta["outbound_service_url"])
    for key in ("secret_file_path", "secret_table_name", "remote_code_executable_path",
                "admin_username", "default_username", "default_password"):
        if meta.get(key) is not None:
            config[key] = meta[key]

    return cve_id, config, target_url
