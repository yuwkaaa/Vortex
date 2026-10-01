from __future__ import annotations

import json
import os
try:
    import resource  # Unix-only; absent on Windows (project targets Linux/WSL).
except ImportError:
    resource = None
import shutil
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator


_CURRENT_NODE: ContextVar[str] = ContextVar("current_node", default="unknown")
_RUN: dict[str, Any] | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def metrics_enabled() -> bool:
    return os.getenv("RUN_METRICS", "1") != "0"


def start_run() -> None:
    global _RUN
    if not metrics_enabled():
        _RUN = None
        return
    _RUN = {
        "run_id": uuid.uuid4().hex,
        "started_at": _now_iso(),
        "finished_at": None,
        "duration_seconds": None,
        "nodes": [],
        "llm": {
            "calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "missing_usage_count": 0,
            "by_node": {},
            "calls_detail": [],
        },
        "cleanup": {},
        "resources": {"start": _resource_snapshot()},
        "warnings": [],
        "_start_monotonic": time.monotonic(),
    }


def finish_run(status: str) -> dict[str, Any]:
    if _RUN is None:
        return {}
    _RUN["finished_at"] = _now_iso()
    _RUN["status"] = status
    _RUN["duration_seconds"] = round(time.monotonic() - _RUN["_start_monotonic"], 3)
    _RUN.setdefault("resources", {})["end"] = _resource_snapshot()
    return snapshot()


def _current_rss_mb() -> float | None:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return round(int(parts[1]) / 1024, 3)
    except OSError:
        return None
    return None


def _resource_snapshot() -> dict[str, Any]:
    max_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource is not None else None
    disk = shutil.disk_usage(os.getcwd())
    # Linux reports ru_maxrss in KiB; macOS reports bytes. This project runs on Linux
    # in the target environment, but keep the value labeled by unit for clarity.
    return {
        "timestamp": _now_iso(),
        "cwd": os.getcwd(),
        "process_rss_mb": _current_rss_mb(),
        "process_max_rss_kb": max_rss_kb,
        "disk_total_gb": round(disk.total / (1024**3), 3),
        "disk_used_gb": round(disk.used / (1024**3), 3),
        "disk_free_gb": round(disk.free / (1024**3), 3),
    }


def snapshot() -> dict[str, Any]:
    if _RUN is None:
        return {}
    data = deepcopy(_RUN)
    data.pop("_start_monotonic", None)
    return data


@contextmanager
def node_context(name: str) -> Iterator[None]:
    token = _CURRENT_NODE.set(name)
    try:
        yield
    finally:
        _CURRENT_NODE.reset(token)


def timed_node(name: str, fn: Callable[[Any], dict[str, Any]]) -> Callable[[Any], dict[str, Any]]:
    def wrapped(state: Any) -> dict[str, Any]:
        if _RUN is None:
            return fn(state)
        start = time.monotonic()
        status = "ok"
        error = None
        with node_context(name):
            try:
                return fn(state)
            except Exception as exc:
                status = "error"
                error = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                _RUN["nodes"].append(
                    {
                        "node": name,
                        "status": status,
                        "duration_seconds": round(time.monotonic() - start, 3),
                        "error": error,
                    }
                )

    return wrapped


def _extract_token_usage(response: Any) -> dict[str, int] | None:
    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        input_tokens = usage.get("input_tokens") or usage.get("prompt_tokens") or 0
        output_tokens = usage.get("output_tokens") or usage.get("completion_tokens") or 0
        total_tokens = usage.get("total_tokens") or input_tokens + output_tokens
        return {
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "total_tokens": int(total_tokens or 0),
        }

    response_metadata = getattr(response, "response_metadata", None)
    if isinstance(response_metadata, dict):
        token_usage = response_metadata.get("token_usage") or response_metadata.get("usage")
        if isinstance(token_usage, dict):
            input_tokens = (
                token_usage.get("prompt_tokens")
                or token_usage.get("input_tokens")
                or token_usage.get("promptTokenCount")
                or 0
            )
            output_tokens = (
                token_usage.get("completion_tokens")
                or token_usage.get("output_tokens")
                or token_usage.get("candidatesTokenCount")
                or 0
            )
            total_tokens = (
                token_usage.get("total_tokens")
                or token_usage.get("totalTokenCount")
                or input_tokens + output_tokens
            )
            return {
                "input_tokens": int(input_tokens or 0),
                "output_tokens": int(output_tokens or 0),
                "total_tokens": int(total_tokens or 0),
            }

    return None


def record_llm_call(
    *,
    provider: str,
    model: str,
    elapsed_seconds: float,
    response: Any | None = None,
    error: BaseException | None = None,
) -> None:
    if _RUN is None:
        return

    node = _CURRENT_NODE.get()
    llm = _RUN["llm"]
    llm["calls"] += 1
    if error is None:
        llm["successful_calls"] += 1
    else:
        llm["failed_calls"] += 1

    usage = _extract_token_usage(response) if response is not None else None
    if usage is None:
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        llm["missing_usage_count"] += 1

    for key in ("input_tokens", "output_tokens", "total_tokens"):
        llm[key] += usage[key]

    by_node = llm["by_node"].setdefault(
        node,
        {
            "calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "duration_seconds": 0.0,
        },
    )
    by_node["calls"] += 1
    by_node["successful_calls"] += 1 if error is None else 0
    by_node["failed_calls"] += 1 if error is not None else 0
    by_node["duration_seconds"] = round(by_node["duration_seconds"] + elapsed_seconds, 3)
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        by_node[key] += usage[key]

    llm["calls_detail"].append(
        {
            "node": node,
            "provider": provider,
            "model": model,
            "duration_seconds": round(elapsed_seconds, 3),
            "input_tokens": usage["input_tokens"],
            "output_tokens": usage["output_tokens"],
            "total_tokens": usage["total_tokens"],
            "usage_available": response is not None and _extract_token_usage(response) is not None,
            "error": f"{type(error).__name__}: {error}" if error else None,
        }
    )


def record_cleanup(*, duration_seconds: float, messages: list[str]) -> None:
    if _RUN is None:
        return
    _RUN["cleanup"] = {
        "duration_seconds": round(duration_seconds, 3),
        "messages": messages,
        "docker_cache_pruned": os.getenv("CLEAN_DOCKER_CACHE", "0") == "1",
        "docker_system_pruned": os.getenv("CLEAN_DOCKER_SYSTEM", "0") == "1",
    }


def write_metrics(out_dir: str = "reports") -> str | None:
    data = snapshot()
    if not data:
        return None
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = Path(out_dir) / f"metrics_{ts}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def render_markdown_summary(data: dict[str, Any] | None = None) -> str:
    metrics = data or snapshot()
    if not metrics:
        return "\n## Run Metrics\n\nMetrics disabled with `RUN_METRICS=0`.\n"
    llm = metrics.get("llm", {})
    node_rows = "\n".join(
        f"| {item.get('node')} | {item.get('status')} | {item.get('duration_seconds')} | {item.get('error') or ''} |"
        for item in metrics.get("nodes", [])
    ) or "| N/A | N/A | N/A | N/A |"
    by_node = llm.get("by_node", {})
    llm_rows = "\n".join(
        f"| {node} | {values.get('calls', 0)} | {values.get('input_tokens', 0)} | "
        f"{values.get('output_tokens', 0)} | {values.get('total_tokens', 0)} | {values.get('duration_seconds', 0)} |"
        for node, values in sorted(by_node.items())
    ) or "| N/A | 0 | 0 | 0 | 0 | 0 |"
    cleanup = metrics.get("cleanup", {})
    resources = metrics.get("resources", {})
    resource_end = resources.get("end") or resources.get("start") or {}
    cleanup_note = "not recorded"
    if cleanup:
        cache_state = "pruned" if cleanup.get("docker_cache_pruned") else "kept"
        cleanup_note = f"{cleanup.get('duration_seconds')}s; Docker build cache {cache_state}"

    return f"""
## Run Metrics

| Field | Value |
|-------|-------|
| Run ID | `{metrics.get('run_id', 'N/A')}` |
| Started At | {metrics.get('started_at', 'N/A')} |
| Finished At | {metrics.get('finished_at', 'N/A')} |
| Total Duration Seconds | {metrics.get('duration_seconds', 'N/A')} |
| LLM Calls | {llm.get('calls', 0)} |
| LLM Successful Calls | {llm.get('successful_calls', 0)} |
| LLM Failed Calls | {llm.get('failed_calls', 0)} |
| Input Tokens | {llm.get('input_tokens', 0)} |
| Output Tokens | {llm.get('output_tokens', 0)} |
| Total Tokens | {llm.get('total_tokens', 0)} |
| Missing Token Usage Calls | {llm.get('missing_usage_count', 0)} |
| Process RSS MB At End | {resource_end.get('process_rss_mb', 'N/A')} |
| Process Max RSS KB | {resource_end.get('process_max_rss_kb', 'N/A')} |
| Disk Free GB At End | {resource_end.get('disk_free_gb', 'N/A')} |
| Cleanup | {cleanup_note} |

### Node Timing

| Node | Status | Duration Seconds | Error |
|------|--------|------------------|-------|
{node_rows}

### LLM Usage By Node

| Node | Calls | Input Tokens | Output Tokens | Total Tokens | LLM Duration Seconds |
|------|-------|--------------|---------------|--------------|----------------------|
{llm_rows}
"""


def append_metrics_to_report(report_path: str, metrics_path: str | None = None) -> None:
    data = snapshot()
    if not data:
        return
    extra = render_markdown_summary(data)
    if metrics_path:
        extra += f"\nFull metrics JSON: `{metrics_path}`\n"
    with open(report_path, "a", encoding="utf-8") as f:
        f.write("\n---\n")
        f.write(extra)
