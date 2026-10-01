from __future__ import annotations

from typing import Any, Literal, NotRequired, Optional, TypedDict


AgentStatus = Literal[
    "init",
    "sandbox_ready",
    "planned",
    "recon_done",
    "executed",
    "needs_inner_loop",
    "needs_outer_loop",
    "exploited",
    "failed",
    "reported",
]


class AttemptRecord(TypedDict):
    """Single exploitation attempt recorded by the Executor (written by Python, read by LLM)."""
    loop: int
    loop_type: str          # "INITIAL" | "INNER LOOP" | "OUTER LOOP"
    injection_type: str     # e.g. "union_select", "error_based", "shell"
    payloads_tried: list[str]
    error_type: str         # canonical label from classify_error()
    response_snippet: str   # first 200 chars of last HTTP response body
    verdict: str            # "SUCCESS" | "FAILED: <reason>"


class PentestState(TypedDict):
    # Inputs
    cve: str
    cve_config: NotRequired[dict[str, Any]]  # CVE metadata from JSON (CWE, CVSS, vulnerability type, etc.)

    target_path: NotRequired[Optional[str]]
    target_url: NotRequired[Optional[str]]

    # Infrastructure outputs
    sandbox_meta: NotRequired[dict[str, Any]]

    # Planner / Navigator / Executor outputs
    plan: NotRequired[str]
    recon: NotRequired[str]
    poc: NotRequired[str]

    # Loop memory — written by Python, injected verbatim into LLM prompts
    attempt_history: NotRequired[list[AttemptRecord]]

    # Loop + logs
    execution_logs: list[str]
    verbose_logs: NotRequired[list[str]]  # For detailed thought/action/observation output
    last_error: NotRequired[str]
    status: AgentStatus
    loop_count: int
    dual_loop_decision: NotRequired[str]  # routing-only key (graph reads this)

    # Strategist reflection: written by the Dual-Loop Controller after a failed
    # loop, read verbatim by the next Executor/Planner prompt. `guidance` is the
    # concrete next-step directive; `cause` is the AXE-taxonomy failure label kept for
    # analysis (distribution of causes ≈ AXE's failure breakdown on our own bench).
    reflection_guidance: NotRequired[str]
    reflection_cause: NotRequired[str]

    # Live session carried across dual-loop iterations.
    # Cookie name→value map; restored into the Executor's requests.Session at the
    # start of each invocation so login/register state survives inner/outer loops.
    session_cookies: NotRequired[dict[str, str]]

    # Black-box discovery fields
    discovery_mode: NotRequired[bool]           # True when running without a known vuln type
    discovered_params: NotRequired[list[str]]   # Params found by param_discoverer
    discovered_endpoints: NotRequired[list[dict[str, Any]]]  # Hidden paths from content_discovery (ffuf)
    detected_stack: NotRequired[str]            # Tech stack label from stack_fingerprinter
    injection_hints: NotRequired[list[tuple[str, float]]]  # [(vuln_type, confidence), ...]
    # how to deliver a payload (body_format: query|form|json), params/endpoints
    # that live only in JS. Written by Navigator, read by the Executor prompt.
    input_delivery: NotRequired[dict[str, Any]]

    # Demo / future flags
    demo_mode: NotRequired[bool]

    # Final output
    run_metrics: NotRequired[dict[str, Any]]
    metrics_path: NotRequired[str]
    report_markdown: NotRequired[str]
    report_path: NotRequired[str]


def initial_state(
    *,
    cve: str = "BLACKBOX",
    cve_config: Optional[dict[str, Any]] = None,
    target_path: Optional[str] = None,
    target_url: Optional[str] = None,
    blackbox: bool = False,
) -> PentestState:
    """
    Build the initial pipeline state.

    CVE mode  : pass cve + cve_config (vulnerability_type must be set).
    Black-box : pass target_url only, or set blackbox=True explicitly.
                cve defaults to "BLACKBOX", vulnerability_type to "unknown".
    """
    if not target_path and not target_url:
        raise ValueError("Either target_path or target_url must be provided.")

    # Auto-detect black-box: no cve_config or missing/unknown vulnerability_type
    cfg = cve_config or {}
    vt = cfg.get("vulnerability_type", "")
    is_blackbox = blackbox or cve == "BLACKBOX" or not vt or vt.lower() == "unknown"

    if is_blackbox:
        cfg = {**cfg, "vulnerability_type": "unknown"}

    return {
        "cve": cve,
        "cve_config": cfg,
        "target_path": target_path,
        "target_url": target_url,
        "discovery_mode": is_blackbox,
        "attempt_history": [],
        "execution_logs": [],
        "verbose_logs": [],
        "status": "init",
        "loop_count": 0,
    }
