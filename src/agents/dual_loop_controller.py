"""Dual-Loop Controller — Strategist reflection agent.

Deterministic guards (unchanged, regression-safe):
  * success + no error   -> poc_generator
  * loop_count >= max     -> fail
  * terminal failure       -> fail   (status=="failed" or missing target_url)

Ambiguous branch (what to change after a non-terminal failure) is where the old
if/else-on-status router lost: it could not tell "fix the payload" from "the whole
approach is wrong", and just cycled injection variants. This module replaces that
single branch with ONE LLM reflection call that diagnoses *why* the loop failed (AXE
failure taxonomy), decides the route, and emits a concrete next-step directive
(`reflection_guidance`) that the next Executor/Planner prompt acts on.

The reflection is bounded to one LLM call, falls back to the legacy string routing
on any error, and can be disabled with DUAL_LOOP_REFLECT=0 for a deterministic,
no-LLM-call run of the ambiguous branch (the current test suite never exercises
that branch — its one dual-loop test hits a deterministic guard instead — so this
flag is unused by tests today, but is there for offline/deterministic runs).
"""
from __future__ import annotations

import json
import os
from typing import Any, Literal

from src.state import PentestState
from src.logging_utils import VerboseLogger
from src.memory import build_attempt_context


DualLoopDecision = Literal["poc_generator", "executor", "planner", "fail"]

# AXE failure taxonomy (arXiv:2602.14345, Table of failure attribution). Kept as the
# closed label set the reflector must choose from so the cause distribution is
# comparable to AXE's on our own benchmark.
CAUSE_LABELS = {
    "vuln_misunderstanding",  # wrong threat model / misread the vuln nature (AXE 60%)
    "wrong_surface",          # wrong endpoint/param/entrypoint targeted (AXE 44%)
    "precondition",           # missing auth / CSRF / config setup (AXE 44%)
    "payload",                # right target, malformed/ineffective payload (AXE 24%)
    "loop_inefficiency",      # repeating ineffective actions w/o adapting (AXE 20%)
}

REFLECT_SYSTEM_PROMPT = """You are the Strategist of an autonomous web-injection pentest agent.
An exploitation loop just FAILED. Diagnose WHY, then decide the single best next move.

Choose exactly one CAUSE from this closed set:
- vuln_misunderstanding : the agent misread the vulnerability / wrong threat model.
- wrong_surface         : agent attacked the wrong endpoint/parameter/entrypoint.
- precondition          : a required step was skipped (login/session, CSRF token, setup).
- payload               : right target & class, but the payload was malformed/ineffective.
- loop_inefficiency     : agent repeated near-identical ineffective actions without adapting.

Choose ROUTE:
- "executor" : the strategy is sound; retry with a concrete fix (payload/surface/precondition tweak).
- "planner"  : the whole approach is wrong; the strategy must be redesigned.

Return ONLY minified JSON:
{"cause":"<label>","route":"executor|planner","guidance":"<=80 words, imperative, specific: which endpoint/param/technique to try next and what to STOP doing>"}
No prose, no code fence."""


# Opt-in (ENABLE_CHAIN_PLANNING / ENABLE_CONFIG_A_PLUS): let the Strategist reason about
# MULTI-STAGE chains rather than cycling single-primitive variants. This is a generic planning
# principle appended to the Strategist's role — it is not a per-target vulnerability hint; the
# reflector must still decide whether and how a chain applies to THIS target from the evidence.
CHAIN_REASONING_CLAUSE = """

CHAINING: an injection primitive often needs a SECOND stage to reach the objective. If direct
exploitation of the identified class did not reach the goal, weigh whether the primitive FEEDS a
downstream sink, and if so set cause=vuln_misunderstanding with guidance naming the chain — e.g.
input you control is stored/returned then RENDERED (template injection at the render step); a value
crossing from one query/table/DB into another query (injection lands at the second sink); filtered
command output (encode it, e.g. base64/hex, to defeat a response filter); a low-priv foothold that
must PIVOT to the objective via an authenticated-only route."""


def _reflect_system_prompt() -> str:
    """Strategist prompt, plus the opt-in chaining principle when enabled (default: base only)."""
    if (os.getenv("ENABLE_CHAIN_PLANNING", "0") == "1"
            or os.getenv("ENABLE_CONFIG_A_PLUS", "0") == "1"):
        return REFLECT_SYSTEM_PROMPT + CHAIN_REASONING_CLAUSE
    return REFLECT_SYSTEM_PROMPT


def _legacy_route(status: str) -> tuple[DualLoopDecision, str]:
    """Original string-based routing — the fallback when reflection is off/fails."""
    if status == "needs_inner_loop":
        return "executor", "payload syntax/implementation error — retry with a fixed payload"
    if status == "needs_outer_loop":
        return "planner", "strategy not viable — redesign the approach"
    return "planner", "unexpected status — returning to Planner for review"


def _reflect(state: PentestState, status: str, last_error: str,
             logger: VerboseLogger) -> tuple[DualLoopDecision, str, str] | None:
    """One bounded LLM reflection. Returns (route, cause, guidance) or None on failure."""
    from src.llm import get_llm  # local import: keeps controller importable without llm deps

    attempt_history = list(state.get("attempt_history") or [])
    attempt_block = build_attempt_context(attempt_history)
    plan = (state.get("plan") or "")[:800]
    recon = (state.get("recon") or "")[:600]
    endpoints = state.get("discovered_endpoints") or []
    ep_lines = "\n".join(f"  - [{e.get('status')}] {e.get('path')}" for e in endpoints[:30])

    human = "\n".join(filter(None, [
        f"STATUS: {status}",
        f"LAST ERROR: {last_error}" if last_error else "",
        f"\n{attempt_block}" if attempt_block else "",
        f"\nDISCOVERED ENDPOINTS:\n{ep_lines}" if ep_lines else "",
        f"\nPLAN (excerpt):\n{plan}" if plan else "",
        f"\nRECON (excerpt):\n{recon}" if recon else "",
        "\nDiagnose the failure and return the JSON directive.",
    ]))

    from langchain_core.messages import HumanMessage, SystemMessage
    llm = get_llm(max_tokens=int(os.getenv("REFLECT_MAX_TOKENS", "400")))
    raw = llm.invoke([
        SystemMessage(content=_reflect_system_prompt()),
        HumanMessage(content=human),
    ]).content or ""

    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON in reflection output: {raw[:200]!r}")
    data = json.loads(text[start:end + 1])

    route = data.get("route", "").strip().lower()
    if route not in ("executor", "planner"):
        raise ValueError(f"bad route: {route!r}")
    cause = data.get("cause", "").strip().lower()
    if cause not in CAUSE_LABELS:
        cause = "loop_inefficiency"  # safe default; still a valid taxonomy label
    guidance = " ".join((data.get("guidance") or "").split())[:600]
    if not guidance:
        raise ValueError("empty guidance")
    return route, cause, guidance  # type: ignore[return-value]


def dual_loop_controller_node(state: PentestState) -> dict[str, Any]:
    logger = VerboseLogger()
    logger.log_node_start("dual_loop_controller")

    status = state.get("status", "init")
    last_error = (state.get("last_error") or "").strip()
    loop_count = int(state.get("loop_count", 0))
    max_loop_count = int(os.getenv("DUAL_LOOP_MAX_COUNT", "3"))

    logger.log_thought(
        f"Analyzing exploitation status. status={status}, loop_count={loop_count}, "
        f"last_error={last_error or 'None'}."
    )

    cause = ""
    guidance = ""

    # --- deterministic guards (unchanged) ---
    if status == "exploited" and not last_error:
        decision: DualLoopDecision = "poc_generator"
        logger.log_observation({"decision": "success", "reason": "Exploitation succeeded"})

    elif loop_count >= max_loop_count:
        decision = "fail"
        logger.log_observation({"decision": "failure",
                                "reason": f"Max loop count ({max_loop_count}) exceeded"})

    elif status == "failed" or last_error == "missing target_url":
        decision = "fail"
        logger.log_observation({"decision": "failure",
                                "reason": "Terminal failure; no usable target"})

    else:
        # --- ambiguous branch: reflect instead of string-matching ---
        reflect_on = os.getenv("DUAL_LOOP_REFLECT", "1") != "0"
        result = None
        if reflect_on:
            try:
                result = _reflect(state, status, last_error, logger)
            except Exception as exc:  # noqa: BLE001 — any failure -> safe legacy path
                logger.log_observation({"reflection_error": str(exc), "fallback": "legacy_routing"})
        if result is not None:
            decision, cause, guidance = result
            logger.log_observation({"decision": "reflected", "cause": cause,
                                    "route": decision, "guidance": guidance})
            logger.log_thought(f"[reflect] cause={cause} route={decision} :: {guidance}")
        else:
            decision, reason = _legacy_route(status)
            guidance = reason  # still feed the (weaker) directive forward
            logger.log_observation({"decision": "legacy", "route": decision, "reason": reason})

    logs = list(state["execution_logs"])
    logs.append(
        f"[dual-loop] decision={decision} loop_count={loop_count} status={status}"
        + (f" cause={cause}" if cause else "")
    )

    verbose_logs = state.get("verbose_logs", [])
    verbose_logs.append(logger.get_logs())
    logger.log_state_update({"decision": decision, "loop_count": loop_count, "next_node": decision})
    print(logger.get_logs())

    new_loop_count = loop_count + (1 if decision in ("executor", "planner") else 0)

    patch: dict[str, Any] = {
        "execution_logs": logs,
        "verbose_logs": verbose_logs,
        "loop_count": new_loop_count,
        "dual_loop_decision": decision,
    }
    # Only publish guidance when routing back for another attempt.
    if decision in ("executor", "planner"):
        patch["reflection_guidance"] = guidance
        patch["reflection_cause"] = cause
    return patch
