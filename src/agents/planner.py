"""Planner Agent - Analyzes CVE and creates exploitation plan for injection vulnerabilities."""
from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm import get_llm
from src.memory import build_attempt_context
from src.state import PentestState
from src.logging_utils import VerboseLogger
from src.knowledge import format_kb_context
from src.tools.cve_validator import validate_cve_config, format_validation_result


PLANNER_SYSTEM_PROMPT = """You are a penetration testing planner specialized in injection vulnerabilities (SQL, Command, LDAP, XPath, Template Injection, etc.).

Your role is to analyze CVE details and create a detailed, actionable exploitation plan.

Given a CVE configuration with vulnerability metadata, you must:
1. Identify the vulnerability type and attack surface
2. Extract key parameters (target URL path, HTTP method, affected parameters, payload template)
3. Determine entry points and injection sinks
4. Propose a step-by-step exploitation strategy
5. List expected outcomes and success indicators

Output your plan as detailed markdown with clear sections:
- Vulnerability Summary
- Attack Surface Analysis
- Exploitation Steps
- Expected Outcomes
- Success Indicators
- Fallback Strategies (in case main approach fails)

Keep the plan concise, focusing on practical exploitation steps."""


def planner_node(state: PentestState) -> dict[str, Any]:
    """
    Planner Agent: Analyze CVE and produce detailed exploitation plan for injection attacks.

    Works in both cases:
    - Case A (--target-path): target_url is already populated by the Infra agent.
    - Case B (--target-url):  target_url is user-supplied.
    """
    llm = get_llm(max_tokens=int(os.getenv("PLANNER_MAX_TOKENS", "1200")))
    logger = VerboseLogger()
    
    logger.log_node_start("planner")
    
    cve_config = state.get("cve_config", {})
    target_url = state.get("target_url") or "(missing)"
    cve_id = state.get("cve", "UNKNOWN")
    attempt_history: list = list(state.get("attempt_history") or [])

    vulnerability_type = cve_config.get("vulnerability_type", "Unknown Injection")
    is_replanning = len(attempt_history) > 0

    # Validate CVE config and surface issues early
    validation = validate_cve_config(cve_config)
    logger.log_observation({"cve_config_validation": format_validation_result(validation)})
    if not validation["valid"]:
        logger.log_thought(f"CVE config has errors: {validation['errors']}")

    logger.log_thought(
        f"{'[OUTER LOOP] Replanning' if is_replanning else 'Analyzing'} {cve_id} ({vulnerability_type}). "
        f"Target: {target_url}. "
        f"{'Prior attempts: ' + str(len(attempt_history)) + '. Must produce a DIFFERENT strategy.' if is_replanning else 'First plan.'}"
    )

    # Build attempt context block (empty string on first run — no overhead)
    attempt_context = build_attempt_context(attempt_history)

    if attempt_context:
        logger.log_thought(f"Injecting attempt history into prompt:\n{attempt_context}")

    cve_json_display = json.dumps(cve_config, indent=2, ensure_ascii=False)[:1000]

    replan_instruction = (
        "IMPORTANT: Previous exploitation strategies have FAILED (see above). "
        "You MUST propose a strategy that is completely different from any approach already attempted. "
        "Do NOT repeat failed injection types, payloads, or parameters.\n\n"
        if is_replanning else ""
    )

    # Strategist diagnosis of why the last approach failed — steer the redesign.
    reflection_guidance = (state.get("reflection_guidance") or "").strip()
    if reflection_guidance and is_replanning:
        replan_instruction += (
            f"STRATEGIST DIAGNOSIS (base the new plan on this):\n{reflection_guidance}\n\n"
        )

    # Inject KB context for this specific vulnerability type
    kb_context = format_kb_context(vulnerability_type)

    # Opt-in (ENABLE_CHAIN_PLANNING / ENABLE_CONFIG_A_PLUS): a generic planning principle so the
    # plan reasons about multi-stage chains to the objective instead of one primitive in isolation.
    # Not a per-target hint — it names no vuln/param for THIS target; the planner still reasons.
    chain_principle = ""
    if (os.getenv("ENABLE_CHAIN_PLANNING", "0") == "1"
            or os.getenv("ENABLE_CONFIG_A_PLUS", "0") == "1"):
        chain_principle = (
            "CHAINING PRINCIPLE: reaching the objective may require a SECOND stage, not just the "
            "primary primitive. Consider whether the primitive feeds a downstream sink — input you "
            "control being stored/returned then rendered (template injection at the render step), a "
            "value crossing between queries/tables/DBs (injection at the second sink), filtered "
            "command output that must be encoded to pass a response filter, or a low-priv foothold "
            "that must pivot via an authenticated-only route — and if so, plan the full chain.\n\n"
        )

    prompt = [
        SystemMessage(content=PLANNER_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                attempt_context
                + replan_instruction
                + chain_principle
                + f"CVE ID: {cve_id}\n"
                f"Target URL: {target_url}\n\n"
                f"CVE Configuration:\n```json\n{cve_json_display}\n```\n\n"
                + (f"---\n{kb_context}\n---\n\n" if kb_context else "")
                + "Create a detailed exploitation plan for this injection vulnerability. "
                "Include specific attack vectors, payload variations, and step-by-step execution plan."
            )
        ),
    ]
    
    logger.log_action(
        "llm_invoke",
        {
            "prompt_type": "planner_system_prompt",
            "cve": cve_id,
            "vulnerability_type": vulnerability_type,
        }
    )
    
    try:
        plan_text = llm.invoke(prompt).content
    except Exception as exc:
        plan_text = (
            f"Fallback plan for {cve_id}: exploit {vulnerability_type} at "
            f"{target_url}{cve_config.get('target_url_path', '/')}. "
            f"Use method {cve_config.get('http_method', 'GET')} with parameters "
            f"{cve_config.get('affected_parameters', [])}. "
            f"Strategy: {cve_config.get('exploit_strategy') or cve_config.get('exploitation_notes') or 'test known injection payloads and verify the success regex.'}"
        )
        logger.log_observation({"llm_error": str(exc), "fallback_plan": True})
    
    logger.log_observation({
        "plan_generated": True,
        "plan_length": len(plan_text),
        "preview": plan_text[:300] + "..." if len(plan_text) > 300 else plan_text,
    })
    
    logs = list(state["execution_logs"])
    logs.append(f"[planner] plan created for {cve_id} (vulnerability: {vulnerability_type})")
    
    verbose_logs = state.get("verbose_logs", [])
    verbose_logs.append(logger.get_logs())
    
    logger.log_state_update({
        "status": "planned",
        "plan_ready": True,
        "vulnerability_type": vulnerability_type,
    })
    
    print(logger.get_logs())  # Print verbose output
    
    return {
        "plan": plan_text,
        "execution_logs": logs,
        "verbose_logs": verbose_logs,
        "status": "planned",
    }
