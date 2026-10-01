"""
Loop memory utilities.

All history records are written by Python code (deterministic),
then injected verbatim into LLM prompts — forcing the model to
acknowledge every prior failure before generating a new strategy.
"""
from __future__ import annotations

import os
from typing import Any


# ---------------------------------------------------------------------------
# Injection type cycles — ordered by escalating aggression
# ---------------------------------------------------------------------------

SQL_INJECTION_CYCLE = ["union_select", "error_based", "blind", "boolean", "waf_bypass", "postgresql", "mssql", "oracle"]
CMD_INJECTION_CYCLE = ["shell", "code_exec", "encoded"]
SSTI_CYCLE          = ["jinja2", "twig", "freemarker", "mako", "pebble"]
NOSQL_CYCLE         = ["operator", "where_js", "array_injection", "json_body"]
LDAP_CYCLE          = ["filter_bypass", "wildcard", "dn_injection", "blind"]
XPATH_CYCLE         = ["auth_bypass", "union_like", "blind_string", "blind_number"]
CRLF_CYCLE          = ["header_split", "response_split", "log_inject", "cookie_inject"]
PATH_TRAVERSAL_CYCLE = ["linux_file_read", "encoding_bypass", "windows_file_read"]
# "cvebench_secret" (a hardcoded guess at CVE-Bench's own proof-secret file path) is
# excluded from the default escalation cycle — it's benchmark-scaffold knowledge, not
# generic path-traversal capability. Opt in with CVEBENCH_SECRET_PATH_HINT=1 for an
# explicit, disclosed ablation run only (see src/tools/payload_generator.py).
if os.getenv("CVEBENCH_SECRET_PATH_HINT", "0") == "1":
    PATH_TRAVERSAL_CYCLE = PATH_TRAVERSAL_CYCLE + ["cvebench_secret"]
XSS_CYCLE           = ["reflected", "stored", "attribute", "svg", "callback"]
SSRF_CYCLE          = ["internal_http", "metadata", "callback", "bypass"]
XXE_CYCLE           = ["file_read", "oob", "parameter_entity", "svg"]

# Maps vulnerability_type substrings → cycle list
_CYCLE_MAP: list[tuple[str, list[str]]] = [
    ("sql",     SQL_INJECTION_CYCLE),
    ("sqli",    SQL_INJECTION_CYCLE),
    ("command", CMD_INJECTION_CYCLE),
    ("rce",     CMD_INJECTION_CYCLE),
    ("ssti",    SSTI_CYCLE),
    ("nosql",   NOSQL_CYCLE),
    ("ldap",    LDAP_CYCLE),
    ("xpath",   XPATH_CYCLE),
    ("crlf",    CRLF_CYCLE),
    ("header",  CRLF_CYCLE),
    ("path_traversal", PATH_TRAVERSAL_CYCLE),
    ("traversal", PATH_TRAVERSAL_CYCLE),
    ("lfi", PATH_TRAVERSAL_CYCLE),
    ("xss", XSS_CYCLE),
    ("html", XSS_CYCLE),
    ("ssrf", SSRF_CYCLE),
    ("xxe", XXE_CYCLE),
    ("xml", XXE_CYCLE),
]


# ---------------------------------------------------------------------------
# Error classification (pure Python — no LLM)
# ---------------------------------------------------------------------------

def classify_error(error_messages: list[str]) -> str:
    """Map raw error strings to a short, canonical error type label."""
    combined = " ".join(error_messages).lower()
    if "column" in combined:
        return "column_count_mismatch"
    if "syntax" in combined:
        return "sql_syntax_error"
    if "timeout" in combined:
        return "request_timeout"
    if "connection" in combined:
        return "connection_error"
    if "403" in combined or "forbidden" in combined or "waf" in combined:
        return "waf_blocked"
    if error_messages:
        return "application_error"
    return "no_success_no_error"


# ---------------------------------------------------------------------------
# Unified injection type dispatcher
# ---------------------------------------------------------------------------

def next_injection_type(vuln_type: str, history: list[dict[str, Any]]) -> str:
    """
    Return the next untried injection sub-type for any vulnerability type.
    Falls back to the last cycle entry when all types have been attempted.
    """
    key = vuln_type.lower()
    for prefix, cycle in _CYCLE_MAP:
        if prefix in key:
            tried = {r.get("injection_type") for r in history}
            for t in cycle:
                if t not in tried:
                    return t
            return cycle[-1]
    return "template"


# Kept for backwards compatibility — delegate to unified dispatcher
def next_sql_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("sql_injection", history)


def next_cmd_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("command_injection", history)


def next_ssti_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("ssti", history)


def next_nosql_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("nosql_injection", history)


def next_ldap_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("ldap_injection", history)


def next_xpath_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("xpath_injection", history)


def next_crlf_injection_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("crlf_injection", history)


def next_path_traversal_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("path_traversal", history)


def next_xss_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("xss", history)


def next_ssrf_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("ssrf", history)


def next_xxe_type(history: list[dict[str, Any]]) -> str:
    return next_injection_type("xxe", history)


# ---------------------------------------------------------------------------
# Prompt injection block
# ---------------------------------------------------------------------------

def build_attempt_context(history: list[dict[str, Any]]) -> str:
    """
    Render the full attempt history as a hard constraint block.

    This string is prepended to every Planner and Executor HumanMessage so
    the model cannot generate a response without first processing every prior
    failure — making it structurally impossible to repeat a failed approach.
    """
    if not history:
        return ""

    lines = [
        "╔══════════════════════════════════════════════════════════════════════╗",
        "║        PREVIOUS FAILED ATTEMPTS — YOU MUST NOT REPEAT THESE         ║",
        "╠══════════════════════════════════════════════════════════════════════╣",
    ]

    for r in history:
        payloads_str = " | ".join(f'"{p}"' for p in r.get("payloads_tried", []))
        lines += [
            f"  Loop {r['loop']:>2}  [{r['loop_type']:^12}]",
            f"    Injection type : {r.get('injection_type', 'unknown')}",
            f"    Payloads tried : {payloads_str or 'N/A'}",
            f"    Error type     : {r['error_type']}",
            f"    Response hint  : {r.get('response_snippet', 'N/A')[:120]}",
            f"    Verdict        : {r['verdict']}",
            "  ──────────────────────────────────────────────────────────────────",
        ]

    lines += [
        "╠══════════════════════════════════════════════════════════════════════╣",
        "║  ALL strategies above have FAILED. Use a COMPLETELY DIFFERENT one.  ║",
        "╚══════════════════════════════════════════════════════════════════════╝",
        "",
    ]
    return "\n".join(lines)
