"""Injection knowledge base loader."""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any


_KB_PATH = os.path.join(os.path.dirname(__file__), "injections.json")

# Maps vulnerability_type substrings → KB key
_KEY_MAP: list[tuple[str, str]] = [
    ("sqli",    "sql_injection"),
    ("sql",     "sql_injection"),
    ("command", "command_injection"),
    ("rce",     "command_injection"),
    ("ssti",    "ssti"),
    ("nosql",   "nosql_injection"),
    ("ldap",    "ldap_injection"),
    ("xpath",   "xpath_injection"),
    ("crlf",    "crlf_injection"),
    ("header",  "crlf_injection"),
    ("path_traversal", "path_traversal"),
    ("traversal", "path_traversal"),
    ("lfi", "path_traversal"),
    ("file_inclusion", "path_traversal"),
    ("xss", "xss"),
    ("html", "xss"),
    ("ssrf", "ssrf"),
    ("xxe", "xxe"),
    ("xml", "xxe"),
]


@lru_cache(maxsize=1)
def _load_kb() -> dict[str, Any]:
    with open(_KB_PATH, encoding="utf-8") as f:
        return json.load(f)


def get_injection_info(vuln_type: str) -> dict[str, Any] | None:
    """
    Return the KB entry for a vulnerability type string.
    Matches by substring so 'sql_injection', 'sqli', 'SQL Injection' all work.
    Returns None if no match found.
    """
    key = vuln_type.lower()
    kb = _load_kb()
    for prefix, kb_key in _KEY_MAP:
        if prefix in key:
            return kb.get(kb_key)
    return None


def format_kb_context(vuln_type: str) -> str:
    """
    Return a compact plain-text block summarising the KB entry for a vuln type.
    Intended for injection into LLM prompts.
    """
    info = get_injection_info(vuln_type)
    if not info:
        return ""

    lines = [
        f"## Injection KB: {info['display_name']} ({info['cwe']})",
        f"**Description**: {info['description']}",
        "",
        "**Detection hints**:",
        *[f"  - {h}" for h in info.get("detection_hints", [])],
        "",
        "**Common vulnerable sinks**:",
        *[f"  - {s}" for s in info.get("common_sinks", [])],
        "",
        "**Exploit approach**:",
        *[f"  {step}" for step in info.get("exploit_approach", [])],
        "",
        "**Success indicators**:",
        *[f"  - {s}" for s in info.get("success_indicators", [])],
        "",
        f"**WAF bypass notes**: {info.get('waf_bypass_notes', 'N/A')}",
        f"**Auth notes**: {info.get('auth_notes', 'N/A')}",
    ]
    return "\n".join(lines)
