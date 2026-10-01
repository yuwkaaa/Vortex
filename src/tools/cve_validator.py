"""
CVE config validator.

Checks that a CVE config dict has all required fields before the graph runs.
Returns a list of issues so the caller can decide whether to abort or warn.
"""
from __future__ import annotations

from typing import Any


# Fields that must exist and be non-empty
_REQUIRED: list[tuple[str, type]] = [
    ("cve_id",              str),
    ("vulnerability_type",  str),
    ("target_url_path",     str),
    ("http_method",         str),
    ("affected_parameters", list),
    ("success_regex_pattern", str),
]

# Fields that are strongly recommended (warn, not error)
_RECOMMENDED: list[str] = [
    "cwe_id",
    "cvss_score",
    "vulnerable_code_snippet",
    "payload_template",
    "patch_diff",
]

# Known vulnerability types — warn if vuln type isn't recognised
_KNOWN_VULN_TYPES = {
    "sql_injection", "sqli",
    "command_injection", "rce",
    "ssti",
    "nosql_injection",
    "ldap_injection",
    "xpath_injection",
    "crlf_injection", "header_injection",
    "path_traversal", "lfi", "file_inclusion",
    "xss", "html_injection",
    "ssrf",
    "xxe", "xml_external_entity",
}


def validate_cve_config(config: dict[str, Any]) -> dict[str, Any]:
    """
    Validate a CVE config dict.

    Returns:
      valid    : bool — False if any required field is missing or wrong type
      errors   : list[str] — blocking issues
      warnings : list[str] — non-blocking issues
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(config, dict):
        return {"valid": False, "errors": ["cve_config is not a dict"], "warnings": []}

    # Required field checks
    for field, expected_type in _REQUIRED:
        val = config.get(field)
        if val is None:
            errors.append(f"Missing required field: '{field}'")
        elif not isinstance(val, expected_type):
            errors.append(f"Field '{field}' must be {expected_type.__name__}, got {type(val).__name__}")
        elif isinstance(val, (str, list)) and len(val) == 0:
            errors.append(f"Required field '{field}' is empty")

    # affected_parameters must have at least one entry
    params = config.get("affected_parameters", [])
    if isinstance(params, list) and len(params) == 0:
        errors.append("'affected_parameters' list is empty — executor cannot inject without a target parameter")

    # http_method sanity
    method = config.get("http_method", "")
    if isinstance(method, str) and method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        warnings.append(f"Unusual http_method '{method}' — expected GET or POST")

    # vulnerability_type recognition
    vt = config.get("vulnerability_type", "").lower()
    if vt and not any(known in vt for known in _KNOWN_VULN_TYPES):
        warnings.append(
            f"vulnerability_type '{vt}' not recognised — executor will fall back to template payload. "
            f"Known types: {', '.join(sorted(_KNOWN_VULN_TYPES))}"
        )

    # Recommended fields
    for field in _RECOMMENDED:
        if not config.get(field):
            warnings.append(f"Recommended field missing: '{field}' (recon / planning quality may suffer)")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


def format_validation_result(result: dict[str, Any]) -> str:
    """Human-readable summary for logging."""
    lines = [f"CVE config validation: {'PASS' if result['valid'] else 'FAIL'}"]
    for e in result["errors"]:
        lines.append(f"  [ERROR] {e}")
    for w in result["warnings"]:
        lines.append(f"  [WARN]  {w}")
    return "\n".join(lines)
