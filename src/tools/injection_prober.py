"""Injection Prober — fire lightweight marker probes to rank likely injection types."""
from __future__ import annotations

from typing import Any

from src.knowledge import get_injection_info
from src.tools.http_client import http_request


# Time delta threshold (seconds) to flag time-based blind injection
_TIME_THRESHOLD = 3.0
# Body length change ratio to flag boolean-based blind injection
_LEN_THRESHOLD = 0.10

# Ordered list of injection types to probe (SSTI first for Flask targets)
_PROBE_ORDER = [
    "ssti",
    "sql_injection",
    "command_injection",
    "nosql_injection",
    "xpath_injection",
    "ldap_injection",
    "crlf_injection",
    "path_traversal",
    "xss",
    "ssrf",
    "xxe",
]


def _send(
    base_url: str,
    path: str,
    method: str,
    param: str,
    value: str,
    timeout: int,
) -> dict[str, Any]:
    p = {param: value} if method.upper() == "GET" else {}
    d = {param: value} if method.upper() != "GET" else {}
    return http_request(
        base_url, path,
        method=method,
        params=p or None,
        data=d or None,
        timeout=timeout,
    )


def _probe_reflected(
    base_url: str,
    path: str,
    method: str,
    param: str,
    probe_input: str,
    expected_output: str,
    timeout: int,
) -> float:
    """
    Send probe_input and check if expected_output appears in response body.
    Returns confidence score (0.0 or 0.92).
    """
    try:
        resp = _send(base_url, path, method, param, probe_input, timeout)
        if resp.get("status") != "success":
            return 0.0
        body = str(resp.get("body", ""))
        if expected_output in body:
            return 0.92
    except Exception:
        pass
    return 0.0


def _probe_blind(
    base_url: str,
    path: str,
    method: str,
    param: str,
    true_payload: str,
    false_payload: str,
    timeout: int,
) -> float:
    """Send true/false probe pair and return confidence based on delta metrics."""
    try:
        baseline = _send(base_url, path, method, param, "", timeout)
        true_resp = _send(base_url, path, method, param, true_payload, timeout)
        false_resp = _send(base_url, path, method, param, false_payload, timeout)
    except Exception:
        return 0.0

    base_len  = len(str(baseline.get("body", "")))
    true_len  = len(str(true_resp.get("body", "")))
    false_len = len(str(false_resp.get("body", "")))
    true_time  = true_resp.get("response_time", 0.0)
    false_time = false_resp.get("response_time", 0.0)

    len_delta  = abs(true_len - false_len) / max(base_len, 1)
    time_delta = abs(true_time - false_time)

    conf = 0.0
    if time_delta >= _TIME_THRESHOLD:
        conf = max(conf, 0.85)
    if len_delta >= _LEN_THRESHOLD:
        conf = max(conf, 0.75)
    elif len_delta >= 0.03:
        conf = max(conf, 0.35)
    return conf


def probe_injections(
    base_url: str,
    path: str = "/",
    method: str = "GET",
    params: list[str] | None = None,
    timeout: int = 8,
) -> list[tuple[str, float]]:
    """
    Fire reflected + blind probe pairs from injections.json for each type × param.

    Returns (injection_type, confidence) sorted by confidence descending.
    """
    if not params:
        return []

    scores: dict[str, float] = {}

    for vuln_type in _PROBE_ORDER:
        info = get_injection_info(vuln_type)
        if not info:
            continue

        best_conf = 0.0

        for param in params:
            # 1. Reflected probe (e.g. SSTI: send {{7*7}}, check for 49)
            rp = info.get("reflected_probe", {})
            if rp.get("input") and rp.get("expected_output"):
                conf = _probe_reflected(
                    base_url, path, method, param,
                    rp["input"], rp["expected_output"], timeout,
                )
                best_conf = max(best_conf, conf)

            # 2. Boolean / time-based / file-read probe pairs
            for pair in info.get("blind_probes", {}).values():
                t_val = pair.get("true")
                f_val = pair.get("false")
                if t_val and f_val:
                    conf = _probe_blind(
                        base_url, path, method, param, t_val, f_val, timeout,
                    )
                    best_conf = max(best_conf, conf)

        if best_conf > 0:
            scores[vuln_type] = round(best_conf, 3)

    return sorted(scores.items(), key=lambda x: x[1], reverse=True)
