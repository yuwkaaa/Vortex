"""
Blind injection detector.

Sends a true-condition and a false-condition payload, then compares
response length and response time to confirm a blind injection point.
Works for boolean-based blind SQLi, NoSQL, XPath, and time-based blind SQLi.
"""
from __future__ import annotations

import time
from typing import Any

import requests
from urllib.parse import urljoin


# Thresholds
_TIME_DELTA_THRESHOLD = 3.0   # seconds — gap that indicates time-based sleep
_LEN_DELTA_THRESHOLD  = 0.10  # 10 % difference → boolean-based


def _raw_request(
    url: str,
    method: str,
    params: dict | None,
    data: dict | None,
    headers: dict | None,
    cookies: dict | None,
    timeout: int,
) -> tuple[int, float]:
    """Return (response_length, elapsed_seconds). Returns (-1, -1) on error."""
    try:
        t0 = time.monotonic()
        r = requests.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            verify=False,
        )
        elapsed = time.monotonic() - t0
        return len(r.text), elapsed
    except Exception:
        return -1, -1


def detect_blind_injection(
    base_url: str,
    path: str,
    method: str,
    parameter: str,
    true_payload: str,
    false_payload: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    baseline_value: str = "1",
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Probe a single parameter with true/false payloads and compare responses.

    Returns a dict with:
      confirmed_blind  : bool
      blind_type       : "boolean" | "time_based" | "none"
      true_length      : int
      false_length     : int
      true_time        : float
      false_time       : float
      length_delta_pct : float
      time_delta       : float
      evidence         : str (human-readable summary)
    """
    url = urljoin(base_url, path) if not path.startswith("http") else path

    def build_args(payload: str) -> tuple[dict | None, dict | None]:
        if method.upper() == "GET":
            return {parameter: payload}, None
        return None, {parameter: payload}

    # Baseline (known-good value to establish a reference length)
    base_params, base_data = build_args(baseline_value)
    base_len, base_time = _raw_request(url, method, base_params, base_data, headers, cookies, timeout)

    # True condition
    t_params, t_data = build_args(true_payload)
    true_len, true_time = _raw_request(url, method, t_params, t_data, headers, cookies, timeout)

    # False condition
    f_params, f_data = build_args(false_payload)
    false_len, false_time = _raw_request(url, method, f_params, f_data, headers, cookies, timeout)

    if true_len == -1 or false_len == -1:
        return {
            "confirmed_blind": False,
            "blind_type": "none",
            "error": "one or more probe requests failed",
        }

    # Time-based: true payload caused a significant delay
    time_delta = true_time - false_time
    time_based = time_delta >= _TIME_DELTA_THRESHOLD

    # Boolean-based: meaningful length difference between true and false
    avg_len = (true_len + false_len) / 2 if (true_len + false_len) > 0 else 1
    len_delta_pct = abs(true_len - false_len) / avg_len
    bool_based = len_delta_pct >= _LEN_DELTA_THRESHOLD and true_len != false_len

    if time_based:
        blind_type = "time_based"
        confirmed = True
        evidence = (
            f"Time-based blind confirmed: true payload took {true_time:.2f}s vs "
            f"false payload {false_time:.2f}s (delta {time_delta:.2f}s ≥ {_TIME_DELTA_THRESHOLD}s threshold)"
        )
    elif bool_based:
        blind_type = "boolean"
        confirmed = True
        evidence = (
            f"Boolean-based blind confirmed: true response {true_len} bytes vs "
            f"false response {false_len} bytes ({len_delta_pct*100:.1f}% difference ≥ {_LEN_DELTA_THRESHOLD*100:.0f}% threshold)"
        )
    else:
        blind_type = "none"
        confirmed = False
        evidence = (
            f"No blind injection detected. true={true_len}B/{true_time:.2f}s "
            f"false={false_len}B/{false_time:.2f}s"
        )

    return {
        "confirmed_blind": confirmed,
        "blind_type": blind_type,
        "true_length": true_len,
        "false_length": false_len,
        "true_time": round(true_time, 3),
        "false_time": round(false_time, 3),
        "length_delta_pct": round(len_delta_pct * 100, 1),
        "time_delta": round(time_delta, 3),
        "evidence": evidence,
    }


# Convenience probe pairs per injection type
BLIND_PROBE_PAIRS: dict[str, tuple[str, str]] = {
    # SQL
    "sql_boolean": ("' OR 1=1-- ", "' OR 1=2-- "),
    "sql_time":    ("' AND SLEEP(5)-- ", "' AND SLEEP(0)-- "),
    # NoSQL
    "nosql_boolean": ('{"$gt": ""}', '{"$gt": "zzzzzzzzz"}'),
    # XPath
    "xpath_boolean": ("' or '1'='1", "' or '1'='2"),
    # LDAP
    "ldap_boolean":  ("admin)(|(a=a", "admin)(|(a=b"),
}
