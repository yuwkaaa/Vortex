"""Stack Fingerprinter — detect web tech stack from HTTP response headers and body."""
from __future__ import annotations

from typing import Any

from src.tools.http_client import http_request


# (signal_description, confidence_contribution, stack_label)
_HEADER_RULES: list[tuple[str, str, float, str]] = [
    # (header_name_lower, value_substring_lower, confidence, stack)
    ("x-powered-by",   "express",     0.9,  "express"),
    ("x-powered-by",   "php",         0.9,  "php"),
    ("x-powered-by",   "asp.net",     0.9,  "asp.net"),
    ("x-powered-by",   "next.js",     0.8,  "nextjs"),
    ("server",         "werkzeug",    0.85, "flask"),
    ("server",         "gunicorn",    0.5,  "python"),   # could be django or flask
    ("server",         "uvicorn",     0.6,  "python"),
    ("server",         "apache",      0.3,  "php"),      # weak signal
    ("server",         "nginx",       0.1,  "unknown"),  # too generic
    ("server",         "iis",         0.8,  "asp.net"),
    ("server",         "jetty",       0.85, "java"),
    ("server",         "tomcat",      0.9,  "java"),
]

_COOKIE_RULES: list[tuple[str, float, str]] = [
    # (cookie_name_lower, confidence, stack)
    ("phpsessid",        0.95, "php"),
    ("jsessionid",       0.95, "java"),
    ("csrftoken",        0.75, "django"),
    ("django_",          0.85, "django"),
    ("laravel_session",  0.95, "laravel"),
    ("ci_session",       0.9,  "codeigniter"),
    ("rack.session",     0.85, "rails"),
    ("asp.net_sessionid",0.95, "asp.net"),
    ("connect.sid",      0.85, "express"),
]

_BODY_RULES: list[tuple[str, float, str]] = [
    # (body_substring_lower, confidence, stack)
    ("django",                 0.7,  "django"),
    ("traceback (most recent", 0.6,  "python"),
    ("at org.springframework", 0.9,  "spring"),
    ("whitelabel error page",  0.9,  "spring"),
    ("java.lang.",             0.75, "java"),
    ("javax.servlet",          0.8,  "java"),
    ("laravel",                0.7,  "laravel"),
    ("rails",                  0.5,  "rails"),
    ("ruby on rails",          0.85, "rails"),
    ("syntax error near",      0.3,  "php"),   # generic PHP parse error
    ("<title>error</title>",   0.1,  "unknown"),
]

# When multiple signals point at the same stack, cap contribution
_MAX_CONFIDENCE = 0.98


def fingerprint_stack(
    base_url: str,
    path: str = "/",
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Send a GET request and analyse response to guess the tech stack.

    Returns:
        {
            "stack"     : str,          # best-guess label  e.g. "django"
            "confidence": float,        # 0.0–1.0
            "signals"   : [str, ...],   # human-readable evidence lines
            "all_scores": {stack: float},
            "error"     : str | None,
        }
    """
    resp = http_request(base_url, path, method="GET", timeout=timeout)
    if resp.get("status") != "success":
        return {
            "stack": "unknown",
            "confidence": 0.0,
            "signals": [],
            "all_scores": {},
            "error": resp.get("error_message"),
        }

    headers = {k.lower(): v.lower() for k, v in resp.get("headers", {}).items()}
    cookies = {k.lower(): v.lower() for k, v in resp.get("cookies", {}).items()}
    body = resp.get("body", "")
    body_lower = (body if isinstance(body, str) else "").lower()

    scores: dict[str, float] = {}
    signals: list[str] = []

    def _add(stack: str, conf: float, reason: str) -> None:
        scores[stack] = min(_MAX_CONFIDENCE, scores.get(stack, 0.0) + conf)
        signals.append(f"[{stack}] {reason} (+{conf:.2f})")

    # Header-based signals
    for h_name, h_val_sub, conf, stack in _HEADER_RULES:
        v = headers.get(h_name, "")
        if h_val_sub in v:
            _add(stack, conf, f"Header {h_name}: {v!r} contains '{h_val_sub}'")

    # Cookie-based signals
    for ck_name, conf, stack in _COOKIE_RULES:
        for cookie_key in cookies:
            if ck_name in cookie_key:
                _add(stack, conf, f"Cookie name contains '{ck_name}'")
                break

    # Body-based signals
    for body_sub, conf, stack in _BODY_RULES:
        if body_sub in body_lower:
            _add(stack, conf, f"Response body contains '{body_sub}'")

    if not scores:
        return {
            "stack": "unknown",
            "confidence": 0.0,
            "signals": signals,
            "all_scores": scores,
            "error": None,
        }

    best_stack = max(scores, key=lambda s: scores[s])
    return {
        "stack": best_stack,
        "confidence": round(scores[best_stack], 3),
        "signals": signals,
        "all_scores": {k: round(v, 3) for k, v in scores.items()},
        "error": None,
    }
