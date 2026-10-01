"""
Smart response slicing.

Turns a raw HTTP body into a compact, high-signal summary so the Executor LLM
spends tokens on what matters (flag, errors, reflected payload) instead of on
framework boilerplate. Replaces the old `body[:2000]` hard truncation.

Strategy:
  1. Flag-safe   : scan the FULL body for the success pattern before trimming.
  2. High-signal : surface SQL/template/stack error signatures verbatim.
  3. Reflection  : locate where our payload landed and show the surrounding context.
  4. De-boilerplate: strip <script>/<style>/<head>/data-URIs/__NEXT_DATA__ from HTML.
  5. Header-first: return a structured summary; the excerpt comes last and is short.
"""
from __future__ import annotations

import re
from typing import Any

from src.tools.regex_matcher import match_success_pattern


# Whole blocks to drop before building an HTML excerpt
_STRIP_BLOCKS = re.compile(
    r"<(script|style|head|svg|noscript)\b[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_NEXT_DATA = re.compile(r'<script[^>]*id="__NEXT_DATA__".*?</script>', re.IGNORECASE | re.DOTALL)
_DATA_URI = re.compile(r"data:[^;\s\"']+;base64,[A-Za-z0-9+/=]+")
_TAG = re.compile(r"<[^>]+>")
_INLINE_WS = re.compile(r"[ \t]{2,}")
_BLANKLINES = re.compile(r"\n{3,}")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# High-signal error/server signatures worth surfacing verbatim for an injection agent
_ERROR_SIGNATURES = [
    r"You have an error in your SQL syntax[^\n]{0,160}",
    r"Warning: \w+\(\)[^\n]{0,160}",                       # PHP warnings
    r"(?:MySQL|PostgreSQL|SQLite|psycopg2|sqlite3|ORA-\d+)[^\n]{0,160}",
    r"Traceback \(most recent call last\)[\s\S]{0,400}",
    r"jinja2\.[A-Za-z]+Error[^\n]{0,160}",
    r"TemplateSyntaxError[^\n]{0,160}",
    r"(?:Internal Server Error|Fatal error|Stack trace)[^\n]{0,160}",
    r"(?:Exception|Error):[^\n]{0,160}",
]
_ERROR_RE = re.compile("|".join(f"(?:{p})" for p in _ERROR_SIGNATURES), re.IGNORECASE)

_NEVER_MATCH = r"(?!x)x"  # used to disable flag scanning without changing call sites


def _flag_context(body: str, success_pattern: str) -> tuple[str | None, str | None]:
    """Return (evidence, surrounding_context) if the success pattern matches anywhere."""
    chk = match_success_pattern(body, success_pattern)
    if not chk.get("matched"):
        return None, None
    evidence = chk.get("evidence") or ""
    idx = body.find(evidence) if evidence else -1
    if idx == -1:
        return evidence, None
    lo = max(0, idx - 120)
    hi = min(len(body), idx + len(evidence) + 120)
    return evidence, body[lo:hi].strip()


def _error_signatures(body: str, limit: int = 3) -> list[str]:
    out: list[str] = []
    for m in _ERROR_RE.finditer(body):
        raw = m.group(0)
        # On minified HTML the trailing capture runs into markup — cut at the first
        # tag boundary (harmless for plain-text stack traces, which have no '<').
        raw = raw.split("<", 1)[0]
        s = " ".join(raw.split())[:200]
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _strip_html(body: str) -> str:
    t = _NEXT_DATA.sub(" ", body)
    t = _STRIP_BLOCKS.sub(" ", t)
    t = _DATA_URI.sub("data:…", t)
    t = _TAG.sub(" ", t)            # drop tags, keep visible text
    t = _INLINE_WS.sub(" ", t)
    t = _BLANKLINES.sub("\n\n", t)
    return t.strip()


def _reflection_context(body: str, marker: str) -> str | None:
    """If our payload appears in the response, return the surrounding context."""
    if not marker or len(marker) < 3:
        return None
    idx = body.find(marker)
    if idx == -1:
        return None
    lo = max(0, idx - 80)
    hi = min(len(body), idx + len(marker) + 80)
    return body[lo:hi].strip()


def summarize_response(
    *,
    body: str,
    success_pattern: str,
    status_code: Any = "?",
    response_time: float = 0.0,
    cookies_set: dict[str, Any] | None = None,
    error: str | None = None,
    marker: str = "",
    excerpt_chars: int = 700,
    flag_check: bool = True,
) -> dict[str, Any]:
    """Build a compact, high-signal summary of an HTTP response body."""
    head = body[:1024].lower()
    looks_html = "<html" in head or "<!doctype" in head

    flag, flag_ctx = _flag_context(body, success_pattern if flag_check else _NEVER_MATCH)
    errors = _error_signatures(body)
    reflected_ctx = _reflection_context(body, marker) if marker else None

    cleaned = _strip_html(body) if looks_html else body
    excerpt = cleaned[:excerpt_chars]
    truncated = len(cleaned) > excerpt_chars

    title_m = _TITLE.search(body)
    title = " ".join(title_m.group(1).split())[:120] if title_m else None

    return {
        "status_code": status_code,
        "response_time": round(response_time, 3),
        "body_length": len(body),
        "content_kind": "html" if looks_html else "text/json",
        "title": title,
        "flag_found": flag,
        "flag_context": flag_ctx,
        "error_signatures": errors,
        "reflected": bool(reflected_ctx),
        "reflection_context": reflected_ctx,
        "cookies_set": cookies_set or {},
        "body_excerpt": excerpt + ("…(truncated)" if truncated else ""),
        "error": error,
    }
