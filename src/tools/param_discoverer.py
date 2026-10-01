"""Param Discoverer — extract form fields and URL query params from an HTML page."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from src.tools.http_client import http_request


# Regex patterns for lightweight HTML parsing (no BeautifulSoup dep)
_RE_INPUT   = re.compile(r'<input[^>]+name=["\']?([^\s"\'>/]+)', re.IGNORECASE)
_RE_SELECT  = re.compile(r'<select[^>]+name=["\']?([^\s"\'>/]+)', re.IGNORECASE)
_RE_TEXTAREA = re.compile(r'<textarea[^>]+name=["\']?([^\s"\'>/]+)', re.IGNORECASE)
_RE_FORM    = re.compile(r'<form([^>]*)>', re.IGNORECASE)
_RE_ACTION  = re.compile(r'action=["\']?([^\s"\'>/][^\s"\']*)', re.IGNORECASE)
_RE_METHOD  = re.compile(r'method=["\']?(\w+)', re.IGNORECASE)

# Keywords that hint a form is an auth form
_AUTH_HINTS = {"login", "signin", "sign-in", "logout", "register",
               "signup", "sign-up", "auth", "account", "password", "passwd"}

# params are frequently NOT in the HTML form — they live in JS that builds an
# ajax/fetch/axios request body (e.g. a hidden `submit:'submit'` field, or a pure
# JSON API taking a field like `job_type`). Recover those field names + detect
# whether the endpoint expects a JSON body so the Executor delivers the payload
# the right way.
_RE_SCRIPT      = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
# `data: { username: x, password: y, submit: 'submit' }`  /  `body: JSON.stringify({...})`
_RE_DATA_BLOCK  = re.compile(r"(?:data|body)\s*:\s*(?:JSON\.stringify\s*\()?\{(.*?)\}", re.IGNORECASE | re.DOTALL)
# object keys:  foo:  /  "foo":  /  'foo':
_RE_OBJ_KEY     = re.compile(r"""['"]?([A-Za-z_][\w-]*)['"]?\s*:""")
# fetch/axios url first arg:  fetch('/api/x'  /  axios.post("/api/y"
_RE_FETCH_URL   = re.compile(r"""(?:fetch|axios\.\w+|\.open)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_RE_AJAX_URL    = re.compile(r"""url\s*:\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_JSON_HINTS     = re.compile(
    r"application/json|JSON\.stringify|dataType\s*:\s*['\"]json|contentType\s*:\s*['\"]application/json",
    re.IGNORECASE,
)
# non-field noise sometimes captured as object keys inside data blocks
_JS_KEY_NOISE   = {"type", "url", "method", "success", "error", "datatype", "contenttype",
                   "headers", "beforesend", "complete", "async", "data", "body",
                   "processdata", "cache", "timeout", "crossdomain"}


def extract_js_request_shape(html: str) -> dict[str, Any]:
    """Pull request field names + JSON-body hint + JS endpoint URLs out of inline <script>.

    Returns {"js_params": [...], "json_api": bool, "js_endpoints": [...]}.
    """
    scripts = "\n".join(_RE_SCRIPT.findall(html))
    if not scripts:
        return {"js_params": [], "json_api": False, "js_endpoints": []}

    params: set[str] = set()
    for block in _RE_DATA_BLOCK.findall(scripts):
        for key in _RE_OBJ_KEY.findall(block):
            if key.lower() not in _JS_KEY_NOISE:
                params.add(key)

    endpoints: set[str] = set()
    for rx in (_RE_FETCH_URL, _RE_AJAX_URL):
        for u in rx.findall(scripts):
            if u and not u.startswith(("http://", "https://", "//")) and len(u) < 120:
                endpoints.add(u)

    return {
        "js_params": sorted(params),
        "json_api": bool(_JSON_HINTS.search(scripts)),
        "js_endpoints": sorted(endpoints),
    }


# External client code (WordPress plugin/theme scripts, bundled JS) is where a huge class
# of real-world CVEs actually live: the vulnerable surface is an admin-ajax.php action
# registered `wp_ajax_nopriv_*` (reachable unauthenticated), whose name + request params
# only appear in the enqueued .js — invisible to inline-<script>/<form>/<a href> scans.
# This recovers them GENERICALLY (no per-CVE knowledge): fetch same-origin external JS,
# pull the ajax action names + data params, and synthesise the admin-ajax endpoint(s).
_RE_SCRIPT_SRC    = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_RE_AJAX_ACTION   = re.compile(r"""['"]?action['"]?\s*[:=]\s*['"]([A-Za-z][\w-]+)['"]""", re.IGNORECASE)
_RE_APPEND_ACTION = re.compile(r"""append\(\s*['"]action['"]\s*,\s*['"]([A-Za-z][\w-]+)['"]""", re.IGNORECASE)
_RE_APPEND_KEY    = re.compile(r"""\.append\(\s*['"]([A-Za-z_][\w-]*)['"]""")
_RE_WP_MARK       = re.compile(r"wp-content|wp-includes|wp-json|/wp-admin/", re.IGNORECASE)
# WP localizes the ajax nonce into an inline script: {"ajax_url":"…admin-ajax.php","nonce":"ab12cd34ef"}
# Unauthenticated actions still call check_ajax_referer(), so the attacker MUST replay this nonce.
_RE_WP_NONCE      = re.compile(r"""["']?nonce["']?\s*:\s*["']([A-Za-z0-9]{6,})["']""", re.IGNORECASE)


def discover_external_js_ajax(base_url: str, html: str, timeout: int = 8, max_js: int = 8) -> dict[str, Any]:
    """Fetch same-origin external JS and recover admin-ajax action names + request params.

    Returns {"ext_params", "ajax_actions", "ajax_endpoints", "is_wp"}. Bounded (max_js files,
    per-file timeout). Host is always rewritten to `base_url` so the app's configured host
    (e.g. WP home_url `target:9090`) is fetched via the reachable host.
    """
    empty = {"ext_params": [], "ajax_actions": [], "ajax_endpoints": [], "is_wp": bool(_RE_WP_MARK.search(html or ""))}
    srcs = _RE_SCRIPT_SRC.findall(html or "")
    if not srcs:
        return empty
    # prioritise plugin/theme scripts (where the vuln surface lives), dedupe, cap.
    srcs = sorted(set(srcs), key=lambda s: 0 if "wp-content" in s.lower() else 1)[:max_js]
    js_parts: list[str] = []
    for src in srcs:
        try:
            pr = urlparse(src)
            opath = pr.path + (f"?{pr.query}" if pr.query else "")
            if not opath:
                continue
            resp = http_request(base_url, opath, method="GET", timeout=timeout)
            body = resp.get("body")
            if resp.get("status") == "success" and isinstance(body, str):
                js_parts.append(body[:200_000])  # bound per-file
        except Exception:
            continue
    js = "\n".join(js_parts)
    if not js:
        return empty

    params: set[str] = set()
    for block in _RE_DATA_BLOCK.findall(js):
        for key in _RE_OBJ_KEY.findall(block):
            if key.lower() not in _JS_KEY_NOISE:
                params.add(key)
    params.update(k for k in _RE_APPEND_KEY.findall(js) if k.lower() not in _JS_KEY_NOISE)
    actions = set(_RE_AJAX_ACTION.findall(js)) | set(_RE_APPEND_ACTION.findall(js))
    params.discard("action")

    is_ajax = bool(re.search(r"admin-ajax\.php|wp_ajax", js + (html or ""), re.IGNORECASE))
    endpoints: list[str] = []
    if is_ajax and actions:
        endpoints = [f"/wp-admin/admin-ajax.php?action={a}" for a in sorted(actions)]
    elif is_ajax:
        endpoints = ["/wp-admin/admin-ajax.php"]
    # Recover the ajax nonce (from the page's localized inline script) — required to pass
    # check_ajax_referer() even for nopriv actions.
    nonce_m = _RE_WP_NONCE.search(html or "")
    return {
        "ext_params": sorted(params),
        "ajax_actions": sorted(actions),
        "ajax_endpoints": endpoints,
        "ajax_nonce": nonce_m.group(1) if nonce_m else "",
        "is_wp": bool(_RE_WP_MARK.search(html or "")),
    }


def _classify_form(action: str, fields: list[str]) -> str:
    """Return 'login' | 'register' | 'general' based on action path + field names."""
    tokens = set(re.split(r"[/_.\s-]+", (action + " " + " ".join(fields)).lower()))
    tokens.update(f.lower() for f in fields)
    if tokens & {"register", "signup", "sign-up", "create", "join"}:
        return "register"
    if tokens & {"login", "signin", "sign-in", "auth", "session"}:
        return "login"
    lower_fields = {f.lower() for f in fields}
    if {"password", "passwd", "pwd"} & lower_fields and ({"username", "user", "email", "login"} & lower_fields):
        return "login"
    return "general"
_RE_HREF    = re.compile(r'href=["\']([^"\']+)', re.IGNORECASE)


def _extract_query_params_from_url(url: str) -> list[str]:
    """Return query param names from a URL string."""
    try:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
    except Exception:
        return []


def _extract_params_from_hrefs(html: str, base_url: str) -> list[str]:
    """Pull query param names from all <a href=...> links in the page."""
    params: set[str] = set()
    for href in _RE_HREF.findall(html):
        params.update(_extract_query_params_from_url(href))
    return list(params)


def discover_params(
    base_url: str,
    path: str = "/",
    timeout: int = 10,
) -> dict[str, Any]:
    """
    GET a page and extract injectable parameters.

    Returns:
        {
            "forms": [{"action": str, "fields": [str, ...]}],
            "query_params": [str, ...],   # from <a href> links
            "all_params": [str, ...],     # deduped union of all found params
            "error": str | None,
        }
    """
    resp = http_request(base_url, path, method="GET", timeout=timeout)

    if resp.get("status") != "success":
        return {
            "forms": [],
            "query_params": [],
            "all_params": [],
            "error": resp.get("error_message", "request failed"),
        }

    html = resp.get("body", "")
    if not isinstance(html, str):
        # JSON response — no HTML params to extract
        return {"forms": [], "query_params": [], "all_params": [], "error": None}

    all_params: set[str] = set()

    # Extract form fields
    forms: list[dict[str, Any]] = []
    form_attrs_list = _RE_FORM.findall(html)  # list of attr strings inside <form ...>
    form_fields  = (
        _RE_INPUT.findall(html)
        + _RE_SELECT.findall(html)
        + _RE_TEXTAREA.findall(html)
    )
    # Exclude submit/button/image/reset inputs that are not injection points
    excluded = {"submit", "button", "image", "reset"}
    form_fields = [f for f in form_fields if f.lower() not in excluded]

    # recover params/endpoints that only exist in JS (ajax/fetch bodies) + whether
    # the endpoint speaks JSON. These are invisible to the <input>/<a href> scan above.
    js_shape = extract_js_request_shape(html)
    js_endpoints = js_shape.get("js_endpoints", [])

    for attrs in (form_attrs_list or [""]):
        action_m = _RE_ACTION.search(attrs)
        method_m = _RE_METHOD.search(attrs)
        action = action_m.group(1) if action_m else path
        method = method_m.group(1).upper() if method_m else ""
        form_type = _classify_form(action, form_fields)
        if not method:
            method = "POST" if (form_type in ("login", "register") or any(k in [f.lower() for f in form_fields] for k in ("password", "passwd", "pwd"))) else "GET"
        if form_type in ("login", "register") and (not action_m or action in ("/", path, "/login.php", "login.php")):
            for ep in js_endpoints:
                if any(w in ep.lower() for w in ("login", "auth", "signin", "register", "ajax")):
                    action = ep
                    method = "POST"
                    break
        forms.append({"action": action, "method": method, "fields": form_fields, "type": form_type})

    all_params.update(form_fields)

    # Extract query params from anchor links
    href_params = _extract_params_from_hrefs(html, base_url)
    all_params.update(href_params)

    # Also check the requested URL itself
    all_params.update(_extract_query_params_from_url(f"{base_url}{path}"))

    # Infer dominant form method (POST beats GET)
    form_method = "GET"
    for f in forms:
        if f.get("method") == "POST":
            form_method = "POST"
            break

    # Surface auth-related forms separately so Navigator/Executor know they exist
    auth_forms = [f for f in forms if f.get("type") in ("login", "register")]

    all_params.update(js_shape["js_params"])
    body_format = "json" if js_shape["json_api"] else form_method_body_format(form_method)

    # WP-plugin CVE class: the vuln surface (admin-ajax.php nopriv action + its params) lives
    # in enqueued external JS. When the page looks WordPress-like, fetch that JS and recover it.
    ext = {"ext_params": [], "ajax_endpoints": [], "ajax_actions": [], "ajax_nonce": "", "is_wp": False}
    if _RE_WP_MARK.search(html):
        ext = discover_external_js_ajax(base_url, html, timeout=min(timeout, 8))
        all_params.update(ext["ext_params"])

    return {
        "forms": forms,
        "auth_forms": auth_forms,
        "query_params": href_params,
        "all_params": sorted(all_params),
        "js_params": js_shape["js_params"],
        "js_endpoints": js_shape["js_endpoints"],
        "json_api": js_shape["json_api"],
        "body_format": body_format,
        "form_method": form_method,
        "requires_auth": len(auth_forms) > 0,
        "ajax_endpoints": ext["ajax_endpoints"],
        "ajax_actions": ext["ajax_actions"],
        "ajax_nonce": ext.get("ajax_nonce", ""),
        "is_wp": ext["is_wp"],
        "error": None,
    }


def form_method_body_format(form_method: str) -> str:
    """Map an HTML form method to a payload body-delivery format hint."""
    return "form" if form_method.upper() == "POST" else "query"
