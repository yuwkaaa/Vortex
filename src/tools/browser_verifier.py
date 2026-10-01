"""Headless-browser XSS execution verifier.

HTTP-only tooling (requests/session) can observe that a payload string was
*reflected* or *stored*, but it cannot observe whether that string actually
*executes* as JavaScript — there is no JS engine behind a `requests.get()`.
This module closes that gap with a real (headless) browser, so an XSS claim
can be backed by the same kind of honest, differential evidence the executor
already uses for auth-bypass impact (`confirm_access`): the check either
objectively fires or it doesn't, it is never a self-report.

Optional dependency: this module is only imported when
`ENABLE_HEADLESS_BROWSER=1` is set (see executor.py's `verify_xss` tool), so
Playwright not being installed has ZERO effect on the default baseline.
"""
from __future__ import annotations

import html
import urllib.parse
from typing import Any


def verify_js_execution(
    url: str,
    method: str = "GET",
    data: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    wait_ms: int = 2500,
    timeout_ms: int = 15000,
) -> dict[str, Any]:
    """Load `url` in headless Chromium and report whether an injected payload
    actually ran as JavaScript.

    Detection uses the standard, payload-agnostic XSS canary: a real
    `alert()`/`confirm()`/`prompt()` dialog. Only a genuine JS engine
    executing the injected script can produce one, so `dialog_fired=True`
    is objective proof of execution — not an assumption from response text.

    Args:
        url    : target page.
        method : "GET" appends `data` as a query string; "POST" auto-submits
                 `data` as a real HTML form (so the browser performs a true
                 POST navigation and renders whatever the server sends back,
                 needed for reflected/stored payloads triggered server-side).
        data   : extra query/form fields (the field carrying the payload
                 included).
        cookies: session cookies to carry over, so authenticated /
                 stored-XSS surfaces render the same as for the HTTP tools.
    Returns:
        dict with dialog_fired(bool), dialog_type, dialog_text, page_title,
        console_errors (first 5 console.error messages, diagnostic only).
    """
    from playwright.sync_api import sync_playwright  # optional dep, lazy import

    fired: dict[str, Any] = {"dialog_fired": False, "dialog_type": None, "dialog_text": None}
    console_errors: list[str] = []
    title = ""

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            context = browser.new_context(ignore_https_errors=True)
            if cookies:
                parsed = urllib.parse.urlparse(url)
                context.add_cookies([
                    {"name": k, "value": v, "domain": parsed.hostname, "path": "/"}
                    for k, v in cookies.items()
                ])
            page = context.new_page()

            def _on_dialog(dialog):
                fired["dialog_fired"] = True
                fired["dialog_type"] = dialog.type
                fired["dialog_text"] = dialog.message
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.on("console", lambda m: (
                console_errors.append(m.text) if m.type == "error" and len(console_errors) < 5 else None
            ))

            if method.upper() == "POST" and data:
                inputs = "".join(
                    f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
                    for k, v in data.items()
                )
                stub = (f'<html><body onload="document.forms[0].submit()">'
                        f'<form method="POST" action="{html.escape(url)}">{inputs}</form>'
                        f'</body></html>')
                page.set_content(stub)
                try:
                    page.wait_for_load_state("networkidle", timeout=timeout_ms)
                except Exception:
                    pass
            else:
                target = url
                if data:
                    sep = "&" if "?" in url else "?"
                    target = url + sep + urllib.parse.urlencode(data)
                page.goto(target, timeout=timeout_ms, wait_until="domcontentloaded")

            page.wait_for_timeout(wait_ms)
            try:
                title = page.title()
            except Exception:
                title = ""
        finally:
            browser.close()

    return {
        "dialog_fired": fired["dialog_fired"],
        "dialog_type": fired["dialog_type"],
        "dialog_text": (fired["dialog_text"] or "")[:200],
        "page_title": title,
        "console_errors": console_errors,
    }
