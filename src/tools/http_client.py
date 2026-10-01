"""HTTP Client Tool - For sending HTTP requests to target web applications."""
from __future__ import annotations

import json
import re
import time
import requests
from typing import Any, Optional
from urllib.parse import urljoin


def http_request(
    base_url: str,
    path: str = "/",
    method: str = "GET",
    params: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
    data: Optional[dict[str, str]] = None,
    json_body: Optional[dict[str, Any]] = None,
    cookies: Optional[dict[str, str]] = None,
    auth: Optional[tuple[str, str]] = None,
    timeout: int = 10,
    max_retries: int = 2,
) -> dict[str, Any]:
    """
    Send HTTP request to target URL.

    Args:
        base_url    : Base URL of target (e.g., "http://localhost:8080")
        path        : URL path (e.g., "/api/users")
        method      : HTTP method (GET, POST, PUT, DELETE, etc.)
        params      : Query parameters
        headers     : Custom headers (Bearer tokens, X-API-Key, etc.)
        data        : Form-encoded body
        json_body   : JSON body (sent as application/json — takes precedence over data)
        cookies     : Cookie dict (session cookies, CSRF tokens, etc.)
        auth        : (username, password) for HTTP Basic auth
        timeout     : Request timeout in seconds
        max_retries : Retry count on Timeout/ConnectionError (default 2, with 1s backoff)
    """
    url = urljoin(base_url, path) if not path.startswith("http") else path
    last_err: dict[str, Any] = {}

    for attempt in range(max_retries + 1):
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                data=data if json_body is None else None,
                json=json_body,
                cookies=cookies,
                auth=auth,
                timeout=timeout,
                verify=False,
            )

            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError):
                body = response.text

            return {
                "status": "success",
                "url": str(response.url),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "body": body,
                "response_time": response.elapsed.total_seconds(),
            }

        except requests.exceptions.Timeout:
            last_err = {
                "status": "error",
                "error_type": "timeout",
                "error_message": f"Request timed out after {timeout}s",
                "attempt": attempt + 1,
            }
        except requests.exceptions.ConnectionError as e:
            last_err = {
                "status": "error",
                "error_type": "connection_error",
                "error_message": f"Connection failed: {str(e)}",
                "attempt": attempt + 1,
            }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "unknown",
                "error_message": str(e),
            }

        if attempt < max_retries:
            time.sleep(1)

    return last_err


def fetch_dynamic_token(base_url: str, dynamic_auth: dict[str, Any]) -> dict[str, Any]:
    """
    POST to a login endpoint, extract a JWT/token, return headers dict for use in http_request.

    CVE config `dynamic_auth` fields:
        login_url       : str   — path to login endpoint  (default "/api/login")
        method          : str   — HTTP method              (default "POST")
        credentials     : dict  — body sent to login endpoint
        content_type    : str   — "json" | "form"          (default "json")
        token_json_key  : str   — key in JSON response containing the token
        token_regex     : str   — regex with group(1) capturing the token (fallback)
        token_header    : str   — request header name      (default "Authorization")
        token_prefix    : str   — prefix before token      (default "Bearer ")
    """
    login_url    = dynamic_auth.get("login_url", "/api/login")
    method       = dynamic_auth.get("method", "POST")
    credentials  = dynamic_auth.get("credentials", {})
    content_type = dynamic_auth.get("content_type", "json")
    token_key    = dynamic_auth.get("token_json_key")
    token_regex  = dynamic_auth.get("token_regex")
    token_header = dynamic_auth.get("token_header", "Authorization")
    token_prefix = dynamic_auth.get("token_prefix", "Bearer ")

    resp = http_request(
        base_url,
        login_url,
        method=method,
        json_body=credentials if content_type == "json" else None,
        data=credentials if content_type == "form" else None,
    )

    if resp.get("status") != "success":
        return {}

    body = resp.get("body")
    token: str | None = None

    if token_key and isinstance(body, dict):
        token = body.get(token_key)
    elif token_regex:
        body_str = body if isinstance(body, str) else json.dumps(body)
        m = re.search(token_regex, body_str)
        if m:
            token = m.group(1)
    elif isinstance(body, dict):
        for candidate in ("token", "access_token", "jwt", "id_token", "auth_token"):
            if candidate in body:
                token = body[candidate]
                break

    if not token:
        return {}

    return {"headers": {token_header: f"{token_prefix}{token}"}}


def build_auth_from_cve_config(
    cve_config: dict[str, Any],
    base_url: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract auth material from CVE config and return kwargs for http_request.

    CVE config fields consumed:
      required_authentication   : bool
      authentication_headers    : dict  — static headers  e.g. {"Authorization": "Bearer <token>"}
      required_cookies          : dict  — static cookies  e.g. {"session": "abc123"}
      basic_auth                : list  — [username, password] for HTTP Basic
      dynamic_auth              : dict  — POST to login endpoint, extract JWT
                                          requires base_url to be passed
    """
    if not cve_config.get("required_authentication"):
        return {}

    kwargs: dict[str, Any] = {}

    # Static auth headers
    auth_headers = cve_config.get("authentication_headers")
    if auth_headers:
        kwargs["headers"] = dict(auth_headers)

    # Static cookies
    required_cookies = cve_config.get("required_cookies")
    if required_cookies:
        kwargs["cookies"] = dict(required_cookies)

    # HTTP Basic auth
    basic_auth = cve_config.get("basic_auth")
    if basic_auth and len(basic_auth) == 2:
        kwargs["auth"] = tuple(basic_auth)

    # Dynamic login — POST creds → extract JWT → inject as Bearer header
    dynamic_auth = cve_config.get("dynamic_auth")
    if dynamic_auth and base_url:
        token_kwargs = fetch_dynamic_token(base_url, dynamic_auth)
        if token_kwargs:
            # Merge dynamic headers on top of any static headers
            existing = kwargs.get("headers", {})
            existing.update(token_kwargs.get("headers", {}))
            kwargs["headers"] = existing

    return kwargs
