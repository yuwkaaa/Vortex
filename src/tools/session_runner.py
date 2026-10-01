"""
Multi-step session runner.

Executes an ordered sequence of HTTP requests where later steps can reference
values extracted from earlier responses (tokens, cookies, CSRF values).
Each step is a dict matching the StepConfig schema below.

Example step sequence (login → exploit):
  steps = [
    {
      "name": "login",
      "method": "POST",
      "path": "/login",
      "data": {"username": "admin", "password": "admin"},
      "extract": {"csrf_token": r'name="csrfmiddlewaretoken" value="([^"]+)"'},
      "store_cookies": True,
    },
    {
      "name": "exploit",
      "method": "GET",
      "path": "/search",
      "params": {"q": "{payload}"},   # {payload} is replaced at runtime
      "use_cookies": True,
      "inject_extracted": True,        # merges extracted vars into params/data
    },
  ]
"""
from __future__ import annotations

import re
import json
import time
from typing import Any

import requests
from urllib.parse import urljoin


class SessionRunner:
    """Stateful multi-request executor."""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.extracted: dict[str, str] = {}   # values pulled from prior responses

    def run(
        self,
        steps: list[dict[str, Any]],
        payload: str = "",
    ) -> list[dict[str, Any]]:
        """
        Execute all steps in order.  Returns a list of result dicts, one per step.
        Stops early and marks remaining steps as skipped if a step fails critically.
        """
        results: list[dict[str, Any]] = []

        for step in steps:
            result = self._execute_step(step, payload)
            results.append(result)
            if result.get("status") == "error" and step.get("required", True):
                # Mark remaining steps as skipped
                for remaining in steps[steps.index(step) + 1:]:
                    results.append({
                        "name": remaining.get("name", "unnamed"),
                        "status": "skipped",
                        "reason": f"prior step '{step.get('name')}' failed",
                    })
                break

        return results

    def _execute_step(self, step: dict[str, Any], payload: str) -> dict[str, Any]:
        name   = step.get("name", "unnamed")
        method = step.get("method", "GET").upper()
        path   = step.get("path", "/")

        # Substitute {payload} and extracted vars into params/data
        params = self._substitute(step.get("params"), payload)
        data   = self._substitute(step.get("data"), payload)
        hdrs   = dict(step.get("headers") or {})
        if step.get("inject_extracted"):
            params = {**(params or {}), **self.extracted}

        url = urljoin(self.base_url, path) if not path.startswith("http") else path

        try:
            t0 = time.monotonic()
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=hdrs or None,
                timeout=self.timeout,
            )
            elapsed = time.monotonic() - t0

            try:
                body = resp.json()
                body_text = json.dumps(body)
            except Exception:
                body = resp.text
                body_text = resp.text

            # Extract values from this response for later steps
            for var_name, pattern in (step.get("extract") or {}).items():
                m = re.search(pattern, body_text)
                if m:
                    self.extracted[var_name] = m.group(1) if m.lastindex else m.group(0)

            # Optionally save cookies from this response
            if step.get("store_cookies"):
                self.session.cookies.update(resp.cookies)

            return {
                "name": name,
                "status": "success",
                "status_code": resp.status_code,
                "url": resp.url,
                "body": body,
                "response_time": round(elapsed, 3),
                "extracted": dict(self.extracted),
            }

        except requests.exceptions.Timeout:
            return {"name": name, "status": "error", "error_type": "timeout",
                    "error_message": f"step '{name}' timed out after {self.timeout}s"}
        except requests.exceptions.ConnectionError as e:
            return {"name": name, "status": "error", "error_type": "connection_error",
                    "error_message": str(e)}
        except Exception as e:
            return {"name": name, "status": "error", "error_type": "unknown",
                    "error_message": str(e)}

    def _substitute(
        self,
        mapping: dict[str, str] | None,
        payload: str,
    ) -> dict[str, str] | None:
        if not mapping:
            return mapping
        result = {}
        for k, v in mapping.items():
            v = v.replace("{payload}", payload)
            for var, val in self.extracted.items():
                v = v.replace(f"{{{var}}}", val)
            result[k] = v
        return result


def run_steps(
    base_url: str,
    steps: list[dict[str, Any]],
    payload: str = "",
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Convenience wrapper — creates a fresh SessionRunner and executes steps."""
    runner = SessionRunner(base_url=base_url, timeout=timeout)
    return runner.run(steps, payload=payload)
