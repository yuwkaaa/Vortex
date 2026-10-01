"""
Hidden-parameter discovery (Arjun-style).

`param_discoverer.py` only recovers params that are VISIBLE in the HTML/JS (form
fields, <a href> queries, ajax bodies). Many injection points are parameters the
server processes but never advertises — a `?debug=`, `?id=`, `?file=`, `?admin=`
branch. This tool brute-forces candidate param names and keeps the ones the server
actually reacts to (the canary is reflected, or the response changes vs a baseline
built from a random non-existent param). Prefers the `arjun` binary when present,
else a bounded pure-Python differential probe.

Safety / stable-runtime (the LLM drives this only indirectly, via a path):
- The target URL comes from the pipeline, never from the model.
- Bounded by a wordlist cap + a wall-clock budget so it never blows benchmark runtime.
- arjun args are fixed here.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import string
import subprocess
import time
from typing import Any

from src.tools.http_client import http_request

# Common hidden-parameter names (compact, high-signal; extend via PARAM_WORDLIST file).
_BUILTIN_PARAMS = [
    "id", "page", "file", "path", "dir", "action", "cmd", "exec", "query", "q",
    "search", "s", "keyword", "name", "user", "username", "email", "type", "cat",
    "category", "item", "product", "order", "sort", "filter", "view", "mode",
    "debug", "test", "admin", "role", "token", "key", "api_key", "apikey", "auth",
    "redirect", "url", "next", "return", "callback", "ref", "lang", "locale",
    "format", "output", "json", "xml", "template", "tpl", "include", "inc",
    "load", "read", "download", "upload", "img", "image", "doc", "report",
    "date", "from", "to", "start", "end", "limit", "offset", "count", "size",
    "status", "state", "flag", "value", "data", "content", "message", "msg",
    "code", "hash", "sig", "signature", "session", "sid", "uid", "pid", "gid",
]

_CANARY_LEN = 10


def _canary() -> str:
    return "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=_CANARY_LEN))


def _load_wordlist() -> list[str]:
    path = os.getenv("PARAM_WORDLIST", "") or os.getenv("ARJUN_WORDLIST", "")
    words: list[str] = list(_BUILTIN_PARAMS)
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                extra = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
            words = extra + words
        except OSError:
            pass
    # dedupe, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def _body_str(resp: dict[str, Any]) -> str:
    body = resp.get("body", "")
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body)
    except Exception:
        return str(body)


def _run_arjun(base_url: str, path: str, method: str, maxtime: int) -> dict[str, Any] | None:
    if not shutil.which("arjun"):
        return None
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    import tempfile
    out_fd, out_path = tempfile.mkstemp(prefix="arjun_", suffix=".json")
    os.close(out_fd)
    cmd = ["arjun", "-u", url, "-m", method.upper(), "-oJ", out_path, "-t", "10"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=maxtime + 20, check=False)
    except Exception:  # noqa: BLE001
        return None
    params: list[str] = []
    try:
        data = json.loads(open(out_path, encoding="utf-8").read() or "{}")
        # arjun -oJ maps url -> {"params": [...]} (or a flat list depending on version)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, dict) and isinstance(v.get("params"), list):
                    params.extend(v["params"])
                elif isinstance(v, list):
                    params.extend(v)
        elif isinstance(data, list):
            params.extend(data)
    except Exception:
        pass
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass
    params = sorted({str(p) for p in params if p})
    return {"tool": "arjun", "hidden_params": params, "count": len(params)}


def _python_probe(base_url: str, path: str, method: str, known: set[str],
                  maxtime: int, max_results: int,
                  cookies: dict[str, str] | None = None) -> dict[str, Any]:
    method = method.upper()
    deadline = time.monotonic() + maxtime

    def _send(param_name: str, value: str) -> dict[str, Any]:
        kv = {param_name: value}
        if method == "GET":
            return http_request(base_url, path, method="GET", params=kv,
                                cookies=cookies, timeout=6)
        return http_request(base_url, path, method=method, data=kv,
                            cookies=cookies, timeout=6)

    # Baseline from a random, near-certainly-nonexistent param name.
    base_canary = _canary()
    base_resp = _send(_canary(), base_canary)
    base_ok = base_resp.get("status") == "success"
    base_body = _body_str(base_resp) if base_ok else ""
    base_len = len(base_body)
    base_sc = base_resp.get("status_code", 0)
    base_reflects = base_canary in base_body  # app echoes ANY param -> reflection is useless here

    found: list[dict[str, Any]] = []
    tested = 0
    for name in _load_wordlist():
        if name in known:
            continue
        if time.monotonic() >= deadline or len(found) >= max_results:
            break
        tested += 1
        canary = _canary()
        resp = _send(name, canary)
        if resp.get("status") != "success":
            continue
        body = _body_str(resp)
        sc = resp.get("status_code", 0)
        signal = None
        if not base_reflects and canary in body:
            signal = "reflected"          # strongest: the value came back
        elif sc != base_sc:
            signal = "status_change"      # e.g. param flips 404->200 or 200->500
        elif base_ok and abs(len(body) - base_len) > max(50, int(base_len * 0.15)):
            signal = "length_change"      # response body meaningfully different
        if signal:
            found.append({"param": name, "signal": signal,
                          "status": sc, "length": len(body)})
    return {"tool": "python_probe", "hidden_params": [f["param"] for f in found],
            "details": found, "tested": tested, "count": len(found)}


def discover_hidden_params(
    base_url: str,
    path: str = "/",
    method: str = "GET",
    known_params: list[str] | None = None,
    *,
    cookies: dict[str, str] | None = None,
    maxtime: int | None = None,
    max_results: int = 25,
) -> dict[str, Any]:
    """Find parameters the server processes but does not advertise (Arjun-style).

    Pass `cookies` (the agent's live session) to fuzz post-auth endpoints.
    Returns {"tool", "hidden_params": [...], "details"?, "count", "error"?}.
    """
    maxtime = maxtime or int(os.getenv("PARAM_FUZZ_MAXTIME", "40"))
    known = {p.lower() for p in (known_params or [])}
    try:
        # arjun (external) is unauthenticated here; only use it when no session is needed.
        if not cookies:
            arj = _run_arjun(base_url, path, method, maxtime)
            if arj is not None and arj.get("hidden_params"):
                arj["hidden_params"] = [p for p in arj["hidden_params"] if p.lower() not in known]
                arj["count"] = len(arj["hidden_params"])
                return arj
        return _python_probe(base_url, path, method, known, maxtime, max_results, cookies)
    except Exception as exc:  # noqa: BLE001
        return {"tool": "param_fuzzer", "hidden_params": [], "count": 0, "error": str(exc)}
