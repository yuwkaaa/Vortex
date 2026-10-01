"""
Content / endpoint discovery.

The agent used to *guess* paths (/login, /admin, …) which made real targets (esp.
CVE-Bench apps with a specific vulnerable file like payroll_items.php) a coin flip.
This tool brute-forces hidden endpoints with ffuf (falling back to a small built-in
pure-Python probe), so Navigator/Executor work from a real map instead of luck.

Safety (LLM drives this indirectly):
- The target URL comes from the pipeline, never from the model.
- ffuf args are fixed here; the only model-supplied input (extensions) is whitelisted.
- Bounded by a wordlist cap + `-maxtime` so it never blows the benchmark runtime.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.tools.http_client import http_request


# First existing wins; override with FFUF_WORDLIST.
_WORDLIST_CANDIDATES = [
    os.getenv("FFUF_WORDLIST", ""),
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# Tiny built-in fallback when no wordlist/ffuf is available (better than nothing).
_BUILTIN_PATHS = [
    "admin", "administrator", "login", "logout", "register", "signup", "dashboard",
    "home", "index.php", "user", "users", "profile", "account", "search", "api",
    "api/login", "config", "config.php", "upload", "uploads", "files", "file",
    "download", "export", "import", "report", "reports", "view", "edit", "delete",
    "list", "data", "db", "sql", "query", "console", "phpinfo.php", "info.php",
    "server-status", "backup", "test", "debug", "settings", "setup", "install",
    "manage", "panel", "cpanel", "secret", "flag", "static", "assets", "images",
]

_SAFE_EXT = re.compile(r"^\.?[A-Za-z0-9]{1,6}$")
_MATCH_CODES = "200,201,204,301,302,307,308,401,403,405,500"


def _pick_wordlist() -> str | None:
    for cand in _WORDLIST_CANDIDATES:
        if cand and os.path.isfile(cand):
            return cand
    return None


def _sanitize_extensions(extensions: str | list[str] | None) -> list[str]:
    if not extensions:
        return []
    items = extensions.split(",") if isinstance(extensions, str) else list(extensions)
    out: list[str] = []
    for e in items:
        e = e.strip()
        if e and _SAFE_EXT.match(e):
            out.append(e if e.startswith(".") else f".{e}")
    return out[:5]


def _run_ffuf(base_url: str, wordlist: str, extensions: list[str], maxtime: int, max_results: int) -> dict[str, Any]:
    fuzz_url = urljoin(base_url + "/", "FUZZ")
    out_fd, out_path = tempfile.mkstemp(prefix="ffuf_", suffix=".json")
    os.close(out_fd)
    cmd = [
        "ffuf", "-u", fuzz_url, "-w", wordlist,
        "-mc", _MATCH_CODES,
        "-ac",                      # auto-calibrate to drop catch-all false positives
        "-t", "40",
        "-timeout", "5",
        "-maxtime", str(maxtime),
        "-of", "json", "-o", out_path,
        "-s",
    ]
    if extensions:
        cmd += ["-e", ",".join(extensions)]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=maxtime + 30, check=False)
    except subprocess.TimeoutExpired:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"tool": "ffuf", "error": str(exc), "endpoints": []}

    endpoints: list[dict[str, Any]] = []
    try:
        data = json.loads(open(out_path, encoding="utf-8").read() or "{}")
        for r in data.get("results", []):
            path = (r.get("input", {}) or {}).get("FUZZ") or r.get("url", "")
            endpoints.append({
                "path": "/" + str(path).lstrip("/"),
                "status": r.get("status"),
                "length": r.get("length"),
            })
    except Exception:
        pass
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass

    endpoints = endpoints[:max_results]
    return {"tool": "ffuf", "wordlist": wordlist, "endpoints": endpoints, "count": len(endpoints)}


def _run_python_probe(base_url: str, paths: list[str], max_results: int) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    for p in paths:
        resp = http_request(base_url, "/" + p.lstrip("/"), method="GET", timeout=5)
        if resp.get("status") != "success":
            continue
        sc = resp.get("status_code", 0)
        if sc and sc not in (404,):
            body = resp.get("body", "")
            found.append({"path": "/" + p.lstrip("/"), "status": sc,
                          "length": len(body) if isinstance(body, str) else None})
        if len(found) >= max_results:
            break
    return {"tool": "python_probe", "endpoints": found, "count": len(found)}


_HREF_RE = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"'#>\s]+)""", re.IGNORECASE)


def _run_katana(base_url: str, cookies: dict[str, str] | None, depth: int, maxtime: int, max_results: int) -> dict[str, Any]:
    host = urlparse(base_url).netloc
    cmd = ["katana", "-u", base_url, "-d", str(depth), "-silent", "-nc", "-jc"]
    if cookies:
        cmd += ["-H", "Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items())]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=maxtime + 30, check=False)
    except subprocess.TimeoutExpired as e:
        proc = e  # partial stdout below
    except Exception as exc:  # noqa: BLE001
        return {"tool": "katana", "error": str(exc), "endpoints": []}
    seen: dict[str, dict[str, Any]] = {}
    for line in (getattr(proc, "stdout", "") or "").splitlines():
        u = line.strip()
        if not u:
            continue
        pr = urlparse(u)
        if pr.netloc and pr.netloc != host:
            continue
        path = pr.path or "/"
        seen.setdefault(path, {"path": path, "status": None})
    return {"tool": "katana", "endpoints": list(seen.values())[:max_results], "count": len(seen)}


def _python_crawl(base_url: str, cookies: dict[str, str] | None, depth: int, max_pages: int) -> dict[str, Any]:
    host = urlparse(base_url).netloc
    sess = requests.Session()
    if cookies:
        sess.cookies.update(cookies)
    seen: set[str] = set()
    found: dict[str, int] = {}
    queue: list[tuple[str, int]] = [(base_url.rstrip("/") + "/", 0)]
    while queue and len(seen) < max_pages:
        url, d = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = sess.get(url, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            continue
        pr = urlparse(r.url)
        if pr.netloc == host:
            found[pr.path or "/"] = r.status_code
        if d < depth and "text/html" in r.headers.get("Content-Type", ""):
            for href in _HREF_RE.findall(r.text):
                nu = urljoin(r.url, href)
                if urlparse(nu).netloc == host and nu not in seen:
                    queue.append((nu, d + 1))
    return {"tool": "python_crawl", "endpoints": [{"path": k, "status": v} for k, v in found.items()], "count": len(found)}


def crawl_site(
    base_url: str,
    *,
    cookies: dict[str, str] | None = None,
    depth: int = 2,
    max_pages: int = 50,
    maxtime: int | None = None,
) -> dict[str, Any]:
    """Crawl linked pages (katana if available, else a bounded Python BFS).

    Pass `cookies` (e.g. the agent's live session) to crawl POST-auth pages —
    that is how app-specific files linked only from a logged-in menu (e.g.
    payroll_items.php) get discovered, which ffuf wordlists miss.
    """
    maxtime = maxtime or int(os.getenv("CONTENT_DISCOVERY_MAXTIME", "60"))
    if shutil.which("katana"):
        return _run_katana(base_url, cookies, depth, maxtime, max_pages)
    return _python_crawl(base_url, cookies, depth, max_pages)


def discover_content(
    base_url: str,
    *,
    extensions: str | list[str] | None = None,
    maxtime: int | None = None,
    max_results: int = 60,
) -> dict[str, Any]:
    """Discover hidden endpoints on base_url. Prefers ffuf+seclists; falls back to Python probe."""
    maxtime = maxtime or int(os.getenv("CONTENT_DISCOVERY_MAXTIME", "60"))
    exts = _sanitize_extensions(extensions)
    wordlist = _pick_wordlist()

    if shutil.which("ffuf") and wordlist:
        return _run_ffuf(base_url, wordlist, exts, maxtime, max_results)

    # Fallback: probe a small built-in list (+ extension variants).
    paths = list(_BUILTIN_PATHS)
    for e in exts:
        paths += [f"index{e}", f"admin{e}", f"login{e}", f"search{e}"]
    return _run_python_probe(base_url, paths, max_results)
