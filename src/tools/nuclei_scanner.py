"""
Nuclei known-vulnerability template scan.

Generic, target-agnostic recon tool: runs ProjectDiscovery's `nuclei` scanner
against a target URL using its community-maintained template library
(10,000+ templates, many mapped directly to a specific CVE ID), giving the
agent a "known-CVE checklist" signal to complement its own from-scratch
injection probing. This is the framework's only mechanism for recognizing a
*known, previously-disclosed* vulnerability by signature rather than by
re-discovering it through blind injection attempts each run.

Scope: this framework measures INJECTION vulnerabilities specifically (see
README) — the default tag filter is restricted to injection-class templates
so this tool cannot silently pull the agent into unrelated vulnerability
classes (e.g. misconfig, exposed-panels, CVEs with no injection component).

Optional — degrades to an explicit "not available" result if the `nuclei`
binary isn't installed, never blocking the rest of the pipeline (same
opt-degrade pattern as `content_discovery.py`'s ffuf/katana fallbacks).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

# Default template tags — restricted to the injection-vulnerability families this
# framework's own payload_generator.py/injection_prober.py already cover (SQLi,
# command injection, SSTI, XXE, path traversal/LFI, SSRF, NoSQL injection, XSS,
# CRLF/header injection). Override explicitly via the `tags` arg for a deliberate,
# disclosed out-of-scope ablation only — never left implicit.
_DEFAULT_INJECTION_TAGS = (
    "sqli,rce,command-injection,ssti,xxe,lfi,path-traversal,ssrf,nosqli,xss,crlf"
)


def nuclei_scan(
    base_url: str,
    *,
    severity: str = "",   # e.g. "critical,high" — empty = nuclei default (all)
    tags: str = _DEFAULT_INJECTION_TAGS,
    maxtime: int | None = None,
    max_results: int = 50,
) -> dict[str, Any]:
    """Run nuclei against base_url and return matched findings.

    Args:
        base_url   : target URL
        severity   : comma-separated severity filter (info,low,medium,high,critical)
        tags       : comma-separated template tag filter — defaults to this
                     framework's injection-vulnerability scope; pass "" for
                     nuclei's full (unrestricted) template set.
        maxtime    : hard wall-clock cap in seconds (default NUCLEI_MAXTIME env or 120)
        max_results: cap on returned findings
    """
    if not shutil.which("nuclei"):
        return {"tool": "nuclei", "available": False,
                "error": "nuclei binary not found on PATH", "findings": []}

    maxtime = maxtime or int(os.getenv("NUCLEI_MAXTIME", "120"))
    out_fd, out_path = tempfile.mkstemp(prefix="nuclei_", suffix=".jsonl")
    os.close(out_fd)
    cmd = [
        "nuclei", "-u", base_url,
        "-jsonl", "-o", out_path,
        "-silent", "-nc",
        "-timeout", "5",
        "-rate-limit", "50",
    ]
    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=maxtime + 30, check=False)
    except subprocess.TimeoutExpired:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"tool": "nuclei", "available": True, "error": str(exc), "findings": []}

    findings: list[dict[str, Any]] = []
    try:
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = rec.get("info", {}) or {}
                findings.append({
                    "template_id": rec.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": rec.get("matched-at") or rec.get("host"),
                    "cve_ids": (info.get("classification") or {}).get("cve-id"),
                    "description": info.get("description"),
                })
    except Exception:
        pass
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass

    findings = findings[:max_results]
    return {
        "tool": "nuclei", "available": True,
        "findings": findings, "count": len(findings),
        "summary": (f"{len(findings)} known-vulnerability template match(es)" if findings
                    else "no known-CVE/misconfig templates matched"),
    }
