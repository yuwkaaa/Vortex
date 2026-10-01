"""PoC Generator Agent - Generates final exploitation report."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from src.state import PentestState
from src.logging_utils import VerboseLogger


def _render_markdown_report(state: PentestState) -> str:
    """Generate markdown report of exploitation attempt."""
    cve_id = state.get("cve", "UNKNOWN")
    cve_config = state.get("cve_config", {})
    target_url = state.get("target_url", "")
    status = state.get("status", "unknown")
    
    plan = state.get("plan", "")
    recon = state.get("recon", "")
    poc = state.get("poc", "")
    
    logs = state.get("execution_logs", [])
    logs_text = "\n".join(f"- {line}" for line in logs[-50:])

    verbose_logs = state.get("verbose_logs", [])
    verbose_text = "\n\n".join(verbose_logs) if verbose_logs else "(No detailed logs)"

    cve_summary = ""
    if cve_config:
        cve_summary = f"""
### CVE Details

| Field | Value |
|-------|-------|
| CVE ID | {cve_config.get('cve_id', cve_id)} |
| CWE ID | {cve_config.get('cwe_id', 'N/A')} |
| CVSS Score | {cve_config.get('cvss_score', 'N/A')} |
| Vulnerability Type | {cve_config.get('vulnerability_type', 'N/A')} |
| Title | {cve_config.get('title', 'N/A')} |
| Affected Component | {cve_config.get('affected_component', 'N/A')} |
| Target Tech Stack | {', '.join(cve_config.get('target_tech_stack', [])) or 'N/A'} |
"""
    
    blind_evidence_entries = [
        r for r in state.get("attempt_history", [])
        if r.get("error_type") == "none" and "blind" in r.get("verdict", "").lower()
    ]
    blind_from_poc = ""
    if poc and "Blind Injection Type" in poc:
        blind_from_poc = poc

    success_indicator = "✅ SUCCESSFUL" if status == "exploited" else "❌ FAILED"
    
    return f"""# Automated Penetration Testing Report

**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

---

## Executive Summary

- **CVE**: {cve_id}
- **Target URL**: `{target_url}`
- **Status**: {success_indicator}
- **Exploitation Outcome**: {status}

{cve_summary}

---

## Attack Surface

### Target Information

- **URL Path**: {cve_config.get('target_url_path', 'N/A')}
- **HTTP Method**: {cve_config.get('http_method', 'N/A')}
- **Affected Parameters**: {', '.join(cve_config.get('affected_parameters', [])) or 'N/A'}
- **Authentication Required**: {cve_config.get('required_authentication', False)}

### Vulnerable Code

```
{cve_config.get('vulnerable_code_snippet', 'N/A')}
```

**Vulnerable File**: `{cve_config.get('vulnerable_file_path', 'N/A')}`

---

## Exploitation Plan

{plan or '(No plan generated)'}

---

## Reconnaissance Findings

{recon or '(No reconnaissance data)'}

---

## Exploitation Execution

### Proof of Concept

{poc or '(No PoC data)'}

### Blind Injection Evidence

{blind_from_poc if blind_from_poc else '(No blind injection evidence — either regex match succeeded or injection was not confirmed via probing)'}

### Success Pattern Regex

```
{cve_config.get('success_regex_pattern', 'N/A')}
```

### Patch Recommendation

```diff
{cve_config.get('patch_diff', 'N/A')}
```

---

## Execution Trace (Detailed Agent Output)

{verbose_text}

---

## Execution Logs (Summary)

{logs_text or '(No logs)'}

---

## Recommendations

### Immediate Actions

1. Apply security patch (see Patch Recommendation above)
2. Review all user input handling in affected component
3. Implement parameterized queries/statements
4. Add input validation and output encoding

### Long-term Improvements

- Implement Web Application Firewall (WAF)
- Regular security code review process
- Automated vulnerability scanning in CI/CD
- Security training for development team
- Penetration testing on schedule

---

## Report Information

- **Test Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
- **Report Version**: 1.0
- **System**: Multi-Agent Penetration Testing System

---
"""


def _write_report(markdown: str, *, out_dir: str = "reports") -> str:
    """Write report to markdown file with timestamp."""
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(out_dir, f"report_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown)
    return path


def poc_generator_node(state: PentestState) -> dict[str, Any]:
    """Generate final markdown report of exploitation attempt."""
    logger = VerboseLogger()
    logger.log_node_start("poc_generator")
    
    logger.log_thought(
        "Generating final penetration testing report. Combining all agent outputs "
        "(plan, recon, execution results) into markdown documentation."
    )
    
    logger.log_action("render_markdown_report", {"state_keys": list(state.keys())})
    
    report_md = _render_markdown_report(state)
    
    logger.log_observation({
        "report_generated": True,
        "report_length": len(report_md),
        "sections": ["Executive Summary", "CVE Details", "Exploitation Plan", "Recon Findings", "PoC", "Recommendations"],
    })
    
    logger.log_action("write_report", {"output_directory": "reports"})
    
    report_path = _write_report(report_md)
    
    logger.log_observation({
        "report_saved": True,
        "path": report_path,
    })
    
    logs = list(state["execution_logs"])
    logs.append(f"[poc-generator] report written to {report_path}")
    
    verbose_logs = state.get("verbose_logs", [])
    verbose_logs.append(logger.get_logs())
    
    logger.log_state_update({
        "status": "reported",
        "report_path": report_path,
    })
    
    print(logger.get_logs())  # Print verbose output
    
    return {
        "report_markdown": report_md,
        "report_path": report_path,
        "execution_logs": logs,
        "verbose_logs": verbose_logs,
        "status": "reported",
    }

