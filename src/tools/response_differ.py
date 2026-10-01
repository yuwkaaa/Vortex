"""
Response differ.

Diffs two HTTP response bodies to surface meaningful content differences.
Used by the executor to detect boolean-based blind injection without a regex.
"""
from __future__ import annotations

import difflib
import re
from typing import Any


def diff_responses(
    response_a: str,
    response_b: str,
    label_a: str = "true_condition",
    label_b: str = "false_condition",
    context_lines: int = 2,
) -> dict[str, Any]:
    """
    Compare two response bodies and return a structured diff summary.

    Returns:
      identical         : bool
      length_a          : int
      length_b          : int
      length_delta      : int
      length_delta_pct  : float
      changed_lines     : int  — number of lines that differ
      diff_preview      : str  — first 500 chars of unified diff
      significant       : bool — True if differences are likely injection-induced
    """
    lines_a = response_a.splitlines(keepends=True)
    lines_b = response_b.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile=label_a, tofile=label_b,
        n=context_lines,
    ))

    len_a = len(response_a)
    len_b = len(response_b)
    len_delta = abs(len_a - len_b)
    avg = (len_a + len_b) / 2 if (len_a + len_b) > 0 else 1
    len_delta_pct = len_delta / avg * 100

    changed_lines = sum(1 for line in diff if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))

    diff_text = "".join(diff)
    diff_preview = diff_text[:500] + ("..." if len(diff_text) > 500 else "")

    # Heuristic: significant if length differs by >5% OR more than 3 lines changed
    significant = len_delta_pct > 5.0 or changed_lines > 3

    return {
        "identical": response_a == response_b,
        "length_a": len_a,
        "length_b": len_b,
        "length_delta": len_delta,
        "length_delta_pct": round(len_delta_pct, 1),
        "changed_lines": changed_lines,
        "diff_preview": diff_preview,
        "significant": significant,
    }


def extract_unique_content(
    response_a: str,
    response_b: str,
) -> dict[str, Any]:
    """
    Return content present in response_a but NOT in response_b (injection output).
    Useful when one response contains extra database data the other doesn't.
    """
    lines_a = set(response_a.splitlines())
    lines_b = set(response_b.splitlines())

    unique_to_a = lines_a - lines_b
    unique_to_b = lines_b - lines_a

    # Filter out trivial whitespace-only lines
    unique_to_a = {l for l in unique_to_a if l.strip()}
    unique_to_b = {l for l in unique_to_b if l.strip()}

    return {
        "unique_to_a": sorted(unique_to_a)[:20],
        "unique_to_b": sorted(unique_to_b)[:20],
        "injection_evidence": sorted(unique_to_a)[:5],
    }
