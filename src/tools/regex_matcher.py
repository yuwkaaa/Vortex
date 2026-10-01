"""Regex Matcher Tool - For verifying successful exploitation."""
from __future__ import annotations

import re
from typing import Optional


def match_success_pattern(
    response_text: str,
    success_pattern: str,
    case_sensitive: bool = False,
) -> dict:
    """
    Check if response matches the success pattern regex.
    
    Args:
        response_text: Response body from HTTP request
        success_pattern: Regex pattern to match (e.g., r'FLAG{.*}', 'Welcome.*', etc.)
        case_sensitive: Whether to do case-sensitive matching
    
    Returns:
        Dict with match results and captured groups
    """
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        matches = re.findall(success_pattern, response_text, flags)
        
        return {
            "status": "success",
            "pattern": success_pattern,
            "matched": len(matches) > 0,
            "match_count": len(matches),
            "matches": matches,
            "evidence": matches[0] if matches else None,
        }
    except re.error as e:
        return {
            "status": "error",
            "pattern": success_pattern,
            "error_type": "invalid_regex",
            "error_message": str(e),
        }


def check_error_pattern(
    response_text: str,
    error_patterns: Optional[list[str]] = None,
) -> dict:
    """
    Check if response contains error patterns (database errors, etc.).
    
    Args:
        response_text: Response body from HTTP request
        error_patterns: List of error patterns to check for
    
    Returns:
        Dict with error detection results
    """
    if error_patterns is None:
        error_patterns = [
            r"(?:SQL|MySQL|PostgreSQL|MSSQL)\s+(?:syntax\s+)?[Ee]rror",
            r"You have an error in your SQL syntax",
            r"Traceback \(most recent call last\)",
            r"(?:TemplateSyntaxError|TemplateError|UndefinedError):",
            r"(?:Fatal error|Parse error|Uncaught Error):",
            r"(?:Query failed|Query error):",
            r"SQLSTATE\[",
        ]
    
    detected_errors = {}
    for pattern in error_patterns:
        try:
            if re.search(pattern, response_text, re.IGNORECASE):
                detected_errors[pattern] = True
        except re.error:
            pass
    
    return {
        "status": "success",
        "error_detected": len(detected_errors) > 0,
        "detected_errors": list(detected_errors.keys()),
    }
