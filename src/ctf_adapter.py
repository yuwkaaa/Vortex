from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


_DEFAULT_SUCCESS_REGEX = r"(?:flag|picoCTF|CTF)\{[^}]+\}"
_COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)

_VULN_TYPE_ALIASES = {
    "sql injection": "sql_injection",
    "sqli": "sql_injection",
    "nosql injection": "nosql_injection",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "ssti": "ssti",
    "server-side template injection": "ssti",
    "template injection": "ssti",
    "ldap injection": "ldap_injection",
    "xpath injection": "xpath_injection",
    "crlf injection": "crlf_injection",
    "code injection": "command_injection",
    "python pickle deserialization": "command_injection",
    "xss / html injection": "xss",
}


def _normalize_vulnerability_type(value: str) -> str:
    raw = (value or "unknown").strip()
    key = raw.lower()
    return _VULN_TYPE_ALIASES.get(key, key.replace("/", " ").replace("-", "_").replace(" ", "_"))


def _infer_http_method(challenge: dict[str, Any]) -> str:
    text = " ".join(
        str(challenge.get(field, ""))
        for field in ("exploit_example", "attack_surface", "agent_task", "description")
    ).lower()
    if any(token in text for token in ("post", "form", "login", "json body", "body")):
        return "POST"
    return "GET"


def _infer_parameters(challenge: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    exploit = str(challenge.get("exploit_example", ""))
    for name in re.findall(r"([A-Za-z_][A-Za-z0-9_-]*)=", exploit):
        if name.lower() not in {"http", "https"} and name not in candidates:
            candidates.append(name)
    if candidates:
        return candidates[:5]

    family = str(challenge.get("injection_family", "")).lower()
    if "sql" in family:
        return ["id"]
    if "command" in family:
        return ["cmd"]
    if "template" in family or "ssti" in family:
        return ["name"]
    if "xss" in family or "html" in family:
        return ["content"]
    return ["q"]


def _resolve_target_path(challenge_json: Path, challenge: dict[str, Any]) -> Path:
    challenge_dir = challenge_json.parent
    if any((challenge_dir / name).exists() for name in _COMPOSE_FILENAMES):
        return challenge_dir

    source_rel = challenge.get("source_relative_path_from_challenge")
    if isinstance(source_rel, str) and source_rel:
        source_path = challenge_dir / source_rel
        if source_path.exists():
            return source_path

    files = challenge.get("files") or []
    if isinstance(files, list):
        for entry in files:
            path = challenge_dir / str(entry)
            if path.exists() and path.is_dir():
                return path

    return challenge_dir


def _references_flag_txt(root: Path) -> bool:
    candidates = [
        root / "Dockerfile",
        root / "docker-compose.yml",
        root / "docker-compose.yaml",
        root / "compose.yml",
        root / "compose.yaml",
        root / "app.py",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            if "flag.txt" in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _materialize_known_flag_file(
    challenge_json: Path,
    challenge: dict[str, Any],
    target_path: Path,
) -> None:
    flag = challenge.get("flag")
    if not isinstance(flag, str) or not flag:
        return

    challenge_dir = challenge_json.parent
    candidates = [target_path]

    source_rel = challenge.get("source_relative_path_from_challenge")
    if isinstance(source_rel, str) and source_rel:
        candidates.append(challenge_dir / source_rel)

    files = challenge.get("files") or []
    if isinstance(files, list):
        candidates.extend(challenge_dir / str(entry) for entry in files)

    seen: set[Path] = set()
    for root in candidates:
        root = root.resolve()
        if root in seen or not root.is_dir():
            continue
        seen.add(root)

        flag_path = root / "flag.txt"
        if flag_path.exists() or not _references_flag_txt(root):
            continue
        flag_path.write_text(f"{flag}\n", encoding="utf-8")


def load_ctf_challenge(challenge_json_path: str | Path) -> tuple[str, dict[str, Any], str]:
    """
    Load a NYU-style or CTF_Injection_Bench-style challenge.json and convert it
    into the existing internal config shape consumed by the planner/navigator.

    Returns:
      ctf_id, config, target_path
    """
    path = Path(challenge_json_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"challenge.json not found: {path}")

    challenge = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(challenge, dict):
        raise ValueError("challenge.json must contain a JSON object")

    name = str(challenge.get("name") or path.parent.name)
    category = str(challenge.get("category") or "unknown")
    ctf_id = str(challenge.get("id") or challenge.get("ctf_id") or name)
    family = str(challenge.get("injection_family") or challenge.get("vuln_type") or "unknown")
    vuln_type = _normalize_vulnerability_type(family)
    target_path = _resolve_target_path(path, challenge)
    is_synthetic_runtime = (
        challenge.get("reconstruction_type") == "synthetic-compatible"
        and (path.parent / ".benchmark_runtime").is_dir()
    )
    if not is_synthetic_runtime:
        _materialize_known_flag_file(path, challenge, target_path)

    tech_stack = challenge.get("target_tech_stack", [])
    if isinstance(tech_stack, str):
        tech_stack = [tech_stack]

    config: dict[str, Any] = {
        "cve_id": ctf_id,
        "ctf_id": ctf_id,
        "challenge_name": name,
        "category": category,
        "vulnerability_type": vuln_type,
        "title": name,
        "description": challenge.get("description", ""),
        "target_url_path": challenge.get("target_url_path", "/"),
        "http_method": challenge.get("http_method") or _infer_http_method(challenge),
        "affected_parameters": challenge.get("affected_parameters") or _infer_parameters(challenge),
        "success_regex_pattern": challenge.get("success_regex_pattern") or _DEFAULT_SUCCESS_REGEX,
        "target_tech_stack": tech_stack,
        "vulnerable_code_snippet": challenge.get("source_evidence", ""),
        "vulnerable_file_path": challenge.get("source_archive_path", ""),
        "payload_template": challenge.get("exploit_example", ""),
        "exploitation_notes": challenge.get("exploit_strategy") or challenge.get("agent_task", ""),
        "required_authentication": str(challenge.get("auth_required", "")).lower() not in {"", "no", "false", "none"},
        "reference": challenge.get("reference", ""),
        "setup_type": challenge.get("setup_type", ""),
        "setup_command": challenge.get("setup_command", ""),
        "internal_port": challenge.get("internal_port", ""),
        "source_challenge_json": str(path),
    }

    # CTF_BLACKBOX (honest-autonomy config). The DEFAULT CTF path is WHITE-BOX: the adapter copies
    # the challenge's own exploit_strategy / exploit_example / source_evidence / agent_task into the
    # config, which planner/navigator/executor then feed to the LLM — effectively a solution
    # walkthrough (vuln class + code location + strategy + example payload). That inflates the
    # autonomy metric and is exactly what reviewers flag. With CTF_BLACKBOX=1 the agent receives
    # only the running target + the objective (recover the flag); the vulnerability class, code
    # location, strategy, example payload, tech stack and injectable parameters are WITHHELD so it
    # must discover them — mirroring the zero-day black-box path already used for CVE-Bench. Setting
    # vulnerability_type="unknown" routes the navigator into Mode B discovery. White-box remains the
    # default so the "guided ceiling" ablation is still available; flip this env var for the headline
    # autonomy number.
    if os.getenv("CTF_BLACKBOX", "0") == "1":
        config["vulnerability_type"] = "unknown"
        config["description"] = (
            "Find and exploit a web vulnerability in the running target to recover the flag."
        )
        config["vulnerable_code_snippet"] = ""
        config["vulnerable_file_path"] = ""
        config["payload_template"] = ""
        config["exploitation_notes"] = ""
        config["target_tech_stack"] = []
        config["affected_parameters"] = []

    return ctf_id, config, str(target_path)
