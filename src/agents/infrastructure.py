"""
Infrastructure Agent
====================
A *real* LLM-powered agent (not a stub) that:

1. Inspects the target_path directory with the LLM to understand what is there.
2. Uses the LLM to decide the best Docker strategy (compose vs bare Dockerfile).
3. Builds and starts the container(s) via subprocess.
4. Performs a healthcheck loop (LLM-guided retry on failure).
5. Returns a ready-to-attack target_url and full sandbox metadata.

The LLM is used for:
- Analysing the project structure and docker files
- Deciding which command / compose service / exposed port to use
- Diagnosing build/start failures and proposing a fix command
- Composing the final summary for downstream agents
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import hashlib
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm import get_llm
from src.state import PentestState
from src.logging_utils import VerboseLogger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SYSTEM_INFRA = SystemMessage(
    content=(
        "You are an expert DevOps / infrastructure agent embedded inside a "
        "security-research pipeline.  Your job is to analyse Docker project "
        "files, decide how to build and start the target sandbox, and "
        "diagnose failures.  Always respond ONLY with a valid JSON object — "
        "no markdown fences, no preamble."
    )
)

_COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


def _llm_json(messages: list, llm) -> dict:
    """Invoke the LLM and parse the response as JSON."""
    raw = llm.invoke(messages).content.strip()
    # Strip optional ```json … ``` wrapping
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


def _log(logs: list[str], message: str) -> None:
    logs.append(message)
    print(message, flush=True)


def _scan_directory(target_path: str) -> dict[str, str]:
    """Return {relative_path: file_content_or_summary} for relevant files."""
    result: dict[str, str] = {}
    root = Path(target_path)
    interesting = {
        "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.override.yml", "docker-compose.override.yaml",
        "Dockerfile", "Dockerfile.dev", "Dockerfile.prod",
        ".env", ".env.example",
    }
    for fname in interesting:
        fpath = root / fname
        if fpath.exists():
            try:
                content = fpath.read_text(errors="replace")[:4000]  # cap at 4K
                result[fname] = content
            except Exception as exc:
                result[fname] = f"(read error: {exc})"

    # Also list the first two directory levels for context
    tree_lines: list[str] = []
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if any(part.startswith(".") for part in Path(rel).parts):
            continue
        tree_lines.append(rel)
        if len(tree_lines) >= 60:
            tree_lines.append("... (truncated)")
            break
    result["_directory_tree"] = "\n".join(tree_lines)
    return result


def _has_docker_entrypoint(target_path: str) -> bool:
    root = Path(target_path)
    return any(
        (root / name).exists()
        for name in (*_COMPOSE_FILENAMES, "Dockerfile")
    )


def _source_only_blocker(target_path: str, cve_config: dict[str, Any]) -> Optional[str]:
    """
    Explain why a source-only target cannot be started automatically.

    The pipeline can reliably start Dockerfile/compose challenges. A source-only
    CTF archive (no Dockerfile/docker-compose.yml) is not something this pipeline
    can build a sandbox from, so fail early with the raw evidence (the challenge's
    own setup_type/setup_command plus the actual file listing) instead of letting
    the LLM invent a Docker command. This is intentionally generic — it reports
    what is present, not a per-challenge guess at what is missing.
    """
    if _has_docker_entrypoint(target_path):
        return None

    setup_type = str(cve_config.get("setup_type", "")).lower()
    setup_command = str(cve_config.get("setup_command", ""))
    if not setup_type and not setup_command:
        return None

    root = Path(target_path)
    files = sorted(p.name for p in root.iterdir()) if root.exists() else []

    details = [
        "source-only challenge has no Dockerfile or docker-compose.yml",
        f"setup_type={cve_config.get('setup_type', 'N/A')}",
        f"setup_command={setup_command or 'N/A'}",
        f"files_present={files}",
    ]
    return "; ".join(details)


def _compose_service_names(target_path: str) -> list[str]:
    for cmd in (
        ["docker", "compose", "config", "--services"],
        ["docker-compose", "config", "--services"],
    ):
        try:
            rc, stdout, _ = _run(cmd, cwd=target_path, timeout=20)
        except Exception:
            continue
        if rc == 0 and stdout.strip():
            return [line.strip() for line in stdout.splitlines() if line.strip()]
    return []


def _docker_compose_command_prefix() -> Optional[list[str]]:
    """Return the available Docker Compose command prefix, if installed."""
    for prefix in (["docker", "compose"], ["docker-compose"]):
        try:
            proc = subprocess.run(
                [*prefix, "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            continue
        except Exception:
            continue
        if proc.returncode == 0:
            return prefix
    return None


def _container_name_for_path(target_path: str) -> str:
    root = Path(target_path).resolve()
    base = re.sub(r"[^a-z0-9_.-]+", "-", root.name.lower()).strip("-._")
    if not base:
        base = "challenge"
    digest = hashlib.sha1(str(root).encode("utf-8")).hexdigest()[:8]
    return f"pentest-{base[:40]}-{digest}"


def _deterministic_docker_strategy(target_path: str, cve_config: dict[str, Any]) -> Optional[dict[str, Any]]:
    root = Path(target_path)
    has_compose = any((root / f).exists() for f in _COMPOSE_FILENAMES)
    expected_port = cve_config.get("internal_port") or 8080
    if isinstance(expected_port, str):
        match = re.search(r"\d+", expected_port)
        expected_port = int(match.group(0)) if match else 8080
    expected_port = int(expected_port)
    if has_compose:
        compose_prefix = _docker_compose_command_prefix()
        if compose_prefix:
            services = _compose_service_names(target_path)
            service_name = None
            if len(services) == 1:
                service_name = services[0]
            elif "challenge" in services:
                service_name = "challenge"
            return {
                "build_command": [*compose_prefix, "build"],
                "start_command": [*compose_prefix, "up", "-d"],
                "expected_port": expected_port,
                "service_name": service_name,
                "container_name": None,
                "stop_command": [*compose_prefix, "down", "--volumes"],
                "notes": "deterministic: root docker-compose file found",
            }

        runtime_dockerfile = root / ".benchmark_runtime" / "Dockerfile"
        if runtime_dockerfile.exists():
            name = _container_name_for_path(target_path)
            return {
                "build_command": ["docker", "build", "-t", name, "./.benchmark_runtime"],
                "start_command": [
                    "docker", "run", "-d", "-p", str(expected_port),
                    "--name", name, name,
                ],
                "expected_port": expected_port,
                "service_name": None,
                "container_name": name,
                "stop_command": ["docker", "rm", "-f", name],
                "notes": (
                    "deterministic: root docker-compose file found, but Docker Compose "
                    "is unavailable; using synthetic .benchmark_runtime Dockerfile"
                ),
            }
    if (root / "Dockerfile").exists():
        name = "pentest-target"
        return {
            "build_command": ["docker", "build", "-t", name, "."],
            "start_command": [
                "docker", "run", "-d", "-p", f"{expected_port}:{expected_port}",
                "--name", name, name,
            ],
            "expected_port": expected_port,
            "service_name": None,
            "container_name": name,
            "stop_command": ["docker", "rm", "-f", name],
            "notes": "deterministic: root Dockerfile found",
        }
    return None


def _run(cmd: list[str], cwd: str, timeout: int = 300) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    cmd = _normalize_docker_compose_command(cmd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout[-3000:], proc.stderr[-3000:]


def _normalize_docker_compose_command(cmd: list[str]) -> list[str]:
    """
    Prefer Docker Compose v2 (`docker compose`) when available, but fall back to
    Debian's v1 binary (`docker-compose`) if only that is installed.
    """
    if len(cmd) < 2 or cmd[0] != "docker" or cmd[1] != "compose":
        return cmd
    try:
        probe = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        probe = None
    if probe is not None and probe.returncode == 0:
        return cmd
    return ["docker-compose", *cmd[2:]]


def _healthcheck(url: str, retries: int = 10, delay: float = 3.0) -> bool:
    """Poll url until HTTP response or retries exhausted."""
    import urllib.request
    for _ in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=4) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def _extract_host_port(ports: str) -> Optional[int]:
    """Extract the first host port from a Docker ports string."""
    if not ports:
        return None
    for part in re.split(r"\s*,\s*", str(ports).strip()):
        match = re.search(r"(?:0\.0\.0\.0|\[::\]|localhost):(?P<port>\d+)->", part)
        if match:
            return int(match.group("port"))
        match = re.search(r"(?P<port>\d+)->", part)
        if match:
            return int(match.group("port"))
    return None


def _docker_compose_target_url(target_path: str, service_name: Optional[str] = None) -> Optional[str]:
    """Resolve the sandbox target URL from docker compose service port mappings."""
    compose_json_cmds = [
        ["docker", "compose", "ps", "--format", "json"],
        ["docker-compose", "ps", "--format", "json"],
        ["docker", "compose", "ps", "--format", "{{json .}}"],
        ["docker-compose", "ps", "--format", "{{json .}}"],
    ]

    def _parse_json_output(output: str) -> list[dict[str, Any]]:
        if not output:
            return []
        try:
            parsed = json.loads(output)
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            # Try parsing line-delimited JSON objects
            objects: list[dict[str, Any]] = []
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        objects.append(obj)
                except json.JSONDecodeError:
                    continue
            return objects
        return []

    def _resolve_from_containers(containers: list[dict[str, Any]]) -> Optional[str]:
        if not containers:
            return None
        chosen = None
        if service_name:
            for container in containers:
                if str(container.get("Service", "")).strip() == service_name:
                    chosen = container
                    break
        if chosen is None:
            chosen = containers[0]
        ports = chosen.get("Ports", "")
        host_port = _extract_host_port(str(ports))
        if host_port:
            return f"http://localhost:{host_port}"
        return None

    for cmd in compose_json_cmds:
        rc, stdout, stderr = _run(cmd, cwd=target_path, timeout=20)
        if rc != 0:
            continue
        containers = _parse_json_output(stdout)
        target_url = _resolve_from_containers(containers)
        if target_url:
            return target_url

    # Fallback: use service list and docker compose port lookup
    service_cmds = [
        ["docker", "compose", "ps", "--services"],
        ["docker-compose", "ps", "--services"],
        ["docker", "compose", "config", "--services"],
        ["docker-compose", "config", "--services"],
    ]
    services: list[str] = []
    for cmd in service_cmds:
        rc, stdout, stderr = _run(cmd, cwd=target_path, timeout=20)
        if rc != 0 or not stdout.strip():
            continue
        services = [line.strip() for line in stdout.splitlines() if line.strip()]
        if services:
            break

    if service_name:
        services = [service_name] + [s for s in services if s != service_name]

    for service in services:
        for port_cmd in (["docker", "compose", "port", service, "80"],
                         ["docker", "compose", "port", service, "443"],
                         ["docker-compose", "port", service, "80"],
                         ["docker-compose", "port", service, "443"]):
            rc, stdout, stderr = _run(port_cmd, cwd=target_path, timeout=20)
            if rc != 0 or not stdout.strip():
                continue
            match = re.search(r"(?P<host>[^:]+):(?P<port>\d+)", stdout.strip())
            if match:
                host = match.group("host").strip()
                # docker compose port reports the bind address (often 0.0.0.0/::),
                # which is not a reliable connect target — normalize to loopback.
                if host in ("0.0.0.0", "::", "[::]", ""):
                    host = "127.0.0.1"
                return f"http://{host}:{match.group('port')}"

    # Final fallback: parse docker compose ps plain output
    ps_cmds = [
        ["docker", "compose", "ps"],
        ["docker-compose", "ps"],
    ]
    for cmd in ps_cmds:
        rc, stdout, stderr = _run(cmd, cwd=target_path, timeout=20)
        if rc != 0 or not stdout.strip():
            continue
        lines = [line for line in stdout.splitlines() if line.strip()]
        if len(lines) < 2:
            continue
        # Skip header row and parse remaining lines
        for line in lines[1:]:
            parts = re.split(r"\s{2,}", line.strip())
            if not parts:
                continue
            ports = parts[-1] if len(parts) >= 4 else ""
            host_port = _extract_host_port(ports)
            if host_port:
                return f"http://localhost:{host_port}"

    return None


def _docker_inspect_target_url(container_id: str) -> Optional[str]:
    """Resolve the sandbox target URL by inspecting container port mappings."""
    if not container_id:
        return None
    rc, stdout, stderr = _run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container_id],
        cwd=".",
        timeout=20,
    )
    if rc != 0:
        return None
    try:
        ports = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    if isinstance(ports, dict):
        for port_mappings in ports.values():
            if isinstance(port_mappings, list) and port_mappings:
                host_port = port_mappings[0].get("HostPort")
                if host_port:
                    return f"http://localhost:{host_port}"
    return None


# ---------------------------------------------------------------------------
# Main agent node
# ---------------------------------------------------------------------------

def infrastructure_node(state: PentestState) -> dict[str, Any]:  # noqa: C901
    """
    Infrastructure Agent (LLM-powered).

    Flow
    ----
    1. Scan target_path and send file contents to the LLM.
    2. LLM decides: build_command, start_command, expected_port, service_name.
    3. Execute build, then start.
    4. If start fails → LLM diagnoses and proposes a fix command (1 retry).
    5. Healthcheck the URL.
    6. LLM writes a brief summary for downstream agents.
    """
    target_path: str = state.get("target_path") or ""
    logs: list[str] = list(state["execution_logs"])

    if not target_path:
        _log(logs, "[infra] ERROR: no target_path provided.")
        return {"execution_logs": logs, "verbose_logs": [], "status": "failed"}

    if not Path(target_path).is_dir():
        _log(logs, f"[infra] ERROR: '{target_path}' is not a directory.")
        return {"execution_logs": logs, "verbose_logs": [], "status": "failed"}

    _log(logs, f"[infra] scanning target directory: {target_path}")
    cve_config = dict(state.get("cve_config") or {})
    blocker = _source_only_blocker(target_path, cve_config)
    if blocker:
        return _fail(
            state,
            logs,
            (
                "Cannot auto-start this challenge. "
                f"{blocker}. Pick a Docker-backed challenge or add the missing runtime files."
            ),
        )

    # ------------------------------------------------------------------
    # Step 1 – LLM analyses the project files
    # ------------------------------------------------------------------
    scanned = _scan_directory(target_path)
    file_dump = "\n\n".join(
        f"=== {name} ===\n{content}" for name, content in scanned.items()
    )

    analysis_prompt = [
        _SYSTEM_INFRA,
        HumanMessage(
            content=(
                "Analyse the following Docker project files and return a JSON "
                "object with these exact keys:\n\n"
                "  build_command   – list[str] | null  "
                "(e.g. [\"docker\", \"compose\", \"build\"] or null if no build needed)\n"
                "  start_command   – list[str]          "
                "(e.g. [\"docker\", \"compose\", \"up\", \"-d\"])\n"
                "  expected_port   – int                "
                "(the primary HTTP port exposed by the target service)\n"
                "  service_name    – str | null         "
                "(compose service name for the target, or null if bare Dockerfile)\n"
                "  container_name  – str | null         "
                "(optional explicit container name to use with docker run)\n"
                "  stop_command    – list[str]          "
                "(command to stop and clean up, e.g. [\"docker\", \"compose\", \"down\"])\n"
                "  notes           – str                "
                "(brief explanation of your reasoning)\n\n"
                "Project files:\n"
                f"{file_dump}"
            )
        ),
    ]

    llm = None
    analysis = _deterministic_docker_strategy(target_path, cve_config)
    if analysis:
        _log(logs, f"[infra] using deterministic Docker strategy: {analysis['notes']}")
    else:
        llm = get_llm()
        _log(logs, "[infra] LLM analysing project structure …")
        try:
            analysis = _llm_json(analysis_prompt, llm)
        except Exception as exc:
            _log(logs, f"[infra] LLM analysis failed: {exc}. Using fallback strategy.")
            # Fallback: try docker compose up if compose file exists, else docker build + run
            analysis = _deterministic_docker_strategy(target_path, cve_config) or {
                "build_command": ["docker", "build", "-t", "pentest-target", "."],
                "start_command": [
                    "docker", "run", "-d", "-p", "8080:8080",
                    "--name", "pentest-target", "pentest-target",
                ],
                "expected_port": 8080,
                "service_name": None,
                "container_name": "pentest-target",
                "stop_command": ["docker", "rm", "-f", "pentest-target"],
                "notes": "fallback: bare Dockerfile strategy",
            }

    _log(logs, f"[infra] strategy → {analysis.get('notes', '')}")
    _log(logs, f"[infra] build_command : {analysis.get('build_command')}")
    _log(logs, f"[infra] start_command : {analysis.get('start_command')}")
    _log(logs, f"[infra] expected_port : {analysis.get('expected_port', 'unknown')}")

    # ------------------------------------------------------------------
    # Step 2 – Build
    # ------------------------------------------------------------------
    build_cmd = analysis.get("build_command")
    if build_cmd:
        _log(logs, f"[infra] running build: {' '.join(build_cmd)}")
        try:
            rc, stdout, stderr = _run(build_cmd, cwd=target_path, timeout=600)
        except subprocess.TimeoutExpired:
            rc, stdout, stderr = 1, "", "build timeout"

        _log(logs, f"[infra] build exit={rc}")
        if rc != 0:
            logs.append(f"[infra] build stderr (tail): {stderr[-500:]}")
            # LLM diagnoses build failure
            diag = _diagnose_failure(
                llm=llm,
                stage="build",
                command=build_cmd,
                stdout=stdout,
                stderr=stderr,
                target_path=target_path,
            )
            logs.append(f"[infra] LLM diagnosis: {diag.get('explanation', '')}")
            fix_cmd = diag.get("fix_command")
            if fix_cmd:
                logs.append(f"[infra] retrying with fix: {' '.join(fix_cmd)}")
                try:
                    rc2, _, err2 = _run(fix_cmd, cwd=target_path, timeout=600)
                except subprocess.TimeoutExpired:
                    rc2, err2 = 1, "timeout"
                if rc2 != 0:
                    logs.append(f"[infra] fix build also failed: {err2[-300:]}")
                    return _fail(state, logs, "docker build failed after retry")
            else:
                return _fail(state, logs, f"docker build failed: {stderr[-300:]}")
    else:
        _log(logs, "[infra] no build step required, skipping.")

    # ------------------------------------------------------------------
    # Step 3 – Start
    # ------------------------------------------------------------------
    start_cmd: list[str] = analysis.get("start_command") or []
    if not start_cmd:
        return _fail(state, logs, "LLM did not provide a start_command")

    _log(logs, f"[infra] starting sandbox: {' '.join(start_cmd)}")
    try:
        rc, stdout, stderr = _run(start_cmd, cwd=target_path, timeout=120)
    except subprocess.TimeoutExpired:
        rc, stdout, stderr = 1, "", "start timeout"

    _log(logs, f"[infra] start exit={rc}")

    if rc != 0:
        logs.append(f"[infra] start stderr: {stderr[-500:]}")
        diag = _diagnose_failure(
            llm=llm,
            stage="start",
            command=start_cmd,
            stdout=stdout,
            stderr=stderr,
            target_path=target_path,
        )
        logs.append(f"[infra] LLM diagnosis: {diag.get('explanation', '')}")
        fix_cmd = diag.get("fix_command")
        if fix_cmd:
            logs.append(f"[infra] retrying start with fix: {' '.join(fix_cmd)}")
            try:
                rc2, _, err2 = _run(fix_cmd, cwd=target_path, timeout=120)
            except subprocess.TimeoutExpired:
                rc2, err2 = 1, "timeout"
            if rc2 != 0:
                return _fail(state, logs, f"docker start failed after retry: {err2[-300:]}")
        else:
            return _fail(state, logs, f"docker start failed: {stderr[-300:]}")

    _log(logs, "[infra] waiting for Docker mapping to stabilize before resolving URL...")
    time.sleep(10)
    _log(logs, "[infra] resolving sandbox target URL from Docker runtime mapping...")
    command_text = " ".join(start_cmd)
    target_url: Optional[str] = None
    if "docker compose" in command_text or "docker-compose" in command_text:
        target_url = _docker_compose_target_url(target_path, analysis.get("service_name"))
    elif "docker run" in command_text:
        container_id = stdout.strip().splitlines()[-1].strip()
        target_url = _docker_inspect_target_url(container_id)

    if not target_url:
        return _fail(
            state,
            logs,
            "Failed to resolve sandbox target URL from Docker after startup. "
            "Do not assume a default host port."
        )

    # ------------------------------------------------------------------
    # Step 4 – Healthcheck
    # ------------------------------------------------------------------
    _log(logs, f"[infra] waiting for service at {target_url} …")
    healthy = _healthcheck(target_url, retries=15, delay=3.0)
    if not healthy:
        _log(logs, f"[infra] WARNING: healthcheck timed out for {target_url}")
        # Don't hard-fail — service might still be starting; let downstream decide
    else:
        _log(logs, f"[infra] healthcheck passed → {target_url}")

    # ------------------------------------------------------------------
    # Step 5 – LLM summary for downstream agents
    # ------------------------------------------------------------------
    summary_prompt = [
        _SYSTEM_INFRA,
        HumanMessage(
            content=(
                "The Docker sandbox has been started. Summarise what was deployed "
                "so that downstream pentest agents have useful context. "
                "Return a JSON object with keys:\n"
                "  summary       – str (2–4 sentences describing the sandbox)\n"
                "  attack_notes  – str (hints about likely attack surface based on the project)\n\n"
                f"Project notes from analysis: {analysis.get('notes','')}\n"
                f"Target URL: {target_url}\n"
                f"CVE under test: {state.get('cve', 'unknown')}\n"
                f"Directory tree:\n{scanned.get('_directory_tree','')}"
            )
        ),
    ]
    fallback_summary = {
        "summary": f"Docker sandbox running at {target_url}.",
        "attack_notes": cve_config.get("exploit_strategy") or "Refer to the Dockerfile/compose file for service details.",
    }
    try:
        if llm is None:
            llm = get_llm()
        summary = _llm_json(summary_prompt, llm)
        if not summary.get("summary"):
            raise ValueError("LLM summary response missing 'summary' key")
    except Exception as exc:
        _log(logs, f"[infra] LLM summary failed: {exc}. Using fallback summary.")
        summary = fallback_summary

    _log(logs, f"[infra] summary: {summary.get('summary', '')}")

    meta = {
        "target_path": target_path,
        "strategy": analysis,
        "healthy": healthy,
        "summary": summary.get("summary", ""),
        "attack_notes": summary.get("attack_notes", ""),
    }

    return {
        "target_url": target_url,
        "sandbox_meta": meta,
        "execution_logs": logs,
        "verbose_logs": state.get("verbose_logs", []),
        "status": "sandbox_ready",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _diagnose_failure(
    *,
    llm: Any | None,
    stage: str,
    command: list[str],
    stdout: str,
    stderr: str,
    target_path: str,
) -> dict:
    """Ask the LLM to diagnose a build/start failure and propose a fix."""
    prompt = [
        _SYSTEM_INFRA,
        HumanMessage(
            content=(
                f"The Docker {stage} step failed.\n\n"
                f"Command: {' '.join(command)}\n"
                f"Working directory: {target_path}\n\n"
                f"stdout (tail):\n{stdout[-1500:]}\n\n"
                f"stderr (tail):\n{stderr[-1500:]}\n\n"
                "Return a JSON object with:\n"
                "  explanation  – str  (what went wrong, 1–2 sentences)\n"
                "  fix_command  – list[str] | null  "
                "(a single corrected command to retry, or null if unrecoverable)\n"
            )
        ),
    ]
    try:
        if llm is None:
            llm = get_llm()
        return _llm_json(prompt, llm)
    except Exception as exc:
        return {"explanation": f"LLM diagnosis failed: {exc}", "fix_command": None}


def _fail(state: PentestState, logs: list[str], reason: str) -> dict[str, Any]:
    message = f"[infra] FATAL: {reason}"
    logs.append(message)
    print(message, flush=True)
    return {
        "execution_logs": logs,
        "verbose_logs": state.get("verbose_logs", []),
        "status": "failed",
        "last_error": reason,
    }
