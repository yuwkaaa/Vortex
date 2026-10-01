from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


def _run_quiet(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode, (proc.stdout + proc.stderr)[-1200:]
    except Exception as exc:
        return 1, str(exc)


def _compose_commands() -> list[list[str]]:
    return [
        ["docker", "compose", "down", "--volumes", "--rmi", "local", "--remove-orphans"],
        ["docker-compose", "down", "--volumes", "--rmi", "local", "--remove-orphans"],
    ]


def _docker_disk_usage() -> str:
    rc, out = _run_quiet(["docker", "system", "df"])
    if rc == 0 and out.strip():
        return out.strip()
    return "docker system df unavailable"


def _image_tags_for_target(target_path: str | None) -> list[str]:
    tags = ["pentest-target"]
    if not target_path:
        return tags
    root = Path(target_path)
    try:
        compose_text = ""
        for name in ("docker-compose.yml", "docker-compose.yaml"):
            path = root / name
            if path.exists():
                compose_text += "\n" + path.read_text(errors="ignore")
        for match in re.finditer(r"container_name:\s*['\"]?([A-Za-z0-9_.-]+)", compose_text):
            tags.append(match.group(1))
    except Exception:
        pass
    return sorted(set(tags))


def _remove_known_containers_and_images(target_path: str | None, messages: list[str]) -> None:
    names = _image_tags_for_target(target_path)
    for name in names:
        for cmd in (
            ["docker", "rm", "-f", name],
            ["docker", "rmi", "-f", name],
        ):
            rc, _ = _run_quiet(cmd)
            if rc == 0:
                messages.append(f"[cleanup] ok: {' '.join(cmd)}")


def _prune_runtime_storage(messages: list[str]) -> None:
    commands = [
        (["docker", "container", "prune", "-f"], "stopped containers pruned"),
        (["docker", "volume", "prune", "-f"], "dangling volumes pruned"),
        (["docker", "network", "prune", "-f"], "unused networks pruned"),
        (["docker", "image", "prune", "-f"], "dangling images pruned"),
    ]
    for cmd, ok_msg in commands:
        rc, out = _run_quiet(cmd)
        if rc == 0:
            messages.append(f"[cleanup] {ok_msg}")
        else:
            messages.append(f"[cleanup] {' '.join(cmd)} failed: {out}")


def cleanup_target_runtime(target_path: str | None, *, logs: list[str] | None = None) -> list[str]:
    """Best-effort cleanup for the Docker runtime *started by the pipeline*.

    Only the Infrastructure agent brings up a sandbox, and only when a
    ``target_path`` (``--target-path`` / ``--challenge-json``) is provided. In
    ``--target-url`` mode the target is managed by an external harness (a benchmark
    runner such as CVE-Bench's ``./run`` or a manually started third-party target), so the
    pipeline must NOT prune Docker: a global ``docker … prune -f`` would destroy
    containers, volumes and networks it never created — including the live target
    under test — and even leak into other users' Docker state.
    """
    if os.getenv("AUTO_CLEANUP", "1") == "0":
        if logs is not None:
            logs.append("[cleanup] skipped because AUTO_CLEANUP=0")
        return ["[cleanup] skipped because AUTO_CLEANUP=0"]

    if not target_path:
        message = (
            "[cleanup] skipped: no pipeline-managed sandbox (external --target-url target); "
            "not pruning Docker to avoid destroying externally-managed containers"
        )
        print(message, flush=True)
        if logs is not None:
            logs.append(message)
        return [message]

    messages: list[str] = []
    messages.append("[cleanup] starting Docker runtime cleanup")
    root = Path(target_path).resolve()
    if root.exists():
        if any((root / f).exists() for f in ("docker-compose.yml", "docker-compose.yaml")):
            for cmd in _compose_commands():
                rc, out = _run_quiet(cmd, cwd=str(root))
                if rc == 0:
                    messages.append(f"[cleanup] compose down ok: {' '.join(cmd)}")
                    break
                messages.append(f"[cleanup] compose down failed: {' '.join(cmd)} :: {out}")

    _remove_known_containers_and_images(target_path, messages)
    _prune_runtime_storage(messages)

    if os.getenv("CLEAN_DOCKER_CACHE", "0") == "1":
        rc, out = _run_quiet(["docker", "builder", "prune", "-af"])
        if rc == 0:
            messages.append("[cleanup] docker builder cache pruned (-af)")
        else:
            messages.append(f"[cleanup] docker builder prune failed: {out}")
    else:
        messages.append(
            "[cleanup] NOTE: docker build cache kept. "
            "Set CLEAN_DOCKER_CACHE=1 to prune build cache too."
        )
    if os.getenv("CLEAN_DOCKER_SYSTEM", "0") == "1":
        rc, out = _run_quiet(["docker", "system", "prune", "-af", "--volumes"])
        if rc == 0:
            messages.append("[cleanup] docker system prune completed (-af --volumes)")
        else:
            messages.append(f"[cleanup] docker system prune failed: {out}")

    messages.append("[cleanup] docker disk usage after cleanup:")
    messages.append(_docker_disk_usage())

    for message in messages:
        print(message, flush=True)
    if logs is not None:
        logs.extend(messages)
    return messages
