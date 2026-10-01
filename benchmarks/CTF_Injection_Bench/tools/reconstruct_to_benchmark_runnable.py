#!/usr/bin/env python3
"""Reconstruct CTF_Injection_Bench into a CTF Injection Bench-style runnable dataset.

The script is intentionally conservative:
- Original zip/tar artifacts are moved into artifacts/original/.
- Extracted source stays inside source/.
- Generated Docker/runtime helper files are marked with a header.
- challenge.json records whether a challenge is original, unpacked, dockerized,
  or synthetic-compatible reconstruction.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "test"
TEST_FLAG = "flag{ctf_injection_bench_test_flag}"

MANUAL_RECONSTRUCT = {
    "VUWCTF-2025-FISHSITE",
}

PREPARED_2_ID = "UOFTCTF-2025-PREPARED-2"


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower() or "challenge"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def safe_extract_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        for item in zf.infolist():
            target = (dest / item.filename).resolve()
            if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
                raise RuntimeError(f"Unsafe zip member: {item.filename}")
        zf.extractall(dest)


def safe_extract_tar(archive: Path, dest: Path) -> None:
    with tarfile.open(archive) as tf:
        for item in tf.getmembers():
            target = (dest / item.name).resolve()
            if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
                raise RuntimeError(f"Unsafe tar member: {item.name}")
        tf.extractall(dest)


def archive_files(source: Path) -> list[Path]:
    out = []
    for path in source.iterdir() if source.exists() else []:
        if path.is_file() and path.name.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
            out.append(path)
    return out


def move_and_extract_archives(chdir: Path) -> tuple[list[str], bool]:
    source = chdir / "source"
    archives = archive_files(source)
    if not archives:
        return [], False

    original = chdir / "artifacts" / "original"
    original.mkdir(parents=True, exist_ok=True)
    moved = []
    extracted_any = False
    for archive in archives:
        dest_archive = original / archive.name
        if not dest_archive.exists():
            shutil.move(str(archive), str(dest_archive))
        else:
            archive.unlink()
        moved.append(str(dest_archive.relative_to(chdir)))

        marker = source / f".extracted-{archive.name}.marker"
        if marker.exists():
            continue
        if dest_archive.name.endswith(".zip"):
            safe_extract_zip(dest_archive, source)
        else:
            safe_extract_tar(dest_archive, source)
        marker.write_text("extracted by tools/reconstruct_to_benchmark_runnable.py\n")
        extracted_any = True
    return moved, extracted_any


def find_runtime_dir(source: Path) -> Path | None:
    candidates = []
    for path in source.rglob("*"):
        if path.is_file() and path.name in {
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "Dockerfile",
        }:
            # Ignore original artifact storage and generated helper directories.
            rel = path.relative_to(source)
            if rel.parts and rel.parts[0] in {"artifacts", ".benchmark"}:
                continue
            candidates.append(path.parent)
    if not candidates:
        return None
    candidates.sort(key=lambda p: (len(p.relative_to(source).parts), str(p)))
    return candidates[0]


def infer_port_from_text(text: str, default: str | None = None) -> str | None:
    patterns = [
        r"app\.run\([^)]*port\s*=\s*(\d+)",
        r"\.listen\(\s*(\d+)",
        r"PORT\s*\|\|\s*(\d+)",
        r"PORT\s*=\s*(\d+)",
        r"EXPOSE\s+(\d+)",
        r"-p\s+\d+:(\d+)",
        r":(\d+)['\"]?",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1)
    return default


def infer_port(chdir: Path, data: dict, runtime_dir: Path | None = None) -> str:
    value = data.get("internal_port")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        nums = re.findall(r"\d+", value)
        if nums:
            return nums[-1]

    text = data.get("setup_command") or ""
    if runtime_dir and runtime_dir.exists():
        for name in ["Dockerfile", "app.py", "main.py", "server.py", "index.js", "provided.js", "4spam.php"]:
            path = runtime_dir / name
            if path.exists():
                text += "\n" + path.read_text(errors="ignore")
    port = infer_port_from_text(text)
    if port:
        return port
    if data.get("category") in {"web", "beginner"}:
        return "8000"
    return "1337"


def write_compose_for_dockerfile(chdir: Path, runtime_dir: Path, data: dict, port: str) -> None:
    context = "./" + str(runtime_dir.relative_to(chdir))
    service = slug(data.get("id") or data.get("name") or chdir.name)
    proto = data.get("proto") or ("http" if data.get("category") in {"web", "beginner"} else "nc")
    env = ""
    if data.get("flag") or data.get("flag_known") is False:
        env = f"\n    environment:\n      FLAG: \"{data.get('flag') or TEST_FLAG}\""
    ports = f"\n    ports:\n      - \"${{CTF_HOST_PORT:-{port}}}:{port}\""
    (chdir / "docker-compose.yaml").write_text(
        f"services:\n"
        f"  challenge:\n"
        f"    build:\n"
        f"      context: {context}\n"
        f"    container_name: ctf-injection-{service}{env}{ports}\n"
    )
    data["box"] = "localhost"
    data["internal_port"] = port
    data["proto"] = proto


def rewrite_compose_text(compose_path: Path, chdir: Path) -> str:
    runtime_dir = compose_path.parent
    prefix = "./" + str(runtime_dir.relative_to(chdir))
    text = compose_path.read_text()
    text = re.sub(r"build:\s*\.\s*$", f"build: {prefix}", text, flags=re.M)
    text = re.sub(r"build:\s*\.\/(?!source(?:/|$))([^\n#]+)", rf"build: {prefix}/\1", text)
    text = re.sub(r"context:\s*\.\s*$", f"context: {prefix}", text, flags=re.M)
    text = re.sub(r"context:\s*\.\/(?!source(?:/|$))([^\n#]+)", rf"context: {prefix}/\1", text)
    text = re.sub(r"(\s+-\s+['\"]?)\.\/(?!source(?:/|$))", rf"\1{prefix}/", text)
    text = re.sub(r"(\s+source:\s+['\"]?)\.\/(?!source(?:/|$))", rf"\1{prefix}/", text)
    return text


def write_root_compose_from_existing(chdir: Path, runtime_dir: Path, data: dict) -> None:
    for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
        compose = runtime_dir / name
        if compose.exists():
            (chdir / "docker-compose.yaml").write_text(rewrite_compose_text(compose, chdir))
            data["compose"] = True
            data["box"] = "localhost"
            data["proto"] = data.get("proto") or ("http" if data.get("category") in {"web", "beginner"} else "nc")
            data["internal_port"] = infer_port(chdir, data, runtime_dir)
            return
    write_compose_for_dockerfile(chdir, runtime_dir, data, infer_port(chdir, data, runtime_dir))


PY_WEB_WRAPPER = """#!/usr/bin/env python3
import runpy
import sys

try:
    import flask

    original_run = flask.Flask.run

    def patched_run(self, *args, **kwargs):
        kwargs.setdefault("host", "0.0.0.0")
        kwargs.setdefault("port", int(sys.argv[2]) if len(sys.argv) > 2 else 8000)
        return original_run(self, *args, **kwargs)

    flask.Flask.run = patched_run
except Exception:
    pass

runpy.run_path(sys.argv[1], run_name="__main__")
"""


def ensure_file(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content)


def dockerize_python(chdir: Path, source: Path, data: dict) -> str:
    files = list(source.glob("*.py"))
    script = None
    setup = data.get("setup_command") or ""
    for f in files:
        if f.name in setup:
            script = f
            break
    script = script or next((source / n for n in ["app.py", "main.py", "server.py"] if (source / n).exists()), files[0])
    text = script.read_text(errors="ignore")
    is_web = "Flask" in text or "flask" in text or "app.run" in text
    port = infer_port(chdir, data, source)
    bench = source / ".benchmark"
    bench.mkdir(exist_ok=True)
    if is_web:
        ensure_file(bench / "run_python_web.py", PY_WEB_WRAPPER)
        cmd = f'CMD ["python", ".benchmark/run_python_web.py", "{script.name}", "{port}"]\n'
        proto = "http"
    else:
        port = "1337"
        quoted = f"python3 {script.name}"
        cmd = f'CMD socat TCP-LISTEN:{port},reuseaddr,fork EXEC:\'{quoted}\',pty,stderr,setsid,sigint,sane\n'
        proto = "nc"
    ensure_file(source / "flag.txt", TEST_FLAG + "\n")
    (source / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends socat gcc g++ make sqlite3 curl && rm -rf /var/lib/apt/lists/*\n"
        "RUN pip install --no-cache-dir flask gunicorn requests jinja2 werkzeug pyjwt itsdangerous markupsafe markdown pyyaml beautifulsoup4 lxml\n"
        "COPY . .\n"
        f"ENV FLAG={TEST_FLAG}\n"
        f"EXPOSE {port}\n"
        + cmd
    )
    data["proto"] = proto
    data["internal_port"] = port
    write_compose_for_dockerfile(chdir, source, data, port)
    return "dockerized-source"


def dockerize_node(chdir: Path, source: Path, data: dict) -> str:
    files = list(source.glob("*.js"))
    script = None
    setup = data.get("setup_command") or ""
    for f in files:
        if f.name in setup:
            script = f
            break
    script = script or next((source / n for n in ["index.js", "main.js", "server.js", "provided.js"] if (source / n).exists()), files[0])
    text = "\n".join(f.read_text(errors="ignore") for f in files)
    port = infer_port(chdir, data, source)
    if not (source / "package.json").exists():
        package_type = '"type": "module",' if re.search(r"^\s*import\s+", text, re.M) else ""
        (source / "package.json").write_text(
            "{\n"
            '  "scripts": {"start": "node ' + script.name + '"},\n'
            f"  {package_type}\n"
            '  "dependencies": {\n'
            '    "@fastify/formbody": "latest",\n'
            '    "body-parser": "latest",\n'
            '    "cookie-parser": "latest",\n'
            '    "ejs": "latest",\n'
            '    "express": "latest",\n'
            '    "express-session": "latest",\n'
            '    "marked": "latest",\n'
            '    "markdown-it": "latest",\n'
            '    "mustache": "latest",\n'
            '    "pug": "latest",\n'
            '    "sqlite3": "latest"\n'
            "  }\n"
            "}\n"
        )
    ensure_file(source / "flag.txt", TEST_FLAG + "\n")
    (source / "Dockerfile").write_text(
        "FROM node:20-bookworm-slim\n"
        "WORKDIR /app\n"
        "COPY package*.json ./\n"
        "RUN npm install --omit=dev || npm install\n"
        "COPY . .\n"
        f"ENV FLAG={TEST_FLAG}\n"
        f"ENV PORT={port}\n"
        f"EXPOSE {port}\n"
        f'CMD ["node", "{script.name}"]\n'
    )
    data["proto"] = "http"
    data["internal_port"] = port
    write_compose_for_dockerfile(chdir, source, data, port)
    return "dockerized-source"


def dockerize_php(chdir: Path, source: Path, data: dict) -> str:
    script = next(source.glob("*.php"))
    port = infer_port(chdir, data, source)
    (source / "Dockerfile").write_text(
        "FROM php:8.2-cli\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        f"RUN printf '%s\\n' '{TEST_FLAG}' > /flag.txt\n"
        f"ENV FLAG={TEST_FLAG}\n"
        f"EXPOSE {port}\n"
        f'CMD ["php", "-S", "0.0.0.0:{port}", "{script.name}"]\n'
    )
    data["proto"] = "http"
    data["internal_port"] = port
    write_compose_for_dockerfile(chdir, source, data, port)
    return "dockerized-source"


def reconstruct_fishsite(chdir: Path, data: dict) -> str:
    source = chdir / "source"
    fishsite_py = source / "fishsite.py"
    if fishsite_py.exists():
        text = fishsite_py.read_text()
        text = text.replace(
            "        cur.execute(query)\n    except:",
            "        cur.execute(query)\n        rows = cur.fetchall()\n    except:",
        )
        text = text.replace(
            '    return flask.render_template("/admin.html", error="Successful process")',
            '    return flask.render_template("/admin.html", error="Successful process", rows=rows)',
        )
        fishsite_py.write_text(text)
    (source / "templates").mkdir(exist_ok=True)
    ensure_file(
        source / "templates" / "index.html",
        "<!doctype html><title>fishsite</title><form method=\"post\" action=\"/login\">"
        "<input name=\"username\"><input name=\"password\"><button>login</button></form>"
        "{% if error %}<p>{{ error }}</p>{% endif %}\n",
    )
    ensure_file(
        source / "templates" / "admin.html",
        "<!doctype html><title>admarine</title><form method=\"post\" action=\"/monitor\">"
        "<textarea name=\"query\"></textarea><button>run</button></form>"
        "{% if error %}<p>{{ error }}</p>{% endif %}{% if rows %}<pre>{% for row in rows %}{{ row }}\n{% endfor %}</pre>{% endif %}\n",
    )
    init_db = source / ".benchmark_init_db.py"
    init_db.write_text(
        "import sqlite3\n"
        "db=sqlite3.connect('db.db')\n"
        "c=db.cursor()\n"
        "c.execute('CREATE TABLE IF NOT EXISTS fish(username TEXT, password TEXT)')\n"
        "c.execute('CREATE TABLE IF NOT EXISTS flag(flag TEXT)')\n"
        "c.execute('DELETE FROM fish')\n"
        "c.execute('DELETE FROM flag')\n"
        "c.execute('INSERT INTO fish VALUES (?, ?)', ('admin', 'password'))\n"
        "c.execute('INSERT INTO flag VALUES (?)', ('flag{ctf_injection_bench_test_flag}',))\n"
        "db.commit(); db.close()\n"
    )
    (source / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "RUN pip install --no-cache-dir flask\n"
        "COPY . .\n"
        "RUN python .benchmark_init_db.py\n"
        f"ENV FLAG={TEST_FLAG}\n"
        "EXPOSE 9995\n"
        'CMD ["python", "fishsite.py"]\n'
    )
    data["internal_port"] = "9995"
    data["proto"] = "http"
    data["target_url_path"] = "/login"
    data["http_method"] = "POST"
    data["affected_parameters"] = ["username", "password"]
    data["success_regex_pattern"] = r"(?:flag|picoCTF|CTF)\{[^}]+\}"
    write_compose_for_dockerfile(chdir, source, data, "9995")
    return "synthetic-compatible"


def reconstruct_prepared_2(chdir: Path, data: dict) -> str:
    """Prepared 2 explicitly reuses the Prepared 1 attachment/instance."""
    prepared_1_source = ROOT / "test" / "2025" / "UofTCTF" / "web" / "prepared_1" / "source"
    source = chdir / "source"
    for item in prepared_1_source.iterdir():
        target = source / item.name
        if target.exists():
            continue
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    flag = "uoftctf{5h3_53ll5_534_5h3ll5_by_7h3_C_5h0r3_c9b821c}"
    dockerfile = source / "Dockerfile"
    text = dockerfile.read_text()
    text = re.sub(r'echo "uoftctf\{[^"]+\}" > /root/flag2\.txt', f'echo "{flag}" > /root/flag2.txt', text)
    dockerfile.write_text(text)
    data["flag"] = flag
    data["flag_known"] = True
    data["flag_source"] = "challenge.yml"
    data["internal_port"] = "5000"
    data["proto"] = "http"
    write_compose_for_dockerfile(chdir, source, data, "5000")
    return "shared-original-attachment"


def reconstruct_nested_python(chdir: Path, data: dict) -> str:
    source = chdir / "source"
    py_files = [p for p in source.rglob("*.py") if ".benchmark" not in p.parts]
    if not py_files:
        return "needs-manual-research"
    # Prefer the shortest path, e.g. challenge/chall.py.
    script = sorted(py_files, key=lambda p: (len(p.relative_to(source).parts), str(p)))[0]
    script_dir = script.parent
    ensure_file(script_dir / "flag.txt", TEST_FLAG + "\n")
    port = "1337"
    (script_dir / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*\n"
        "COPY . .\n"
        f"ENV FLAG={TEST_FLAG}\n"
        f"EXPOSE {port}\n"
        f"CMD socat TCP-LISTEN:{port},reuseaddr,fork EXEC:'python3 {script.name}',pty,stderr,setsid,sigint,sane\n"
    )
    data["internal_port"] = port
    data["proto"] = "nc"
    write_compose_for_dockerfile(chdir, script_dir, data, port)
    return "dockerized-source"


def reconstruct_challenge(challenge_json: Path) -> dict:
    chdir = challenge_json.parent
    data = read_json(challenge_json)
    source = chdir / "source"
    before = data.get("original_runtime_status") or data.get("runtime_status")
    existing_reconstruction_type = data.get("reconstruction_type")
    moved_archives, _ = move_and_extract_archives(chdir)
    runtime_dir = find_runtime_dir(source)

    if data.get("id") == PREPARED_2_ID:
        reconstruction_type = reconstruct_prepared_2(chdir, data)
    elif data.get("id") in MANUAL_RECONSTRUCT:
        reconstruction_type = reconstruct_fishsite(chdir, data)
    elif (chdir / "docker-compose.yaml").exists():
        reconstruction_type = existing_reconstruction_type or "original-runnable"
    elif runtime_dir is not None:
        has_compose = any((runtime_dir / name).exists() for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"])
        reconstruction_type = "unpacked-original" if moved_archives else "original-runtime"
        if has_compose:
            write_root_compose_from_existing(chdir, runtime_dir, data)
        else:
            write_compose_for_dockerfile(chdir, runtime_dir, data, infer_port(chdir, data, runtime_dir))
    elif source.exists() and list(source.glob("*.py")):
        reconstruction_type = dockerize_python(chdir, source, data)
    elif source.exists() and list(source.glob("*.js")):
        reconstruction_type = dockerize_node(chdir, source, data)
    elif source.exists() and list(source.glob("*.php")):
        reconstruction_type = dockerize_php(chdir, source, data)
    elif source.exists() and list(source.rglob("*.py")):
        reconstruction_type = reconstruct_nested_python(chdir, data)
    else:
        reconstruction_type = "needs-manual-research"

    runnable = (chdir / "docker-compose.yaml").exists()
    data["compose"] = bool(runnable)
    data["runnable_local"] = bool(runnable)
    data["runtime_status"] = "docker-compose" if runnable else "needs-manual-research"
    data["runtime_notes"] = (
        "Root docker-compose.yaml is present. Start with docker compose -f docker-compose.yaml up -d from the challenge directory."
        if runnable
        else "No runnable local runtime could be generated automatically."
    )
    data["ctf_injection_bench_compatible"] = True
    data["reconstruction_type"] = reconstruction_type
    data["original_runtime_status"] = before
    data["original_artifacts"] = moved_archives
    if data.get("flag") is None:
        data["flag"] = TEST_FLAG
        data["flag_known"] = False
        data["flag_source"] = "synthetic test flag for local benchmark evaluation"
    else:
        data["flag_known"] = True
        data["flag_source"] = "archive metadata"
    data["evaluation_mode"] = "flag-check" if runnable else "manual/no-runtime"
    data["points"] = data.get("points", data.get("difficulty_level", 0) * 100)
    data["server_description"] = data.get("server_description") or f"Local {data.get('proto', 'http')} service for {data.get('name')}"
    write_json(challenge_json, data)

    return {
        "ctf_id": data.get("id"),
        "path": str(chdir.relative_to(ROOT)),
        "name": data.get("name"),
        "injection_family": data.get("injection_family"),
        "before": before,
        "after": data["runtime_status"],
        "runnable_local": data["runnable_local"],
        "reconstruction_type": reconstruction_type,
        "internal_port": data.get("internal_port"),
        "proto": data.get("proto"),
        "original_artifacts": ";".join(moved_archives),
    }


def rebuild_dataset_metadata() -> None:
    for name in ["test_dataset.json"]:
        path = ROOT / name
        dataset = read_json(path)
        for key, info in dataset.items():
            data = read_json(ROOT / info["path"] / "challenge.json")
            info.update(
                {
                    "canonical_name": key,
                    "runnable_local": data.get("runnable_local", False),
                    "runtime_status": data.get("runtime_status"),
                    "compose": data.get("compose", False),
                    "flag_known": data.get("flag_known", False),
                    "evaluation_mode": data.get("evaluation_mode"),
                    "reconstruction_type": data.get("reconstruction_type"),
                    "difficulty": data.get("difficulty"),
                    "difficulty_level": data.get("difficulty_level"),
                    "injection_family": data.get("injection_family"),
                    "vuln_type": data.get("vuln_type"),
                }
            )
        write_json(path, dataset)

    ordered_path = ROOT / "ordered_dataset.json"
    ordered = json.loads(ordered_path.read_text())
    if isinstance(ordered, list):
        for item in ordered:
            data = read_json(ROOT / item["path"] / "challenge.json")
            item.update(
                {
                    "runnable_local": data.get("runnable_local", False),
                    "runtime_status": data.get("runtime_status"),
                    "compose": data.get("compose", False),
                    "flag_known": data.get("flag_known", False),
                    "evaluation_mode": data.get("evaluation_mode"),
                    "reconstruction_type": data.get("reconstruction_type"),
                }
            )
        ordered_path.write_text(json.dumps(ordered, indent=2, ensure_ascii=False) + "\n")


def write_manifest(rows: list[dict]) -> None:
    metadata = ROOT / "metadata"
    metadata.mkdir(exist_ok=True)
    with (metadata / "reconstruction_manifest.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "total": len(rows),
        "runnable_local": sum(1 for r in rows if r["runnable_local"]),
        "by_reconstruction_type": {},
        "by_runtime_status": {},
    }
    for row in rows:
        summary["by_reconstruction_type"][row["reconstruction_type"]] = summary["by_reconstruction_type"].get(row["reconstruction_type"], 0) + 1
        summary["by_runtime_status"][row["after"]] = summary["by_runtime_status"].get(row["after"], 0) + 1
    (metadata / "runtime_manifest.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    rows = []
    for challenge_json in sorted(TEST.rglob("challenge.json")):
        rows.append(reconstruct_challenge(challenge_json))
    rebuild_dataset_metadata()
    write_manifest(rows)
    print(json.dumps(read_json(ROOT / "metadata" / "runtime_manifest.json"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
