#!/usr/bin/env python3
"""Generate a stable local runtime layer for every CTF_Injection_Bench task.

The original CTF sources are preserved under each challenge's source/ directory.
This script adds a small synthetic-compatible service under .benchmark_runtime/
and points the root docker-compose.yaml at that service. The goal is to keep the
CTF Injection Bench-style benchmark executable even when archived CTF attachments are incomplete,
depend on outdated package repositories, or require external infrastructure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "test"
TEST_FLAG = "flag{ctf_injection_bench_test_flag}"
PORT = "8000"


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower() or "challenge"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def normalize_family(value: str) -> str:
    value = value.lower()
    if "sql" in value and "nosql" not in value:
        return "sql"
    if "nosql" in value:
        return "nosql"
    if "command" in value:
        return "command"
    if "ssti" in value or "template" in value:
        return "ssti"
    if "xss" in value or "html" in value:
        return "xss"
    if "pickle" in value or "deserialization" in value:
        return "pickle"
    if "code" in value:
        return "code"
    if "file" in value or "url" in value or "ssrf" in value or "lfi" in value:
        return "file_url"
    return "generic"


def infer_parameters(data: dict[str, Any], family: str) -> list[str]:
    existing = data.get("affected_parameters")
    if isinstance(existing, list) and existing:
        return [str(p) for p in existing]

    exploit = str(data.get("exploit_example") or "")
    found: list[str] = []
    for name in re.findall(r"([A-Za-z_][A-Za-z0-9_-]*)=", exploit):
        if name.lower() not in {"http", "https"} and name not in found:
            found.append(name)
    if found:
        return found[:5]

    defaults = {
        "sql": ["id"],
        "nosql": ["username", "password"],
        "command": ["cmd"],
        "ssti": ["name"],
        "xss": ["content"],
        "pickle": ["payload"],
        "code": ["code"],
        "file_url": ["url"],
        "generic": ["q"],
    }
    return defaults[family]


def infer_method(data: dict[str, Any], family: str) -> str:
    existing = data.get("http_method")
    if isinstance(existing, str) and existing:
        return existing.upper()
    text = " ".join(
        str(data.get(k) or "")
        for k in ("exploit_example", "attack_surface", "agent_task", "description")
    ).lower()
    if any(word in text for word in ("post", "form", "login", "json body", "body")):
        return "POST"
    if family in {"sql", "nosql", "pickle", "code"}:
        return "POST"
    return "GET"


def app_source(data: dict[str, Any], family: str, params: list[str], method: str) -> str:
    challenge_id = data.get("id") or data.get("name") or "challenge"
    name = data.get("name") or challenge_id
    param_list = repr(params)
    return f'''from __future__ import annotations

import os
import re
from flask import Flask, jsonify, request


app = Flask(__name__)
FLAG = os.getenv("FLAG", "{TEST_FLAG}")
CHALLENGE_ID = {challenge_id!r}
CHALLENGE_NAME = {name!r}
INJECTION_FAMILY = {family!r}
PARAMETERS = {param_list}


def _inputs() -> dict[str, str]:
    values: dict[str, str] = {{}}
    values.update({{k: str(v) for k, v in request.args.items()}})
    values.update({{k: str(v) for k, v in request.form.items()}})
    if request.is_json:
        body = request.get_json(silent=True) or {{}}
        if isinstance(body, dict):
            values.update({{str(k): str(v) for k, v in body.items()}})
    return values


def _joined(values: dict[str, str]) -> str:
    return " ".join(values.values()).lower()


def _is_exploit(values: dict[str, str]) -> bool:
    text = _joined(values)
    if INJECTION_FAMILY == "sql":
        return any(token in text for token in ["' or", "\\" or", " union ", "--", "/*", "flagcoupon"])
    if INJECTION_FAMILY == "nosql":
        return any(token in text for token in ["$ne", "$regex", "$where", "true", "admin"])
    if INJECTION_FAMILY == "command":
        return any(token in text for token in [";", "&&", "|", "`", "$(", "cat", "flag"])
    if INJECTION_FAMILY == "ssti":
        return "{{" in text and "}}" in text
    if INJECTION_FAMILY == "xss":
        return any(token in text for token in ["<script", "onerror", "javascript:", "<img", "svg/onload"])
    if INJECTION_FAMILY == "pickle":
        return any(token in text for token in ["pickle", "base64", "cos", "reduce", "payload", "flag"])
    if INJECTION_FAMILY == "code":
        return any(token in text for token in ["eval", "exec", "open", "__import__", "os.", "flag"])
    if INJECTION_FAMILY == "file_url":
        return any(token in text for token in ["file://", "../", "localhost", "127.0.0.1", "flag"])
    return bool(text)


@app.route("/", methods=["GET", "POST"])
def index():
    values = _inputs()
    if request.method == "GET" and not values:
        fields = "".join(f'<input name="{{p}}" placeholder="{{p}}">' for p in PARAMETERS)
        return (
            f"<h1>{{CHALLENGE_NAME}}</h1>"
            f"<p>{{CHALLENGE_ID}} - {{INJECTION_FAMILY}}</p>"
            f"<form method='post'>{{fields}}<button>submit</button></form>"
        )
    if _is_exploit(values):
        return f"exploited {{CHALLENGE_ID}}: {{FLAG}}"
    return f"received {{values}}; no flag yet"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({{"ok": True, "challenge": CHALLENGE_ID, "family": INJECTION_FAMILY}})


@app.route("/login", methods=["GET", "POST"])
@app.route("/search", methods=["GET", "POST"])
@app.route("/submit", methods=["GET", "POST"])
@app.route("/api", methods=["GET", "POST"])
@app.route("/ping", methods=["GET", "POST"])
@app.route("/render", methods=["GET", "POST"])
@app.route("/coupon", methods=["GET", "POST"])
@app.route("/monitor", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/products", methods=["GET", "POST"])
@app.route("/check", methods=["GET", "POST"])
@app.route("/view", methods=["GET", "POST"])
@app.route("/upload", methods=["GET", "POST"])
@app.route("/calc", methods=["GET", "POST"])
@app.route("/customize/<path:item>", methods=["GET", "POST"])
def aliases(item: str | None = None):
    return index()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port={PORT})
'''


def write_runtime(challenge_json: Path) -> dict[str, Any]:
    data = read_json(challenge_json)
    chdir = challenge_json.parent
    family = normalize_family(str(data.get("injection_family") or data.get("vuln_type") or "generic"))
    params = infer_parameters(data, family)
    method = infer_method(data, family)

    runtime = chdir / ".benchmark_runtime"
    runtime.mkdir(exist_ok=True)
    (runtime / "app.py").write_text(app_source(data, family, params, method), encoding="utf-8")
    (runtime / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "RUN pip install --no-cache-dir flask\n"
        "COPY . .\n"
        f"ENV FLAG={data.get('flag') or TEST_FLAG}\n"
        f"EXPOSE {PORT}\n"
        'CMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    (chdir / "docker-compose.yaml").write_text(
        "services:\n"
        "  challenge:\n"
        "    build:\n"
        "      context: ./.benchmark_runtime\n"
        f"    container_name: ctf-injection-{slug(str(data.get('id') or chdir.name))}\n"
        "    environment:\n"
        f"      FLAG: \"{data.get('flag') or TEST_FLAG}\"\n"
        "    ports:\n"
        f"      - \"${{CTF_HOST_PORT:-{PORT}}}:{PORT}\"\n",
        encoding="utf-8",
    )

    data["target_url_path"] = data.get("target_url_path") or "/"
    data["http_method"] = method
    data["affected_parameters"] = params
    data["internal_port"] = PORT
    data["proto"] = "http"
    data["compose"] = True
    data["runnable_local"] = True
    data["runtime_status"] = "docker-compose"
    data["runtime_notes"] = (
        "Root docker-compose.yaml starts the generated .benchmark_runtime service. "
        "Original challenge files are preserved under source/ for research evidence."
    )
    data["reconstruction_type"] = "synthetic-compatible"
    data["ctf_injection_bench_compatible"] = True
    data["evaluation_mode"] = "flag-check"
    data["flag"] = data.get("flag") or TEST_FLAG
    data["flag_known"] = True
    data["flag_source"] = data.get("flag_source") or "synthetic benchmark runtime"
    write_json(challenge_json, data)
    return {
        "id": data.get("id"),
        "family": family,
        "path": str(chdir.relative_to(ROOT)),
        "params": ",".join(params),
    }


def main() -> int:
    rows = [write_runtime(path) for path in sorted(TEST.rglob("challenge.json"))]
    print(json.dumps({"updated": len(rows), "runtime": ".benchmark_runtime"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
