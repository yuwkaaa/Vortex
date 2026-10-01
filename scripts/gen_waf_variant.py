#!/usr/bin/env python3
"""Generate ModSecurity + OWASP-CRS WAF variants of CTF injection challenges.

Every challenge in ``CTF_Injection_Bench`` is a single-service docker-compose that
builds ``./.benchmark_runtime`` and publishes the app on an internal port. This
script emits, for each requested challenge, a sibling variant under
``<challenge>/.waf_variants/PL<k>/`` that puts an OWASP Core Rule Set reverse
proxy in front of the original app, parameterised by CRS *paranoia level* (1-4).

Run a variant with the existing pipeline exactly like any other challenge:

    python main.py --challenge-json <challenge>/.waf_variants/PL<k>/challenge.json

Design notes
------------
* The WAF service is named ``challenge`` so the Infrastructure agent's
  deterministic resolver (which prefers a service literally called
  ``challenge``) targets the *proxy*, not the backend.
* The real app is renamed ``app`` and is **not** published to the host — only
  the WAF's port is reachable, so every agent request transits ModSecurity.
* ``internal_port`` in the variant challenge.json is set to the WAF listen port
  (8080) so the infra healthcheck / expected-port logic points at the proxy.
* The backend build context is rewritten to a relative path that still resolves
  to the original ``.benchmark_runtime`` from inside the nested variant dir.

The WAF measurement (solve-rate at PL1..PL4 vs no-WAF) is the intended benchmark
axis: the delta is a robustness metric the agent paper reports.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is in requirements.txt
    sys.exit("PyYAML is required: pip install -r requirements.txt")


_COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)
DEFAULT_WAF_IMAGE = "owasp/modsecurity-crs:nginx"
WAF_LISTEN_PORT = 8080


def _find_compose(challenge_dir: Path) -> Path | None:
    for name in _COMPOSE_FILENAMES:
        candidate = challenge_dir / name
        if candidate.exists():
            return candidate
    return None


def _container_port(service: dict[str, Any], fallback: int) -> int:
    """Best-effort container-side port of the app service."""
    ports = service.get("ports") or []
    for entry in ports:
        text = str(entry).split("/")[0]  # drop /tcp
        if ":" in text:
            return int(text.rsplit(":", 1)[1])
        if text.strip().isdigit():
            return int(text.strip())
    expose = service.get("expose") or []
    if expose:
        return int(str(expose[0]))
    return fallback


def _app_environment(service: dict[str, Any]) -> Any:
    """Preserve the app's environment (FLAG, etc.) verbatim."""
    return service.get("environment")


def build_variant_compose(
    *,
    app_build_context: str,
    app_port: int,
    app_environment: Any,
    paranoia: int,
    waf_image: str,
    slug: str,
) -> dict[str, Any]:
    app_service: dict[str, Any] = {
        "build": {"context": app_build_context},
        "container_name": f"ctf-waf-{slug}-app",
        "expose": [str(app_port)],
        "restart": "no",
    }
    if app_environment is not None:
        app_service["environment"] = app_environment

    waf_service: dict[str, Any] = {
        "image": waf_image,
        # Named 'challenge' so the infra resolver targets the proxy, not the app.
        "container_name": f"ctf-waf-{slug}-pl{paranoia}",
        "depends_on": ["app"],
        "environment": {
            "BACKEND": f"http://app:{app_port}",
            "PORT": str(WAF_LISTEN_PORT),
            "SERVER_NAME": "localhost",
            # Blocking mode with anomaly scoring at the requested paranoia level.
            "MODSEC_RULE_ENGINE": "On",
            "PARANOIA": str(paranoia),           # CRS 3.x env name
            "BLOCKING_PARANOIA": str(paranoia),  # CRS 4.x env name
            "DETECTION_PARANOIA": str(paranoia),
            "ANOMALY_INBOUND": "5",
            "ANOMALY_OUTBOUND": "4",
            "MODSEC_REQ_BODY_ACCESS": "On",
            "MODSEC_RESP_BODY_ACCESS": "On",
        },
        "ports": [f"${{CTF_HOST_PORT:-{WAF_LISTEN_PORT}}}:{WAF_LISTEN_PORT}"],
        "restart": "no",
    }

    return {"services": {"app": app_service, "challenge": waf_service}}


def build_variant_challenge_json(
    original: dict[str, Any],
    *,
    paranoia: int,
    waf_image: str,
    original_rel: str,
) -> dict[str, Any]:
    variant = dict(original)
    name = str(original.get("name") or "challenge")
    variant["name"] = f"{name} [WAF-PL{paranoia}]"
    variant["internal_port"] = str(WAF_LISTEN_PORT)
    variant["waf"] = {
        "engine": "modsecurity-crs",
        "image": waf_image,
        "paranoia_level": paranoia,
        "rule_engine": "On",
        "anomaly_inbound_threshold": 5,
    }
    variant["variant_of"] = original_rel
    variant["variant_kind"] = "waf"
    # Drop any pre-baked host port hint; the WAF owns the published port now.
    variant.pop("box_port", None)
    return variant


def generate_for_challenge(
    challenge_json: Path,
    *,
    levels: list[int],
    waf_image: str,
    force: bool,
) -> list[Path]:
    challenge_dir = challenge_json.parent
    compose_path = _find_compose(challenge_dir)
    if compose_path is None:
        raise SystemExit(f"no docker-compose file next to {challenge_json}")

    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    services = compose.get("services") or {}
    if len(services) != 1:
        raise SystemExit(
            f"expected exactly 1 service in {compose_path}, found {list(services)}"
        )
    (_app_name, app_service), = services.items()

    original = json.loads(challenge_json.read_text(encoding="utf-8"))
    fallback_port = int(str(original.get("internal_port") or "8000").strip() or "8000")
    app_port = _container_port(app_service, fallback_port)
    app_env = _app_environment(app_service)
    slug = challenge_dir.name.lower().replace("_", "-")
    original_rel = os.path.relpath(challenge_json, challenge_dir.parents[0])

    written: list[Path] = []
    for k in levels:
        variant_dir = challenge_dir / ".waf_variants" / f"PL{k}"
        variant_dir.mkdir(parents=True, exist_ok=True)

        # Build context is relative to the deep variant dir; still points at the
        # original .benchmark_runtime.
        original_ctx_abs = (challenge_dir / "./.benchmark_runtime").resolve()
        app_build_context = os.path.relpath(original_ctx_abs, variant_dir).replace(os.sep, "/")

        compose_out = variant_dir / "docker-compose.yaml"
        cj_out = variant_dir / "challenge.json"
        if compose_out.exists() and not force:
            print(f"skip (exists): {compose_out}")
        else:
            variant_compose = build_variant_compose(
                app_build_context=app_build_context,
                app_port=app_port,
                app_environment=app_env,
                paranoia=k,
                waf_image=waf_image,
                slug=slug,
            )
            compose_out.write_text(
                yaml.safe_dump(variant_compose, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
        variant_cj = build_variant_challenge_json(
            original, paranoia=k, waf_image=waf_image, original_rel=original_rel
        )
        cj_out.write_text(json.dumps(variant_cj, indent=2) + "\n", encoding="utf-8")
        written.append(cj_out)
        print(f"generated PL{k}: {cj_out}")

    return written


def _iter_challenges(suite_root: Path) -> list[Path]:
    return sorted(
        p
        for p in suite_root.rglob("challenge.json")
        if ".waf_variants" not in p.parts
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--challenge", help="path to a single challenge.json")
    src.add_argument("--all", action="store_true", help="every challenge under --suite-root")
    parser.add_argument(
        "--suite-root",
        default="CTF_Injection_Bench",
        help="root to scan when --all is used (default: CTF_Injection_Bench)",
    )
    parser.add_argument(
        "--levels",
        default="1,2,3,4",
        help="comma-separated CRS paranoia levels (default: 1,2,3,4)",
    )
    parser.add_argument("--waf-image", default=DEFAULT_WAF_IMAGE)
    parser.add_argument("--force", action="store_true", help="overwrite existing compose files")
    args = parser.parse_args(argv)

    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    for lvl in levels:
        if lvl not in (1, 2, 3, 4):
            parser.error(f"paranoia level must be 1-4, got {lvl}")

    if args.all:
        challenges = _iter_challenges(Path(args.suite_root))
        if not challenges:
            parser.error(f"no challenge.json found under {args.suite_root}")
    else:
        challenges = [Path(args.challenge)]

    total = 0
    for cj in challenges:
        generate_for_challenge(
            cj, levels=levels, waf_image=args.waf_image, force=args.force
        )
        total += len(levels)
    print(f"\nDone: {total} variant(s) across {len(challenges)} challenge(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
