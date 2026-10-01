from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from src.cleanup import cleanup_target_runtime
from src.ctf_adapter import load_ctf_challenge
from src.llm import configure_llm_environment
from src.metrics import append_metrics_to_report, finish_run, record_cleanup, start_run, write_metrics
from src.state import initial_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Multi-agent penetration testing system for injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Case A: local source (Infra agent will build Docker sandbox)
  python main.py --cve-config "./cve_configs/example.json" --target-path "./ctf-lab"

  # Case B: pre-built environment with known CVE
  python main.py --cve-config "./cve_configs/example.json" --target-url "http://127.0.0.1:8080"

  # Case C: black-box (no CVE info — Navigator discovers everything)
  python main.py --target-url "http://challenge.picoctf.org:PORT"

  # Case D: NYU/CTF benchmark challenge.json
  python main.py --challenge-json "./CTF_Injection_Bench/test/2025/VuwCTF/web/fishsite/challenge.json"

  # Use BytePlus GLM-5 for this run
  python main.py --byteplus-glm5 --target-url "http://127.0.0.1:8080"
        """,
    )
    parser.add_argument(
        "--cve-config",
        required=False,
        default=None,
        help=(
            "Path to CVE configuration JSON file. "
            "Optional in black-box mode — omit to let Navigator discover the vulnerability type."
        ),
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target-path",
        metavar="PATH",
        help=(
            "Case A: path to local directory containing docker-compose.yml or Dockerfile. "
            "Infra agent will build and start the sandbox automatically."
        ),
    )
    target_group.add_argument(
        "--target-url",
        metavar="URL",
        help=(
            "Case B/C: URL of an already-running target (e.g. http://127.0.0.1:8080). "
            "Infra agent is skipped. Without --cve-config, runs in black-box discovery mode."
        ),
    )
    target_group.add_argument(
        "--challenge-json",
        metavar="PATH",
        help=(
            "Case D: path to a NYU-style or CTF_Injection_Bench-style challenge.json. "
            "The file is converted to the internal injection config format."
        ),
    )
    parser.add_argument(
        "--demo-loop",
        action="store_true",
        help="Optional flag reserved for custom loop demos.",
    )
    parser.add_argument(
        "--state-out",
        metavar="PATH",
        default=None,
        help=(
            "Optional: dump a JSON summary of the final pipeline state "
            "(status, per-loop attempt_history, report/metrics paths). "
            "Used by scripts/run_bench.py to aggregate batch results."
        ),
    )
    parser.add_argument(
        "--llm-provider",
        choices=["openrouter", "vertexai_adc", "vertexai", "byteplus", "modelark", "ark", "bytedance"],
        default="",
        help="Override LLM provider for this run.",
    )
    parser.add_argument(
        "--llm-model",
        default="",
        help="Override provider model for this run.",
    )
    parser.add_argument(
        "--byteplus-glm5",
        action="store_true",
        help="Shortcut for --llm-provider byteplus --llm-model glm-5 with a GLM-safe token budget.",
    )

    args = parser.parse_args(argv)

    try:
        configure_llm_environment(
            env=os.environ,
            provider=args.llm_provider,
            model=args.llm_model,
            byteplus_glm5=args.byteplus_glm5,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 2

    # Load CVE config if provided; otherwise default to black-box mode
    cve_config: dict = {}
    cve_id = "BLACKBOX"
    challenge_target_path = None

    if args.challenge_json:
        try:
            cve_id, cve_config, challenge_target_path = load_ctf_challenge(args.challenge_json)
        except Exception as exc:
            print(f"Error: Failed to load challenge JSON: {exc}")
            return 1

    if args.cve_config and args.challenge_json:
        print("Error: use either --cve-config or --challenge-json, not both.")
        return 1

    if args.cve_config:
        cve_config_path = Path(args.cve_config)
        if not cve_config_path.exists():
            print(f"Error: CVE config file not found: {cve_config_path}")
            return 1
        try:
            with open(cve_config_path, "r", encoding="utf-8") as f:
                cve_config = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse CVE config JSON: {e}")
            return 1
        cve_id = cve_config.get("cve_id") or cve_config.get("cve") or "UNKNOWN"
        if cve_id == "UNKNOWN":
            print("Warning: CVE config missing 'cve_id' — using UNKNOWN")
    elif not args.challenge_json:
        print("[*] No --cve-config provided. Running in black-box discovery mode.")

    effective_target_path = args.target_path or challenge_target_path

    if effective_target_path:
        # Case A: infra agent builds Docker sandbox
        state = initial_state(
            cve=cve_id,
            cve_config=cve_config or None,
            target_path=effective_target_path,
            target_url=None,
        )
    else:
        # Case B / C: target already running
        state = initial_state(
            cve=cve_id,
            cve_config=cve_config or None,
            target_path=None,
            target_url=args.target_url,
        )

    if args.demo_loop:
        state["demo_mode"] = True

    start_run()

    from src.graph import build_graph

    app = build_graph()
    
    # Draw graph (cosmetic only). draw_mermaid_png() calls the external mermaid.ink API,
    # which crashes the ENTIRE run on any DNS/network hiccup (socket.gaierror) — and it runs
    # BEFORE the pipeline, so a failure means the agent never executes (0 calls, lost metrics,
    # a false "grader=false"). Never let a diagram render abort a benchmark run.
    try:
        png_data = app.get_graph(xray=True).draw_mermaid_png()
        with open("graph.png", "wb") as f:
            f.write(png_data)
    except Exception as exc:
        print(f"[graph.png skipped: {type(exc).__name__}] {str(exc)[:120]}")
        
    final_state = None
    try:
        final_state = app.invoke(state)
    except Exception as exc:
        print(f"\n❌ Pipeline failed: {exc}")
        return_code = 1
    else:
        return_code = 0
    finally:
        cleanup_start = time.monotonic()
        cleanup_messages = cleanup_target_runtime(effective_target_path)
        record_cleanup(
            duration_seconds=time.monotonic() - cleanup_start,
            messages=cleanup_messages,
        )

    metrics = finish_run("success" if return_code == 0 else "failed")
    metrics_path = write_metrics()

    if args.state_out:
        attempt_history = (final_state or {}).get("attempt_history", [])
        # Exploitation success is NOT the final node status (poc_generator sets
        # "reported"); derive it from whether any attempt verdict starts with SUCCESS.
        exploited = any(
            str(r.get("verdict", "")).upper().startswith("SUCCESS")
            for r in attempt_history
        )
        summary = {
            "cve": cve_id,
            "challenge_json": args.challenge_json,
            "vulnerability_type": (cve_config or {}).get("vulnerability_type"),
            "exploited": exploited,
            "final_status": (final_state or {}).get("status"),
            "loop_count": (final_state or {}).get("loop_count"),
            "target_url": (final_state or {}).get("target_url"),
            "attempt_history": attempt_history,
            "report_path": (final_state or {}).get("report_path"),
            "metrics_path": metrics_path,
            "return_code": return_code,
        }
        try:
            out_path = Path(args.state_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            print(f"Warning: failed to write --state-out: {exc}")

    if final_state is None:
        if metrics_path:
            print(f"\n📊 Metrics saved to: {metrics_path}")
        return return_code

    report_path = final_state.get("report_path")
    if report_path:
        if metrics_path:
            append_metrics_to_report(report_path, metrics_path)
        print(f"\n✅ Report saved to: {report_path}")
    else:
        print("\n⚠️  No report_path produced (check execution logs).")
    if metrics_path:
        print(f"📊 Metrics saved to: {metrics_path}")
        final_state["metrics_path"] = metrics_path
        final_state["run_metrics"] = metrics

    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
