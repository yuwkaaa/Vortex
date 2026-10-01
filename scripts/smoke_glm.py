#!/usr/bin/env python3
"""Smoke-test GLM-4.7-Flash via Z.ai (OpenAI-compatible) before a full benchmark run.

Verifies the API key + exact model id reach the endpoint and return a completion,
using the SAME OpenAI SDK path this agent / AXE use. Cheap (a few tokens).

    ZAI_API_KEY=xxxx python scripts/smoke_glm.py
    # or explicitly:
    python scripts/smoke_glm.py --model glm-4.7-flash --base-url https://api.z.ai/api/paas/v4
"""
from __future__ import annotations
import argparse
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.environ.get("OPENROUTER_MODEL", "glm-4.7-flash"))
    ap.add_argument("--base-url", default=os.environ.get("OPENROUTER_BASE_URL",
                                                         "https://api.z.ai/api/paas/v4"))
    args = ap.parse_args()

    key = (os.environ.get("ZAI_API_KEY") or os.environ.get("GLM_API_KEY")
           or os.environ.get("OPENROUTER_API_KEY"))
    if not key:
        print("!! No key. Export ZAI_API_KEY (or GLM_API_KEY).", file=sys.stderr)
        return 2

    try:
        from openai import OpenAI
    except ImportError:
        print("!! openai SDK missing. Activate this repo's venv / env 'ctf' first.", file=sys.stderr)
        return 2

    client = OpenAI(api_key=key, base_url=args.base_url)
    print(f"-> endpoint={args.base_url} model={args.model}")
    try:
        r = client.chat.completions.create(
            model=args.model,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            temperature=0.0,
            max_tokens=8,
        )
    except Exception as exc:
        print(f"!! CALL FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    msg = (r.choices[0].message.content or "").strip()
    usage = getattr(r, "usage", None)
    print(f"<- reply={msg!r}  usage={usage}")
    print("SMOKE_OK" if msg else "SMOKE_EMPTY_REPLY")
    return 0 if msg else 1


if __name__ == "__main__":
    raise SystemExit(main())
