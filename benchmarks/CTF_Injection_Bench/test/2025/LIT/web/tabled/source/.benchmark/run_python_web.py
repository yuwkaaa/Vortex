#!/usr/bin/env python3
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
