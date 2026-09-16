#!/usr/bin/env python3
"""Pause this fixture's original Docker client at one physical race boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).parent
fixture = json.loads((root / "fixture.json").read_text())
args = sys.argv[1:]
operation = args[2:]
body = sys.stdin.buffer.read() if operation[:2] == ["run", "--rm"] else None
request = json.loads(body) if body is not None else None
creation = fixture["mode"] == "create" and operation[:2] == ["container", "create"]
completion = fixture["mode"] == "completion" and request is not None and request.get("op") == "deliver"

def pause():
    (root / "ready").write_text("ready")
    deadline = time.monotonic() + 25
    while not (root / "release").exists():
        if time.monotonic() > deadline:
            raise TimeoutError("worker race was not released")
        time.sleep(0.05)

active = root / f"client-{os.getpid()}.active"
active.write_text("active")
with (root / "calls").open("a") as calls:
    calls.write(json.dumps({"operation": operation, "request": request.get("op") if request else None}) + "\n")
try:
    if creation:
        pause()
    result = subprocess.run([fixture["docker"], *args], input=body, capture_output=True, timeout=30)
    if creation and result.returncode == 0:
        (root / "created").write_bytes(result.stdout)
    if completion:
        assert result.returncode == 0, "delivery did not complete"
        retained = json.loads(result.stdout)
        assert retained["response"]["action"]["action"] == "replay", "delivery did not retain completion"
        pause()
    try:
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    except BrokenPipeError:
        pass  # The test deliberately killed the worker, not this client.
    sys.exit(result.returncode)
finally:
    active.unlink(missing_ok=True)
    if creation or completion:
        (root / "done").write_text("done")
