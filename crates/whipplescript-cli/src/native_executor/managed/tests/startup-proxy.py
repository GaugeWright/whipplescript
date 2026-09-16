#!/usr/bin/env python3
"""Forward real Docker calls; pause one adapter after its actual start returns."""
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(__file__).parent
args = sys.argv[1:]
data = None
if args[2:4] == ["run", "--rm"]:
    data = sys.stdin.buffer.read()
    if json.loads(data)["op"] == "deliver":
        (root / "delivered").touch()
result = subprocess.run(["docker", *args], input=data, stdout=subprocess.PIPE)
if args[2:4] == ["container", "start"] and result.returncode == 0:
    (root / "started").touch()
    until = time.monotonic() + 120
    while not (root / "release").exists():
        if time.monotonic() >= until:
            sys.exit(8)
        time.sleep(0.02)
sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
