#!/usr/bin/env python3
"""Name the real finish helper so the physical fixture can observe its launch."""
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).parent
args = sys.argv[1:]
data = None
if args[2:4] == ["run", "--rm"]:
    data = sys.stdin.buffer.read()
    request = json.loads(data)
    if request.get("command", {}).get("op") == "finish":
        args[3:3] = ["--name", (root / "finish-name").read_text()]
        (root / "finish-started").touch()
result = subprocess.run(["docker", *args], input=data, stdout=subprocess.PIPE)
sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
