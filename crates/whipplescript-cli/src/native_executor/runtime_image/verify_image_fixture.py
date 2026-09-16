#!/usr/bin/env python3
"""Exact Docker transport fixture for immutable runtime image verification."""
import json
from pathlib import Path
import sys
root = Path(__file__).parent
mode = (root / "mode").read_text()
runtime = json.loads((root / "runtime").read_text())
assert sys.argv[1:3] == ["--host", "unix:///fixture"]
args = sys.argv[3:]
calls = json.loads((root / "calls").read_text())
calls.append(args)
(root / "calls").write_text(json.dumps(calls))
image = "sha256:" + "c" * 64
if args == ["info", "--format", "{{.ID}}"]:
    print("other" if mode == "daemon" and len(calls) > 1 else "fixture-daemon")
elif args == ["image", "inspect", "--format", "{{.Id}}", image]:
    print("sha256:" + "d" * 64 if mode == "first-image" or (mode == "last-image" and len(calls) > 3) else image)
elif args == ["image", "inspect", "--format", "{{json .Config.Entrypoint}}", image]:
    print(json.dumps(["changed"] if mode == "entrypoint" else ["whip", "executor", "--bind", "0.0.0.0:8080"]))
else:
    assert args == ["run", "--rm", "-i", "--pull=never", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", runtime["executable"], image, "executor", "verify-norm-runtime"], args
    assert json.load(sys.stdin) == runtime
    if mode == "failed-probe": sys.exit(7)
    if mode == "profile": runtime["environment"] = "changed"
    receipt = {"protocol":"whipplescript.norm.runtime-probe/v1", "runtime":runtime}
    if mode == "extra": receipt["untrusted"] = True
    print(json.dumps({} if mode == "bad-probe" else receipt))
