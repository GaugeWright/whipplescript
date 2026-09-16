#!/usr/bin/env python3
"""Test-only Docker implementation for the runtime installer boundary."""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(__file__).parent
args = sys.argv[3:]
mode = (root / "mode").read_text()
with (root / "calls").open("a") as out:
    out.write(args[0] + chr(10))
if args[:2] == ["info", "--format"]:
    count = int((root / "count").read_text()) if (root / "count").exists() else 0
    count += 1
    (root / "count").write_text(str(count))
    print("changed" if mode == f"daemon-{count}" else "daemon")
elif args[:2] == ["image", "ls"]:
    if mode == "cached":
        print("sha256:" + "b" * 64)
    elif mode == "alias-conflict":
        print("sha256:" + "d" * 64)
elif args[:2] == ["image", "tag"]:
    assert args[2] == "sha256:" + "b" * 64
elif args[:2] == ["image", "inspect"]:
    if "Entrypoint" in args[3]:
        print(json.dumps(["sh"] if mode == "entrypoint" else ["whip", "executor", "--bind", "0.0.0.0:8080"]))
    elif args[-1].startswith("whip-native-runtime-base:"):
        print("changed" if mode == "alias-id" else "sha256:" + "b" * 64)
    else:
        print("changed" if mode == "image-lookup" else "sha256:" + "c" * 64)
elif args[0] == "build":
    context = pathlib.Path(args[-1])
    runtime = json.loads((root / "runtime").read_text())
    assert (context / "Dockerfile").read_text().splitlines()[0].endswith("@sha256:" + "b" * 64)
    assert hashlib.sha256((context / "reactor.wasm").read_bytes()).hexdigest() == runtime["engine"]["artifact_sha256"]
    assert args[args.index("--network") + 1] == "none"
    assert "--pull=false" in args
    pathlib.Path(args[args.index("--iidfile") + 1]).write_text("mutable:tag" if mode == "image-id" else "sha256:" + "c" * 64)
elif args[0] == "run":
    runtime = json.load(sys.stdin)
    assert runtime == json.loads((root / "runtime").read_text())
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--entrypoint") + 1] == runtime["executable"]
    assert "--read-only" in args and "--mount" not in args and "--volume" not in args
    assert args[-2:] == ["executor", "verify-norm-runtime"]
    if mode == "probe":
        runtime["environment"] = "substituted"
    print(json.dumps({"protocol":"whipplescript.norm.runtime-probe/v1", "runtime":runtime}))
else:
    raise AssertionError("unexpected installer operation")
