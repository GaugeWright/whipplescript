#!/usr/bin/env python3
"""Test-only Docker transcript; never invokes an executor or a Docker daemon."""
import json
import pathlib
import sys
import traceback

root = pathlib.Path(__file__).parent
def report_error(kind, value, trace):
    (root / "error").write_text("".join(traceback.format_exception(kind, value, trace)))
sys.excepthook = report_error
# The fixture writes this script beside its state, independently of this source.
def read(name):
    return json.loads((root / name).read_text())

def write(name, value):
    (root / name).write_text(json.dumps(value))

def call(name):
    with (root / "calls").open("a") as out:
        out.write(name + chr(10))

args = sys.argv[3:]
mode = read("mode")
if args[:2] == ["info", "--format"]:
    print("daemon")
elif args[:2] == ["volume", "create"]:
    print(read("volume"))
elif args[:2] == ["volume", "inspect"]:
    print(json.dumps(read("labels")))
elif args[:2] == ["run", "--rm"]:
    request = json.load(sys.stdin)
    op = request.get("command", {}).get("op", request["op"])
    call(op)
    cursor = read("cursor") if (root / "cursor").exists() else 0
    steps = read("steps")
    assert cursor < len(steps), "unscripted helper invocation"
    assert request == steps[cursor]["request"], "changed helper request"
    if op == "finish":
        assert not read("present"), "barrier finish before physical absence"
    write("cursor", cursor + 1)
    print(json.dumps(steps[cursor]["reply"]))
elif args[:2] == ["container", "ls"]:
    if read("present"):
        print(read("inspection")["id"])
elif args[:2] == ["container", "inspect"]:
    call("inspect")
    if '"env"' in args[3]:
        call("profile")
        print(json.dumps(read("profile")))
    else:
        print(json.dumps(read("inspection")))
elif args[:2] == ["container", "start"]:
    call("start")
    if mode == "changed-profile":
        profile = read("profile")
        profile["pid"] = "host"
        write("profile", profile)
    if mode == "lost-target":
        write("present", False)
    print("changed" if mode == "changed-start-id" else read("inspection")["id"])
elif args[:2] == ["container", "rm"]:
    call("remove")
    if mode == "remove-error":
        sys.exit(9)
    if mode != "remove-pending":
        write("present", False)
    print(read("inspection")["id"])
else:
    raise AssertionError("unexpected Docker operation")
