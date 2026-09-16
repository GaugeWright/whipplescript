"""Exercise the production controller through Wrangler's native local container API.

Uses the production Dockerfile with the locally built test binary. Docker,
the worker toolchain/WASM build and target/debug/whip must already be available.
Retains logs and SQLite under this worktree's target; stops only its own dev
process group. No account, deployment, remote provider or shared Docker cleanup.
"""
import base64
import concurrent.futures
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[4]
WORKER = ROOT / "crates/whipplescript-host-do/worker"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    docker("version", "--format", "{{.Server.Version}}")
    run_name = "whip-barrier-" + str(time.time_ns())
    directory = ROOT / "target" / run_name
    directory.mkdir()
    # Strip a copy; never alter the worktree's build output.
    subprocess.run(["strip", "-o", str(directory / "whip"), str(ROOT / "target/debug/whip")], check=True)
    shutil.copyfile(WORKER / "executor/Dockerfile", directory / "Dockerfile")
    print("Production Dockerfile sha256:", hashlib.sha256((directory / "Dockerfile").read_bytes()).hexdigest(), flush=True)
    print("Test executor binary sha256:", hashlib.sha256((directory / "whip").read_bytes()).hexdigest(), flush=True)
    config = directory / "wrangler.json"
    config.write_text(json.dumps({
        "name": run_name,
        "main": str(WORKER / "scripts/fixtures/executor-container-local.ts"),
        "compatibility_date": "2026-07-08",
        "rules": [{"type": "Text", "globs": ["**/*.sql"], "fallthrough": False}],
        "durable_objects": {"bindings": [{"name": "EXECUTOR", "class_name": "ExecutorContainer"}, {"name": "WORKSPACE_BROKER", "class_name": "WorkspaceBroker"}]},
        "containers": [{"class_name": "ExecutorContainer", "image": "./Dockerfile", "max_instances": 1}],
        "migrations": [{"tag": "v1", "new_sqlite_classes": ["ExecutorContainer", "WorkspaceBroker"]}],
        "vars": {"WHIP_EXECUTOR_TOKEN": "local-barrier-fixture", "WHIP_EXECUTOR_POOL_SIZE": "1"},
    }))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    process = None
    output = None

    def call(body):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            # `url` is this script's own
            # f"http://127.0.0.1:{port}", built from a port it bound above.
            # No caller supplies it and no scheme but http can reach here.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            return {"http_error": error.code, "body": error.read().decode()[:500]}

    def stop():
        nonlocal process, output
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=20)
            process = None
        prefix = f"workerd-{run_name}-ExecutorContainer-"
        rows = docker("ps", "-a", "--filter", f"name={prefix}", "--format", "{{.ID}} {{.Names}}")
        for row in rows.splitlines():
            container_id, name = row.split()
            if name.startswith(prefix) and re.fullmatch(r"[0-9a-f]{64}(-proxy)?", name[len(prefix):]):
                docker("rm", "-f", container_id)
        if output is not None:
            output.close()
            output = None

    def start(label):
        nonlocal process, output
        log = directory / f"wrangler-{label}.log"
        output = log.open("w")
        process = subprocess.Popen([
            str(WORKER / "node_modules/.bin/wrangler"), "dev", "--config", str(config),
            "--local", "--ip", "127.0.0.1", "--port", str(port), "--persist-to", str(directory / "state"),
        ], cwd=directory, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            assert process.poll() is None, log.read_text()[-4000:]
            if f"Ready on {url}" in log.read_text():
                return
            time.sleep(.2)
        raise AssertionError(f"Wrangler readiness timed out; inspect {log}")

    def containers():
        # Exact unique Worker name scopes observations to this fixture.
        prefix = f"workerd-{run_name}-ExecutorContainer-"
        rows = docker("ps", "--filter", f"name={prefix}", "--format", "{{.ID}} {{.Names}}")
        return [row.split()[0] for row in rows.splitlines()
                if row.split()[1].startswith(prefix)
                and re.fullmatch(r"[0-9a-f]{64}", row.split()[1][len(prefix):])]

    def operation(op, placement):
        return call({"operation": op, "placement": placement})

    try:
        print(f"Physical fixture evidence: {directory}", flush=True)
        start("initial")
        # A retained protected request cannot start an unconfigured container.
        protected_effect = run_name + "-protected-unconfigured"
        runtime = {
            "engine": {"kind": "cpython3147_wasi", "artifact_path": "/opt/runtime.wasm",
                       "artifact_sha256": "a" * 64},
            "executable": "/usr/local/bin/whip", "python_version": "3.14.7",
            "environment": "original-epoch",
        }
        protected = call({"operation": "place", "effect": protected_effect, "dispatch": {
            "protocol": "whip-executor/1", "effect_id": protected_effect,
            "argv": [runtime["executable"], "executor", "observe-norm", "{script}"],
            "stdin": {"method_definition_json": json.dumps({"runtime": runtime,
                      "module": "main", "function": "check", "cases": []})},
        }})
        assert "container_id" in protected, protected
        before = operation("read", protected)
        refused = operation("deliver", protected)
        assert refused.get("http_error") == 500, refused
        assert "configured runtime" in refused.get("body", ""), refused
        assert operation("read", protected) == before
        assert not containers(), "unconfigured protected invocation started a process"
        print("PASS: unconfigured protected invocation refuses before physical startup", flush=True)
        # Close the host-crash window before the broker ever received dispatch.
        absent_effect = run_name + "-unclaimed"
        absent_script = "echo must-not-run\n"
        absent_dispatch = {
            "protocol": "whip-executor/1", "effect_id": absent_effect,
            "script_sha256": hashlib.sha256(absent_script.encode()).hexdigest(),
            "script_b64": base64.b64encode(absent_script.encode()).decode(),
            "script_ext": "sh", "argv": ["sh", "{script}"], "script_index": 1,
            "stdin": None, "timeout_ms": 1000,
        }
        absent = call({"operation": "provider-prepare", "effect": absent_effect, "dispatch": absent_dispatch})
        assert "envelope" in absent and "selected" in absent, absent
        never = call({"operation": "provider-ensure-fence", "invocation": absent})
        assert never.get("lifetime") == {"state": "not_admitted", "fence_id": "physical-provider-fence"}, never
        assert never["outcome"] == {"state": "not_executed"}, never
        assert not containers(), "preplacement fencing started a process"
        stop()
        start("preplacement-cold")
        assert call({"operation": "provider-ensure-fence", "invocation": absent}) == never
        late = call({"operation": "provider-invoke", "invocation": absent})
        assert late == {"protocol": "whipplescript.exec.reconciliation/v1", "state": "pending"}, late
        assert not containers(), "late handoff bypassed non-admission"
        print("PASS: preplacement non-admission survives restart and blocks late execution without startup", flush=True)
        placements = []
        for index in range(2):
            effect = f"{run_name}-{index}"
            script = f"sleep 120 &\necho $! > /tmp/barrier-child-{index}\necho $$ > /tmp/barrier-parent-{index}\nwait\n"
            dispatch = {
                "protocol": "whip-executor/1", "effect_id": effect,
                "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
                "script_b64": base64.b64encode(script.encode()).decode(),
                "script_ext": "sh", "argv": ["sh", "{script}"], "script_index": 1,
                "stdin": None, "timeout_ms": 180000,
            }
            placement = call({"operation": "place", "effect": effect, "dispatch": dispatch})
            assert "container_id" in placement, placement
            placements.append(placement)
        (directory / "placements.json").write_text(json.dumps(placements))
        with concurrent.futures.ThreadPoolExecutor() as pool:
            deliveries = [pool.submit(operation, "deliver", p) for p in placements]
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                ids = containers()
                if ids:
                    assert len(ids) == 1, ids
                    tree = docker("top", ids[0], "-eo", "pid,args")
                    if tree.count("sleep 120") == 2:
                        break
                for delivery in deliveries:
                    assert not delivery.done(), delivery.result() if delivery.done() else None
                time.sleep(.2)
            else:
                raise AssertionError("two sibling commands did not start")
            print(tree, flush=True)
            assert all(operation("read", p)["action"]["action"] == "pending" for p in placements)
            fence = operation("fence", placements[0])["action"]
            assert fence["action"] == "terminated", fence
            assert not containers(), "destruction acknowledged while the container is still running"
            for delivery in deliveries:
                result = delivery.result()
                assert result.get("http_error") == 500, result
            retained = [operation("read", p)["action"] for p in placements]
            for result in retained:
                assert result["action"] == "terminated", result
                assert result["incarnation"] == fence["incarnation"], result
                assert result["barrier_id"] == fence["barrier_id"], result
            print("Sibling terminal bindings:", json.dumps(retained), flush=True)
        stop()
        start("cold")
        for placement, expected in zip(placements, retained):
            for op in ["read", "deliver", "fence"]:
                replayed = operation(op, placement)
                assert replayed.get("action") == expected, (op, replayed, expected)
        assert not containers(), "cold replay restarted the container"
        print("PASS: physical sibling termination, cold retention, and no late restart", flush=True)
        # A timeout result is available while its descendant is still alive.
        # Every current invocation is completed here, so an unresolved-only
        # snapshot would wrongly skip destruction.
        effect = run_name + "-timeout"
        script = "sleep 120 &\necho $! > /tmp/barrier-timeout-child\nwait\n"
        dispatch = {
            "protocol": "whip-executor/1", "effect_id": effect,
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
            "script_b64": base64.b64encode(script.encode()).decode(),
            "script_ext": "sh", "argv": ["sh", "{script}"], "script_index": 1,
            "stdin": None, "timeout_ms": 2000,
        }
        placement = call({"operation": "place", "effect": effect, "dispatch": dispatch})
        result = operation("deliver", placement)["action"]
        assert result["action"] == "replay" and result["status"] == 200, result
        assert result["body"]["timed_out"] is True, result
        assert "termination" not in result, result
        ids = containers()
        assert len(ids) == 1, ids
        descendant = docker("exec", ids[0], "cat", "/tmp/barrier-timeout-child")
        docker("exec", ids[0], "test", "-d", f"/proc/{descendant}")
        tree = docker("top", ids[0], "-eo", "pid,args")
        assert "sleep 120" in tree, tree
        print("Descendant alive after returned timeout:", tree, flush=True)
        fenced = operation("fence", placement)["action"]
        proof = fenced.get("termination")
        assert proof and all(proof.get(field) for field in ["incarnation", "fence_id", "barrier_id"]), fenced
        assert {key: value for key, value in fenced.items() if key != "termination"} == result
        assert not containers(), "completed result bypassed physical destruction"
        stop()
        start("completed-cold")
        for op in ["read", "deliver", "fence"]:
            assert operation(op, placement)["action"] == fenced
        assert not containers(), "completed cold replay restarted descendants"
        print("PASS: completed timeout keeps its output, gains physical proof, and stays fenced after restart", flush=True)
        # Repeat through the real provider broker and its retained receipt, not
        # the controller fixture door. The result must remain byte-for-byte JSON
        # equivalent while separate lifetime proof survives both owner restarts.
        effect = run_name + "-provider-timeout"
        dispatch["effect_id"] = effect
        invocation = call({"operation": "provider-prepare", "effect": effect, "dispatch": dispatch})
        provider = lambda op: call({"operation": "provider-" + op, "invocation": invocation})
        provider_output = provider("invoke")
        assert provider_output.get("timed_out") is True, provider_output
        before = provider("read")
        assert before["lifetime"] == {"state": "pending"}, before
        assert before["outcome"] == {"state": "completed", "status": 200, "body": provider_output}, before
        ids = containers()
        assert len(ids) == 1, ids
        descendant = docker("exec", ids[0], "cat", "/tmp/barrier-timeout-child")
        docker("exec", ids[0], "test", "-d", f"/proc/{descendant}")
        older = call({"operation": "intent", "placement": before["placement"]})
        assert older["intent"]["action"] == "fence_required", older
        assert older["intent"]["fence_id"] == "older-controller-fence", older
        assert older["gate"]["closing"] is False, older
        docker("exec", ids[0], "test", "-d", f"/proc/{descendant}")
        tree = docker("top", ids[0], "-eo", "pid,args")
        assert "sleep 120" in tree, tree
        print("Provider descendant alive with older standalone intent:", tree, flush=True)
        proof = provider("fence")
        assert proof["lifetime"]["state"] == "terminated", proof
        assert proof["lifetime"]["fence_id"] == "older-controller-fence", proof
        assert all(proof["lifetime"].get(field) for field in ["incarnation", "fence_id", "barrier_id"]), proof
        assert proof["outcome"] == before["outcome"], proof
        assert not containers(), "provider proof preceded physical destruction"
        stop()
        start("provider-cold")
        assert provider("read") == proof
        assert provider("fence") == proof
        assert provider("invoke") == provider_output
        assert not containers(), "provider cold replay restarted execution"
        print("PASS: broker resumes older intent after failed barrier creation, preserves output and proof across cold restart", flush=True)

    finally:
        stop()


if __name__ == "__main__":
    main()
