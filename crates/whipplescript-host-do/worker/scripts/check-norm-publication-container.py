"""Real local hosted norm execution and custody-signed publication.

Invoked by the Rust fixture while its native custody service remains alive.
Only loopback Wrangler and uniquely named containers belong to this harness.
"""
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[4]
WORKER = ROOT / "crates/whipplescript-host-do/worker"


def main():
    vector_path, whip = map(Path, sys.argv[1:])
    vector = json.loads(vector_path.read_text())
    directory = vector_path.parent
    name = "whip-norm-" + str(time.time_ns())
    print(f"Hosted physical publication evidence: {directory}", flush=True)
    context_request = directory / "context-request.json"
    context_request.write_text(json.dumps({"runtime": vector["runtime"], "artifact_source": vector["reactor"], "build_root": str(directory / "images")}))
    prepared = subprocess.run([str(whip), "executor", "prepare-norm-runtime-context", "--request", str(context_request)], check=True, capture_output=True, text=True)
    context = json.loads(prepared.stdout)
    (directory / "context-receipt.json").write_text(prepared.stdout)
    # Only public trust and candidate artifacts enter the worker environment.
    public_vector = {"cases": [{k: case[k] for k in ["public_bindings", "checkpoint", "artifacts", "planning"]} for case in vector["cases"]]}
    config = directory / "wrangler.json"
    config.write_text(json.dumps({
        "name": name, "main": str(WORKER / "scripts/fixtures/norm-publication-local.ts"),
        "compatibility_date": "2026-07-08",
        "rules": [{"type": "Text", "globs": ["**/*.sql"], "fallthrough": False}],
        "durable_objects": {"bindings": [{"name": cls, "class_name": clsname} for cls, clsname in [("WORKFLOW_INSTANCE", "WorkflowInstance"), ("EXECUTOR", "ExecutorContainer"), ("WORKSPACE_BROKER", "WorkspaceBroker")]]},
        "containers": [{"class_name": "ExecutorContainer", "image": str(Path(context["directory"]) / "Dockerfile"), "max_instances": 1}],
        "migrations": [{"tag": "v1", "new_sqlite_classes": ["WorkflowInstance", "ExecutorContainer", "WorkspaceBroker"]}],
        "vars": {"WHIP_CONTROL_TOKEN": "physical-control", "WHIP_EXECUTOR_TOKEN": "physical-executor",
                 "WHIP_EXECUTOR_POOL_SIZE": "1", "WHIP_EXECUTOR_URL": "http://executor:8080",
                 "WHIP_COMPUTE_ENV_HASH": "ordinary-cache-epoch", "WHIP_NORM_RUNTIME": json.dumps(vector["runtime"]),
                 "WHIP_SCRIPT_CAPABILITIES_JSON": json.dumps(vector["scripts"]), "NORM_PHYSICAL_VECTOR": json.dumps(public_vector)},
    }))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    process = output = None

    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True).strip()

    def containers(all_states=False):
        prefix = f"workerd-{name}-ExecutorContainer-"
        rows = docker("ps", *(["-a"] if all_states else []), "--filter", f"name={prefix}", "--format", "{{.ID}} {{.Names}}")
        return [r.split()[0] for r in rows.splitlines() if r.split()[1].startswith(prefix)
                and re.fullmatch(r"[0-9a-f]{64}(-proxy)?", r.split()[1][len(prefix):])]

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
        for container in containers(True):
            docker("rm", "-f", container)
        if output:
            output.close()
            output = None

    def start(label):
        nonlocal process, output
        log = directory / f"wrangler-{label}.log"
        output = log.open("w")
        process = subprocess.Popen([str(WORKER / "node_modules/.bin/wrangler"), "dev", "--config", str(config), "--local", "--ip", "127.0.0.1", "--port", str(port), "--persist-to", str(directory / "state")], cwd=directory, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            assert process.poll() is None, log.read_text()[-4000:]
            if f"Ready on {origin}" in log.read_text():
                return
            time.sleep(0.2)
        raise AssertionError(f"Wrangler readiness timed out; inspect {log}")

    def call(index, path, body, status=200):
        request = urllib.request.Request(f"{origin}{path}?id=norm-{index}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "Authorization": "Bearer physical-control"})
        try:
            # loopback origin this script built from a
            # port it bound; no external value reaches the URL.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            observed_status = response.code
            text = response.read().decode()
        if observed_status != status:
            diagnostic = {"path": path, "case": index, "status": observed_status,
                          "body": text, "wrangler_exit": process.poll()}
            # Failure-only reads distinguish a dead runtime from an object-
            # specific failure. They never retry the failed command.
            for target in ["health", f"norm-{index}"]:
                suffix = "/fixture/health" if target == "health" else f"/fixture/inspect?id={target}"
                check = urllib.request.Request(origin + suffix, data=b"{}", headers={"Content-Type":"application/json"})
                try:
                    # same loopback origin, fixed suffix.
                    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    with urllib.request.urlopen(check, timeout=10) as observed:
                        diagnostic[target] = {"status": observed.code, "bytes": len(observed.read())}
                except Exception as error:
                    diagnostic[target] = {"error": str(error)}
            diagnostic["wrangler_exit_after_reads"] = process.poll()
            (directory / "failure-diagnostic.json").write_text(json.dumps(diagnostic, indent=2))
            raise AssertionError((path, observed_status, text[:2000], diagnostic))
        return json.loads(text)

    def command(index, value):
        return call(index, "/host/norm/commands", {"protocol": "whipplescript.norm.commands/v1", "command": value})

    def publication(index, value, status=200):
        return call(index, "/host/norm/publications", {"protocol": "whipplescript.norm.publication/v1", "command": value}, status)

    retained = []
    executed_images = set()
    try:
        start("initial")
        for index, case in enumerate(vector["cases"]):
            call(index, "/host/norm/provision", {})
            command(index, {"kind": "import", "events": case["events"]})
            call(index, "/host/norm/commands", {"protocol": "whipplescript.norm.commands/v1", "command": {"kind": "resources", "point": {"cut": "cut"}}}, 400)
            call(index, "/fixture/seed", {})
            started = call(index, "/start", {"program": "workflow HostedNorm\nuse std.script\noutput result Verdict\nclass Verdict {\n  ok int\n}\n", "principal": "local/HostedNorm"})
            state = call(index, "/fixture/inspect", {})
            (directory / f"initial-{index}.json").write_text(json.dumps({"started": started, "state": state}))
            assert len(state["instances"]) == 1 and not state["runs"], state
            initial_frontier = command(index, {"kind": "snapshot"})["result"]["snapshot"]["frontier"]
            instance = state["instances"][0]["instance_id"]
            enqueue = {"protocol": "whipplescript.norm.enqueue/v1", "command": {"instance": instance, "requirement": case["requirement"], "cut": "cut", "effect": "observe", "capability": "observer", "publisher": "owner", "deadline_seconds": 120}}
            acknowledgment = call(index, "/host/norm/enqueues", enqueue)
            # The normal worker shell drives the queued effect and real broker.
            driven = call(index, "/start", {})
            state = call(index, "/fixture/inspect", {})
            (directory / f"executed-{index}.json").write_text(json.dumps({"driven": driven, "state": state}))
            assert len(state["runs"]) == 1, state
            run = state["runs"][0]
            assert run["status"] == ("failed" if case["actual"] else "completed"), state
            workload = [container for container in containers(True)
                        if not docker("inspect", "--format", "{{.Name}}", container).endswith("-proxy")]
            assert workload, "physical workload container identity is unavailable"
            identities = {docker("inspect", "--format", "{{.Image}}", container) for container in workload}
            assert len(identities) == 1, identities
            executed_images.update(identities)
            (directory / f"execution-image-{index}.json").write_text(json.dumps({"containers": workload, "images": sorted(identities)}))
            before = command(index, {"kind": "export"})
            draft_command = {"kind": "prepare", "instance": instance, "run": run["run_id"], "vocabulary": "local-observation@1", "actor": case["public_bindings"][0]["actor"], "created_at": "2026-09-13T00:00:00Z"}
            wrong = publication(index, {**draft_command, "actor": case["public_bindings"][1]["actor"]}, 400)
            assert "publisher" in json.dumps(wrong), wrong
            assert command(index, {"kind": "export"}) == before
            draft = publication(index, draft_command)
            statement = directory / f"statement-{index}.json"
            statement.write_text(json.dumps(draft["result"]["statement"]))
            signed = subprocess.run([str(whip), "--json", "norm", "sign", "--as", "owner", "--statement", str(statement)], env={"WHIPPLESCRIPT_CUSTODIAN_SOCKET": case["signing"]["socket"], "WHIPPLESCRIPT_NORM_TRUST": json.dumps(case["signing"]["trust"])}, capture_output=True, text=True)
            assert signed.returncode == 0, signed.stderr
            event = json.loads(signed.stdout)
            publish = {"kind": "publish", "instance": instance, "run": run["run_id"], "event": event}
            # An uploaded invalid signature cannot publish even the exact draft.
            invalid = {**publish, "event": {**event, "signature": "invalid"}}
            journal = call(index, "/fixture/inspect", {})
            refused = publication(index, invalid, 400)
            assert "signature" in json.dumps(refused).lower(), refused
            assert command(index, {"kind": "export"}) == before
            assert call(index, "/fixture/inspect", {}) == journal
            result = publication(index, publish)
            observation = result["result"]["observation"]
            assert observation["observation_integrity"] == {"kind": "protected_interpreter"}, observation
            assert observation["judgment"]["outcome"] == ("fail" if case["actual"] else "pass"), observation
            assert observation["report"]["observations"][0]["actual"] is case["actual"], observation
            assert len(observation["judgment"]["counterexamples"]) == int(case["actual"]), observation
            after = command(index, {"kind": "export"})
            assert len(after["result"]["events"]) == len(before["result"]["events"]) + 1
            retained.append((index, enqueue, acknowledgment, publish, result, after, initial_frontier))
            (directory / f"published-{index}.json").write_text(json.dumps(result))
            print(f"PASS: actual={case['actual']} admitted, physically executed and custody-published", flush=True)
        assert len(executed_images) == 1, executed_images
        image_id = next(iter(executed_images))
        probe_request = directory / "image-verification-request.json"
        endpoint = docker("context", "inspect", "--format", '{{.Endpoints.docker.Host}}')
        probe_request.write_text(json.dumps({"endpoint": endpoint, "image_id": image_id, "runtime": vector["runtime"]}))
        probe = subprocess.run([str(whip), "executor", "verify-norm-runtime-image", "--request", str(probe_request)], check=True, capture_output=True, text=True)
        binding = json.loads(probe.stdout)
        assert binding["image_id"] == image_id and binding["runtime"] == vector["runtime"], binding
        (directory / "image-binding.json").write_text(probe.stdout)
        stop()
        installed_config = json.loads(config.read_text())
        installed_config["vars"]["WHIP_NORM_IMAGE_BINDING"] = probe.stdout
        installed_config["vars"]["WHIP_NORM_DEPLOYMENT_IMAGE"] = "sha256:" + "0" * 64
        config.write_text(json.dumps(installed_config))
        start("mismatched-image")
        before_mismatch = call(0, "/fixture/inspect", {})
        mismatch = call(0, "/host/norm/impacts", {"protocol": "whipplescript.norm.impact/v1", "command": {"before_cut": "cut", "after_cut": "cut"}}, 400)
        assert "image" in json.dumps(mismatch), mismatch
        assert call(0, "/fixture/inspect", {}) == before_mismatch
        assert not containers(), "mismatched deployment query started a container"
        stop()
        installed_config["vars"]["WHIP_NORM_DEPLOYMENT_IMAGE"] = image_id
        config.write_text(json.dumps(installed_config))
        start("cold")
        for index, enqueue, acknowledgment, publish, result, after, initial_frontier in retained:
            assert call(index, "/host/norm/enqueues", enqueue) == acknowledgment
            assert publication(index, publish) == result
            assert command(index, {"kind": "export"}) == after
            assert len(call(index, "/fixture/inspect", {})["runs"]) == 1
            assert not containers(), "cold publication replay started a container"
            journal = call(index, "/fixture/inspect", {})
            impact_request = {"protocol": "whipplescript.norm.impact/v1", "command": {"before_cut": "cut", "after_cut": "cut"}}
            for repeat in range(2):
                impact = call(index, "/host/norm/impacts", impact_request)
                (directory / f"impact-{index}-{repeat}.json").write_text(json.dumps(impact))
                plans = impact["result"]["plan"]["requirements"][vector["cases"][index]["requirement"]]
                assert plans[0]["work"]["kind"] == ("repair" if vector["cases"][index]["actual"] else "supported"), impact
            historical = call(index, "/host/norm/impacts", {**impact_request, "command": {**impact_request["command"], "before_frontier": initial_frontier, "after_frontier": initial_frontier}})
            assert historical["result"]["plan"]["requirements"][vector["cases"][index]["requirement"]][0]["work"]["kind"] == "check", historical
            assert call(index, "/fixture/inspect", {}) == journal
            assert command(index, {"kind": "export"}) == after
            assert not containers(), "cold impact query started a container"
            call(index, "/fixture/remove-cut", {})
            unavailable = call(index, "/host/norm/impacts", {**impact_request, "command": {"before_cut": "same-content", "after_cut": "same-content"}})
            assert unavailable["result"]["plan"]["requirements"][vector["cases"][index]["requirement"]][0]["work"]["kind"] == "verify_evidence", unavailable
            assert call(index, "/fixture/inspect", {}) == journal
            assert not containers(), "missing-cut impact query started a container"
            refused = publication(index, publish, 400)
            assert "is not recorded" in json.dumps(refused), refused
            assert command(index, {"kind": "export"}) == after
        print("PASS: cold publication and installed impact queries retain journals, one run, no startup, and original-cut requirements", flush=True)
    finally:
        stop()


if __name__ == "__main__":
    main()
