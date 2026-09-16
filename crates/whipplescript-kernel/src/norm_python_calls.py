"""Bundled norm adapter: invoke declared Python cases, reporting actual values.

This is trusted method code, executed by the existing Class-A executor. It is
not a security sandbox for hostile Python; interpreter/runtime integrity is an
explicit observer assumption. Materialization identifies the tested source but
does not constrain external reads or establish a closure for evidence reuse.
"""
import contextlib
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

PROTOCOL = "whipplescript.norm.python-calls/v1"


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)


def main():
    request = json.load(sys.stdin)
    adapter_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    definition_json = request["method_definition_json"]
    definition = json.loads(definition_json)
    contract_json = request["contract_json"]
    contract = json.loads(contract_json)
    # Hash the exact canonical definition bytes prepared by the shared Rust
    # layer; re-encoding arbitrary floating-point arguments in Python can
    # change their spelling without changing the represented JSON value.
    method_material = json.dumps([PROTOCOL, adapter_digest], separators=(",", ":"))[:-1] + "," + definition_json + "]"
    method = {"name": "python-calls", "version": "1",
              "digest": hashlib.sha256(method_material.encode("utf-8")).hexdigest()}
    artifact_material = json.dumps(["whipplescript.norm.candidate/v1", request["files"]],
                                   sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    artifact = hashlib.sha256(artifact_material.encode("utf-8")).hexdigest()
    emit({"kind": "started", "protocol": PROTOCOL,
          "run_id": request["run_id"], "artifact": artifact,
          "contract_digest": hashlib.sha256(contract_json.encode("utf-8")).hexdigest(),
          "requirement": contract["subject"]["requirement"],
          "method": method, "environment": definition["runtime"]["environment"],
          "adapter_digest": adapter_digest,
          "python_version": sys.version.split()[0]})
    failed = False
    broken = False
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=Path(__file__).parent) as directory:
        root = Path(directory)
        for name, content in request["files"].items():
            # Preparation validates paths; repeat at the executable boundary.
            path = Path(name)
            if path.is_absolute() or any(p in ("", ".", "..") for p in name.split("/")) or "\\" in name:
                raise ValueError("candidate path escapes its materialization")
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode("utf-8"))
        os.chdir(root)
        sys.path.insert(0, str(root))
        try:
            with contextlib.redirect_stdout(sys.stderr):
                module_path = definition["module"].replace(".", "/")
                candidates = [root / (module_path + ".py"), root / module_path / "__init__.py"]
                candidates = [path for path in candidates if path.is_file()]
                spec = importlib.util.find_spec(definition["module"])
                if len(candidates) != 1 or spec is None or spec.origin is None or Path(spec.origin).resolve() != candidates[0].resolve():
                    raise RuntimeError("entry point resolved outside its exact candidate module")
                module = importlib.import_module(definition["module"])
                function = getattr(module, definition["function"])
            required = {case["id"]: case for case in contract["cases"]}
            for inputs in definition["cases"]:
                case = required[inputs["id"]]
                try:
                    with contextlib.redirect_stdout(sys.stderr):
                        actual = function(*inputs["args"], **inputs["kwargs"])
                    # Serializability is part of this adapter's contract. Convert
                    # through JSON before equality so tuple/list representation
                    # does not disagree with the shared JSON-value evaluator.
                    actual = json.loads(json.dumps(actual, allow_nan=False))
                    emit({"kind": "case", "case": case["id"],
                          "assertion": case["assertion"], "actual": actual})
                    failed = failed or json.dumps(actual, sort_keys=True) != json.dumps(case["expected"], sort_keys=True)
                except Exception as error:
                    broken = True
                    emit({"kind": "error", "case": case["id"],
                          "message": type(error).__name__ + ": " + str(error)})
        except Exception as error:
            broken = True
            emit({"kind": "error", "case": None,
                  "message": type(error).__name__ + ": " + str(error)})
    emit({"kind": "complete"})
    return 2 if broken else 1 if failed else 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        code = 2
    sys.exit(code)
