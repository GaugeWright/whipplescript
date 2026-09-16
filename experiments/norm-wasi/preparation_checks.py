"""Exercise readiness refusals while preserving the prepared artifact and metadata."""
from pathlib import Path
import copy
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[1] / "target"
path = ROOT / "norm-wasi-prepared.json"
original = path.read_bytes()
base = json.loads(original)
command = [sys.executable, str(HERE / "prepare.py"), str(ROOT), "--check"]

def check():
    return subprocess.run(command, text=True, capture_output=True)

result = check()
assert result.returncode == 0, result.stderr
print("prepared reactor readiness passes", flush=True)
variants = []
value = copy.deepcopy(base)
del value["files"]["norm-cpython-observer.wasm"]
variants.append(("missing required artifact entry", value))
value = copy.deepcopy(base)
value["files"]["../unlisted"] = "0" * 64
variants.append(("extra file entry", value))
value = copy.deepcopy(base)
value["artifact_sha256"] = "0" * 64
variants.append(("inconsistent artifact identity", value))
value = copy.deepcopy(base)
value["recipe"]["sources"]["bridge.c"] = "0" * 64
variants.append(("changed recipe", value))
value = copy.deepcopy(base)
value["files"]["norm-wasi-build.json"] = "0" * 64
variants.append(("changed input bytes", value))
try:
    for name, value in variants:
        path.write_text(json.dumps(value))
        result = check()
        assert result.returncode != 0 and "runtime is not prepared" in result.stderr, (name, result.stdout, result.stderr)
        print(name, "refused", flush=True)
finally:
    path.write_bytes(original)
result = check()
assert result.returncode == 0, result.stderr
assert path.read_bytes() == original
print("readiness metadata restored and verified", flush=True)
