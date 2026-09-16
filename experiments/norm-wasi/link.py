"""Link the experimental reactor from an already built, pinned CPython tree."""
from pathlib import Path
import hashlib
import json
import subprocess
import argparse

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("build_root", nargs="?", type=Path, default=HERE.parents[1] / "target")
parser.add_argument("--inventory-only", action="store_true", help="relink separately and require byte identity with the existing reactor")
args = parser.parse_args()
ROOT = args.build_root.resolve()
SOURCE = ROOT / "norm-cpython-wasi"
BUILD = SOURCE / "cross-build/wasm32-wasip1"
REVISION = "823f0323ee6ec1402088b73bce1a38473cac36dc"

revision = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True
).strip()
if revision != REVISION:
    raise SystemExit("CPython source revision differs from the experiment pin")
subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=SOURCE, check=True)

compiler = ROOT / "wasi-sdk-24.0-x86_64-linux/bin/clang"
artifact = ROOT / "norm-cpython-observer.wasm"
linked_output = ROOT / "norm-wasi-inventory.wasm" if args.inventory_only else artifact
link_map = ROOT / "norm-wasi-link.map"
command = [
    str(compiler), "-O2", "-mexec-model=reactor",
    # Assertion paths must not encode the checkout location. Debug sections
    # carry build paths from upstream archives and are not distributed.
    f"-ffile-prefix-map={ROOT}=/build",
    f"-ffile-prefix-map={HERE}=/src/norm-observer", "-Wl,--strip-debug",
    "-I" + str(SOURCE / "Include"), "-I" + str(BUILD), "-I" + str(ROOT),
    str(HERE / "bridge.c"), "-Wl,--stack-first",
    "-Wl,-z,stack-size=16777216", "-Wl,--initial-memory=41943040",
    "-Wl,-Map=" + str(link_map),
]
exports = [
    "norm_python_version", "norm_init", "norm_load", "norm_call", "norm_call_json", "norm_result_ptr",
    "norm_result_len", "norm_new_none", "norm_new_bool", "norm_new_string",
    "norm_new_integer", "norm_new_float", "norm_new_list", "norm_new_dict",
    "norm_list_push", "norm_dict_set", "norm_drop", "norm_call_values",
    "norm_install_files", "norm_select", "malloc", "free",
]
command.extend("-Wl,--export=" + name for name in exports)
command.append(str(BUILD / "libpython3.14.a"))
command.extend(str(path) for path in sorted((BUILD / "Modules").rglob("*.a")))
command.extend([
    "-ldl", "-lwasi-emulated-signal", "-lwasi-emulated-getpid",
    "-lwasi-emulated-process-clocks", "-lm", "-o", str(linked_output),
])
subprocess.run(command, check=True)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

if args.inventory_only and digest(linked_output) != digest(artifact):
    raise SystemExit("inventory relink differs from the existing reactor")
(ROOT / "norm-wasi-link-evidence.json").write_text(json.dumps({
    "artifact_sha256": digest(artifact),
    "link_map_sha256": digest(link_map),
    "status": "byte-identical-relink" if args.inventory_only else "direct-link",
}, indent=2) + "\n")
if args.inventory_only:
    print("inventory relink is byte-identical to the existing reactor")
    raise SystemExit(0)

# Build evidence, not a trusted artifact allowlist or reproducibility proof.
manifest = {
    "cpython_revision": revision,
    "compiler_sha256": digest(compiler),
    "bridge_sha256": digest(HERE / "bridge.c"),
    "frozen_header_sha256": digest(ROOT / "norm-frozen-stdlib.h"),
    "frozen_manifest_sha256": digest(ROOT / "norm-frozen-stdlib.json"),
    "loader_sha256": digest(HERE.parents[1] / "crates/whipplescript-kernel/src/norm_embedded_calls.py"),
    "artifact_sha256": digest(artifact),
    "exports": exports,
}
(ROOT / "norm-wasi-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
