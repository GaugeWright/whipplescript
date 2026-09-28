"""Record guest build inputs; this is not a license or artifact approval."""
from pathlib import Path
import hashlib
import json
import re
import sys
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[1] / "target"
SOURCE = ROOT / "norm-cpython-wasi"
BUILD = SOURCE / "cross-build/wasm32-wasip1"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest = json.loads((ROOT / "norm-wasi-build.json").read_text())
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
if revision != manifest["cpython_revision"]:
    raise SystemExit("CPython source differs from the recorded build revision")
subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=SOURCE, check=True)
checked = {
    "compiler_sha256": ROOT / "wasi-sdk-24.0-x86_64-linux/bin/clang",
    "artifact_sha256": ROOT / "norm-cpython-observer.wasm",
    "bridge_sha256": HERE / "bridge.c",
    "frozen_header_sha256": ROOT / "norm-frozen-stdlib.h",
    "frozen_manifest_sha256": ROOT / "norm-frozen-stdlib.json",
    "loader_sha256": HERE.parents[1] / "crates/whipplescript-kernel/src/norm_embedded_calls.py",
}
for key, path in checked.items():
    if digest(path) != manifest[key]:
        raise SystemExit(f"build evidence differs from current input: {key}")

sbom_path = SOURCE / "Misc/sbom.spdx.json"
sbom = json.loads(sbom_path.read_text())
modules = dict(re.findall(r"^MODULE_(\w+)_STATE=(.*)$", (BUILD / "Makefile").read_text(), re.M))
archives = [BUILD / "libpython3.14.a", *sorted((BUILD / "Modules").rglob("*.a"))]
link_evidence = json.loads((ROOT / "norm-wasi-link-evidence.json").read_text())
link_map = ROOT / "norm-wasi-link.map"
if link_evidence["artifact_sha256"] != manifest["artifact_sha256"] or digest(link_map) != link_evidence["link_map_sha256"]:
    raise SystemExit("link inventory does not match the recorded reactor")
linked = {}
pattern = re.escape(str(ROOT)) + r"/(.+?\.a)\(([^)]+)\)"
for archive, member in re.findall(pattern, link_map.read_text()):
    path = (ROOT / archive).resolve()
    relative = str(path.relative_to(ROOT))
    linked.setdefault(relative, set()).add(member)
if not linked:
    raise SystemExit("link map contains no recognized archive contributions")
result = {
    "status": "build-evidence-only",
    "artifact_sha256": manifest["artifact_sha256"],
    "cpython_revision": manifest["cpython_revision"],
    "source_license_sha256": digest(SOURCE / "LICENSE"),
    "upstream_source_sbom_sha256": digest(sbom_path),
    "upstream_source_packages": [
        {key: package.get(key) for key in ["name", "versionInfo", "licenseConcluded", "licenseDeclared"]}
        for package in sbom.get("packages", [])
    ],
    "configured_module_states": modules,
    "supplied_cpython_archives": {
        str(path.relative_to(SOURCE)): digest(path) for path in archives
    },
    "link_map_sha256": link_evidence["link_map_sha256"],
    "archive_objects_in_link_map": {
        archive: {"sha256": digest(ROOT / archive), "members": sorted(members)}
        for archive, members in sorted(linked.items())
    },
    "unresolved": [
        "The upstream SBOM describes the source tree, not exact linked contributions.",
        "Archive objects represented in the link map are inventoried; source-level license mapping remains open.",
        "WASI libc and compiler runtime archive contributions are inventoried; their notices remain to be assembled.",
        "Package licenseConcluded=NOASSERTION is not an approval or a license classification.",
        "No guest distribution or licensing-policy approval is established by this file.",
    ],
}
output = ROOT / "norm-wasi-guest-inventory.json"
output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
print(f"recorded {len(modules)} module states, {len(archives)} supplied CPython archives, and {len(linked)} contributing archives in {output}")
