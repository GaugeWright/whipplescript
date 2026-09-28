"""Collect revision-pinned upstream notices without asserting distribution approval."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("build_root", nargs="?", type=Path, default=HERE.parents[1] / "target")
parser.add_argument("--fetch-llvm", action="store_true", help="fetch three small, digest-pinned upstream notice files")
args = parser.parse_args()
ROOT = args.build_root.resolve()
PINS = {
    "norm-cpython-wasi": "823f0323ee6ec1402088b73bce1a38473cac36dc",
    "norm-wasi-sdk-source": "d2bea01edcc46f731156a817f710cdd9fc9c1c19",
    "norm-wasi-sdk-source/src/wasi-libc": "b9ef79d7dbd47c6c5bafdae760823467c2f60b70",
}
LLVM = "26a1d6601d727a96f4301d0d8647b5a42760ae0c"
LLVM_FILES = {
    "compiler-rt/LICENSE.TXT": "1a8f1058753f1ba890de984e48f0242a3a5c29a6a8f2ed9fd813f36985387e8d",
    "compiler-rt/CREDITS.TXT": "a9901f47a089da41e4690682d00ce4cedaa2baf41fedbe79beee366d43ac2461",
    "llvm/LICENSE.TXT": "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee",
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

for name, expected in PINS.items():
    source = ROOT / name
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if actual != expected:
        raise SystemExit(f"wrong notice source revision: {name}")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=source, check=True)

inventory = json.loads((ROOT / "norm-wasi-guest-inventory.json").read_text())
if digest((ROOT / "norm-cpython-observer.wasm").read_bytes()) != inventory["artifact_sha256"]:
    raise SystemExit("notice inventory does not match the guest artifact")
output = ROOT / "norm-wasi-notices"
output.mkdir(exist_ok=True)
entries = []

def record(name, data, source, revision, extraction="whole-file"):
    (output / name).write_bytes(data)
    entries.append({"file": name, "source": source, "revision": revision,
                    "extraction": extraction, "sha256": digest(data)})

files = {
    "norm-cpython-wasi": ["LICENSE", "Doc/license.rst", "Modules/expat/COPYING"],
    "norm-wasi-sdk-source": ["LICENSE"],
    "norm-wasi-sdk-source/src/wasi-libc": [
        "LICENSE", "LICENSE-APACHE", "LICENSE-APACHE-LLVM", "LICENSE-MIT",
        "libc-top-half/musl/COPYRIGHT", "libc-bottom-half/cloudlibc/LICENSE",
        "tools/wasi-headers/LICENSE",
    ],
}
for source, paths in files.items():
    prefix = "cpython" if source == "norm-cpython-wasi" else "wasi-libc" if source.endswith("wasi-libc") else "wasi-sdk"
    for path in paths:
        record(prefix + "-" + path.replace("/", "-"), (ROOT / source / path).read_bytes(),
               source + "/" + path, PINS[source])

for source, path, name in [
    ("norm-cpython-wasi", "Modules/_decimal/libmpdec/mpdecimal.h", "mpdecimal-notice.txt"),
    ("norm-cpython-wasi", "Modules/_hacl/Hacl_HMAC.c", "hacl-hmac-notice.txt"),
    ("norm-wasi-sdk-source/src/wasi-libc", "dlmalloc/src/malloc.c", "dlmalloc-notice.txt"),
]:
    data = (ROOT / source / path).read_bytes()
    if not data.startswith(b"/*") or b"*/" not in data:
        raise SystemExit(f"missing expected leading notice: {path}")
    record(name, data[:data.index(b"*/") + 2] + b"\n", source + "/" + path,
           PINS[source], "leading-C-comment")

cache = ROOT / "norm-llvm-notices"
cache.mkdir(exist_ok=True)
for path, expected in LLVM_FILES.items():
    name = path.replace("/", "-")
    url = f"https://raw.githubusercontent.com/llvm/llvm-project/{LLVM}/{path}"
    cached = cache / name
    if args.fetch_llvm:
        # `url` is raw.githubusercontent.com at the pinned
        # `LLVM` revision for a path from the in-file `LLVM_FILES` table, and
        # the next line refuses any body whose digest is not the pinned one.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        data = urllib.request.urlopen(url, timeout=30).read()
        if digest(data) != expected:
            raise SystemExit(f"downloaded notice digest mismatch: {path}")
        cached.write_bytes(data)
    data = cached.read_bytes()
    if digest(data) != expected:
        raise SystemExit(f"cached notice digest mismatch: {path}")
    record(name, data, url, LLVM)

manifest = {
    "status": "source-notice-collection-not-distribution-approval",
    "artifact_sha256": inventory["artifact_sha256"],
    "inventory_sha256": digest((ROOT / "norm-wasi-guest-inventory.json").read_bytes()),
    "entries": entries,
    "remaining": [
        "Complete source-level mapping of retained objects and frozen modules to notices.",
        "Confirm distribution contents and notice obligations under the repository policy.",
        "The CPython documentation includes notices for components absent from this build.",
    ],
}
(output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
print(f"collected {len(entries)} pinned upstream notice files in {output}")
