"""Prepare the pinned test reactor; downloads require an explicit --fetch flag."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("build_root", nargs="?", type=Path, default=HERE.parents[1] / "target")
parser.add_argument("--fetch", action="store_true")
parser.add_argument("--check", action="store_true", help="verify an existing prepared reactor without rebuilding")
parser.add_argument("--jobs", type=int, default=2)
args = parser.parse_args()
ROOT = args.build_root.resolve()
ROOT.mkdir(parents=True, exist_ok=True)
SOURCE = ROOT / "norm-cpython-wasi"
REVISION = "823f0323ee6ec1402088b73bce1a38473cac36dc"
SOURCE_DATE_EPOCH = "1785925789"  # Timestamp of the pinned CPython commit.
SDK = "wasi-sdk-24.0-x86_64-linux"
WASMTIME = "wasmtime-v48.0.1-x86_64-linux"
# Each entry names the file that proves the archive was extracted in full.
# A directory that merely EXISTS proves nothing here: `ROOT` is `target/`, which
# a CI cache restores and prunes, so a partially-present `wasi-sdk-.../` skipped
# the extraction and `configure-wasi` then failed on a toolchain with no clang
# in it.
ARCHIVES = {
    SDK + ".tar.gz": ("https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-24/" + SDK + ".tar.gz",
                      "c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5", SDK, "bin/clang"),
    WASMTIME + ".tar.xz": ("https://github.com/bytecodealliance/wasmtime/releases/download/v48.0.1/" + WASMTIME + ".tar.xz",
                          "4c2e31b68ad99e0a519f225a261fda099eb15f056d4a24fdb3c2a46517bde1df", WASMTIME, "wasmtime"),
}
STAMP = ROOT / "norm-wasi-prepared.json"

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def head_revision():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()

def verify_source():
    if head_revision() != REVISION:
        raise SystemExit("CPython checkout differs from the runtime pin")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=SOURCE, check=True)

def recipe():
    return {"cpython_revision": REVISION, "source_date_epoch": SOURCE_DATE_EPOCH, "archives": {name: data[1] for name, data in ARCHIVES.items()},
            "sources": {name: digest(HERE / name) for name in ["prepare.py", "bridge.c", "freeze_stdlib.py", "link.py"]},
            "loader": digest(HERE.parents[1] / "crates/whipplescript-kernel/src/norm_embedded_calls.py")}

def inputs_and_outputs():
    wasi = SOURCE / "cross-build/wasm32-wasip1"
    paths = [ROOT / "norm-cpython-observer.wasm", ROOT / "norm-wasi-build.json", ROOT / "norm-frozen-stdlib.h", ROOT / "norm-frozen-stdlib.json",
             ROOT / SDK / "bin/clang", ROOT / WASMTIME / "wasmtime", wasi / "Makefile", wasi / "libpython3.14.a"]
    return paths + sorted((wasi / "Modules").rglob("*.a"))

def verify_ready():
    stamp = json.loads(STAMP.read_text())
    if stamp["recipe"] != recipe():
        raise ValueError("runtime preparation recipe changed")
    verify_source()
    required = {str(path.relative_to(ROOT)) for path in inputs_and_outputs()}
    if set(stamp["files"]) != required:
        raise ValueError("prepared runtime file inventory differs from the required inputs and outputs")
    if stamp["artifact_sha256"] != stamp["files"]["norm-cpython-observer.wasm"]:
        raise ValueError("prepared runtime artifact identity is inconsistent")
    for name, expected in stamp["files"].items():
        if digest(ROOT / name) != expected:
            raise ValueError(f"prepared runtime input/output changed: {name}")
    return stamp

if args.check:
    try: verify_ready()
    except (OSError, ValueError, KeyError) as error: raise SystemExit(f"runtime is not prepared: {error}")
    print(ROOT / "norm-cpython-observer.wasm")
    raise SystemExit(0)
if args.jobs < 1:
    raise SystemExit("jobs must be positive")
if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
    raise SystemExit("this builder currently requires a Linux x86-64 build host")
if STAMP.exists():
    try:
        verify_ready()
        print(ROOT / "norm-cpython-observer.wasm")
        raise SystemExit(0)
    except (OSError, ValueError, KeyError):
        pass

started_recipe = recipe()
logdir = ROOT / "norm-wasi-build-logs" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}")
logdir.mkdir(parents=True)
env = dict(os.environ, PATH=str(ROOT / WASMTIME) + os.pathsep + os.environ.get("PATH", ""),
           SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, LC_ALL="C", TZ="UTC", PYTHONHASHSEED="0")

def run(label, command, cwd=ROOT):
    print(label, flush=True)
    with (logdir / (label + ".log")).open("w") as log:
        result = subprocess.run([str(part) for part in command], cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"{label} failed; see {logdir / (label + '.log')}")

for name, (url, expected, directory, marker) in ARCHIVES.items():
    archive = ROOT / name
    if not archive.exists():
        if not args.fetch:
            raise SystemExit(f"missing {archive}; rerun with --fetch to provision pinned prerequisites")
        temporary = archive.with_suffix(archive.suffix + ".download")
        # `url` comes from the in-file `ARCHIVES` table and
        # what it returns is refused below unless `digest(temporary)` equals
        # the pin. A substituted URL cannot get its bytes past that.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        if digest(temporary) != expected:
            temporary.unlink()
            raise SystemExit(f"download digest mismatch: {name}")
        temporary.replace(archive)
    if digest(archive) != expected:
        raise SystemExit(f"prerequisite archive digest mismatch: {name}")
    # Extract when the MARKER is absent, not when the directory is: see the
    # note on `ARCHIVES`. Removing a partial tree first keeps `extractall`
    # from merging into it.
    if not (ROOT / directory / marker).exists():
        if (ROOT / directory).is_dir():
            print(f"discard-partial-{directory}", flush=True)
            shutil.rmtree(ROOT / directory)
        with tarfile.open(archive) as package:
            package.extractall(ROOT, filter="data")
        if not (ROOT / directory / marker).exists():
            raise SystemExit(f"{name} extracted without {directory}/{marker}")

def clone_cpython():
    run("clone-cpython", ["git", "clone", "--depth", "1", "--branch", "v3.14.7",
                          "https://github.com/python/cpython.git", SOURCE])

# A checkout that EXISTS is not a checkout at the pin. `SOURCE` lives under the
# build root, which belongs to whoever populates it: the hosted green bar
# restores `target/` from a cache, so a cache saved from another revision -- or
# another branch -- arrives already containing this directory, the clone is
# skipped, and the pin fails 1.4 seconds into the job. That happened the first
# time `main` moved and changed the cache key.
#
# Replaced rather than fetched onto the pin. Asking for a bare commit needs the
# server to allow it, which GitHub does not here -- `git fetch origin <sha>`
# against this shallow clone failed on the runner -- and the `cross-build`
# outputs under a wrong checkout describe the wrong source anyway, so keeping
# them buys nothing. Re-cloning by TAG is the operation that is known to work.
if SOURCE.exists() and head_revision() != REVISION:
    if not args.fetch:
        raise SystemExit("CPython checkout differs from the runtime pin; rerun with --fetch")
    print("discard-unpinned-cpython", flush=True)
    shutil.rmtree(SOURCE)
if not SOURCE.exists():
    if not args.fetch:
        raise SystemExit("missing CPython checkout; rerun with --fetch")
    clone_cpython()
# The tag resolved to something else: the pin is authoritative over the name,
# and upstream can move a tag under it.
if head_revision() != REVISION:
    raise SystemExit(
        f"tag v3.14.7 resolves to {head_revision()}, not the pinned {REVISION}"
    )
verify_source()
run("configure-native", [sys.executable, "Tools/wasm/wasi", "configure-build-python", "--quiet", "--", "--config-cache"], SOURCE)
native = SOURCE / "cross-build/x86_64-pc-linux-gnu"
# Upstream's --git-dir-only commands run from the build directory and can
# label a clean source checkout dirty. Read metadata in the verified source root.
build_metadata = ["GITVERSION=git -C ../.. rev-parse --short HEAD",
                  "GITTAG=git -C ../.. describe --all --always --dirty",
                  "GITBRANCH=git -C ../.. name-rev --name-only HEAD"]
# The epoch is a compiler input that make does not track. Force the object
# containing __DATE__/__TIME__ to rebuild even in an existing checkout.
run("build-native", ["make", "-j" + str(args.jobs), "-W", "../../Modules/getbuildinfo.c", *build_metadata], native)
run("configure-wasi", [sys.executable, "Tools/wasm/wasi", "configure-host", "--quiet", "--wasi-sdk", ROOT / SDK, "--", "--config-cache", "--disable-test-modules"], SOURCE)
wasi = SOURCE / "cross-build/wasm32-wasip1"
run("build-wasi", ["make", "-j" + str(args.jobs), "-W", "../../Modules/getbuildinfo.c", *build_metadata], wasi)
run("freeze-stdlib", [native / "python", HERE / "freeze_stdlib.py", ROOT])
run("link-reactor", [sys.executable, HERE / "link.py", ROOT])
manifest = json.loads((ROOT / "norm-wasi-build.json").read_text())
if recipe() != started_recipe:
    raise SystemExit("runtime preparation sources changed during the build")
files = {str(path.relative_to(ROOT)): digest(path) for path in inputs_and_outputs()}
STAMP.write_text(json.dumps({"recipe": recipe(), "files": files, "artifact_sha256": manifest["artifact_sha256"],
                             "build_log_directory": str(logdir)}, sort_keys=True, indent=2) + "\n")
verify_ready()
print(ROOT / "norm-cpython-observer.wasm")
