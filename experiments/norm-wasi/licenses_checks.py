"""Exercise licenses.py's refusals over a synthetic build root, needing no build."""
from pathlib import Path
import copy
import hashlib
import json
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from licenses import problems  # noqa: E402

ARTIFACT = "a" * 64


def fixture(root, archives, notices, artifact=ARTIFACT):
    (root / "norm-wasi-notices").mkdir(parents=True, exist_ok=True)
    entries = []
    for name, text in notices.items():
        (root / "norm-wasi-notices" / name).write_text(text)
        entries.append({"file": name, "sha256": hashlib.sha256(text.encode()).hexdigest()})
    (root / "norm-wasi-notices" / "manifest.json").write_text(
        json.dumps({"artifact_sha256": artifact, "entries": entries}))
    (root / "norm-wasi-guest-inventory.json").write_text(json.dumps(
        {"artifact_sha256": ARTIFACT, "archive_objects_in_link_map": {name: {} for name in archives}}))


MAPPING = {"archives": {
    "lib/libpython.a": {"component": "CPython", "license": "PSF-2.0", "notices": ["cpython-LICENSE"]},
    "lib/libc.a": {"component": "wasi-libc", "license": "MIT", "notices": ["libc-LICENSE"]},
}}
NOTICES = {"cpython-LICENSE": "PSF", "libc-LICENSE": "MIT"}

with tempfile.TemporaryDirectory() as scratch:
    base = Path(scratch)
    root = base / "baseline"
    fixture(root, MAPPING["archives"], NOTICES)
    assert problems(root, MAPPING) == [], problems(root, MAPPING)
    print("the approved mapping passes", flush=True)

    cases = []
    root = base / "unmapped"
    fixture(root, list(MAPPING["archives"]) + ["lib/libz.a"], NOTICES)
    cases.append(("an unmapped linked archive", root, MAPPING, "does not name"))
    root = base / "stale"
    fixture(root, ["lib/libpython.a"], NOTICES)
    cases.append(("a mapping for an archive no longer linked", root, MAPPING, "no longer links"))
    root = base / "missing-notice"
    fixture(root, MAPPING["archives"], {"cpython-LICENSE": "PSF"})
    cases.append(("a notice missing from the collection", root, MAPPING, "does not hold"))
    root = base / "tampered"
    fixture(root, MAPPING["archives"], NOTICES)
    (root / "norm-wasi-notices" / "libc-LICENSE").write_text("changed")
    cases.append(("a notice differing from its digest", root, MAPPING, "differs from the digest"))
    root = base / "other-artifact"
    fixture(root, MAPPING["archives"], NOTICES, artifact="b" * 64)
    cases.append(("a collection for another artifact", root, MAPPING, "different artifacts"))
    root = base / "no-license"
    fixture(root, MAPPING["archives"], NOTICES)
    unlicensed = copy.deepcopy(MAPPING)
    unlicensed["archives"]["lib/libc.a"]["license"] = " "
    cases.append(("an archive with no license", root, unlicensed, "no component or license"))
    root = base / "no-notice"
    fixture(root, MAPPING["archives"], NOTICES)
    unnoticed = copy.deepcopy(MAPPING)
    unnoticed["archives"]["lib/libc.a"]["notices"] = []
    cases.append(("an archive naming no notice", root, unnoticed, "names no notice"))

    for label, root, mapping, expected in cases:
        found = problems(root, mapping)
        assert any(expected in item for item in found), f"{label} was not refused: {found}"
        print(f"refused: {label}", flush=True)
