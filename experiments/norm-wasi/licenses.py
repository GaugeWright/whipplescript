"""Hold a prepared guest to its approved license mapping (DR-0140).

Reads the guest inventory (`inventory.py`) and the notice collection
(`notices.py`) under the build root, and refuses unless every archive the
reactor links is mapped, every mapped archive is still linked, and every
notice a mapping names is in the collection with the digest it recorded. The
inventory and the collection must describe the same artifact.
"""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def problems(root, mapping):
    inventory = json.loads((root / "norm-wasi-guest-inventory.json").read_text())
    notices_dir = root / "norm-wasi-notices"
    collection = json.loads((notices_dir / "manifest.json").read_text())
    found = []
    if inventory.get("artifact_sha256") != collection.get("artifact_sha256"):
        found.append("the inventory and the notice collection describe different artifacts")
    linked = set(inventory.get("archive_objects_in_link_map", {}))
    mapped = set(mapping.get("archives", {}))
    for archive in sorted(linked - mapped):
        found.append(f"the reactor links {archive}, which the license mapping does not name")
    for archive in sorted(mapped - linked):
        found.append(f"the license mapping names {archive}, which the reactor no longer links")
    recorded = {entry["file"]: entry["sha256"] for entry in collection.get("entries", [])}
    entries = list(mapping.get("archives", {}).items()) + list(mapping.get("unarchived", {}).items())
    for name, entry in entries:
        if not str(entry.get("component", "")).strip() or not str(entry.get("license", "")).strip():
            found.append(f"{name} has no component or license")
        for notice in entry.get("notices", []):
            if notice not in recorded:
                found.append(f"{name} names notice {notice}, which the collection does not hold")
            elif not (notices_dir / notice).is_file() or digest(notices_dir / notice) != recorded[notice]:
                found.append(f"notice {notice} differs from the digest its collection recorded")
    for name, entry in mapping.get("archives", {}).items():
        if not entry.get("notices"):
            found.append(f"{name} names no notice")
    return found


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[1] / "target"
    mapping = json.loads((HERE / "licenses.json").read_text())
    found = problems(root, mapping)
    if found:
        raise SystemExit("guest license mapping refused:\n  " + "\n  ".join(found))
    print("every linked archive of the guest is mapped to its license and notices")


if __name__ == "__main__":
    main()
