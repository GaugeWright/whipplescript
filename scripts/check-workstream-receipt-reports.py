#!/usr/bin/env python3
"""Validate real fresh/upgraded/retained v1 receipts, then corrupt each handle.

Input is stdout from the synthetic workstream_receipt_reports example. No
network schema resolution, hand-authored substitute receipts, or store writes.
"""
import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

root = Path(__file__).resolve().parent.parent / "spec/report-schemas"
names = ["branch_home_receipt_v1", "workstream_boundary_receipt_v1", "exact_fork_admission_v1"]
schemas = {name: json.loads((root / f"{name}.schema.json").read_text()) for name in names}
registry = Registry().with_resources(
    (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
)
validators = {
    name: Draft202012Validator(schema, registry=registry) for name, schema in schemas.items()
}
reports = json.load(sys.stdin)
expected_labels = {
    "fresh-main-home", "fresh-named-home", "fresh-fork", "fresh-reserved",
    "fresh-ref-advanced", "fresh-archived", "fresh-closed-home-refusal",
    "retained-fork-source-home.json", "retained-fork-fork.json",
    "retained-archived-boundary.json", "retained-landed-boundary.json",
    "upgraded-home", "upgraded-fork", "upgraded-archived",
}
labels = [report["label"] for report in reports]
assert set(labels) == expected_labels and len(labels) == len(expected_labels), labels


def handle_paths(value, prefix=()):
    for key, child in value.items():
        path = (*prefix, key)
        if key in {"evidence_handle", "fork_evidence_handle", "ref_receipt_handle"} and isinstance(child, str):
            yield path
        if isinstance(child, dict):
            yield from handle_paths(child, path)


negatives = 0
seen = set()
for report in reports:
    label, receipt = report["label"], report["receipt"]
    seen.add(receipt["schema"])
    validator = validators[receipt["schema"]]
    errors = list(validator.iter_errors(receipt))
    assert not errors, f"{label}: " + "; ".join(error.message for error in errors)
    for path in handle_paths(receipt):
        for malformed in ["", "sha256:", "sha256:" + "0" * 31,
                          "sha256:" + "0" * 33, "sha256:" + "0" * 64,
                          "sha256:" + "G" * 32, "sha256:" + "A" * 32,
                          "sha512:" + "0" * 32, 42]:
            changed = copy.deepcopy(receipt)
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = malformed
            assert not validator.is_valid(changed), f"{label}: accepted malformed {path}={malformed!r}"
            negatives += 1
    for changed in [dict(receipt, schema="wrong-version"), dict(receipt, body="not-receipt-data")]:
        assert not validator.is_valid(changed), f"{label}: accepted wrong schema or body"
        negatives += 1
    if receipt["schema"] == "workstream_boundary_receipt_v1" and receipt["outcome"] in {"ref_advanced", "archived"}:
        changed = dict(receipt, ref_receipt_handle=None)
        assert not validator.is_valid(changed), f"{label}: accepted absent accepted-ref evidence"
        negatives += 1
assert seen == set(names), seen
print(f"workstream receipts: {len(reports)} real reports across all three schemas; {negatives} malformed cases refused")
