#!/usr/bin/env python3
"""Check the owned action bundle; --reports validates the Rust codec emitter.

The normal check needs only Python's standard library. Schema validation is a
separate deep check using the existing requirements-dev.txt dependency, like
the workstream receipt contract. All schema references resolve locally.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVISION = "whipplescript-host-action/v1.0.0"
PIN = "spec/host-action-contract-v1.json"
TYPES = {
    "HostActionCommand", "ActionAdmissionReceipt", "ExecuteActionEffect",
    "ReadActionResult", "ActionResultSnapshot", "ReconcileEffectCommand",
    "ReconciliationReceipt", "SaveReceipt", "WriteEvidenceRef",
}
ARTIFACTS = {
    "wire_schema": "spec/report-schemas/host_action_v1.schema.json",
    "fixtures": "spec/host-action-contract-fixtures-v1.json",
    "codec_harness": "crates/whipplescript-kernel/examples/host_action_contract.rs",
}
REQUIRED_CASES = {
    "human-save", "delegated-agent-save", "unicode-and-full-u64", "admitted-save",
    "renewed-execution", "pinned-read", "failed-after-apply", "unknown-after-failure",
    "legacy-attempt-without-dispatch", "reconcile-applied", "reconciled-receipt",
    "save-written", "save-merged", "save-conflicted", "write-evidence",
    "unknown-policy-constraint", "unknown-resource-constraint", "unknown-admission-pin",
    "unknown-result-pin", "unknown-execution-policy", "unknown-recovery-policy",
    "unknown-snapshot-policy", "unknown-snapshot-position", "unknown-recovery-frame",
    "unknown-save-result", "unknown-evidence-reference", "missing-action-program",
    "unsupported-action-version", "empty-action-issuer", "zero-policy-epoch",
    "negative-policy-epoch", "broken-delegation", "unsigned-executor-change",
    "wrong-recovery-version", "missing-optional-read-pin", "null-optional-read-pin",
    "null-optional-policy-key",
}


def require(condition, detail):
    if not condition:
        raise SystemExit(f"host action contract: {detail}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def check_bundle():
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get("schema") == "whipplescript.host_action_contract_pin.v1", "wrong pin schema")
    require(pin.get("contract_revision") == REVISION, "contract revision drifted")
    body = {key: value for key, value in pin.items() if key != "contract_digest"}
    require(pin.get("contract_digest") == digest(canonical(body)), "bundle digest mismatch")
    for name, expected_path in ARTIFACTS.items():
        item = pin.get(name, {})
        require(item.get("path") == expected_path, f"wrong {name} path")
        path = ROOT / expected_path
        require(path.is_file(), f"missing {expected_path}")
        require(item.get("sha256") == digest(path.read_bytes()), f"digest mismatch for {expected_path}")
    require(set(pin.get("message_types", [])) == TYPES, "message type inventory drifted")
    require(pin.get("operations") == [
        "admit_action", "execute_action_file_effect", "read_action_result",
        "reconcile_effect", "reconcile_versioned_save",
    ], "facade operation inventory drifted")
    require(pin.get("compatibility") == {
        "schema_validity_grants_authority": False,
        "receipt_handles_grant_authority": False,
        "reconciliation_advances_workflow": False,
        "legacy_turn_decoding_changed": False,
        "save_receipts_may_contain_protected_content": True,
        "complete_product_mediation": False,
    }, "compatibility/evidence posture drifted")
    require(pin.get("dispatch_kinds") == ["file.read", "file.write", "file.import", "file.export"],
            "published file execution ceiling drifted")
    schema = json.loads((ROOT / ARTIFACTS["wire_schema"]).read_text())
    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "wrong schema dialect")
    roots = [entry.get("$ref", "").removeprefix("#/$defs/") for entry in schema.get("oneOf", [])]
    require(set(roots) == TYPES and len(roots) == len(TYPES), "schema message inventory drifted")

    def local_refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                reference = value["$ref"]
                require(reference.startswith("#/$defs/") and reference[8:] in schema["$defs"],
                        f"nonlocal or missing schema reference: {reference}")
            for child in value.values():
                local_refs(child)
        elif isinstance(value, list):
            for child in value:
                local_refs(child)
    local_refs(schema)
    fixtures = json.loads((ROOT / ARTIFACTS["fixtures"]).read_text())
    require(fixtures.get("schema") == "whipplescript.host_action_contract_fixtures.v1", "wrong fixture schema")
    require(fixtures.get("contract_revision") == REVISION, "fixture revision drifted")
    cases = fixtures.get("cases", [])
    ids = [case.get("id") for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), "fixture inventory incomplete or duplicated")
    require({case.get("message_type") for case in cases if "value" in case} == TYPES,
            "not every message has a positive vector")
    return pin, schema, cases


def check_reports(schema, cases, reports):
    from jsonschema import Draft202012Validator
    Draft202012Validator.check_schema(schema)
    expected = {case["id"]: case for case in cases}
    ids = [report.get("id") for report in reports]
    require(set(ids) == set(expected) and len(ids) == len(expected), "emitter omitted or duplicated vectors")
    validators = {name: Draft202012Validator({
        "$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{name}",
    }) for name in TYPES}
    for report in reports:
        case = expected[report["id"]]
        require(report["message_type"] == case["message_type"], f"{case['id']}: wrong emitted type")
        observation = report["observation"]
        require(observation["wire_valid"] == case["wire_valid"], f"{case['id']}: codec result drifted")
        require(observation["syntax_valid"] == case["syntax_valid"], f"{case['id']}: syntax result drifted")
        validator = validators[case["message_type"]]
        values = [report["value"]]
        if observation["wire_valid"]:
            values.append(observation["normalized"])
        for value in values:
            errors = list(validator.iter_errors(value))
            require((not errors) == case["schema_valid"],
                    f"{case['id']}: schema disagrees: " + "; ".join(error.message for error in errors))
    print(f"host action schemas: {len(reports)} executed vectors, {len(TYPES)} message types")



def check_schema_controls(schema, cases, reports):
    # Each altered schema must fail at the vector whose boundary it weakened.
    # Another failure cannot accidentally count as exercising that boundary.
    controls = [
        ("PolicyEpochRef", "unknown-policy-constraint"),
        ("ResourceRef", "unknown-resource-constraint"),
        ("PinnedPosition", "unknown-admission-pin"),
    ]
    for name, vector in controls:
        weakened = copy.deepcopy(schema)
        weakened["$defs"][name]["additionalProperties"] = True
        try:
            check_reports(weakened, cases, reports)
        except SystemExit as error:
            require(f"{vector}: schema disagrees" in str(error), f"{name}: unrelated control failure: {error}")
        else:
            require(False, f"{name}: weakened schema passed")
    print(f"host action schemas: {len(controls)} weakened-reference controls caught")


def check_revision(pin, previous):
    if previous and previous.get("contract_revision") == pin["contract_revision"]:
        require(previous.get("contract_digest") == pin["contract_digest"],
                "a published revision is immutable; increment the contract revision")


def check_journey_reports(schema, directory):
    from jsonschema import Draft202012Validator
    validators = {name: Draft202012Validator({
        "$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{name}",
    }) for name in TYPES}
    coverage = set()
    count = 0
    for path in sorted(directory.glob("*.json")):
        report = json.loads(path.read_text())
        placement, scenario, name = (report[key] for key in ("placement", "scenario", "message_type"))
        require(placement in {"native", "hosted"} and name in TYPES, f"{path.name}: unknown report")
        errors = list(validators[name].iter_errors(report["value"]))
        require(not errors, f"{placement}/{scenario}/{name}: " + "; ".join(e.message for e in errors))
        coverage.add((placement, scenario, name))
        count += 1
    for placement in ("native", "hosted"):
        require({name for place, _, name in coverage if place == placement} == TYPES,
                f"{placement}: journey omitted a message type")
        for actor in ("person", "agent"):
            for mode in ("saved", "conflict", "interrupted", "failed-after-apply"):
                required = {"HostActionCommand", "ActionAdmissionReceipt", "ExecuteActionEffect", "SaveReceipt"}
                if mode != "conflict":
                    required |= {"WriteEvidenceRef", "ReconcileEffectCommand", "ReconciliationReceipt"}
                observed = {name for place, scenario, name in coverage
                            if place == placement and scenario == f"{actor}:one/{mode}"}
                require(required <= observed, f"{placement}/{actor}/{mode}: missing {sorted(required - observed)}")
            for name in ("ReadActionResult", "ActionResultSnapshot"):
                require((placement, f"{actor}:1", name) in coverage,
                        f"{placement}/{actor}: missing result journey {name}")
    print(f"host action schemas: {count} actual journey messages, native and deployed DO schema")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", action="store_true", help="validate Rust codec reports from stdin with JSON Schema")
    parser.add_argument("--journey-dir", type=Path, help="validate reports emitted by the actual synthetic runtime journeys")
    args = parser.parse_args()
    pin, schema, cases = check_bundle()
    previous = subprocess.run(["git", "show", f"origin/main:{PIN}"], cwd=ROOT,
                              capture_output=True, text=True)
    check_revision(pin, json.loads(previous.stdout) if previous.returncode == 0 else None)
    if args.reports:
        reports = json.load(sys.stdin)
        check_reports(schema, cases, reports)
        check_schema_controls(schema, cases, reports)
    if args.journey_dir:
        check_journey_reports(schema, args.journey_dir)
    print(f"host action contract {REVISION} {pin['contract_digest']}: ok")


if __name__ == "__main__":
    main()
