#!/usr/bin/env python3
"""Verify the pinned GWPW host contract and its body-free fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "spec/workstream-host-contract-v1.json"


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"workstream host contract: {message}")


pin = json.loads(PIN.read_text(encoding="utf-8"))
if pin.get("schema") != "whipplescript.workstream_host_contract_pin.v1":
    fail("wrong pin schema")
if pin.get("contract_revision") != "whipplescript-workstream-host/v1.0.0":
    fail("the published revision changed without a new contract file")

claimed_digest = pin.get("contract_digest")
digest_body = dict(pin)
digest_body.pop("contract_digest", None)
actual_digest = hashlib.sha256(
    json.dumps(
        digest_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
).hexdigest()
if claimed_digest != actual_digest:
    fail(f"contract digest mismatch: expected {actual_digest}, got {claimed_digest}")

required_operations = {
    "reserve_boundary",
    "release_boundary",
    "record_ref_advanced",
    "close_promoted",
    "home_receipt",
    "transfer",
    "promote_line_exact",
    "boundary_ref_evidence",
    "fork_binding_for_instance_at_cut",
    "fork_at_cut_and_admit",
    "materialize_manifest_subset",
    "import_scratch",
}
if set(pin.get("operations", [])) != required_operations:
    fail("operation inventory drifted; publish a new revision instead of editing v1")

schema_names = set()
for item in pin.get("schemas", []):
    name = item.get("name")
    path = ROOT / item.get("path", "")
    if name in schema_names:
        fail(f"duplicate schema {name}")
    schema_names.add(name)
    if not path.is_file():
        fail(f"missing schema {path.relative_to(ROOT)}")
    if digest_file(path) != item.get("sha256"):
        fail(f"schema digest mismatch for {path.relative_to(ROOT)}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail(f"{path.relative_to(ROOT)} is not draft 2020-12")
    properties = set(schema.get("properties", {}))
    forbidden = properties & {"body", "content", "payload", "workspace_body"}
    if forbidden:
        fail(f"receipt schema {name} carries body fields: {sorted(forbidden)}")
if schema_names != {
    "workstream_boundary_receipt_v1",
    "branch_home_receipt_v1",
    "exact_fork_admission_v1",
}:
    fail("schema inventory is incomplete")

fixture_pin = pin.get("fixtures", {})
fixture_path = ROOT / fixture_pin.get("path", "")
if not fixture_path.is_file() or digest_file(fixture_path) != fixture_pin.get("sha256"):
    fail("fixture digest mismatch")
fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
if fixtures.get("contract_revision") != pin.get("contract_revision"):
    fail("fixtures name a different contract revision")
cases = fixtures.get("cases", [])
ids = [case.get("id") for case in cases]
required_cases = {
    "reservation_freezes_topology_and_contribution",
    "conflict_releases_without_main_movement",
    "post_cas_recovery_closes_forward",
    "sparse_member_import_preserves_absent_partition",
    "exact_fork_admits_home_without_rematerialization",
    "archived_inherited_home_creates_nothing",
    "home_rejoin_has_new_authority_position",
    "concurrent_reservation_has_one_winner",
    "concurrent_main_cas_has_one_winner",
}
if len(ids) != len(set(ids)) or set(ids) != required_cases:
    fail("fixture case inventory is incomplete or duplicated")
for case in cases:
    coverage = case.get("coverage")
    if not isinstance(coverage, str) or "::tests::" not in coverage:
        fail(f"fixture {case.get('id')} has no concrete test coverage")

compatibility = pin.get("compatibility", {})
if compatibility != {
    "earlier_revision_accepted": False,
    "receipt_handles_are_evidence_only": True,
    "target_settlement_is_out_of_scope": True,
    "workspace_content_in_receipts": False,
}:
    fail("compatibility posture drifted")

print(f"workstream host contract {pin['contract_revision']} {claimed_digest}: ok")
