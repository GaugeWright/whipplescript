#!/usr/bin/env python3
"""Verify the pinned GWPW host contract and its body-free fixtures."""

from __future__ import annotations

import hashlib
import json
import re
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
if pin.get("contract_revision") != "whipplescript-workstream-host/v1.0.2":
    fail("the current published v1 revision drifted")

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
    "acknowledge_boundary_release",
    "release_reserved_boundary_generic",
    "record_ref_advanced",
    "close_promoted",
    "home_receipt",
    "transfer",
    "reserve_branch_head",
    "branch_head_reservation",
    "release_branch_head_reservation",
    "promote_line_exact",
    "boundary_ref_evidence",
    "fork_binding_for_instance_at_cut",
    "fork_at_cut_and_admit",
    "host_discard_instance",
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
    "cancelled_boundary_cleanup_survives_each_crash",
    "cleanup_failures_and_stale_tokens_preserve_the_owner",
    "post_cas_recovery_closes_forward",
    "receipt_handles_match_shipped_v1_schema",
    "v1_receipt_identity_survives_runtime_upgrade",
    "historical_promotion_receipt_survives_later_main_work",
    "sparse_member_import_preserves_absent_partition",
    "exact_fork_admits_home_without_rematerialization",
    "archived_inherited_home_creates_nothing",
    "home_rejoin_has_new_authority_position",
    "concurrent_reservation_has_one_winner",
    "concurrent_main_cas_has_one_winner",
    "reserved_line_rejects_direct_head_advance",
    "proposal_record_failure_precedes_main_publication",
    "fork_identity_refusal_preserves_existing_home",
    "exact_fork_lost_response_retry_replays_success",
    "native_pre_cas_error_releases_both_reservations",
    "hosted_pre_cas_error_releases_both_reservations",
    "native_post_cas_error_recovers_or_retains",
    "hosted_post_cas_error_recovers_or_retains",
    "discard_requires_unused_fork_evidence",
    "discard_replay_key_is_namespaced_and_verified",
}
if len(ids) != len(set(ids)) or set(ids) != required_cases:
    fail("fixture case inventory is incomplete or duplicated")
test_sources = [path.read_text(encoding="utf-8") for path in (ROOT / "crates").rglob("*.rs")]
for case in cases:
    coverage = case.get("coverage")
    if not isinstance(coverage, str) or "::" not in coverage:
        fail(f"fixture {case.get('id')} has no concrete test coverage")
    test_name = coverage.rsplit("::", 1)[-1]
    test_definition = re.compile(
        r"#\[(?:\w+::)?test(?:\([^]]*\))?\]\s*(?:async\s+)?fn\s+"
        + re.escape(test_name) + r"\s*\("
    )
    if not any(test_definition.search(source) for source in test_sources):
        fail(f"fixture {case.get('id')} names missing test {coverage}")

compatibility = pin.get("compatibility", {})
if compatibility != {
    "earlier_revision_accepted": False,
    "receipt_handles_are_evidence_only": True,
    "target_settlement_is_out_of_scope": True,
    "workspace_content_in_receipts": False,
}:
    fail("compatibility posture drifted")

print(f"workstream host contract {pin['contract_revision']} {claimed_digest}: ok")
