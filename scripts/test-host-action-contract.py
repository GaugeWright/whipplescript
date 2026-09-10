#!/usr/bin/env python3
"""Negative controls for the publication pin's required integrity gate."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().parent / "check-host-action-contract.py"
spec = importlib.util.spec_from_file_location("host_action_contract", source)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
SOURCE_ROOT = contract.ROOT


class BundleIntegrity(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.addCleanup(setattr, contract, "ROOT", SOURCE_ROOT)
        contract.ROOT = self.root
        for relative in [contract.PIN, *contract.ARTIFACTS.values()]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((SOURCE_ROOT / relative).read_bytes())
        self.pin = json.loads((self.root / contract.PIN).read_text())

    def repin(self, artifact=None):
        if artifact:
            path = self.root / self.pin[artifact]["path"]
            self.pin[artifact]["sha256"] = contract.digest(path.read_bytes())
        body = {key: value for key, value in self.pin.items() if key != "contract_digest"}
        self.pin["contract_digest"] = contract.digest(contract.canonical(body))
        (self.root / contract.PIN).write_text(json.dumps(self.pin))

    def test_current_bundle_passes(self):
        contract.check_bundle()

    def test_changed_artifact_bytes_refuse(self):
        for artifact, relative in contract.ARTIFACTS.items():
            with self.subTest(artifact=artifact):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(SystemExit, "digest mismatch"):
                    contract.check_bundle()
                path.write_bytes(original)

    def test_changed_manifest_refuses(self):
        self.pin["contract_revision"] = "unpublished"
        (self.root / contract.PIN).write_text(json.dumps(self.pin))
        with self.assertRaisesRegex(SystemExit, "revision drifted"):
            contract.check_bundle()

    def test_foreign_artifact_path_refuses_even_when_repinned(self):
        self.pin["fixtures"]["path"] = "../foreign.json"
        self.repin()
        with self.assertRaisesRegex(SystemExit, "wrong fixtures path"):
            contract.check_bundle()

    def test_missing_vector_refuses_even_when_repinned(self):
        path = self.root / contract.ARTIFACTS["fixtures"]
        value = json.loads(path.read_text())
        value["cases"] = [case for case in value["cases"] if case["id"] != "unknown-policy-constraint"]
        path.write_text(json.dumps(value))
        self.repin("fixtures")
        with self.assertRaisesRegex(SystemExit, "fixture inventory incomplete"):
            contract.check_bundle()

    def test_remote_schema_reference_refuses_even_when_repinned(self):
        path = self.root / contract.ARTIFACTS["wire_schema"]
        value = json.loads(path.read_text())
        value["$defs"]["HostActionCommand"]["properties"]["policy"] = {"$ref": "https://example.invalid/schema"}
        path.write_text(json.dumps(value))
        self.repin("wire_schema")
        with self.assertRaisesRegex(SystemExit, "nonlocal or missing schema reference"):
            contract.check_bundle()

    def test_schema_cannot_claim_authority(self):
        self.pin["compatibility"]["schema_validity_grants_authority"] = True
        self.repin()
        with self.assertRaisesRegex(SystemExit, "compatibility/evidence posture drifted"):
            contract.check_bundle()

    def test_published_revision_cannot_be_rebound(self):
        changed = copy.deepcopy(self.pin)
        changed["contract_digest"] = "different"
        with self.assertRaisesRegex(SystemExit, "published revision is immutable"):
            contract.check_revision(changed, self.pin)
        contract.check_revision(self.pin, self.pin)
        contract.check_revision(self.pin, None)


class JourneyCoverage(unittest.TestCase):
    def test_every_actor_placement_mode_and_codec_is_required(self):
        coverage = set()
        for placement in ('native', 'hosted'):
            for actor in ('person', 'agent'):
                coverage.update((placement, f'{actor}:1', name) for name in ('ReadActionResult', 'ActionResultSnapshot'))
                for mode in ('saved', 'conflict', 'interrupted', 'failed-after-apply'):
                    names = {'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect', 'SaveReceipt'}
                    if mode != 'conflict':
                        names |= {'WriteEvidenceRef', 'ReconcileEffectCommand', 'ReconciliationReceipt'}
                    for codec in ('text', 'reference', 'enveloped-reference'):
                        coverage.update((placement, f'{actor}:one/{mode}/{codec}', name) for name in names)
        contract.check_journey_coverage(coverage)
        for placement, scenario, name in sorted(coverage):
            with self.subTest(placement=placement, scenario=scenario, name=name):
                with self.assertRaises(SystemExit):
                    contract.check_journey_coverage(coverage - {(placement, scenario, name)})


if __name__ == "__main__":
    unittest.main()
