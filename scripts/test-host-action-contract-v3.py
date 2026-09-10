#!/usr/bin/env python3
"""Recording bundle integrity and complete investigation journey inventory."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

module = importlib.util.spec_from_file_location('recording_action_contract', Path(__file__).with_name('check-host-action-contract-v3.py'))
contract = importlib.util.module_from_spec(module)
module.loader.exec_module(contract)
SOURCE_ROOT = contract.ROOT


class RecordingBundleIntegrity(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for owner in [contract, contract.scoped, contract.legacy]:
            self.addCleanup(setattr, owner, 'ROOT', SOURCE_ROOT)
        contract.ROOT = self.root
        paths = {contract.PIN, *contract.ARTIFACTS.values(), *contract.scoped.ARTIFACTS.values(), *contract.legacy.ARTIFACTS.values()}
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((SOURCE_ROOT / relative).read_bytes())
        self.pin = json.loads((self.root / contract.PIN).read_text())

    def repin(self, artifact=None):
        if artifact:
            path = self.root / self.pin[artifact]['path']
            self.pin[artifact]['sha256'] = contract.digest(path.read_bytes())
        self.pin['contract_digest'] = contract.digest(contract.canonical({k: v for k, v in self.pin.items() if k != 'contract_digest'}))
        (self.root / contract.PIN).write_text(json.dumps(self.pin))

    def alter(self, artifact, change):
        path = self.root / contract.ARTIFACTS[artifact]
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        self.repin(artifact)

    def test_current_bundle_and_both_dependencies_pass(self):
        _, _, cases = contract.check_bundle()
        self.assertEqual(len(cases), 118)

    def test_each_owned_and_transitive_artifact_is_digest_checked(self):
        paths = set(contract.ARTIFACTS.values()) | set(contract.scoped.ARTIFACTS.values()) | set(contract.legacy.ARTIFACTS.values())
        for relative in paths:
            with self.subTest(artifact=relative):
                path = self.root / relative
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b' ')
                    with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
                        contract.check_bundle()
                finally:
                    path.write_bytes(original)

    def test_foreign_path_cannot_be_repinned(self):
        self.pin['fixtures']['path'] = '../foreign.json'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'wrong recording artifact'):
            contract.check_bundle()

    def test_missing_or_duplicate_vectors_cannot_be_repinned(self):
        path = self.root / contract.ARTIFACTS['fixtures']
        original = path.read_bytes()
        for duplicate in (False, True):
            path.write_bytes(original)
            self.alter('fixtures', lambda v: v['cases'].append(v['cases'][0]) if duplicate else v['cases'].pop())
            with self.assertRaisesRegex(SystemExit, 'fixture inventory'):
                contract.check_bundle()

    def test_inherited_definition_cannot_be_reinterpreted(self):
        path = self.root / contract.ARTIFACTS['wire_schema']
        original = path.read_bytes()
        for name in ('PolicyEpochRef', 'ResolutionMemoryBatch', 'ScopedSaveReceipt'):
            path.write_bytes(original)
            self.alter('wire_schema', lambda v: v['$defs'][name].update(additionalProperties=True))
            with self.assertRaisesRegex(SystemExit, f'inherited definition changed: {name}'):
                contract.check_bundle()

    def test_remote_reference_cannot_be_repinned(self):
        self.alter('wire_schema', lambda v: v['$defs']['ResolutionRecordingBinding']['properties'].update(scope={'$ref': 'https://example.invalid/schema'}))
        with self.assertRaisesRegex(SystemExit, 'nonlocal or missing recording reference'):
            contract.check_bundle()

    def test_binding_cannot_claim_authority_or_content_availability(self):
        original = copy.deepcopy(self.pin)
        for name in ('recording_binding_grants_authority', 'batch_receipt_proves_input_serialization', 'reconciliation_rehydrates_content'):
            self.pin = copy.deepcopy(original)
            self.pin['compatibility'][name] = True
            self.repin()
            with self.assertRaisesRegex(SystemExit, 'authority/evidence posture drifted'):
                contract.check_bundle()

    def test_profile_cannot_become_an_arbitrary_executor(self):
        self.pin['recording_profile']['caller_supplied_source'] = True
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'profile ceiling drifted'):
            contract.check_bundle()

    def test_scoped_dependency_identity_cannot_be_rebound(self):
        self.pin['base_contract']['contract_digest'] = 'different'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'scoped dependency identity mismatch'):
            contract.check_bundle()

    def test_published_revision_remains_immutable(self):
        changed = copy.deepcopy(self.pin)
        changed['contract_digest'] = 'different'
        with self.assertRaisesRegex(SystemExit, 'published revision is immutable'):
            contract.legacy.check_revision(changed, self.pin)


class RecordingJourneyCoverage(unittest.TestCase):
    def reports(self):
        # Inventory-only evidence. The deep check separately validates actual
        # emitted values with JSON Schema and executes all Rust codec vectors.
        return [dict(placement=placement, scenario=f'{actor}:one/{mode}', message_type=name,
            value={'provenance': {'executor': 'agent:investigator' if actor == 'human' else 'human:investigator'}})
            for placement in ('native', 'hosted') for actor in ('human', 'agent')
            for mode in ('success', 'failed', 'interrupted') for name in sorted(contract.JOURNEY_TYPES)]

    def test_every_actor_placement_outcome_and_message_is_required(self):
        reports = self.reports()
        self.assertEqual(len(reports), 132)
        contract.check_journey_inventory(reports)
        for index, report in enumerate(reports):
            with self.subTest(missing=(report['placement'], report['scenario'], report['message_type'])):
                with self.assertRaisesRegex(SystemExit, 'missing recording messages'):
                    contract.check_journey_inventory(reports[:index] + reports[index + 1:])

    def test_same_principal_cannot_stand_in_for_independent_investigation(self):
        reports = self.reports()
        for report in reports:
            if report['message_type'] == 'ReconcileEffectCommand':
                report['value']['provenance']['executor'] = report['scenario'].split('/')[0]
                break
        with self.assertRaisesRegex(SystemExit, 'different principal'):
            contract.check_journey_inventory(reports)

    def test_unknown_scenario_cannot_pad_inventory(self):
        reports = self.reports()
        reports.append({**reports[0], 'scenario': 'unclassified'})
        with self.assertRaisesRegex(SystemExit, 'unknown recording scenario'):
            contract.check_journey_inventory(reports)


if __name__ == '__main__':
    unittest.main()
