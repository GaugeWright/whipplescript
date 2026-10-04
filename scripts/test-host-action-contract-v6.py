#!/usr/bin/env python3
"""Integrity controls for current read authority and immutable historical codecs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

module = importlib.util.spec_from_file_location('reconciliation_authority_contract', Path(__file__).with_name('check-host-action-contract-v6.py'))
contract = importlib.util.module_from_spec(module)
module.loader.exec_module(contract)
SOURCE_ROOT = contract.ROOT
OWNERS = [contract, contract.read, contract.read.tracker, contract.read.tracker.recording, contract.read.tracker.recording.scoped, contract.legacy]


class ReconciliationAuthorityBundleIntegrity(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for owner in OWNERS:
            self.addCleanup(setattr, owner, 'ROOT', SOURCE_ROOT)
        contract.ROOT = self.root
        self.paths = {owner.PIN for owner in OWNERS} | {path for owner in OWNERS for path in owner.ARTIFACTS.values()}
        for relative in self.paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((SOURCE_ROOT / relative).read_bytes())
        self.pin = json.loads((self.root / contract.PIN).read_text())

    def repin(self, artifact=None):
        if artifact:
            self.pin[artifact]['sha256'] = contract.digest((self.root / self.pin[artifact]['path']).read_bytes())
        self.pin['contract_digest'] = contract.digest(contract.canonical({k: v for k, v in self.pin.items() if k != 'contract_digest'}))
        (self.root / contract.PIN).write_text(json.dumps(self.pin))

    def alter(self, artifact, change):
        path = self.root / contract.ARTIFACTS[artifact]
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        self.repin(artifact)

    def test_bundle_inherits_all_218_historical_vectors_and_adds_13_reconciliations(self):
        _, _, cases = contract.check_bundle()
        self.assertEqual(len(cases), 231)

    def test_every_owned_and_transitive_artifact_is_digest_checked(self):
        for relative in self.paths - {contract.PIN}:
            with self.subTest(artifact=relative):
                path = self.root / relative
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b' ')
                    with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
                        contract.check_bundle()
                finally:
                    path.write_bytes(original)

    def test_each_version_shape_is_exact_even_when_repinned(self):
        path = self.root / contract.ARTIFACTS['wire_schema']
        original = path.read_bytes()
        for version in (0, 1):
            with self.subTest(version=version):
                path.write_bytes(original)
                self.alter('wire_schema', lambda s: s['$defs']['ReconcileEffectCommand']['oneOf'][version].update(additionalProperties=True))
                with self.assertRaisesRegex(SystemExit, 'versioned reconciliation definition drifted'):
                    contract.check_bundle()

    def test_original_admission_and_policy_definitions_cannot_change(self):
        path = self.root / contract.ARTIFACTS['wire_schema']
        original = path.read_bytes()
        for name in ('PolicyEpochRef', 'ActionAdmissionReceipt', 'ActionResultSnapshot'):
            path.write_bytes(original)
            self.alter('wire_schema', lambda s: s['$defs'][name].update(additionalProperties=True))
            with self.assertRaisesRegex(SystemExit, f'inherited definition changed: {name}'):
                contract.check_bundle()

    def test_fixture_inventory_cannot_be_shortened_or_duplicated(self):
        path = self.root / contract.ARTIFACTS['fixtures']
        original = path.read_bytes()
        for duplicate in (False, True):
            path.write_bytes(original)
            self.alter('fixtures', lambda v: v['cases'].append(v['cases'][0]) if duplicate else v['cases'].pop())
            with self.assertRaisesRegex(SystemExit, 'fixture inventory'):
                contract.check_bundle()

    def test_profile_and_authority_claims_cannot_be_repinned(self):
        original = copy.deepcopy(self.pin)
        for field in contract.COMPATIBILITY:
            self.pin = copy.deepcopy(original)
            self.pin['compatibility'][field] = True
            self.repin()
            with self.assertRaisesRegex(SystemExit, 'authority/evidence posture drifted'):
                contract.check_bundle()
        self.pin = copy.deepcopy(original)
        self.pin['reconciliation_profile']['policy_signer'] = 'equal to authority'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'profile drifted'):
            contract.check_bundle()

    def test_dependency_identity_and_owned_path_cannot_be_substituted(self):
        original = copy.deepcopy(self.pin)
        self.pin['base_contract']['contract_digest'] = 'other'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'dependency identity mismatch'):
            contract.check_bundle()
        self.pin = original
        self.pin['fixtures']['path'] = '../foreign.json'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'wrong reconciliation authority artifact'):
            contract.check_bundle()

    def test_published_revision_remains_immutable(self):
        changed = copy.deepcopy(self.pin)
        changed['contract_digest'] = 'other'
        with self.assertRaisesRegex(SystemExit, 'published revision is immutable'):
            contract.legacy.check_revision(changed, self.pin)


if __name__ == '__main__':
    unittest.main()
