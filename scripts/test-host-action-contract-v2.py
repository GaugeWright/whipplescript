#!/usr/bin/env python3
"""Negative controls for the scoped bundle's dependency and integrity boundary."""
import copy
import contextlib
import importlib.util
import io
import json
import sys
import types
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

source = Path(__file__).with_name('check-host-action-contract-v2.py')
module = importlib.util.spec_from_file_location('scoped_action_contract', source)
contract = importlib.util.module_from_spec(module)
module.loader.exec_module(contract)
SOURCE_ROOT = contract.ROOT


class ScopedBundleIntegrity(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.addCleanup(setattr, contract, 'ROOT', SOURCE_ROOT)
        self.addCleanup(setattr, contract.legacy, 'ROOT', SOURCE_ROOT)
        contract.ROOT = self.root
        paths = {contract.PIN, *contract.ARTIFACTS.values(), *contract.legacy.ARTIFACTS.values()}
        for relative in paths:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((SOURCE_ROOT / relative).read_bytes())
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

    def test_current_bundle_and_dependency_pass(self):
        _, _, cases = contract.check_bundle()
        self.assertEqual(len(cases), 80)

    def test_every_artifact_is_digest_checked(self):
        for name, relative in contract.ARTIFACTS.items():
            with self.subTest(name=name):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
                    contract.check_bundle()
                path.write_bytes(original)

    def test_dependency_artifacts_are_checked_transitively(self):
        path = self.root / contract.legacy.ARTIFACTS['codec_harness']
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
            contract.check_bundle()

    def test_foreign_path_cannot_be_repinned(self):
        self.pin['fixtures']['path'] = '../foreign.json'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'wrong scoped fixtures path'):
            contract.check_bundle()

    def test_missing_or_duplicate_vector_cannot_be_repinned(self):
        path = self.root / contract.ARTIFACTS['fixtures']
        original = path.read_bytes()
        for duplicate in (False, True):
            path.write_bytes(original)
            self.alter('fixtures', lambda v: v['cases'].append(v['cases'][0]) if duplicate else v['cases'].pop())
            with self.assertRaisesRegex(SystemExit, 'fixture inventory'):
                contract.check_bundle()

    def test_new_bundle_cannot_reinterpret_legacy_definition(self):
        self.alter('wire_schema', lambda v: v['$defs']['PolicyEpochRef'].update(additionalProperties=True))
        with self.assertRaisesRegex(SystemExit, 'legacy definition changed: PolicyEpochRef'):
            contract.check_bundle()

    def test_remote_schema_reference_cannot_be_repinned(self):
        self.alter('wire_schema', lambda v: v['$defs']['ScopedSaveReceipt']['properties'].update(binding={'$ref': 'https://example.invalid/schema'}))
        with self.assertRaisesRegex(SystemExit, 'nonlocal or missing scoped reference'):
            contract.check_bundle()

    def test_namespace_cannot_claim_authority(self):
        self.pin['compatibility']['namespace_identity_grants_authority'] = True
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'compatibility posture drifted'):
            contract.check_bundle()

    def test_base_identity_cannot_be_rebound(self):
        self.pin['base_contract']['contract_digest'] = 'different'
        self.repin()
        with self.assertRaisesRegex(SystemExit, 'base bundle identity mismatch'):
            contract.check_bundle()

    def test_published_revision_remains_immutable(self):
        changed = copy.deepcopy(self.pin)
        changed['contract_digest'] = 'different'
        with self.assertRaisesRegex(SystemExit, 'published revision is immutable'):
            contract.legacy.check_revision(changed, self.pin)


class ScopedJourneyCoverage(unittest.TestCase):
    def test_each_actor_placement_outcome_and_message_is_required(self):
        # Isolate coverage from shape. The deep gate uses the real JSON Schema
        # validator against actual emitted messages and weakening controls.
        class ShapeAlreadyChecked:
            def __init__(self, schema):
                pass

            def iter_errors(self, value):
                return iter(())

        names = ['ResolutionMemoryScope', 'ResolutionMemoryReceipt', 'ScopedSaveReceipt',
                 'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect',
                 'ReconcileEffectCommand', 'ReconciliationReceipt']
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for placement in ('native', 'hosted'):
                for actor in ('person', 'agent'):
                    for mode in ('saved', 'interrupted', 'failed-after-apply'):
                        for name in names:
                            path = directory / f'{placement}-{actor}-{mode}-{name}.json'
                            path.write_text(json.dumps(dict(placement=placement,
                                scenario=f'{actor}:one/{mode}', message_type=name, value={})))
            with patch.dict(sys.modules, {'jsonschema': types.SimpleNamespace(Draft202012Validator=ShapeAlreadyChecked)}):
                schema = {'$schema': 'coverage-only', '$defs': {}}
                with contextlib.redirect_stdout(io.StringIO()):
                    contract.check_journey_reports(schema, directory)
                paths = sorted(directory.glob('*.json'))
                self.assertEqual(len(paths), 96)
                for path in paths:
                    with self.subTest(missing=path.name):
                        data = path.read_bytes()
                        path.unlink()
                        try:
                            with self.assertRaisesRegex(SystemExit, 'missing scoped messages'):
                                contract.check_journey_reports(schema, directory)
                        finally:
                            path.write_bytes(data)


if __name__ == '__main__':
    unittest.main()
