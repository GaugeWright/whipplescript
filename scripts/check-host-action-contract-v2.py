#!/usr/bin/env python3
"""Verify the scoped bundle, its immutable v1 dependency and executable evidence."""
import argparse
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

module = importlib.util.spec_from_file_location('legacy_action_contract', Path(__file__).with_name('check-host-action-contract.py'))
legacy = importlib.util.module_from_spec(module)
module.loader.exec_module(legacy)
ROOT = legacy.ROOT
REVISION = 'whipplescript-host-action/v2.0.0'
PIN = 'spec/host-action-contract-v2.json'
ARTIFACTS = {
    'base_contract': legacy.PIN,
    'wire_schema': 'spec/report-schemas/host_action_v2.schema.json',
    'fixtures': 'spec/host-action-contract-fixtures-v2.json',
    'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v2.rs',
}
NEW_TYPES = {'ResolutionMemoryScope', 'ScopedSaveReceipt', 'ResolutionMemoryReceipt'}
TYPES = legacy.TYPES | NEW_TYPES
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical
REQUIRED_CASES = {
    'scope-identity', 'scope-control-separator', 'scope-blank-authority', 'scope-blank-resource', 'scope-blank-compartment',
    'scope-unknown-field', 'scoped-recorded-applied', 'scoped-recorded-unavailable',
    'scoped-recorded-non_text', 'scoped-missing', 'scoped-origin_unavailable',
    'scoped-written', 'scoped-conflicted', 'scoped-unknown-receipt', 'scoped-unknown-binding',
    'scoped-unknown-attempt', 'scoped-unknown-scope', 'scoped-unknown-lookup',
    'scoped-unknown-observation', 'scoped-unknown-origin', 'scoped-missing-observation-unknown',
    'scoped-negative-origin-index', 'scoped-overflow-origin-index', 'scoped-unknown-payload-use',
    'scoped-wrong-protocol', 'scoped-missing-applied', 'scoped-recorded-not-read',
    'scoped-written-observations', 'scoped-missing-scope', 'memory-inserted',
    'memory-existing-winner', 'memory-unknown-receipt', 'memory-unknown-request',
    'memory-unknown-entry', 'memory-unknown-outcome', 'memory-empty-batch',
    'memory-wrong-count', 'memory-wrong-key', 'memory-blank-actor',
    'memory-duplicate-key', 'memory-inserted-content', 'memory-duplicate-winner', 'memory-duplicate-insert',
}


def check_bundle():
    legacy.ROOT = ROOT
    base_pin, base_schema, base_cases = legacy.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v2', 'wrong scoped pin schema')
    require(pin.get('contract_revision') == REVISION, 'scoped contract revision drifted')
    require(pin.get('contract_digest') == digest(canonical({k: v for k, v in pin.items() if k != 'contract_digest'})), 'scoped bundle digest mismatch')
    for name, relative in ARTIFACTS.items():
        artifact = pin.get(name, {})
        require(artifact.get('path') == relative, f'wrong scoped {name} path')
        path = ROOT / relative
        require(path.is_file() and artifact.get('sha256') == digest(path.read_bytes()), f'scoped artifact digest mismatch: {relative}')
    require(pin['base_contract'].get('contract_digest') == base_pin['contract_digest'], 'base bundle identity mismatch')
    require(pin.get('message_types') == base_pin['message_types'] + sorted(NEW_TYPES), 'scoped message inventory drifted')
    require(pin.get('operations') == base_pin['operations'] + ['execute_scoped_save_file_effect', 'reconcile_scoped_versioned_save'], 'scoped operation inventory drifted')
    require(pin.get('dispatch_kinds') == base_pin['dispatch_kinds'], 'scoped dispatch ceiling drifted')
    require(pin.get('compatibility') == {**base_pin['compatibility'], 'namespace_identity_grants_authority': False, 'resolution_receipt_authorizes_recording': False}, 'scoped compatibility posture drifted')
    schema = json.loads((ROOT / ARTIFACTS['wire_schema']).read_text())
    require(schema.get('$schema') == base_schema['$schema'], 'scoped schema dialect drifted')
    roots = [entry.get('$ref', '').removeprefix('#/$defs/') for entry in schema.get('oneOf', [])]
    require(set(roots) == TYPES and len(roots) == len(TYPES), 'scoped schema inventory drifted')
    for name, definition in base_schema['$defs'].items():
        require(schema.get('$defs', {}).get(name) == definition, f'legacy definition changed: {name}')
    def refs(value):
        if isinstance(value, dict):
            if '$ref' in value:
                ref = value['$ref']
                require(ref.startswith('#/$defs/') and ref[8:] in schema['$defs'], f'nonlocal or missing scoped reference: {ref}')
            for child in value.values(): refs(child)
        elif isinstance(value, list):
            for child in value: refs(child)
    refs(schema)
    fixtures = json.loads((ROOT / ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v2' and fixtures.get('contract_revision') == REVISION, 'wrong scoped fixture revision')
    cases = fixtures.get('cases', [])
    ids = [case.get('id') for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'scoped fixture inventory incomplete or duplicated')
    require({case.get('message_type') for case in cases if 'value' in case} == NEW_TYPES, 'missing positive scoped message')
    return pin, schema, base_cases + cases


def check_schema_controls(schema, cases, reports):
    controls = [
        ('scope fields', 'scope-unknown-field', lambda d: d['ResolutionMemoryScope'].update(additionalProperties=True)),
        ('scope blanks', 'scope-blank-authority', lambda d: d['ResolutionMemoryScope']['properties']['authority'].pop('pattern')),
        ('origin fields', 'scoped-unknown-origin', lambda d: d['ResolutionOrigin'].update(additionalProperties=True)),
        ('missing fields', 'scoped-missing-observation-unknown', lambda d: d['ResolutionObservation']['oneOf'][0].update(additionalProperties=True)),
        ('memory request', 'memory-unknown-request', lambda d: d['ResolutionMemoryBatch'].update(additionalProperties=True)),
        ('payload consistency', 'scoped-missing-applied', lambda d: d['ResolutionLookup'].pop('allOf')),
        ('written consistency', 'scoped-written-observations', lambda d: d['ScopedSaveReceipt'].pop('allOf')),
    ]
    for name, vector, weaken in controls:
        altered = copy.deepcopy(schema)
        weaken(altered['$defs'])
        try:
            legacy.check_reports(altered, cases, reports, TYPES)
        except SystemExit as error:
            require(f'{vector}: schema disagrees' in str(error), f'{name}: unrelated failure: {error}')
        else:
            require(False, f'{name}: weakened scoped schema passed')
    print(f'scoped action schemas: {len(controls)} weakening controls caught')


def check_journey_reports(schema, directory):
    from jsonschema import Draft202012Validator
    required = NEW_TYPES | {'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect', 'ReconcileEffectCommand', 'ReconciliationReceipt'}
    validators = {name: Draft202012Validator({'$schema': schema['$schema'], '$defs': schema['$defs'], '$ref': f'#/$defs/{name}'}) for name in required}
    coverage, count = set(), 0
    for path in sorted(directory.glob('*.json')):
        report = json.loads(path.read_text())
        placement, scenario, name = (report[key] for key in ('placement', 'scenario', 'message_type'))
        require(placement in {'native', 'hosted'} and name in required, f'{path.name}: unknown scoped report')
        errors = list(validators[name].iter_errors(report['value']))
        require(not errors, f'{placement}/{scenario}/{name}: ' + '; '.join(error.message for error in errors))
        coverage.add((placement, scenario, name))
        count += 1
    for placement in ('native', 'hosted'):
        for actor in ('person', 'agent'):
            for mode in ('saved', 'interrupted', 'failed-after-apply'):
                scenario = f'{actor}:one/{mode}'
                observed = {name for place, case, name in coverage if place == placement and case == scenario}
                require(required <= observed, f'{placement}/{scenario}: missing scoped messages {sorted(required - observed)}')
    print(f'scoped action schemas: {count} actual messages across twelve actor/outcome/placement combinations')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', action='store_true')
    parser.add_argument('--journey-dir', type=Path)
    args = parser.parse_args()
    pin, schema, cases = check_bundle()
    for path, current in [(PIN, pin), (legacy.PIN, json.loads((ROOT / legacy.PIN).read_text()))]:
        previous = subprocess.run(['git', 'show', f'origin/main:{path}'], cwd=ROOT, capture_output=True, text=True)
        legacy.check_revision(current, json.loads(previous.stdout) if previous.returncode == 0 else None)
    if args.reports:
        reports = json.load(sys.stdin)
        legacy.check_reports(schema, cases, reports, TYPES)
        check_schema_controls(schema, cases, reports)
    if args.journey_dir:
        check_journey_reports(schema, args.journey_dir)
    print(f'host action contract {REVISION} {pin["contract_digest"]}: ok')


if __name__ == '__main__':
    main()
