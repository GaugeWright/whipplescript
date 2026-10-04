#!/usr/bin/env python3
"""Current read authority codec profile over immutable V1-V4 bundles."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

module = importlib.util.spec_from_file_location('tracker_action_contract', Path(__file__).with_name('check-host-action-contract-v4.py'))
tracker = importlib.util.module_from_spec(module)
module.loader.exec_module(tracker)
legacy = tracker.legacy
ROOT = tracker.ROOT
REVISION = 'whipplescript-host-action/v5.0.0'
PIN = 'spec/host-action-contract-v5.json'
ARTIFACTS = {
    'base_contract': tracker.PIN,
    'wire_schema': 'spec/report-schemas/host_action_v5.schema.json',
    'fixtures': 'spec/host-action-contract-fixtures-v5.json',
    'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v5.rs',
}
TYPES = tracker.TYPES
PROFILE = {
    'legacy_protocol': 'whipplescript.action-result.v1',
    'current_protocol': 'whipplescript.action-result.v2',
    'historical_coordinates': ['issuer', 'scope', 'admission'],
    'current_authority': 'read_authority; exact verified envelope authority',
    'policy_signer': 'independent cryptographic signer; exact PolicyEpochRef',
    'explicit_null_authority': 'refused in both versions',
    'result_snapshot_protocol': 'whipplescript.action-result.v1',
}
COMPATIBILITY = {
    'current_read_authority_reissues_history': False,
    'read_authority_grants_access': False,
    'legacy_result_read_signing_changed': False,
}
REQUIRED_CASES = {
    'current-authority-read', 'current-authority-read-missing-authority',
    'current-authority-read-null-authority', 'current-authority-read-number-authority',
    'current-authority-read-empty-authority', 'current-authority-read-blank-authority',
    'current-authority-read-extra', 'current-authority-read-wrong-protocol',
    'current-authority-read-other-authority', 'current-authority-read-old-issuer',
    'legacy-authority-read', 'legacy-authority-read-new-field', 'legacy-authority-read-null-field',
}
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical


def check_bundle():
    tracker.ROOT = ROOT
    base_pin, base_schema, base_cases = tracker.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v5', 'wrong read authority pin schema')
    require(pin.get('contract_revision') == REVISION, 'read authority revision drifted')
    require(pin.get('contract_digest') == digest(canonical({k: v for k, v in pin.items() if k != 'contract_digest'})), 'read authority bundle digest mismatch')
    for name, relative in ARTIFACTS.items():
        artifact = pin.get(name, {})
        path = ROOT / relative
        require(artifact.get('path') == relative and path.is_file(), f'wrong read authority artifact: {name}')
        require(artifact.get('sha256') == digest(path.read_bytes()), f'read authority artifact digest mismatch: {relative}')
    require(pin['base_contract'].get('contract_digest') == base_pin['contract_digest'], 'tracker dependency identity mismatch')
    for field in ('message_types', 'type_aliases', 'operations', 'dispatch_kinds', 'tracker_profile', 'canonicalization'):
        require(pin.get(field) == base_pin[field], f'inherited {field} changed')
    require(pin.get('compatibility') == {**base_pin['compatibility'], **COMPATIBILITY}, 'read authority/evidence posture drifted')
    require(pin.get('read_profile') == PROFILE, 'read authority profile drifted')
    schema = json.loads((ROOT / ARTIFACTS['wire_schema']).read_text())
    require(schema.get('$schema') == base_schema['$schema'] and schema.get('oneOf') == base_schema['oneOf'], 'read authority schema inventory drifted')
    require(set(schema.get('$defs', {})) == set(base_schema['$defs']), 'read authority definitions drifted')
    for name, definition in base_schema['$defs'].items():
        if name != 'ReadActionResult':
            require(schema['$defs'][name] == definition, f'inherited definition changed: {name}')
    original = base_schema['$defs']['ReadActionResult']
    current = copy.deepcopy(original)
    current['properties']['protocol']['const'] = PROFILE['current_protocol']
    current['properties']['read_authority'] = {'type': 'string'}
    current['required'].append('read_authority')
    require(schema['$defs']['ReadActionResult'] == {'oneOf': [original, current]}, 'versioned read definition drifted')
    fixtures = json.loads((ROOT / ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v5' and fixtures.get('contract_revision') == REVISION, 'wrong read authority fixture revision')
    cases = fixtures.get('cases', [])
    ids = [case.get('id') for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'read authority fixture inventory incomplete or duplicated')
    require({case.get('message_type') for case in cases} == {'ReadActionResult'}, 'unknown read authority vector type')
    return pin, schema, base_cases + cases


def check_schema_controls(schema, cases, reports):
    controls = [
        ('current-authority-read-extra', lambda v: v[1].update(additionalProperties=True)),
        ('current-authority-read-missing-authority', lambda v: v[1]['required'].remove('read_authority')),
        ('current-authority-read-null-authority', lambda v: v[1]['properties']['read_authority'].update(type=['string', 'null'])),
        ('current-authority-read-wrong-protocol', lambda v: v[1]['properties']['protocol'].pop('const')),
        ('legacy-authority-read-new-field', lambda v: v[0].update(additionalProperties=True)),
    ]
    for vector, weaken in controls:
        altered = copy.deepcopy(schema)
        weaken(altered['$defs']['ReadActionResult']['oneOf'])
        try:
            legacy.check_reports(altered, cases, reports, TYPES)
        except SystemExit as error:
            require(f'{vector}: schema disagrees' in str(error), f'{vector}: unrelated failure: {error}')
        else:
            require(False, f'{vector}: weakened read authority schema passed')
    print(f'current read authority schemas: {len(controls)} weakening controls caught')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', action='store_true')
    args = parser.parse_args()
    pin, schema, cases = check_bundle()
    previous = subprocess.run(['git', 'show', f'origin/main:{PIN}'], cwd=ROOT, capture_output=True, text=True)
    legacy.check_revision(pin, json.loads(previous.stdout) if previous.returncode == 0 else None)
    if args.reports:
        reports = json.load(sys.stdin)
        legacy.check_reports(schema, cases, reports, TYPES)
        check_schema_controls(schema, cases, reports)
    print(f'host action contract {REVISION} {pin["contract_digest"]}: ok')


if __name__ == '__main__':
    main()
