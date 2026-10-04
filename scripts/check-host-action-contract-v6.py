#!/usr/bin/env python3
"""Current reconciliation authority codec profile over immutable V1-V5 bundles."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

module = importlib.util.spec_from_file_location('read_action_contract', Path(__file__).with_name('check-host-action-contract-v5.py'))
read = importlib.util.module_from_spec(module)
module.loader.exec_module(read)
legacy = read.legacy
ROOT = read.ROOT
REVISION = 'whipplescript-host-action/v6.0.0'
PIN = 'spec/host-action-contract-v6.json'
ARTIFACTS = {
    'base_contract': read.PIN,
    'wire_schema': 'spec/report-schemas/host_action_v6.schema.json',
    'fixtures': 'spec/host-action-contract-fixtures-v6.json',
    'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v6.rs',
}
TYPES = read.TYPES
PROFILE = {'legacy_protocol': 'whipplescript.effect-reconciliation.v1', 'current_protocol': 'whipplescript.effect-reconciliation.v2', 'historical_coordinates': ['original_issuer', 'scope', 'evidence.frame.action_admission'], 'current_authority': 'issuer; exact verified envelope authority', 'policy_signer': 'independent cryptographic signer; exact PolicyEpochRef', 'target_authority': 'evidence.authority_ref; independent exact target authority', 'explicit_null_original_issuer': 'refused in both versions', 'receipt_protocol': 'whipplescript.effect-reconciliation.v1'}
COMPATIBILITY = {'current_reconciliation_reissues_history': False, 'original_issuer_grants_authority': False, 'legacy_reconciliation_signing_changed': False, 'target_authority_is_original_locator': False}
REQUIRED_CASES = {'current-authority-reconciliation-other-current', 'current-authority-reconciliation-number-original', 'legacy-reconciliation-new-field', 'current-authority-reconciliation-null-original', 'legacy-reconciliation', 'current-authority-reconciliation-wrong-protocol', 'current-authority-reconciliation', 'current-authority-reconciliation-extra', 'current-authority-reconciliation-blank-original', 'current-authority-reconciliation-missing-original', 'current-authority-reconciliation-other-original', 'legacy-reconciliation-null-field', 'current-authority-reconciliation-empty-original'}
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical


def check_bundle():
    read.ROOT = ROOT
    base_pin, base_schema, base_cases = read.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v6', 'wrong reconciliation authority pin schema')
    require(pin.get('contract_revision') == REVISION, 'reconciliation authority revision drifted')
    require(pin.get('contract_digest') == digest(canonical({k: v for k, v in pin.items() if k != 'contract_digest'})), 'reconciliation authority bundle digest mismatch')
    for name, relative in ARTIFACTS.items():
        artifact = pin.get(name, {})
        path = ROOT / relative
        require(artifact.get('path') == relative and path.is_file(), f'wrong reconciliation authority artifact: {name}')
        require(artifact.get('sha256') == digest(path.read_bytes()), f'reconciliation authority artifact digest mismatch: {relative}')
    require(pin['base_contract'].get('contract_digest') == base_pin['contract_digest'], 'read dependency identity mismatch')
    for field in ('message_types', 'type_aliases', 'operations', 'dispatch_kinds', 'tracker_profile', 'read_profile', 'canonicalization'):
        require(pin.get(field) == base_pin[field], f'inherited {field} changed')
    require(pin.get('compatibility') == {**base_pin['compatibility'], **COMPATIBILITY}, 'reconciliation authority/evidence posture drifted')
    require(pin.get('reconciliation_profile') == PROFILE, 'reconciliation authority profile drifted')
    schema = json.loads((ROOT / ARTIFACTS['wire_schema']).read_text())
    require(schema.get('$schema') == base_schema['$schema'] and schema.get('oneOf') == base_schema['oneOf'], 'reconciliation authority schema inventory drifted')
    require(set(schema.get('$defs', {})) == set(base_schema['$defs']), 'reconciliation authority definitions drifted')
    for name, definition in base_schema['$defs'].items():
        if name != 'ReconcileEffectCommand':
            require(schema['$defs'][name] == definition, f'inherited definition changed: {name}')
    original = base_schema['$defs']['ReconcileEffectCommand']
    current = copy.deepcopy(original)
    current['properties']['protocol']['const'] = PROFILE['current_protocol']
    current['properties']['original_issuer'] = {'type': 'string'}
    current['required'].append('original_issuer')
    require(schema['$defs']['ReconcileEffectCommand'] == {'oneOf': [original, current]}, 'versioned reconciliation definition drifted')
    fixtures = json.loads((ROOT / ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v6' and fixtures.get('contract_revision') == REVISION, 'wrong reconciliation authority fixture revision')
    cases = fixtures.get('cases', [])
    ids = [case.get('id') for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'reconciliation authority fixture inventory incomplete or duplicated')
    require({case.get('message_type') for case in cases} == {'ReconcileEffectCommand'}, 'unknown reconciliation authority vector type')
    return pin, schema, base_cases + cases


def check_schema_controls(schema, cases, reports):
    controls = [
        ('current-authority-reconciliation-extra', lambda v: v[1].update(additionalProperties=True)),
        ('current-authority-reconciliation-missing-original', lambda v: v[1]['required'].remove('original_issuer')),
        ('current-authority-reconciliation-null-original', lambda v: v[1]['properties']['original_issuer'].update(type=['string', 'null'])),
        ('current-authority-reconciliation-wrong-protocol', lambda v: v[1]['properties']['protocol'].pop('const')),
        ('legacy-reconciliation-new-field', lambda v: v[0].update(additionalProperties=True)),
    ]
    for vector, weaken in controls:
        altered = copy.deepcopy(schema)
        weaken(altered['$defs']['ReconcileEffectCommand']['oneOf'])
        try:
            legacy.check_reports(altered, cases, reports, TYPES)
        except SystemExit as error:
            require(f'{vector}: schema disagrees' in str(error), f'{vector}: unrelated failure: {error}')
        else:
            require(False, f'{vector}: weakened reconciliation authority schema passed')
    print(f'current reconciliation authority schemas: {len(controls)} weakening controls caught')


def check_current_journeys(schema, directory):
    # The recording owner still owns its exact actor/outcome/message inventory.
    read.tracker.recording.check_journey_reports(schema, directory)
    reports = [json.loads(path.read_text()) for path in sorted(directory.glob('*.json'))]
    originals = {(r['placement'], r['scenario']): r['value'] for r in reports if r['message_type'] == 'HostActionCommand'}
    current = {}
    for report in reports:
        key = (report['placement'], report['scenario'])
        value = report['value']
        if report['message_type'] == 'ReconcileEffectCommand':
            require(value['protocol'] == PROFILE['current_protocol'], 'journey did not exercise V2 reconciliation')
            require(value['original_issuer'] == originals[key]['issuer'] and value['issuer'] != value['original_issuer'], 'journey conflated current and original reconciliation issuers')
            require(value['evidence']['authority_ref'] != value['original_issuer'], 'journey overloaded target evidence authority as original issuer')
            current[key] = value['issuer']
    for report in reports:
        if report['message_type'] == 'ReadActionResult':
            key = (report['placement'], report['scenario'])
            value = report['value']
            require(value['protocol'] == read.PROFILE['current_protocol'] and value['issuer'] == originals[key]['issuer'] and value['read_authority'] == current[key], 'journey conflated original history and current read authority')
    print('current reconciliation authority: twelve native/hosted actor/outcome journeys checked')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', action='store_true')
    parser.add_argument('--journey-dir', type=Path)
    args = parser.parse_args()
    pin, schema, cases = check_bundle()
    previous = subprocess.run(['git', 'show', f'origin/main:{PIN}'], cwd=ROOT, capture_output=True, text=True)
    legacy.check_revision(pin, json.loads(previous.stdout) if previous.returncode == 0 else None)
    if args.reports:
        reports = json.load(sys.stdin)
        legacy.check_reports(schema, cases, reports, TYPES)
        check_schema_controls(schema, cases, reports)
    if args.journey_dir:
        check_current_journeys(schema, args.journey_dir)
    print(f'host action contract {REVISION} {pin["contract_digest"]}: ok')


if __name__ == '__main__':
    main()
