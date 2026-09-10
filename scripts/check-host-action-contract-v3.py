#!/usr/bin/env python3
"""Owned recording bundle, immutable dependencies, codecs and actual journeys."""
import argparse
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

module = importlib.util.spec_from_file_location('scoped_action_contract', Path(__file__).with_name('check-host-action-contract-v2.py'))
scoped = importlib.util.module_from_spec(module)
module.loader.exec_module(scoped)
legacy = scoped.legacy
ROOT = scoped.ROOT
REVISION = 'whipplescript-host-action/v3.0.0'
PIN = 'spec/host-action-contract-v3.json'
ARTIFACTS = {
    'base_contract': scoped.PIN,
    'wire_schema': 'spec/report-schemas/host_action_v3.schema.json',
    'fixtures': 'spec/host-action-contract-fixtures-v3.json',
    'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v3.rs',
}
NEW_TYPES = {'ResolutionRecordingInput', 'ResolutionRecordingBinding'}
TYPES = scoped.TYPES | NEW_TYPES
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical
REQUIRED_CASES = {
    'recording-input',
    'recording-deletion',
    'recording-binding',
    'recording-input-protocol',
    'recording-input-empty',
    'recording-input-extra',
    'recording-region-extra',
    'recording-region-type',
    'recording-binding-protocol',
    'recording-binding-extra',
    'recording-input-hash-short',
    'recording-input-hash-upper',
    'recording-label-blank',
    'recording-scope-extra',
    'recording-scope-blank',
    'recording-batch-extra',
    'recording-batch-empty',
    'recording-batch-actor-blank',
    'recording-entry-extra',
    'recording-key-unscoped',
    'recording-key-short',
    'recording-key-upper',
    'recording-resolution-short',
    'recording-resolution-upper',
    'recording-label-control-separator',
    'recording-input-missing-protocol',
    'recording-input-missing-resolutions',
    'recording-input-missing-resolutions-0-base_text',
    'recording-input-missing-resolutions-0-resolution_text',
    'recording-binding-missing-input_hash',
    'recording-binding-missing-input_label',
    'recording-binding-missing-scope',
    'recording-binding-missing-batch',
    'recording-binding-missing-batch-intent',
    'recording-binding-missing-batch-entries-0-triple_key',
    'recording-input-hash-newline',
    'recording-key-newline',
    'recording-resolution-newline',
}
PROFILE = {'operation': 'resolution.record', 'capability': 'vcs.record_resolutions',
           'provider': 'resolution-memory', 'workflow_source': 'runtime-owned',
           'caller_supplied_source': False}
COMPATIBILITY = {'recording_inputs_may_contain_protected_content': True,
                 'recording_binding_grants_authority': False,
                 'batch_receipt_proves_input_serialization': False,
                 'reconciliation_rehydrates_content': False}
JOURNEY_TYPES = NEW_TYPES | {'ResolutionMemoryScope', 'ResolutionMemoryReceipt',
    'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect',
    'ReadActionResult', 'ActionResultSnapshot', 'ReconcileEffectCommand', 'ReconciliationReceipt'}


def check_bundle():
    scoped.ROOT = ROOT
    base_pin, base_schema, base_cases = scoped.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v3', 'wrong recording pin schema')
    require(pin.get('contract_revision') == REVISION, 'recording revision drifted')
    require(pin.get('contract_digest') == digest(canonical({k: v for k, v in pin.items() if k != 'contract_digest'})), 'recording bundle digest mismatch')
    for name, relative in ARTIFACTS.items():
        artifact = pin.get(name, {})
        path = ROOT / relative
        require(artifact.get('path') == relative and path.is_file(), f'wrong recording artifact: {name}')
        require(artifact.get('sha256') == digest(path.read_bytes()), f'recording artifact digest mismatch: {relative}')
    require(pin['base_contract'].get('contract_digest') == base_pin['contract_digest'], 'scoped dependency identity mismatch')
    require(pin.get('message_types') == base_pin['message_types'] + sorted(NEW_TYPES), 'recording message inventory drifted')
    require(pin.get('operations') == base_pin['operations'] + ['execute_resolution_recording', 'reconcile_resolution_recording'], 'recording operation inventory drifted')
    require(pin.get('dispatch_kinds') == base_pin['dispatch_kinds'] + ['capability.call'], 'recording dispatch inventory drifted')
    require(pin.get('recording_profile') == PROFILE, 'recording profile ceiling drifted')
    require(pin.get('canonicalization') == base_pin['canonicalization'], 'recording canonicalization drifted')
    require(pin.get('compatibility') == {**base_pin['compatibility'], **COMPATIBILITY}, 'recording authority/evidence posture drifted')
    schema = json.loads((ROOT / ARTIFACTS['wire_schema']).read_text())
    require(schema.get('$schema') == base_schema['$schema'], 'recording schema dialect drifted')
    roots = [entry.get('$ref', '').removeprefix('#/$defs/') for entry in schema.get('oneOf', [])]
    require(set(roots) == TYPES and len(roots) == len(TYPES), 'recording schema inventory drifted')
    for name, definition in base_schema['$defs'].items():
        require(schema.get('$defs', {}).get(name) == definition, f'inherited definition changed: {name}')
    def refs(value):
        if isinstance(value, dict):
            if '$ref' in value:
                ref = value['$ref']
                require(ref.startswith('#/$defs/') and ref[8:] in schema['$defs'], f'nonlocal or missing recording reference: {ref}')
            for child in value.values(): refs(child)
        elif isinstance(value, list):
            for child in value: refs(child)
    refs(schema)
    fixtures = json.loads((ROOT / ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v3' and fixtures.get('contract_revision') == REVISION, 'wrong recording fixture revision')
    cases = fixtures.get('cases', [])
    ids = [case.get('id') for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'recording fixture inventory incomplete or duplicated')
    require({case.get('message_type') for case in cases if 'value' in case} == NEW_TYPES, 'missing positive recording vector')
    return pin, schema, base_cases + cases


def check_schema_controls(schema, cases, reports):
    def binding(d): return d['ResolutionRecordingBinding']['properties']
    def entry(d): return binding(d)['batch']['allOf'][1]['properties']['entries']['items']['properties']
    controls = [
        ('input fields', 'recording-input-extra', lambda d: d['ResolutionRecordingInput'].update(additionalProperties=True)),
        ('region fields', 'recording-region-extra', lambda d: d['RecordingRegion'].update(additionalProperties=True)),
        ('empty input', 'recording-input-empty', lambda d: d['ResolutionRecordingInput']['properties']['resolutions'].pop('minItems')),
        ('input protocol', 'recording-input-protocol', lambda d: d['ResolutionRecordingInput']['properties']['protocol'].pop('const')),
        ('binding fields', 'recording-binding-extra', lambda d: d['ResolutionRecordingBinding'].update(additionalProperties=True)),
        ('input hash alphabet', 'recording-input-hash-upper', lambda d: binding(d)['input_hash'].pop('pattern')),
        ('input hash newline', 'recording-input-hash-newline', lambda d: binding(d)['input_hash'].pop('maxLength')),
        ('input label', 'recording-label-blank', lambda d: binding(d)['input_label'].pop('pattern')),
        ('key alphabet', 'recording-key-upper', lambda d: entry(d)['triple_key'].pop('pattern')),
        ('resolution alphabet', 'recording-resolution-upper', lambda d: entry(d)['resolution'].pop('pattern')),
    ]
    for name, vector, weaken in controls:
        altered = copy.deepcopy(schema)
        weaken(altered['$defs'])
        try:
            legacy.check_reports(altered, cases, reports, TYPES)
        except SystemExit as error:
            require(f'{vector}: schema disagrees' in str(error), f'{name}: unrelated failure: {error}')
        else:
            require(False, f'{name}: weakened recording schema passed')
    print(f'recording action schemas: {len(controls)} weakening controls caught')


def check_journey_inventory(reports):
    coverage = set()
    for report in reports:
        placement, scenario, name = (report[key] for key in ('placement', 'scenario', 'message_type'))
        require(placement in {'native', 'hosted'} and name in JOURNEY_TYPES, 'unknown recording report')
        require(scenario in {f'{actor}:one/{mode}' for actor in ('human', 'agent') for mode in ('success', 'failed', 'interrupted')}, 'unknown recording scenario')
        if name == 'ReconcileEffectCommand':
            actor = scenario.split('/')[0]
            investigator = 'agent:investigator' if actor == 'human:one' else 'human:investigator'
            require(report['value']['provenance']['executor'] == investigator, 'recording investigation must exercise a different principal')
        coverage.add((placement, scenario, name))
    for placement in ('native', 'hosted'):
        for actor in ('human', 'agent'):
            for mode in ('success', 'failed', 'interrupted'):
                scenario = f'{actor}:one/{mode}'
                observed = {name for place, case, name in coverage if place == placement and case == scenario}
                require(JOURNEY_TYPES <= observed, f'{placement}/{scenario}: missing recording messages {sorted(JOURNEY_TYPES - observed)}')


def check_journey_reports(schema, directory):
    from jsonschema import Draft202012Validator
    validators = {name: Draft202012Validator({'$schema': schema['$schema'], '$defs': schema['$defs'], '$ref': f'#/$defs/{name}'}) for name in JOURNEY_TYPES}
    reports = [json.loads(path.read_text()) for path in sorted(directory.glob('*.json'))]
    check_journey_inventory(reports)
    for report in reports:
        errors = list(validators[report['message_type']].iter_errors(report['value']))
        require(not errors, f"{report['placement']}/{report['scenario']}/{report['message_type']}: " + '; '.join(error.message for error in errors))
    print(f'recording action schemas: {len(reports)} actual messages across twelve actor/outcome/placement combinations')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', action='store_true')
    parser.add_argument('--journey-dir', type=Path)
    args = parser.parse_args()
    pin, schema, cases = check_bundle()
    for path in [PIN, scoped.PIN, legacy.PIN]:
        current = json.loads((ROOT / path).read_text())
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
