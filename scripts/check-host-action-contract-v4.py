#!/usr/bin/env python3
"""Owned typed-workflow/tracker contract, immutable bases, codecs and actual journeys."""
import argparse
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

module = importlib.util.spec_from_file_location('recording_action_contract', Path(__file__).with_name('check-host-action-contract-v3.py'))
recording = importlib.util.module_from_spec(module)
module.loader.exec_module(recording)
legacy = recording.legacy
ROOT = recording.ROOT
REVISION = 'whipplescript-host-action/v4.0.0'
PIN = 'spec/host-action-contract-v4.json'
ARTIFACTS = {
    'base_contract': recording.PIN,
    'wire_schema': 'spec/report-schemas/host_action_v4.schema.json',
    'fixtures': 'spec/host-action-contract-fixtures-v4.json',
    'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v4.rs',
}
NEW_TYPES = {'TrackerBinding', 'TrackerClosureBinding', 'TrackerFiling', 'TrackerClosure',
             'TrackerFilingReceipt', 'TrackerClosureReceipt', 'FilingDispatch', 'ClosureDispatch', 'RecoverTrackerResult'}
TYPES = recording.TYPES | NEW_TYPES
OPERATIONS = ['admit_action_with_inputs', 'execute_tracker_filing', 'execute_tracker_wait',
              'execute_tracker_closure', 'recover_tracker_filing', 'recover_tracker_closure']
ALIASES = {'RecoverTrackerFiling': 'RecoverTrackerResult', 'RecoverTrackerClosure': 'RecoverTrackerResult'}
COMPATIBILITY = {'tracker_requests_may_contain_protected_content': True,
                 'tracker_assignment_grants_authority': False,
                 'tracker_receipt_grants_authority': False,
                 'claim_holder_identifies_closing_actor': False,
                 'tracker_result_delivery_may_advance_workflow': True,
                 'recovery_reopens_expired_attempts': False,
                 'typed_input_materialization_grants_authority': False}
PROFILE = {'provider': 'builtin', 'filing': 'tracker.file', 'closing': 'tracker.finish',
           'wait_capability': 'tracker.wait_closed', 'recovery_protocol': 'whipplescript.tracker-result-delivery.v1',
           'source': 'registered ordinary workflow', 'original_inputs': 'immutable labeled references',
           'assignment': 'advisory; no read grant', 'claim_holder': 'independent of closing actor'}
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical
REQUIRED_CASES = {
    'ClosureDispatch',
    'ClosureDispatch-absent-summary',
    'ClosureDispatch-extra',
    'ClosureDispatch-missing-binding',
    'ClosureDispatch-missing-fingerprint',
    'ClosureDispatch-missing-operation_id',
    'ClosureDispatch-null-summary',
    'FilingDispatch',
    'FilingDispatch-extra',
    'FilingDispatch-missing-binding',
    'FilingDispatch-missing-fingerprint',
    'FilingDispatch-missing-operation_id',
    'FilingDispatch-missing-queue',
    'FilingDispatch-missing-title',
    'RecoverTrackerResult',
    'RecoverTrackerResult-blank-coordinate',
    'RecoverTrackerResult-extra',
    'RecoverTrackerResult-foreign-admission-position',
    'RecoverTrackerResult-missing-admission',
    'RecoverTrackerResult-missing-effect_id',
    'RecoverTrackerResult-missing-issuer',
    'RecoverTrackerResult-missing-policy',
    'RecoverTrackerResult-missing-protocol',
    'RecoverTrackerResult-missing-provenance',
    'RecoverTrackerResult-missing-run_id',
    'RecoverTrackerResult-missing-scope',
    'RecoverTrackerResult-wrong-protocol',
    'TrackerBinding',
    'TrackerBinding-extra',
    'TrackerBinding-missing-queue',
    'TrackerBinding-missing-resource',
    'TrackerBinding-missing-scope',
    'TrackerBinding-resource-extra',
    'TrackerClosure',
    'TrackerClosure-absent-expected_holder',
    'TrackerClosure-absent-summary',
    'TrackerClosure-blank-coordinate',
    'TrackerClosure-extra',
    'TrackerClosure-missing-actor',
    'TrackerClosure-missing-effect_id',
    'TrackerClosure-missing-instance_id',
    'TrackerClosure-missing-item_id',
    'TrackerClosure-missing-operation_id',
    'TrackerClosure-missing-queue',
    'TrackerClosure-missing-subject_id',
    'TrackerClosure-null-expected_holder',
    'TrackerClosure-null-summary',
    'TrackerClosureBinding',
    'TrackerClosureBinding-absent-expected_holder',
    'TrackerClosureBinding-extra',
    'TrackerClosureBinding-holder-type',
    'TrackerClosureBinding-missing-item_id',
    'TrackerClosureBinding-missing-subject_id',
    'TrackerClosureBinding-missing-tracker',
    'TrackerClosureBinding-null-expected_holder',
    'TrackerClosureReceipt',
    'TrackerClosureReceipt-extra',
    'TrackerClosureReceipt-missing-actor',
    'TrackerClosureReceipt-missing-closed_at',
    'TrackerClosureReceipt-missing-event_id',
    'TrackerClosureReceipt-missing-fingerprint',
    'TrackerClosureReceipt-missing-item_id',
    'TrackerClosureReceipt-missing-operation_id',
    'TrackerClosureReceipt-missing-queue',
    'TrackerClosureReceipt-missing-subject_id',
    'TrackerFiling',
    'TrackerFiling-absent-assigned_to',
    'TrackerFiling-blank-coordinate',
    'TrackerFiling-extra',
    'TrackerFiling-labels-type',
    'TrackerFiling-missing-actor',
    'TrackerFiling-missing-body',
    'TrackerFiling-missing-effect_id',
    'TrackerFiling-missing-instance_id',
    'TrackerFiling-missing-labels',
    'TrackerFiling-missing-metadata',
    'TrackerFiling-missing-operation_id',
    'TrackerFiling-missing-queue',
    'TrackerFiling-missing-title',
    'TrackerFiling-null-assigned_to',
    'TrackerFiling-unicode-integers',
    'TrackerFilingReceipt',
    'TrackerFilingReceipt-extra',
    'TrackerFilingReceipt-missing-event_id',
    'TrackerFilingReceipt-missing-fingerprint',
    'TrackerFilingReceipt-missing-item_id',
    'TrackerFilingReceipt-missing-operation_id',
}
JOURNEYS = {
    'file': {'TrackerFiling', 'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect', 'TrackerBinding', 'FilingDispatch', 'TrackerFilingReceipt'},
    'wait': {'ExecuteActionEffect', 'TrackerBinding'},
    'close': {'TrackerClosure', 'HostActionCommand', 'ActionAdmissionReceipt', 'ExecuteActionEffect', 'TrackerClosureBinding', 'ClosureDispatch', 'TrackerClosureReceipt'},
    'recover-file/running': {'RecoverTrackerResult', 'FilingDispatch', 'TrackerFilingReceipt', 'ActionResultSnapshot'},
    'recover-file/expired': {'RecoverTrackerResult', 'FilingDispatch', 'TrackerFilingReceipt', 'ActionResultSnapshot'},
    'recover-close/running': {'RecoverTrackerResult', 'ClosureDispatch', 'TrackerClosureReceipt', 'ActionResultSnapshot'},
    'recover-close/expired': {'RecoverTrackerResult', 'ClosureDispatch', 'TrackerClosureReceipt', 'ActionResultSnapshot'},
}
JOURNEY_TYPES = set().union(*JOURNEYS.values())


def check_bundle():
    recording.ROOT = ROOT
    base_pin, base_schema, base_cases = recording.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v4', 'wrong tracker pin schema')
    require(pin.get('contract_revision') == REVISION, 'tracker revision drifted')
    require(pin.get('contract_digest') == digest(canonical({k: v for k, v in pin.items() if k != 'contract_digest'})), 'tracker bundle digest mismatch')
    for name, relative in ARTIFACTS.items():
        artifact = pin.get(name, {})
        path = ROOT / relative
        require(artifact.get('path') == relative and path.is_file(), f'wrong tracker artifact: {name}')
        require(artifact.get('sha256') == digest(path.read_bytes()), f'tracker artifact digest mismatch: {relative}')
    require(pin['base_contract'].get('contract_digest') == base_pin['contract_digest'], 'recording dependency identity mismatch')
    require(pin.get('message_types') == base_pin['message_types'] + sorted(NEW_TYPES), 'tracker message inventory drifted')
    require(pin.get('type_aliases') == ALIASES, 'tracker recovery aliases drifted')
    require(pin.get('operations') == base_pin['operations'] + OPERATIONS, 'tracker operation inventory drifted')
    require(pin.get('dispatch_kinds') == base_pin['dispatch_kinds'] + ['tracker.file', 'tracker.finish'], 'tracker dispatch inventory drifted')
    require(pin.get('tracker_profile') == PROFILE, 'tracker profile ceiling drifted')
    require(pin.get('canonicalization') == base_pin['canonicalization'], 'tracker canonicalization drifted')
    require(pin.get('compatibility') == {**base_pin['compatibility'], **COMPATIBILITY}, 'tracker authority/evidence posture drifted')
    schema = json.loads((ROOT / ARTIFACTS['wire_schema']).read_text())
    roots = [entry.get('$ref', '').removeprefix('#/$defs/') for entry in schema.get('oneOf', [])]
    require(schema.get('$schema') == base_schema['$schema'], 'tracker schema dialect drifted')
    require(set(roots) == TYPES and len(roots) == len(TYPES), 'tracker schema inventory drifted')
    for name, definition in base_schema['$defs'].items():
        require(schema.get('$defs', {}).get(name) == definition, f'inherited definition changed: {name}')
    def refs(value):
        if isinstance(value, dict):
            if '$ref' in value:
                ref = value['$ref']
                require(ref.startswith('#/$defs/') and ref[8:] in schema['$defs'], f'nonlocal or missing tracker reference: {ref}')
            for child in value.values(): refs(child)
        elif isinstance(value, list):
            for child in value: refs(child)
    refs(schema)
    fixtures = json.loads((ROOT / ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v4' and fixtures.get('contract_revision') == REVISION, 'wrong tracker fixture revision')
    cases = fixtures.get('cases', [])
    ids = [case.get('id') for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'tracker fixture inventory incomplete or duplicated')
    require({case.get('message_type') for case in cases if 'value' in case} == NEW_TYPES, 'missing positive tracker vector')
    return pin, schema, base_cases + cases


def check_schema_controls(schema, cases, reports):
    controls = []
    for name in sorted(NEW_TYPES):
        controls.append((name + '-extra', lambda d, name=name: d[name].update(additionalProperties=True)))
        field = schema['$defs'][name]['required'][0]
        controls.append((name + '-missing-' + field, lambda d, name=name, field=field: d[name]['required'].remove(field)))
    controls.append(('RecoverTrackerResult-wrong-protocol', lambda d: d['RecoverTrackerResult']['properties']['protocol'].pop('const')))
    for vector, weaken in controls:
        altered = copy.deepcopy(schema)
        weaken(altered['$defs'])
        try:
            legacy.check_reports(altered, cases, reports, TYPES)
        except SystemExit as error:
            require(f'{vector}: schema disagrees' in str(error), f'{vector}: unrelated failure: {error}')
        else:
            require(False, f'{vector}: weakened tracker schema passed')
    print(f'tracker action schemas: {len(controls)} weakening controls caught')


def check_journey_inventory(reports):
    coverage = set()
    for report in reports:
        placement, scenario, name = (report[key] for key in ('placement', 'scenario', 'message_type'))
        actor, _, flow = scenario.partition('/')
        require(placement in {'native', 'hosted'} and name in JOURNEY_TYPES, 'unknown tracker report')
        require(actor in {'person:1', 'agent:1'} and flow in JOURNEYS, 'unknown tracker scenario')
        require(name in JOURNEYS[flow], 'tracker message belongs to another scenario')
        coverage.add((placement, scenario, name))
    for placement in ('native', 'hosted'):
        for actor in ('person:1', 'agent:1'):
            for flow, required in JOURNEYS.items():
                scenario = f'{actor}/{flow}'
                observed = {name for place, case, name in coverage if place == placement and case == scenario}
                require(required <= observed, f'{placement}/{scenario}: missing tracker messages {sorted(required - observed)}')


def check_journey_reports(schema, directory):
    from jsonschema import Draft202012Validator
    validators = {name: Draft202012Validator({'$schema': schema['$schema'], '$defs': schema['$defs'], '$ref': f'#/$defs/{name}'}) for name in JOURNEY_TYPES}
    reports = [json.loads(path.read_text()) for path in sorted(directory.glob('*.json'))]
    check_journey_inventory(reports)
    for report in reports:
        errors = list(validators[report['message_type']].iter_errors(report['value']))
        require(not errors, f"{report['placement']}/{report['scenario']}/{report['message_type']}: " + '; '.join(error.message for error in errors))
    print(f'tracker action schemas: {len(reports)} actual messages across native/hosted human/agent filing, wait, closing and recovery')


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
        check_journey_reports(schema, args.journey_dir)
    print(f'host action contract {REVISION} {pin["contract_digest"]}: ok')


if __name__ == '__main__':
    main()
