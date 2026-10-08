#!/usr/bin/env python3
"""Immutable negotiated V4 anchor/footprint codecs over unchanged V1-V6."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
module = importlib.util.spec_from_file_location('previous_contract', Path(__file__).with_name('check-host-action-contract-v6.py'))
previous = importlib.util.module_from_spec(module)
module.loader.exec_module(previous)
legacy = previous.legacy
ROOT = previous.ROOT
REVISION = 'whipplescript-host-action/v7.0.0'
PIN = 'spec/host-action-contract-v7.json'
ARTIFACTS = {'base_contract': previous.PIN, 'wire_schema': 'spec/report-schemas/host_action_v7.schema.json', 'fixtures': 'spec/host-action-contract-fixtures-v7.json', 'codec_harness': 'crates/whipplescript-kernel/examples/host_action_contract_v7.rs'}
TYPES = previous.TYPES | {'ActionAnchor', 'ActFootprint', 'ActionFootprint'}
PROFILE = {'protocol': 'whipplescript.action-result.v4', 'signing_domain': 'whipplescript:action-result:read:v4\0', 'legacy_anchored_reads': 'refused', 'anchor_authority': 'independent live held-claim verification; never inferred', 'counts': 'runtime derives from actual acts; structural decoding does not validate totals', 'zero_act_share': None, 'opaque_and_unknown_kinds': 'unobserved', 'snapshot_protocol': 'whipplescript.action-result.v4'}
COMPATIBILITY = {'anchor_presence_grants_authority': False, 'footprint_proves_external_delivery': False, 'structural_counts_prove_runtime_counts': False, 'unanchored_signing_changed': False, 'unknown_fields_ignored': False}
require, digest, canonical = legacy.require, legacy.digest, legacy.canonical
REQUIRED_CASES = {'anchored-read-v2', 'act-unknown-kind', 'anchor-empty', 'anchored-read-v3', 'anchor-blank', 'act-extra', 'footprint-total-negative', 'anchored-read-v7', 'command-anchor-other', 'legacy-snapshot-forged-footprint', 'command-anchor', 'act-opaque', 'command-anchor-null', 'footprint-snapshot-inconsistent-structural', 'footprint-snapshot-missing', 'footprint-no-acts', 'legacy-snapshot-no-fields', 'footprint-read-null-authority', 'anchor-exact', 'footprint-total-string', 'command-anchor-blank', 'footprint-read-other-authority', 'footprint-extra', 'receipt-anchor', 'anchor-missing-claim_ref', 'footprint-total-fraction', 'footprint-snapshot-null', 'footprint-mixed', 'footprint-read-extra', 'command-anchor-absent', 'receipt-anchor-null', 'footprint-total-overflow', 'receipt-anchor-extra', 'footprint-read', 'footprint-inconsistent-structural', 'anchor-number', 'anchor-missing-authority', 'anchored-read-v1', 'anchor-extra', 'footprint-read-missing-authority', 'footprint-snapshot', 'act-wrong-observation', 'footprint-full-u64'}

def expected_schema(base):
    schema = copy.deepcopy(base)
    schema['$id'] = 'https://whipplescript.dev/schemas/host_action_v7.schema.json'
    defs = schema['$defs']
    defs['LegacyActionAdmissionReceipt'] = copy.deepcopy(defs['ActionAdmissionReceipt'])
    defs['LegacyHostActionCommand'] = copy.deepcopy(defs['HostActionCommand'])
    defs['ActionAnchor'] = {'type':'object','additionalProperties':False,'required':['authority','claim_ref'],'properties':{'authority':{'type':'string'},'claim_ref':{'type':'string'}}}
    defs['ActFootprint'] = {'type':'object','additionalProperties':False,'required':['effect_id','kind','observation'],'properties':{'effect_id':{'type':'string'},'kind':{'type':'string'},'observation':{'enum':['observed','unobserved']}}}
    defs['ActionFootprint'] = {'type':'object','additionalProperties':False,'required':['acts','unobserved','total'],'properties':{'acts':{'type':'array','items':{'$ref':'#/$defs/ActFootprint'}},'unobserved':{'type':'integer','minimum':0,'maximum':18446744073709551615},'total':{'type':'integer','minimum':0,'maximum':18446744073709551615}}}
    for name in ('HostActionCommand','ActionAdmissionReceipt'):
        defs[name]['properties']['anchor'] = {'anyOf':[{'$ref':'#/$defs/ActionAnchor'},{'type':'null'}]}
    reads = defs['ReadActionResult']['oneOf']
    current = copy.deepcopy(reads[1])
    for read in reads:
        read['properties']['admission'] = {'$ref':'#/$defs/LegacyActionAdmissionReceipt'}
    current['properties']['protocol']['const'] = PROFILE['protocol']
    reads.append(current)
    old = copy.deepcopy(defs['ActionResultSnapshot'])
    old['properties']['admission'] = {'$ref':'#/$defs/LegacyActionAdmissionReceipt'}
    old['properties']['command'] = {'$ref':'#/$defs/LegacyHostActionCommand'}
    new = copy.deepcopy(defs['ActionResultSnapshot'])
    new['properties']['protocol']['const'] = PROFILE['snapshot_protocol']
    new['properties']['footprint'] = {'$ref':'#/$defs/ActionFootprint'}
    new['required'].append('footprint')
    defs['ActionResultSnapshot'] = {'oneOf':[old,new]}
    schema['oneOf'] += [{'$ref':'#/$defs/'+name} for name in ('ActionAnchor','ActFootprint','ActionFootprint')]
    return schema

def check_bundle():
    previous.ROOT = ROOT
    base, base_schema, base_cases = previous.check_bundle()
    pin = json.loads((ROOT / PIN).read_text())
    require(pin.get('schema') == 'whipplescript.host_action_contract_pin.v7' and pin.get('contract_revision') == REVISION, 'V7 revision drifted')
    require(pin.get('authority') == 'WhippleScript DR-0207', 'V7 owning authority drifted')
    require(pin.get('contract_digest') == digest(canonical({k:v for k,v in pin.items() if k != 'contract_digest'})), 'V7 bundle digest mismatch')
    for name,path in ARTIFACTS.items():
        require(pin.get(name,{}).get('path') == path and (ROOT/path).is_file(), 'wrong V7 artifact '+name)
        require(pin[name].get('sha256') == digest((ROOT/path).read_bytes()), 'V7 artifact digest mismatch '+path)
    require(pin['base_contract'].get('contract_digest') == base['contract_digest'], 'V6 identity mismatch')
    for field in ('type_aliases','operations','dispatch_kinds','tracker_profile','read_profile','reconciliation_profile','canonicalization'):
        require(pin.get(field) == base[field], 'inherited '+field+' changed')
    require(pin.get('message_types') == base['message_types'] + ['ActionAnchor','ActFootprint','ActionFootprint'], 'V7 type inventory changed')
    require(pin.get('compatibility') == {**base['compatibility'],**COMPATIBILITY}, 'V7 authority posture drifted')
    require(pin.get('footprint_profile') == PROFILE, 'V7 negotiated profile drifted')
    schema = json.loads((ROOT/ARTIFACTS['wire_schema']).read_text())
    require(schema == expected_schema(base_schema), 'V7 versioned wire shape drifted')
    fixtures = json.loads((ROOT/ARTIFACTS['fixtures']).read_text())
    require(fixtures.get('schema') == 'whipplescript.host_action_contract_fixtures.v7' and fixtures.get('contract_revision') == REVISION, 'wrong V7 fixture revision')
    cases = fixtures['cases']
    ids = [case['id'] for case in cases]
    require(set(ids) == REQUIRED_CASES and len(ids) == len(REQUIRED_CASES), 'V7 fixture inventory incomplete or duplicated')
    require({case['message_type'] for case in cases} <= TYPES, 'unknown V7 type')
    return pin,schema,base_cases+cases

def check_signing(reports):
    # Independent canonical byte calculation checks domains and typed null omission.
    for report in reports:
        if report['id'] not in REQUIRED_CASES or report['message_type'] not in ('HostActionCommand','ReadActionResult'):
            continue
        observation = report['observation']
        if not observation['syntax_valid']:
            require(observation['signing_sha256'] is None, report['id']+': invalid request signed')
            continue
        domain = b'whipplescript:host-action:command:v1\0' if report['message_type'] == 'HostActionCommand' else b'whipplescript:action-result:read:v4\0'
        require(observation['signing_sha256'] == digest(domain + canonical(observation['normalized'])), report['id']+': signing domain/bytes drifted')

def check_controls(schema, cases, reports):
    controls = [
        ('anchor-extra', lambda s:s['$defs']['ActionAnchor'].update(additionalProperties=True)),
        ('footprint-total-overflow', lambda s:s['$defs']['ActionFootprint']['properties']['total'].pop('maximum')),
        ('footprint-read-extra', lambda s:s['$defs']['ReadActionResult']['oneOf'][2].update(additionalProperties=True)),
        ('legacy-snapshot-forged-footprint', lambda s:s['$defs']['ActionResultSnapshot']['oneOf'][0].update(additionalProperties=True)),
    ]
    for vector, mutate in controls:
        altered=copy.deepcopy(schema);mutate(altered)
        try: legacy.check_reports(altered,cases,reports,TYPES)
        except SystemExit as error:
            require(vector+': schema disagrees' in str(error),'unrelated schema control failure: '+str(error))
        else: require(False,vector+': weakened schema passed')
    altered=copy.deepcopy(reports)
    report=next(r for r in altered if r['id']=='footprint-read')
    report['observation']['signing_sha256']=digest(b'whipplescript:action-result:read:v2\0'+canonical(report['observation']['normalized']))
    try: check_signing(altered)
    except SystemExit as error: require('footprint-read: signing domain' in str(error),'unrelated signing control failure')
    else: require(False,'V2 domain substitution passed')
    print('V7 actual reports: four schema weakening controls and one signing-domain substitution caught')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports',action='store_true')
    args=parser.parse_args()
    pin,schema,cases=check_bundle()
    old=subprocess.run(['git','show','origin/main:'+PIN],cwd=ROOT,capture_output=True,text=True)
    legacy.check_revision(pin,json.loads(old.stdout) if old.returncode == 0 else None)
    if args.reports:
        reports=json.load(sys.stdin)
        legacy.check_reports(schema,cases,reports,TYPES)
        check_signing(reports)
        check_controls(schema,cases,reports)
    print(f'host action contract {REVISION} {pin["contract_digest"]}: ok')
if __name__ == '__main__': main()
