#!/usr/bin/env python3
"""Repinned semantic drift controls for the immutable V7 owner bundle."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
module=importlib.util.spec_from_file_location('v7',Path(__file__).with_name('check-host-action-contract-v7.py'))
contract=importlib.util.module_from_spec(module)
module.loader.exec_module(contract)
SOURCE=contract.ROOT
OWNERS=[contract,contract.previous,contract.previous.read,contract.previous.read.tracker,contract.previous.read.tracker.recording,contract.previous.read.tracker.recording.scoped,contract.legacy]
class Integrity(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);self.root=Path(directory.name)
        self.paths={o.PIN for o in OWNERS}|{p for o in OWNERS for p in o.ARTIFACTS.values()}
        for path in self.paths:
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((SOURCE/path).read_bytes())
        for owner in OWNERS:
            self.addCleanup(setattr,owner,'ROOT',SOURCE)
        contract.ROOT=self.root
    def alter(self,artifact,change):
        path=self.root/contract.ARTIFACTS[artifact];value=json.loads(path.read_text());change(value);path.write_text(json.dumps(value))
        pin=json.loads((self.root/contract.PIN).read_text());pin[artifact]['sha256']=contract.digest(path.read_bytes());pin['contract_digest']=contract.digest(contract.canonical({k:v for k,v in pin.items() if k!='contract_digest'}));(self.root/contract.PIN).write_text(json.dumps(pin))
    def test_full_inventory(self):
        self.assertEqual(len(contract.check_bundle()[2]),274)
    def test_every_transitive_artifact(self):
        for path in self.paths-{contract.PIN}:
            with self.subTest(path=path):
                target=self.root/path;old=target.read_bytes();target.write_bytes(old+b' ')
                try:
                    with self.assertRaisesRegex(SystemExit,'digest mismatch'):contract.check_bundle()
                finally:target.write_bytes(old)
    def test_repinned_unknown_field_acceptance_refuses(self):
        self.alter('wire_schema',lambda s:s['$defs']['ActionAnchor'].update(additionalProperties=True))
        with self.assertRaisesRegex(SystemExit,'wire shape'):contract.check_bundle()
    def test_repinned_legacy_anchor_promotion_refuses(self):
        self.alter('wire_schema',lambda s:s['$defs']['ReadActionResult']['oneOf'][0]['properties'].update(admission={'$ref':'#/$defs/ActionAdmissionReceipt'}))
        with self.assertRaisesRegex(SystemExit,'wire shape'):contract.check_bundle()
    def test_repinned_count_range_weakening_refuses(self):
        self.alter('wire_schema',lambda s:s['$defs']['ActionFootprint']['properties']['total'].pop('maximum'))
        with self.assertRaisesRegex(SystemExit,'wire shape'):contract.check_bundle()
    def test_repinned_protocol_substitution_refuses(self):
        self.alter('wire_schema',lambda s:s['$defs']['ReadActionResult']['oneOf'][2]['properties']['protocol'].update(const='whipplescript.action-result.v7'))
        with self.assertRaisesRegex(SystemExit,'wire shape'):contract.check_bundle()
    def test_repinned_missing_vector_refuses(self):
        self.alter('fixtures',lambda f:f['cases'].pop())
        with self.assertRaisesRegex(SystemExit,'inventory'):contract.check_bundle()
    def test_published_revision_cannot_be_repinned(self):
        old=json.loads((self.root/contract.PIN).read_text());new=copy.deepcopy(old);new['contract_digest']='changed'
        with self.assertRaises(SystemExit):contract.legacy.check_revision(new,old)
    def test_repinned_authority_and_grant_posture_refuse(self):
        path=self.root/contract.PIN;old=json.loads(path.read_text())
        for field,value in [('authority','caller-authority'),('compatibility',{**old['compatibility'],'anchor_presence_grants_authority':True})]:
            changed=copy.deepcopy(old);changed[field]=value;changed['contract_digest']=contract.digest(contract.canonical({k:v for k,v in changed.items() if k!='contract_digest'}));path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(SystemExit,'authority'):contract.check_bundle()
    @unittest.skipUnless((SOURCE/'AGENTS.md').is_file(),
                         'publisher/native closure belongs to the source repository')
    def test_declared_section_mirror_and_native_closure(self):
        source=(SOURCE/'scripts/check-host-action-contract.sh').read_text()
        self.assertIn('--example host_action_contract_v7',source)
        self.assertIn('check-host-action-contract-v7.py --reports',source)
        section=(SOURCE/'scripts/section.sh').read_text()
        self.assertIn('test-host-action-contract-v7.py',section)
        mirror=(SOURCE/'scripts/publish-mirror.sh').read_text()
        for path in (contract.PIN,contract.ARTIFACTS['fixtures'],'scripts/check-host-action-contract-v7.py','scripts/test-host-action-contract-v7.py'):
            self.assertIn('  '+path+'\n',mirror)
        graph=(SOURCE/'native-crates.bzl').read_text()
        self.assertIn('"spec/host-action-contract-fixtures-v7.json"',graph)
        self.assertIn('rust-test-whipplescript-kernel-host_action_contract_v7',graph)
    def test_domain_drift_refuses(self):
        value={'protocol':'whipplescript.action-result.v4'}
        report={'id':'footprint-read','message_type':'ReadActionResult','observation':{'syntax_valid':True,'normalized':value,'signing_sha256':contract.digest(b'whipplescript:action-result:read:v2\0'+contract.canonical(value))}}
        with self.assertRaisesRegex(SystemExit,'signing domain'):contract.check_signing([report])
if __name__=='__main__':unittest.main()
