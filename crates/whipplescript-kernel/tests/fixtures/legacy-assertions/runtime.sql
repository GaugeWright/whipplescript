PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
INSERT INTO schema_migrations VALUES(1,'runtime-store-schema','2026-09-04 17:48:04');
INSERT INTO schema_migrations VALUES(2,'provider-trust-evidence','2026-09-04 17:48:04');
CREATE TABLE programs (
    program_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO programs VALUES('prg_cbc53f71217f3bc7b0a98061ca262f55','LegacyAssertions','2026-09-04 17:48:04');
CREATE TABLE program_versions (
    version_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(program_id),
    source_hash TEXT NOT NULL,
    ir_hash TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    declared_capabilities TEXT NOT NULL DEFAULT '[]',
    declared_profiles TEXT NOT NULL DEFAULT '[]',
    declared_skills TEXT NOT NULL DEFAULT '[]',
    declared_schemas TEXT NOT NULL DEFAULT '[]',
    analysis_summary TEXT NOT NULL DEFAULT '{}',
    generated_artifacts TEXT NOT NULL DEFAULT '[]',
    artifact_root TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, source_hash, ir_hash)
);
INSERT INTO program_versions VALUES('ver_e942565803b5b778311734ada787ab12','prg_cbc53f71217f3bc7b0a98061ca262f55','8ee0d7b81a981a1e4156d12ba4725f81','ac51dfee21d8a27029c1de627e54340a','legacy-fixture','[]','{"agents":[],"harnesses":[]}','[]','[{"kind":"class","name":"Decision"},{"kind":"class","name":"Choice"},{"kind":"class","name":"Settled"}]','{"bundle_hash":"e3b0c44298fc1c149afbf4c8996fb924","generated_declaration_hashes":[],"generated_declarations":[],"harnesses":[],"include_closure":[],"pattern_applications":[],"schemas":[{"fields":[{"name":"disposition","source_span":{"construct":"class_field","end":132,"start":105},"type":"union<literal<\"keep\"> | literal<\"flag\">>"}],"kind":"class","name":"Decision","source_span":{"construct":"class","end":134,"start":88}},{"fields":[{"name":"disposition","source_span":{"construct":"class_field","end":177,"start":150},"type":"union<literal<\"keep\"> | literal<\"flag\">>"}],"kind":"class","name":"Choice","source_span":{"construct":"class","end":179,"start":135}},{"fields":[{"name":"item","source_span":{"construct":"class_field","end":207,"start":196},"type":"string"},{"name":"stage","source_span":{"construct":"class_field","end":220,"start":208},"type":"string"}],"kind":"class","name":"Settled","source_span":{"construct":"class","end":222,"start":180}}],"workflow":"LegacyAssertions","workflow_contracts":[]}','[]',NULL,'2026-09-04 17:48:04');
CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(program_id),
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    workflow_principal TEXT NOT NULL DEFAULT '',
    effective_authority TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    last_event_id TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
, owner_epoch INTEGER NOT NULL DEFAULT 0);
INSERT INTO instances VALUES('ins_0e17491603794a6ac5e702a783b0316c','prg_cbc53f71217f3bc7b0a98061ca262f55','ver_e942565803b5b778311734ada787ab12',0,'','[]','running','{}',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04','2026-09-04 17:48:04',NULL,0);
CREATE TABLE instance_revisions (
    revision_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    epoch INTEGER NOT NULL,
    from_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    to_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    activated_by_event_id TEXT NOT NULL REFERENCES events(event_id),
    activation_policy_json TEXT NOT NULL DEFAULT '{}',
    cancellation_policy TEXT NOT NULL,
    rule_carries_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, epoch)
);
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    causation_id TEXT,
    correlation_id TEXT,
    idempotency_key TEXT, format_version INTEGER, prev_digest TEXT, entry_digest TEXT,
    UNIQUE(instance_id, sequence)
);
INSERT INTO events VALUES('evt_d5f620fd207ec660d61bb098ca0cf347','ins_0e17491603794a6ac5e702a783b0316c',1,'external.started','{}','2026-09-04 17:48:04','external',NULL,NULL,'start',1,'e21862a63f4202831e3b934ce2c6e2254e2583858b54f797b1e60d22bc840212','a294c8fd8ccce936f994fd826ab1f7874ab7be64c5ec7c20a4a508fda18b9597');
INSERT INTO events VALUES('evt_fbaeb22697031d7feb6f51bd8776b0f0','ins_0e17491603794a6ac5e702a783b0316c',2,'fact.derived','{"correlation_id":null,"fact_id":"key_616ee89e1fa9feea69e64a6ef0af5ae1","key":"first","name":"item.arrived","provenance_class":"external","schema_id":null,"value":{"item":"first"}}','2026-09-04 17:48:04','kernel',NULL,NULL,'first',1,'a294c8fd8ccce936f994fd826ab1f7874ab7be64c5ec7c20a4a508fda18b9597','8c9012aea1a4628399497750a08a2e6e0c48ae45599322cd1f64aaffb2d7e301');
INSERT INTO events VALUES('evt_3cfa6a6a050fa2e4b97073dad2db8190','ins_0e17491603794a6ac5e702a783b0316c',3,'rule.committed','{"consumed_facts":[],"context":{"bindings":[{"binding":"item","fact_id":"key_616ee89e1fa9feea69e64a6ef0af5ae1","key":"first","name":"item.arrived","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"external","revision_epoch":0,"value":{"item":"first"}}],"identity":"item:first","trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"},"dependencies":[],"effects":[{"correlation_id":"item:first","effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","idempotency_key":"key_8c604e456fc9274666e639705c0490c4","input":{"access_grants":[],"argument_exprs":["item.item"],"arguments":{"arg0":"first"},"bindings":{"item":{"item":"first"}},"function_name":"choose","media":[],"output_type":"Choice","prompt_content_type":"markdown","prompt_template":"Return keep. {{ text }}\n{{ ctx.output_format }}","rule":"decide"},"kind":"schema.coerce","profile":null,"program_version_id":"ver_e942565803b5b778311734ada787ab12","required_capabilities":["schema.coerce"],"revision_epoch":0,"source_span":{"construct":"effect","end":506,"path":null,"start":473},"status":"queued","target":"choose"}],"facts":[{"correlation_id":"item:first","fact_id":"key_c394cb1f1b561cc32fd8530c2587b437","key":"Decision:1813aa385340d0bd43a5c865efc61735","name":"Decision","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Decision","source_span":null,"value":{"disposition":"keep"}},{"correlation_id":"item:first","fact_id":"key_94406c063ecfbcb279ac9b1eb751b684","key":"Settled:4639fff342e98d598ef842aa6fbfa7ef","name":"Settled","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Settled","source_span":null,"value":{"item":"first","stage":"top"}}],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null}','2026-09-04 17:48:04','kernel','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0',NULL,'key_69b53f502203c92af8e04575d77f038e',1,'8c9012aea1a4628399497750a08a2e6e0c48ae45599322cd1f64aaffb2d7e301','407299d5bd861c400d2641d2c0c0d4429bdde359d24b8a2d6328bfa2c4adf7d9');
INSERT INTO events VALUES('evt_3f88235233e90c6fcee4866d8eca7837','ins_0e17491603794a6ac5e702a783b0316c',4,'effect.run_started','{"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","lease_expires_at":"2030-01-01T00:00:00Z","lease_id":"lease:key_af770ecd88c7a9fc310a0f87381ad516","metadata":{"execution_fingerprint":"b553b835eabc7f8e4d0af624722ac7af"},"provider":"fixture","run_id":"run:key_af770ecd88c7a9fc310a0f87381ad516","worker_id":"test"}','2026-09-04 17:48:04','kernel','key_af770ecd88c7a9fc310a0f87381ad516',NULL,'run:key_af770ecd88c7a9fc310a0f87381ad516',1,'407299d5bd861c400d2641d2c0c0d4429bdde359d24b8a2d6328bfa2c4adf7d9','592e5d5e1298692360834ed959d4ba6b3aa7a3450f349271029aa161e0985870');
INSERT INTO events VALUES('evt_525c5067f24d5d84a43bbd0c669cc005','ins_0e17491603794a6ac5e702a783b0316c',5,'effect.terminal','{"diagnostic":null,"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","exit_code":0,"metadata":{"error":null,"transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}},"provider":"fixture","run_id":"run:key_af770ecd88c7a9fc310a0f87381ad516","status":"completed","summary":"coerce succeeded","worker_id":"test"}','2026-09-04 17:48:04','kernel','key_af770ecd88c7a9fc310a0f87381ad516',NULL,'key_d887e4e5b15427cd614348a277bbf990',1,'592e5d5e1298692360834ed959d4ba6b3aa7a3450f349271029aa161e0985870','3670e21af8c49d6bdbc4fb61465c955d3a3ef6a01f120e1bf48603cfa8c00543');
INSERT INTO events VALUES('evt_08d33a7f5f357af9c6f89c329ce2fd94','ins_0e17491603794a6ac5e702a783b0316c',6,'schema.coerce.succeeded','{"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_af770ecd88c7a9fc310a0f87381ad516","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}','2026-09-04 17:48:04','kernel','run:key_af770ecd88c7a9fc310a0f87381ad516','key_af770ecd88c7a9fc310a0f87381ad516','key_784cddf8e3675cf5c6b327efe998bbeb',1,'3670e21af8c49d6bdbc4fb61465c955d3a3ef6a01f120e1bf48603cfa8c00543','6227d5ef8fc2981f64bc5776a040260384cf40476a974bff9353c53412b6e0ac');
INSERT INTO events VALUES('evt_e4f4a97821badd7cffde40bc868f161c','ins_0e17491603794a6ac5e702a783b0316c',7,'fact.derived','{"correlation_id":"key_af770ecd88c7a9fc310a0f87381ad516","fact_id":"key_cb9f449877379600663e10c07f64c66d","key":"run:key_af770ecd88c7a9fc310a0f87381ad516","name":"schema.coerce.succeeded","provenance_class":"effect","schema_id":"Choice","value":{"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_af770ecd88c7a9fc310a0f87381ad516","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}}','2026-09-04 17:48:04','kernel','run:key_af770ecd88c7a9fc310a0f87381ad516','key_af770ecd88c7a9fc310a0f87381ad516','key_9e77de61637cb6307271a6f08b114b9e',1,'6227d5ef8fc2981f64bc5776a040260384cf40476a974bff9353c53412b6e0ac','ccb65cc77af751e49b2228559354cc3de7cf3e1909d5177bf0dc9cc19bcbc5c5');
INSERT INTO events VALUES('evt_54e87fafff265c9c4598eb51074ed913','ins_0e17491603794a6ac5e702a783b0316c',8,'rule.committed','{"consumed_facts":[],"context":{"bindings":[{"binding":"item","fact_id":"key_616ee89e1fa9feea69e64a6ef0af5ae1","key":"first","name":"item.arrived","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"external","revision_epoch":0,"value":{"item":"first"}}],"identity":"item:first","trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"},"dependencies":[],"effects":[{"correlation_id":"item:first","effect_id":"key_d04a4c45fac90615a20420847b8ea66b","idempotency_key":"key_a5922b62e512362a2e17d7548be11eb9","input":{"access_grants":[],"after":{"binding":"first","predicate":"succeeds","upstream_effect_id":"key_af770ecd88c7a9fc310a0f87381ad516"},"argument_exprs":["item.item"],"arguments":{"arg0":"first"},"bindings":{"first":{"disposition":"keep"},"item":{"item":"first"},"result":{"disposition":"keep"}},"function_name":"choose","media":[],"output_type":"Choice","prompt_content_type":"markdown","prompt_template":"Return keep. {{ text }}\n{{ ctx.output_format }}","rule":"decide"},"kind":"schema.coerce","profile":null,"program_version_id":"ver_e942565803b5b778311734ada787ab12","required_capabilities":["schema.coerce"],"revision_epoch":0,"source_span":{"construct":"effect","end":675,"path":null,"start":641},"status":"queued","target":"choose"}],"facts":[{"correlation_id":"item:first","fact_id":"key_c7412ab4de4504b6f4b6346bd5a617b3","key":"Decision:1813aa385340d0bd43a5c865efc61735","name":"Decision","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Decision","source_span":null,"value":{"disposition":"keep"}},{"correlation_id":"item:first","fact_id":"key_22ec837f2ff543c8256c29e297fd3dd3","key":"Settled:1fdff75a01658b45ce50b2b132ade6c8","name":"Settled","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Settled","source_span":null,"value":{"item":"first","stage":"after"}}],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null}','2026-09-04 17:48:04','kernel','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0',NULL,'key_80b98f2fc1e4fdadf27318bc78fb2e4e',1,'ccb65cc77af751e49b2228559354cc3de7cf3e1909d5177bf0dc9cc19bcbc5c5','a6505380994d07f6811cef1294589326969dbc8435984cc0294fb47520db1005');
INSERT INTO events VALUES('evt_cbf819d84ae52c570526edd635d589a9','ins_0e17491603794a6ac5e702a783b0316c',9,'rule.committed','{"consumed_facts":[],"context":{"bindings":[{"binding":"item","fact_id":"key_616ee89e1fa9feea69e64a6ef0af5ae1","key":"first","name":"item.arrived","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"external","revision_epoch":0,"value":{"item":"first"}}],"identity":"item:first","trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"},"dependencies":[],"effects":[],"facts":[{"correlation_id":"item:first","fact_id":"key_c7412ab4de4504b6f4b6346bd5a617b3","key":"Decision:1813aa385340d0bd43a5c865efc61735","name":"Decision","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Decision","source_span":null,"value":{"disposition":"keep"}}],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null}','2026-09-04 17:48:04','kernel','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0',NULL,'key_8f6df9e4e78fdbb121207ec7b0f72d5c',1,'a6505380994d07f6811cef1294589326969dbc8435984cc0294fb47520db1005','59d7701b4445c6d00dca870f9b910f9edeba74a844af2fc5eae13d9ed6c2cc3f');
INSERT INTO events VALUES('evt_392198a487318168596521d9bcb8378d','ins_0e17491603794a6ac5e702a783b0316c',10,'effect.run_started','{"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","lease_expires_at":"2030-01-01T00:00:00Z","lease_id":"lease:key_d04a4c45fac90615a20420847b8ea66b","metadata":{"execution_fingerprint":"72d37e8f3170a7fa74f3883763a9a03b"},"provider":"fixture","run_id":"run:key_d04a4c45fac90615a20420847b8ea66b","worker_id":"test"}','2026-09-04 17:48:04','kernel','key_d04a4c45fac90615a20420847b8ea66b',NULL,'run:key_d04a4c45fac90615a20420847b8ea66b',1,'59d7701b4445c6d00dca870f9b910f9edeba74a844af2fc5eae13d9ed6c2cc3f','918942ccc51f0bacb982a285a8853e77ee11bd46583dcd9160ec40a61d00ad6b');
INSERT INTO events VALUES('evt_97bccbc2f3080e451183577ecd59a30d','ins_0e17491603794a6ac5e702a783b0316c',11,'effect.terminal','{"diagnostic":null,"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","exit_code":0,"metadata":{"error":null,"transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}},"provider":"fixture","run_id":"run:key_d04a4c45fac90615a20420847b8ea66b","status":"completed","summary":"coerce succeeded","worker_id":"test"}','2026-09-04 17:48:04','kernel','key_d04a4c45fac90615a20420847b8ea66b',NULL,'key_3883c52a50d92f0bf63d6820c07be23f',1,'918942ccc51f0bacb982a285a8853e77ee11bd46583dcd9160ec40a61d00ad6b','cef751ba29f14a09c78ae7db2fea29d07d1aa370a49f065af72b14123d9b23a5');
INSERT INTO events VALUES('evt_9df129efe1d5bb5ee02d40a2f87b98dd','ins_0e17491603794a6ac5e702a783b0316c',12,'schema.coerce.succeeded','{"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_d04a4c45fac90615a20420847b8ea66b","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}','2026-09-04 17:48:04','kernel','run:key_d04a4c45fac90615a20420847b8ea66b','key_d04a4c45fac90615a20420847b8ea66b','key_1d4e3e1f3d7aecc5771b2b132f827a12',1,'cef751ba29f14a09c78ae7db2fea29d07d1aa370a49f065af72b14123d9b23a5','24ba534a950a55ff0c137062d47c29990e4f4b489cd04a426c486c0cb3c85c95');
INSERT INTO events VALUES('evt_37a80ff16f059a9fa17a3671a072ecc6','ins_0e17491603794a6ac5e702a783b0316c',13,'fact.derived','{"correlation_id":"key_d04a4c45fac90615a20420847b8ea66b","fact_id":"key_82b948b1cb1dc339cd5f476d0203d4ea","key":"run:key_d04a4c45fac90615a20420847b8ea66b","name":"schema.coerce.succeeded","provenance_class":"effect","schema_id":"Choice","value":{"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_d04a4c45fac90615a20420847b8ea66b","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}}','2026-09-04 17:48:04','kernel','run:key_d04a4c45fac90615a20420847b8ea66b','key_d04a4c45fac90615a20420847b8ea66b','key_96cb37cc2e3e139e50233dddf30af2fd',1,'24ba534a950a55ff0c137062d47c29990e4f4b489cd04a426c486c0cb3c85c95','d70a5bcbb6ca948f549c35a2a9d2371866befbb2d11a56dd4c5f4aaa7bbe3f9a');
INSERT INTO events VALUES('evt_7063b2950aa890733f4a84e6da5cc574','ins_0e17491603794a6ac5e702a783b0316c',14,'rule.committed','{"consumed_facts":[],"context":{"bindings":[{"binding":"item","fact_id":"key_616ee89e1fa9feea69e64a6ef0af5ae1","key":"first","name":"item.arrived","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"external","revision_epoch":0,"value":{"item":"first"}}],"identity":"item:first","trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"},"dependencies":[],"effects":[],"facts":[{"correlation_id":"item:first","fact_id":"key_c7412ab4de4504b6f4b6346bd5a617b3","key":"Decision:1813aa385340d0bd43a5c865efc61735","name":"Decision","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Decision","source_span":null,"value":{"disposition":"keep"}},{"correlation_id":"item:first","fact_id":"key_d4b0ad302becf68fdb6ac1bb8a94ea30","key":"Decision:1813aa385340d0bd43a5c865efc61735","name":"Decision","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Decision","source_span":null,"value":{"disposition":"keep"}},{"correlation_id":"item:first","fact_id":"key_85fd1febcd4e3e4f6a62757ac9f22b80","key":"Settled:f38ad73a6ba3cf0b0182326960f902f5","name":"Settled","program_version_id":"ver_e942565803b5b778311734ada787ab12","provenance_class":"rule","revision_epoch":0,"schema_id":"Settled","source_span":null,"value":{"item":"first","stage":"nested"}}],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null}','2026-09-04 17:48:04','kernel','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0',NULL,'key_f2dbe937cc5ac1791486a0d065fc373e',1,'d70a5bcbb6ca948f549c35a2a9d2371866befbb2d11a56dd4c5f4aaa7bbe3f9a','0d5bb1c1c97bcccd96cdd5ee3eca5e1480152c4f3ab5c8bf8617fb02012e7c8c');
CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    program_version_id TEXT REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    source_event_id TEXT,
    source_rule TEXT,
    source_effect_id TEXT,
    source_run_id TEXT,
    schema_id TEXT,
    provenance_class TEXT NOT NULL,
    external_system TEXT,
    external_id TEXT,
    correlation_id TEXT,
    source_span_json TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, name, key)
);
INSERT INTO facts VALUES('key_616ee89e1fa9feea69e64a6ef0af5ae1','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'item.arrived','first','{"item":"first"}','evt_fbaeb22697031d7feb6f51bd8776b0f0','kernel',NULL,NULL,NULL,'external',NULL,NULL,NULL,NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_c394cb1f1b561cc32fd8530c2587b437','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'Decision','Decision:1813aa385340d0bd43a5c865efc61735','{"disposition":"keep"}','evt_3cfa6a6a050fa2e4b97073dad2db8190','decide',NULL,NULL,'Decision','rule',NULL,NULL,'item:first',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_94406c063ecfbcb279ac9b1eb751b684','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'Settled','Settled:4639fff342e98d598ef842aa6fbfa7ef','{"item":"first","stage":"top"}','evt_3cfa6a6a050fa2e4b97073dad2db8190','decide',NULL,NULL,'Settled','rule',NULL,NULL,'item:first',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_cb9f449877379600663e10c07f64c66d','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'schema.coerce.succeeded','run:key_af770ecd88c7a9fc310a0f87381ad516','{"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_af770ecd88c7a9fc310a0f87381ad516","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}','evt_e4f4a97821badd7cffde40bc868f161c','kernel',NULL,NULL,'Choice','effect',NULL,NULL,'key_af770ecd88c7a9fc310a0f87381ad516',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_22ec837f2ff543c8256c29e297fd3dd3','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'Settled','Settled:1fdff75a01658b45ce50b2b132ade6c8','{"item":"first","stage":"after"}','evt_54e87fafff265c9c4598eb51074ed913','decide',NULL,NULL,'Settled','rule',NULL,NULL,'item:first',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_82b948b1cb1dc339cd5f476d0203d4ea','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'schema.coerce.succeeded','run:key_d04a4c45fac90615a20420847b8ea66b','{"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","error":null,"function_name":"choose","output_type":"Choice","run_id":"run:key_d04a4c45fac90615a20420847b8ea66b","status":"completed","summary":"coerce succeeded","value":{"disposition":"keep"}}','evt_37a80ff16f059a9fa17a3671a072ecc6','kernel',NULL,NULL,'Choice','effect',NULL,NULL,'key_d04a4c45fac90615a20420847b8ea66b',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
INSERT INTO facts VALUES('key_85fd1febcd4e3e4f6a62757ac9f22b80','ins_0e17491603794a6ac5e702a783b0316c','ver_e942565803b5b778311734ada787ab12',0,'Settled','Settled:f38ad73a6ba3cf0b0182326960f902f5','{"item":"first","stage":"nested"}','evt_7063b2950aa890733f4a84e6da5cc574','decide',NULL,NULL,'Settled','rule',NULL,NULL,'item:first',NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04');
CREATE TABLE effects (
    effect_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    input_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    created_by_rule TEXT NOT NULL,
    created_by_event_id TEXT,
    program_version_id TEXT REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    correlation_id TEXT,
    idempotency_key TEXT NOT NULL,
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    profile TEXT,
    policy_block_reason TEXT,
    policy_block_category TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, timeout_seconds INTEGER,
    UNIQUE(instance_id, idempotency_key)
);
INSERT INTO effects VALUES('key_af770ecd88c7a9fc310a0f87381ad516','ins_0e17491603794a6ac5e702a783b0316c','schema.coerce','choose','{"access_grants":[],"argument_exprs":["item.item"],"arguments":{"arg0":"first"},"bindings":{"item":{"item":"first"}},"function_name":"choose","media":[],"output_type":"Choice","prompt_content_type":"markdown","prompt_template":"Return keep. {{ text }}\n{{ ctx.output_format }}","rule":"decide"}','completed','decide','evt_3cfa6a6a050fa2e4b97073dad2db8190','ver_e942565803b5b778311734ada787ab12',0,'item:first','key_8c604e456fc9274666e639705c0490c4','["schema.coerce"]',NULL,NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04',NULL);
INSERT INTO effects VALUES('key_d04a4c45fac90615a20420847b8ea66b','ins_0e17491603794a6ac5e702a783b0316c','schema.coerce','choose','{"access_grants":[],"after":{"binding":"first","predicate":"succeeds","upstream_effect_id":"key_af770ecd88c7a9fc310a0f87381ad516"},"argument_exprs":["item.item"],"arguments":{"arg0":"first"},"bindings":{"first":{"disposition":"keep"},"item":{"item":"first"},"result":{"disposition":"keep"}},"function_name":"choose","media":[],"output_type":"Choice","prompt_content_type":"markdown","prompt_template":"Return keep. {{ text }}\n{{ ctx.output_format }}","rule":"decide"}','completed','decide','evt_54e87fafff265c9c4598eb51074ed913','ver_e942565803b5b778311734ada787ab12',0,'item:first','key_a5922b62e512362a2e17d7548be11eb9','["schema.coerce"]',NULL,NULL,NULL,'2026-09-04 17:48:04','2026-09-04 17:48:04',NULL);
CREATE TABLE effect_cancellation_requests (
    request_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    revision_id TEXT REFERENCES instance_revisions(revision_id),
    reason TEXT,
    requested_by TEXT NOT NULL,
    causation_event_id TEXT REFERENCES events(event_id),
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_by_event_id TEXT,
    UNIQUE(instance_id, effect_id, revision_id)
);
CREATE TABLE effect_dependencies (
    dependency_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    upstream_effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    downstream_effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    predicate TEXT NOT NULL,
    created_by_rule TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, upstream_effect_id, downstream_effect_id, predicate)
);
CREATE TABLE workflow_invocations (
    invocation_id TEXT PRIMARY KEY,
    parent_instance_id TEXT NOT NULL,
    parent_effect_id TEXT NOT NULL,
    parent_program_version_id TEXT REFERENCES program_versions(version_id),
    parent_revision_epoch INTEGER NOT NULL DEFAULT 0,
    child_instance_id TEXT NOT NULL,
    child_program_version_id TEXT REFERENCES program_versions(version_id),
    child_revision_epoch INTEGER,
    target_workflow TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'running',
    terminal_event_id TEXT,
    source_span_json TEXT,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    instance_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    exit_code INTEGER,
    summary TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO runs VALUES('run:key_af770ecd88c7a9fc310a0f87381ad516','key_af770ecd88c7a9fc310a0f87381ad516','ins_0e17491603794a6ac5e702a783b0316c','fixture','test','completed','2026-09-04 17:48:04','2026-09-04 17:48:04',0,'coerce succeeded','{"error":null,"transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}}');
INSERT INTO runs VALUES('run:key_d04a4c45fac90615a20420847b8ea66b','key_d04a4c45fac90615a20420847b8ea66b','ins_0e17491603794a6ac5e702a783b0316c','fixture','test','completed','2026-09-04 17:48:04','2026-09-04 17:48:04',0,'coerce succeeded','{"error":null,"transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}}');
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    instance_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    released_at TEXT
);
INSERT INTO leases VALUES('lease:key_af770ecd88c7a9fc310a0f87381ad516','run:key_af770ecd88c7a9fc310a0f87381ad516','key_af770ecd88c7a9fc310a0f87381ad516','ins_0e17491603794a6ac5e702a783b0316c','test','released','2026-09-04 17:48:04','2030-01-01T00:00:00Z','2026-09-04 17:48:04');
INSERT INTO leases VALUES('lease:key_d04a4c45fac90615a20420847b8ea66b','run:key_d04a4c45fac90615a20420847b8ea66b','key_d04a4c45fac90615a20420847b8ea66b','ins_0e17491603794a6ac5e702a783b0316c','test','released','2026-09-04 17:48:04','2030-01-01T00:00:00Z','2026-09-04 17:48:04');
CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT,
    mime_type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES instances(instance_id),
    effect_id TEXT REFERENCES effects(effect_id),
    run_id TEXT REFERENCES runs(run_id),
    provider TEXT,
    policy TEXT NOT NULL,
    uri TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, effect_id, run_id, policy)
);
CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    causation_id TEXT,
    correlation_id TEXT,
    summary TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO evidence VALUES('evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','rule.committed','rule_commit','evt_3cfa6a6a050fa2e4b97073dad2db8190','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','decide','rule committed facts and effects','{"consumed_facts":[],"dependencies":[],"effects":["key_af770ecd88c7a9fc310a0f87381ad516"],"event_id":"evt_3cfa6a6a050fa2e4b97073dad2db8190","facts":["key_c394cb1f1b561cc32fd8530c2587b437","key_94406c063ecfbcb279ac9b1eb751b684"],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null,"trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"}','2026-09-04 17:48:04');
INSERT INTO evidence VALUES('evd_e66dc6fecf14f6295ba1bca3f4167b46','ins_0e17491603794a6ac5e702a783b0316c','schema.coerce.provider','run','run:key_af770ecd88c7a9fc310a0f87381ad516','key_af770ecd88c7a9fc310a0f87381ad516','key_6030ef79aaa6fb7616896b990756b90a','coerce succeeded','{"arguments":{"bytes":18,"redacted":true,"shape":{"keys":1,"type":"object"}},"effect_id":"key_af770ecd88c7a9fc310a0f87381ad516","error":null,"function_name":"choose","generated_coerce_source_hash":"725fed9d1ae909982052ec4fe91a5a14","input_schema_hash":"4d4ac6c4ef54658eb890035c5b4f5684","output_schema_hash":"efa0389ac6fce142eaa954880c31388c","output_type":"Choice","transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}}','2026-09-04 17:48:04');
INSERT INTO evidence VALUES('evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','rule.committed','rule_commit','evt_54e87fafff265c9c4598eb51074ed913','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','decide','rule committed facts and effects','{"consumed_facts":[],"dependencies":[],"effects":["key_d04a4c45fac90615a20420847b8ea66b"],"event_id":"evt_54e87fafff265c9c4598eb51074ed913","facts":["key_c7412ab4de4504b6f4b6346bd5a617b3","key_22ec837f2ff543c8256c29e297fd3dd3"],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null,"trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"}','2026-09-04 17:48:04');
INSERT INTO evidence VALUES('evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','rule.committed','rule_commit','evt_cbf819d84ae52c570526edd635d589a9','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','decide','rule committed facts and effects','{"consumed_facts":[],"dependencies":[],"effects":[],"event_id":"evt_cbf819d84ae52c570526edd635d589a9","facts":["key_c7412ab4de4504b6f4b6346bd5a617b3"],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null,"trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"}','2026-09-04 17:48:04');
INSERT INTO evidence VALUES('evd_365d25570d6022c11af34a314c2a87e9','ins_0e17491603794a6ac5e702a783b0316c','schema.coerce.provider','run','run:key_d04a4c45fac90615a20420847b8ea66b','key_d04a4c45fac90615a20420847b8ea66b','key_51273b8327fe8c8bb4906ae4199e37ab','coerce succeeded','{"arguments":{"bytes":18,"redacted":true,"shape":{"keys":1,"type":"object"}},"effect_id":"key_d04a4c45fac90615a20420847b8ea66b","error":null,"function_name":"choose","generated_coerce_source_hash":"725fed9d1ae909982052ec4fe91a5a14","input_schema_hash":"4d4ac6c4ef54658eb890035c5b4f5684","output_schema_hash":"efa0389ac6fce142eaa954880c31388c","output_type":"Choice","transcript":{"bytes":103,"chars":103,"redacted":true},"usage":{"input_tokens":1,"output_tokens":1},"value":{"bytes":22,"redacted":true,"shape":{"keys":1,"type":"object"}}}','2026-09-04 17:48:04');
INSERT INTO evidence VALUES('evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','rule.committed','rule_commit','evt_7063b2950aa890733f4a84e6da5cc574','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','decide','rule committed facts and effects','{"consumed_facts":[],"dependencies":[],"effects":[],"event_id":"evt_7063b2950aa890733f4a84e6da5cc574","facts":["key_c7412ab4de4504b6f4b6346bd5a617b3","key_d4b0ad302becf68fdb6ac1bb8a94ea30","key_85fd1febcd4e3e4f6a62757ac9f22b80"],"program_version_id":"ver_e942565803b5b778311734ada787ab12","revision_epoch":0,"rule":"decide","terminal":null,"trigger_event_id":"evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0"}','2026-09-04 17:48:04');
CREATE TABLE evidence_links (
    link_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    instance_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(evidence_id, target_type, target_id, relation)
);
INSERT INTO evidence_links VALUES('evl_4529053c445ac1010fc937d830f46722','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','rule_commit','evt_3cfa6a6a050fa2e4b97073dad2db8190','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_fe9c2c1068357a82ec0af51e97bcf458','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','causation','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_37124f9a73f525d29676ca6da7f459d3','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','correlation','decide','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_27e756f9a69bfdc60ae9a031375999ca','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','event','evt_3cfa6a6a050fa2e4b97073dad2db8190','emitted','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_436d835a385f5e013101eb9daa384620','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','rule','decide','committed','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_c564ec458882c97c129e13f2ca368829','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','fact','key_c394cb1f1b561cc32fd8530c2587b437','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_45a90e81c0574f398a1f7b5d280b8740','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','fact','key_94406c063ecfbcb279ac9b1eb751b684','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_5e4cbadaa0f6dd8c02ebc1db68d14fbb','evd_cc0220811e3ffdedc0ce9581d900f6ba','ins_0e17491603794a6ac5e702a783b0316c','effect','key_af770ecd88c7a9fc310a0f87381ad516','queued','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_936b4641b996e9c652a4809f91e96814','evd_e66dc6fecf14f6295ba1bca3f4167b46','ins_0e17491603794a6ac5e702a783b0316c','run','run:key_af770ecd88c7a9fc310a0f87381ad516','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_727f558a615e33de2ca20a96679ecd97','evd_e66dc6fecf14f6295ba1bca3f4167b46','ins_0e17491603794a6ac5e702a783b0316c','causation','key_af770ecd88c7a9fc310a0f87381ad516','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_f99c50b51dfa00895615ee9b6b7f469e','evd_e66dc6fecf14f6295ba1bca3f4167b46','ins_0e17491603794a6ac5e702a783b0316c','correlation','key_6030ef79aaa6fb7616896b990756b90a','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_e16c6f4eee43850d8194433f982c534c','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','rule_commit','evt_54e87fafff265c9c4598eb51074ed913','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_1304a4c9bed9f7474a0e3b3eba7a1798','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','causation','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_e873f380393bab953f0c44c89259086d','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','correlation','decide','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_4b8deda45f4213f12be706109f720ec3','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','event','evt_54e87fafff265c9c4598eb51074ed913','emitted','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_ce5d9acdabea5dabaf63b65d2d2330fe','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','rule','decide','committed','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_d38d0d3f3cdebf5d3aacea9ebfd2d5bb','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','fact','key_c7412ab4de4504b6f4b6346bd5a617b3','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_d70e2a54ff5ddb42376fd80e56b74651','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','fact','key_22ec837f2ff543c8256c29e297fd3dd3','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_28b4cba605853c7157f24be068bce575','evd_3a0aa957c5abfa9c688cffa7dac07c1a','ins_0e17491603794a6ac5e702a783b0316c','effect','key_d04a4c45fac90615a20420847b8ea66b','queued','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_de44e3848917c3319ba3481288a8f146','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','rule_commit','evt_cbf819d84ae52c570526edd635d589a9','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_a6d813df490b1b3c68f93a9e1cd2be6d','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','causation','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_4ecaa8c81b6088a5fd8237268e584406','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','correlation','decide','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_59798e93fb8edef93f4f84446eaaf319','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','event','evt_cbf819d84ae52c570526edd635d589a9','emitted','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_c6eac897283e1264eacf72b78a0b76b1','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','rule','decide','committed','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_0f0330fad2cb09fedcfbc825d69d53d7','evd_81253606ef8907a1f3d77e65d50d09a1','ins_0e17491603794a6ac5e702a783b0316c','fact','key_c7412ab4de4504b6f4b6346bd5a617b3','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_e59059a1f8568d1ad6eed548ab958fab','evd_365d25570d6022c11af34a314c2a87e9','ins_0e17491603794a6ac5e702a783b0316c','run','run:key_d04a4c45fac90615a20420847b8ea66b','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_195a1a649cbeadeff5ac2f53f3cdec37','evd_365d25570d6022c11af34a314c2a87e9','ins_0e17491603794a6ac5e702a783b0316c','causation','key_d04a4c45fac90615a20420847b8ea66b','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_a50c5f61b2428e1677e945d6b7826b8c','evd_365d25570d6022c11af34a314c2a87e9','ins_0e17491603794a6ac5e702a783b0316c','correlation','key_51273b8327fe8c8bb4906ae4199e37ab','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_7f123d3cebb888bd583306f6ca1bdcef','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','rule_commit','evt_7063b2950aa890733f4a84e6da5cc574','subject','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_6c3bff867936a77185d89b439c42fe40','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','causation','evt_d5f620fd207ec660d61bb098ca0cf347|evt_fbaeb22697031d7feb6f51bd8776b0f0','caused_by','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_145b09b81c846c1971d74dbc0d7f5747','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','correlation','decide','correlates_with','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_d12af42f12ea906e3efa54abc37d8a75','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','event','evt_7063b2950aa890733f4a84e6da5cc574','emitted','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_4b5b46bc83e7e429011e32151d9bb14f','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','rule','decide','committed','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_da9897e8eedf91286973d652d96b61a0','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','fact','key_c7412ab4de4504b6f4b6346bd5a617b3','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_3179e3842cbf5fc655c8a76c99571d87','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','fact','key_d4b0ad302becf68fdb6ac1bb8a94ea30','recorded','2026-09-04 17:48:04');
INSERT INTO evidence_links VALUES('evl_0dc7a0031b276e29200a102756d8adc7','evd_8f0634baf4d96f924014b85773563e87','ins_0e17491603794a6ac5e702a783b0316c','fact','key_85fd1febcd4e3e4f6a62757ac9f22b80','recorded','2026-09-04 17:48:04');
CREATE TABLE diagnostics (
    diagnostic_id TEXT PRIMARY KEY,
    instance_id TEXT,
    program_id TEXT,
    program_version_id TEXT,
    severity TEXT NOT NULL,
    code TEXT,
    message TEXT NOT NULL,
    source_span_json TEXT,
    subject_type TEXT,
    subject_id TEXT,
    event_id TEXT,
    effect_id TEXT,
    run_id TEXT,
    assertion_id TEXT,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    causation_id TEXT,
    correlation_id TEXT,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE package_registrations (
    package_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO package_registrations VALUES('std.coercion','std.coercion','0.1.0',replace('{\n  "schema": "whipplescript.package_manifest.v0",\n  "package_id": "std.coercion",\n  "name": "std.coercion",\n  "version": "0.1.0",\n  "libraries": [\n    {\n      "id": "std.coercion",\n      "version": "0.1.0",\n      "standard": true,\n      "effect_contracts": [\n        {\n          "id": "schema.coerce",\n          "effect_kind": "schema.coerce",\n          "source_forms": ["coerce", "decide", "prompt"],\n          "input_schema": "schema.coerce.input",\n          "output_schema": "typed-provider-output",\n          "required_capabilities": ["schema.coerce"],\n          "provider_kinds": ["schema_coercer"],\n          "projected_facts": ["effect.output"],\n          "validation": "runtime_boundary"\n        }\n      ]\n    }\n  ],\n  "capabilities": [\n    {\n      "id": "schema.coerce",\n      "description": "Coerce unstructured data into a typed value through a schema_coercer provider."\n    }\n  ],\n  "providers": [\n    {\n      "id": "fixture",\n      "provider_kind": "schema_coercer",\n      "capability": "schema.coerce",\n      "config": {}\n    },\n    {\n      "id": "native",\n      "provider_kind": "schema_coercer",\n      "capability": "schema.coerce",\n      "config": {}\n    }\n  ],\n  "profiles": [\n    {\n      "id": "profile-coercion-user",\n      "name": "coercion-user",\n      "description": "Allow schema coercion.",\n      "enforcement_mode": "enforce",\n      "allowed_capabilities": ["schema.coerce"],\n      "config": {}\n    }\n  ],\n  "bindings": [\n    {\n      "id": "binding-coercion-default",\n      "program_id": null,\n      "capability": "schema.coerce",\n      "provider": "schema_coercer",\n      "config": { "provider_id": "fixture" }\n    }\n  ]\n}\n','\n',char(10)),'2026-09-04 17:48:04');
CREATE TABLE capability_schemas (
    capability TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    schema_json TEXT NOT NULL DEFAULT '{}',
    registered_by_package_id TEXT REFERENCES package_registrations(package_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO capability_schemas VALUES('agent.tell','Run an agent turn through a provider harness.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('schema.coerce','Coerce unstructured data into a typed value through a schema_coercer provider.','{}','std.coercion','2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('event.emit','Emit an external event.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('workflow.invoke','Start and observe a child workflow.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('capability.call','Call a registered package capability.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('messaging.send','Send an outbound message through a std.messaging channel.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('repo.read','Read repository files and metadata.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('repo.write','Modify repository files and metadata.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('command.run','Run local commands under an operator-selected provider policy.','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO capability_schemas VALUES('internet.research','Use networked research providers.','{}',NULL,'2026-09-04 17:48:04');
CREATE TABLE effect_providers (
    provider_id TEXT PRIMARY KEY,
    effect_kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    capability TEXT NOT NULL REFERENCES capability_schemas(capability),
    config_json TEXT NOT NULL DEFAULT '{}',
    registered_by_package_id TEXT REFERENCES package_registrations(package_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(effect_kind, provider)
);
INSERT INTO effect_providers VALUES('provider_agent_tell_builtin','agent.tell','builtin-agent-harness','agent.tell','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO effect_providers VALUES('provider_coerce_builtin','schema.coerce','builtin-coerce','schema.coerce','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO effect_providers VALUES('provider_event_emit_builtin','event.emit','builtin-event','event.emit','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO effect_providers VALUES('provider_workflow_invoke_builtin','workflow.invoke','builtin-workflow-runtime','workflow.invoke','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO effect_providers VALUES('provider_capability_call_builtin','capability.call','builtin-package-call','capability.call','{}',NULL,'2026-09-04 17:48:04');
INSERT INTO effect_providers VALUES('fixture','schema.coerce','schema_coercer','schema.coerce','{}','std.coercion','2026-09-04 17:48:04');
CREATE TABLE profiles (
    profile_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
    allowed_capabilities TEXT NOT NULL DEFAULT '[]',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO profiles VALUES('profile_permissive','permissive','Allow all registered capabilities.','audit','["*"]','{}','2026-09-04 17:48:04');
INSERT INTO profiles VALUES('profile_repo_reader','repo-reader','Allow repository reads and agent turns without writes.','enforce','["agent.tell","repo.read","schema.coerce","event.emit","workflow.invoke"]','{}','2026-09-04 17:48:04');
INSERT INTO profiles VALUES('profile_repo_writer','repo-writer','Allow repository-writing agent workflows.','enforce','["agent.tell","repo.read","repo.write","command.run","schema.coerce","event.emit","workflow.invoke","capability.call"]','{}','2026-09-04 17:48:04');
INSERT INTO profiles VALUES('profile_internet_research','internet-research','Allow networked research workflows.','enforce','["agent.tell","internet.research","schema.coerce","event.emit","workflow.invoke"]','{}','2026-09-04 17:48:04');
INSERT INTO profiles VALUES('profile-coercion-user','coercion-user','Allow schema coercion.','enforce','["schema.coerce"]','{}','2026-09-04 17:48:04');
CREATE TABLE project_context_docs (
    position INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE compute_result_cache (
    content_key TEXT PRIMARY KEY,
    effect_kind TEXT NOT NULL,
    result_json TEXT NOT NULL,
    source_instance_id TEXT NOT NULL,
    source_effect_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE content_blobs (
    id         TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    byte_len   INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO content_blobs VALUES('8ee0d7b81a981a1e4156d12ba4725f81',replace('use std.coercion\n@service\nworkflow LegacyAssertions\nsignal item.arrived { item string }\nclass Decision { disposition "keep" | "flag" }\nclass Choice { disposition "keep" | "flag" }\nclass Settled { item string stage string }\ncoerce choose(text string) -> Choice {\n  prompt """markdown\nReturn keep. {{ text }}\n{{ ctx.output_format }}\n"""\n}\nrule decide\n  when item.arrived as item\n=> {\n  record Decision { disposition "keep" }\n  record Settled { item item.item stage "top" }\n  coerce choose(item.item) as first\n  after first succeeds as result {\n    record Decision { disposition "keep" }\n    record Settled { item item.item stage "after" }\n    coerce choose(item.item) as second\n    after second succeeds as result {\n      record Decision { disposition "keep" }\n      record Settled { item item.item stage "nested" }\n    }\n  }\n}\n','\n',char(10)),826,'2026-09-04 17:48:04');
INSERT INTO content_blobs VALUES('ac51dfee21d8a27029c1de627e54340a',replace('workflow LegacyAssertions\nsource_tags\n@service workflow LegacyAssertions\nuses\n  package std.coercion\nschemas\n  class Decision\n    disposition union<literal<"keep"> | literal<"flag">>\n  class Choice\n    disposition union<literal<"keep"> | literal<"flag">>\n  class Settled\n    item string\n    stage string\ncoerces\n  coerce choose(text string) -> ref<Choice>\nrules\n  rule decide\n    when item.arrived as item\n    reads\n      pattern:item.arrived as item\n    writes\n      schema:Decision\n      schema:Settled\n    effects\n      first kind=schema.coerce binding=first key=c748807c2c8c7ea3d6a251e9cc0bc973\n      second kind=schema.coerce binding=second key=43fb54fc0a94a5bc88e3c928c54c020d arm=first:succeeds\n    dependencies\n      first --succeeds--> second\n    body_hash 74e3c407f5f349f5b66a07dbe70bea80\n','\n',char(10)),799,'2026-09-04 17:48:04');
CREATE TABLE script_capabilities (
    name TEXT PRIMARY KEY,
    argv_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    env_json TEXT NOT NULL DEFAULT '{}',
    hermetic INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE skills (
    skill_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    source_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
, body TEXT NOT NULL DEFAULT '');
CREATE TABLE skill_attachments (
    attachment_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    skill_id TEXT NOT NULL REFERENCES skills(skill_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scope_type, scope_id, skill_id)
);
CREATE TABLE capability_bindings (
    binding_id TEXT PRIMARY KEY,
    program_id TEXT REFERENCES programs(program_id),
    capability TEXT NOT NULL,
    provider TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, capability, provider)
);
INSERT INTO capability_bindings VALUES('binding_agent_tell_builtin',NULL,'agent.tell','builtin-agent-harness','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_coerce_builtin',NULL,'schema.coerce','builtin-coerce','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_event_emit_builtin',NULL,'event.emit','builtin-event','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_workflow_invoke_builtin',NULL,'workflow.invoke','builtin-workflow-runtime','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_capability_call_builtin',NULL,'capability.call','builtin-package-call','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_repo_read_builtin',NULL,'repo.read','builtin-agent-harness','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_repo_write_builtin',NULL,'repo.write','builtin-agent-harness','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding_command_run_builtin',NULL,'command.run','builtin-agent-harness','{}','2026-09-04 17:48:04');
INSERT INTO capability_bindings VALUES('binding-coercion-default',NULL,'schema.coerce','schema_coercer','{"provider_id":"fixture"}','2026-09-04 17:48:04');
CREATE TABLE provider_trust_evidence (
    effect_kind TEXT NOT NULL,
    provider TEXT NOT NULL,

    -- Rung evidence: the digest frozen by `whip provider pin`. NULL = never
    -- pinned, which is the floor and cannot be missing.
    pinned_digest TEXT,

    -- Custody evidence: a filed claim. `c1`-`c3` are testimony — whip cannot
    -- verify a retention claim — so the signer rides with it for the audit
    -- trail, and the term is mandatory. A claim with no end date is precisely
    -- the thing that rots: contracts get renegotiated and nobody revisits the
    -- registry row.
    claim_class TEXT,
    claim_signer TEXT,
    claim_filed_at TEXT,
    claim_expires_at TEXT,

    -- The one self-checkable class (c4 operator-held): whip supervises the
    -- endpoint. Not testimony, so it carries no signer and no expiry.
    operator_run INTEGER NOT NULL DEFAULT 0,

    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (effect_kind, provider),

    -- Testimony expires; a filed claim without a term is refused at write time
    -- rather than silently treated as perpetual.
    CHECK (claim_class IS NULL OR (claim_signer IS NOT NULL AND claim_expires_at IS NOT NULL))
);
CREATE TABLE repair_scopes (
            instance_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            slice_expr TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
CREATE TABLE store_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
INSERT INTO store_meta VALUES('writer_version','0.5.6','2026-09-04 17:48:04');
INSERT INTO store_meta VALUES('format_version','1','2026-09-04 17:48:04');
CREATE UNIQUE INDEX instance_revisions_instance_idempotency_key_idx
    ON instance_revisions(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX events_instance_idempotency_key_idx
    ON events(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX effect_cancellation_requests_instance_idempotency_key_idx
    ON effect_cancellation_requests(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX diagnostics_instance_idempotency_key_idx
    ON diagnostics(instance_id, idempotency_key)
    WHERE instance_id IS NOT NULL AND idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX diagnostics_program_idempotency_key_idx
    ON diagnostics(program_id, idempotency_key)
    WHERE instance_id IS NULL
      AND program_id IS NOT NULL
      AND program_version_id IS NULL
      AND idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX diagnostics_version_idempotency_key_idx
    ON diagnostics(program_version_id, idempotency_key)
    WHERE instance_id IS NULL AND program_version_id IS NOT NULL AND idempotency_key IS NOT NULL;
CREATE INDEX idx_facts_instance_name ON facts(instance_id, name);
CREATE INDEX idx_runs_instance ON runs(instance_id);
CREATE INDEX idx_evidence_instance ON evidence(instance_id);
CREATE INDEX idx_leases_instance ON leases(instance_id);
COMMIT;
