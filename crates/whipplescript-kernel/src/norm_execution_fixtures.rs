//! Shared captured-history and authenticated-transport fixtures. Test support only.
use super::*;
use crate::exec_http::sha256_hex;
use crate::norm_runner::{PythonCase, PythonEngine, PythonRuntime};
use std::cell::RefCell;
use std::collections::BTreeMap;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::*;
use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
use whipplescript_store::norm_history::NormHistoryLimits;
use whipplescript_store::StoreResult;

// Deterministic authentication boundary for composition tests, not a signing
// algorithm. Cryptographic binding is covered by norm_governance/public_key.
pub struct Boundary;
pub fn actor() -> NormActor {
    NormActor {
        principal: "owner".into(),
        algorithm: "fixture".into(),
        key_id: "owner".into(),
    }
}
impl NormVerifier for Boundary {
    fn verify(&self, who: &NormActor, bytes: &[u8], signature: &str) -> Result<(), String> {
        if who == &actor() && signature == sha256_hex(bytes) {
            Ok(())
        } else {
            Err("fixture binding mismatch".into())
        }
    }
    fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
        if creator == "owner" && owner == &actor() {
            Ok(())
        } else {
            Err("fixture grant mismatch".into())
        }
    }
}
pub fn sign(nonce: &str, action: NormAct) -> SignedNormEvent {
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: actor(),
        nonce: nonce.into(),
        created_at: "2026-09-09T00:00:00Z".into(),
        action,
        premises: None,
    };
    let signature = sha256_hex(
        &statement
            .signing_bytes()
            .expect("valid norm preparation fixture"),
    );
    SignedNormEvent {
        statement,
        signature,
        successor_signature: None,
    }
}
pub fn method() -> PythonCallMethod {
    PythonCallMethod {
        runtime: PythonRuntime {
            engine: PythonEngine::Cpython {},
            executable: "python3".into(),
            python_version: "3.14.7".into(),
            environment: "epoch".into(),
        },
        module: "main".into(),
        function: "allow".into(),
        cases: vec![PythonCase {
            id: "deny".into(),
            args: vec![json!("unknown")],
            kwargs: BTreeMap::new(),
        }],
    }
}
pub fn template() -> Value {
    json!(PythonCallSupport::V1 {
        method: method(),
        cases: vec![RequiredCase {
            id: "deny".into(),
            assertion: "unknown denied".into(),
            expected: json!(false)
        }]
    })
}
pub fn script() -> ScriptCapabilityRecord {
    let body = method().adapter().to_owned();
    ScriptCapabilityRecord {
        name: "observer".into(),
        argv_json: json!(["python3", "-I", "{script}"]).to_string(),
        sha256: sha256_hex(body.as_bytes()),
        env_json: "{}".into(),
        hermetic: false,
        body,
    }
}
pub fn fixture(template: Option<Value>, accepted: bool) -> (WorkItemStore, String) {
    fixture_with_observation(template, accepted, false)
}
pub fn fixture_with_observation(
    template: Option<Value>,
    accepted: bool,
    observation: bool,
) -> (WorkItemStore, String) {
    fixture_with_custom_observation(template, accepted, observation.then(observation_vocabulary))
}
pub fn fixture_with_custom_observation(
    template: Option<Value>,
    accepted: bool,
    observation: Option<NormVocabulary>,
) -> (WorkItemStore, String) {
    let mut store = WorkItemStore::open_in_memory().expect("valid norm preparation fixture");
    // A renamed vocabulary proves classification follows charter data.
    let mut charter = NormCharter::bundled().expect("valid norm preparation fixture");
    if let Some(observation) = observation {
        charter.vocabularies.push(observation);
        charter.owner_scopes.push("observe.publish".into());
    }
    let entry = charter
        .vocabularies
        .iter_mut()
        .find(|e| e.definition.name == "obligation")
        .expect("valid norm preparation fixture");
    entry.definition.name = "local-duty".into();
    let vocabulary = Vocabulary::new(entry.definition.clone())
        .expect("valid norm preparation fixture")
        .reference()
        .clone();
    // The bundled relations name the obligation kind; a renamed vocabulary is
    // renamed wherever the charter names it, or the charter is not one.
    for entry in &mut charter.vocabularies {
        if let Some(relation) = entry.relation.as_mut() {
            for kind in relation
                .source_kinds
                .iter_mut()
                .chain(relation.target_kinds.iter_mut())
            {
                if kind == "obligation" {
                    *kind = "local-duty".into();
                }
            }
        }
    }
    let ledger = store
        .append_norm_event(
            &sign(
                "root",
                NormAct::Bootstrap {
                    creator: "owner".into(),
                    charter,
                },
            ),
            &Boundary,
        )
        .expect("valid norm preparation fixture");
    let mut fields = json!({"name":"allow","proposition":"unknown denied","domain":"workspace","subject":"main.py"});
    if let Some(template) = template {
        fields["support_contract"] = json!(template.to_string());
    }
    let record = store
        .append_norm_event(
            &sign(
                "requirement",
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: vocabulary.clone(),
                    fields_json: fields.to_string(),
                },
            ),
            &Boundary,
        )
        .expect("valid norm preparation fixture");
    if accepted {
        store
            .append_norm_event(
                &sign(
                    "accept",
                    NormAct::Transition {
                        ledger,
                        authority: None,
                        vocabulary,
                        record: record.clone(),
                        previous: record.clone(),
                        status: "accepted".into(),
                    },
                ),
                &Boundary,
            )
            .expect("valid norm preparation fixture");
    }
    (store, record)
}
pub fn history(store: &WorkItemStore) -> CapturedNormHistory {
    CapturedNormHistory::capture(
        &store
            .norm_view(&Boundary)
            .expect("valid norm preparation fixture"),
        &store
            .export_events()
            .expect("valid norm preparation fixture"),
        &Boundary,
        NormHistoryLimits::default(),
    )
    .expect("valid norm preparation fixture")
}
#[derive(Default)]
pub struct Blobs(RefCell<BTreeMap<String, Vec<u8>>>);
impl ContentBlobs for Blobs {
    // The seam is bytes: a workspace holds whatever the work puts in it.
    fn put(&self, body: &[u8]) -> StoreResult<String> {
        let id = whipplescript_store::stable_hash_bytes_hex(body);
        self.0.borrow_mut().insert(id.clone(), body.to_vec());
        Ok(id)
    }
    fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(id).cloned())
    }
}
pub fn artifact(body: &str) -> CapturedArtifact {
    artifact_at(body, "cut")
}
pub fn artifact_at(body: &str, cut_id: &str) -> CapturedArtifact {
    let blobs = Blobs::default();
    let file = blobs
        .put(body.as_bytes())
        .expect("valid norm preparation fixture");
    let root = blobs
        .put(json!({"main.py":file}).to_string().as_bytes())
        .expect("valid norm preparation fixture");
    let mut branches = BranchStore::open(":memory:").expect("valid norm preparation fixture");
    branches
        .ensure_mainline("t0")
        .expect("valid norm preparation fixture");
    branches
        .record_cut(CutRecord {
            cut_id,
            change_id: "change",
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: &root,
            parent_cut_id: None,
            origin: None,
            actor: None,
            intent: None,
            recorded_at: "t1",
        })
        .expect("valid norm preparation fixture");
    capture_cut(&branches, &blobs, cut_id, ArtifactLimits::default())
        .expect("valid norm preparation fixture")
}
pub fn selection<'a>(ledger: &'a str, record: &'a str) -> NormRunSelection<'a> {
    NormRunSelection {
        ledger,
        frontier: None,
        requirement: record,
        effect_id: "observe",
        publisher: "owner",
        executor_url: "https://executor",
        environment_epoch: "epoch",
    }
}

pub fn prepared_fixture() -> PreparedNormExecution {
    let (store, record) = fixture(Some(template()), true);
    let history = history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&ledger, &record),
    )
    .expect("prepared fixture")
}
// This is an authenticated transport fixture, not an actual Python invocation.
// Native process/executor tests independently cover the observer implementation.
pub fn receipt(prepared: &PreparedNormExecution, actual: bool, timeout: bool) -> HttpResponse {
    let stdin = &prepared.request().body["stdin"];
    let contract_json = stdin["contract_json"].as_str().expect("contract JSON");
    let contract: ReportContract = serde_json::from_str(contract_json).expect("contract");
    let method: PythonCallMethod = serde_json::from_str(
        stdin["method_definition_json"]
            .as_str()
            .expect("method JSON"),
    )
    .expect("method");
    let header = json!({"kind":"started","contract_digest":sha256_hex(contract_json.as_bytes()),"requirement":contract.subject.requirement,"protocol":method.protocol(),"run_id":prepared.intent().effect_id,"artifact":contract.subject.artifact,"method":contract.subject.method,"environment":method.runtime.environment,"adapter_digest":sha256_hex(method.adapter().as_bytes()),"python_version":method.runtime.python_version});
    let case = json!({"kind":"case","case":"deny","assertion":"unknown denied","actual":actual});
    let stdout = if timeout {
        format!("{header}\n{case}\n")
    } else {
        format!("{header}\n{case}\n{{\"kind\":\"complete\"}}\n")
    };
    HttpResponse {
        status: 200,
        body: json!({"protocol":"whip-executor/1","effect_id":prepared.intent().effect_id,"stdout":stdout,"stderr":"","stdout_truncated":false,"stderr_truncated":false,"timed_out":timeout,"exit_code":if timeout {124} else if actual {1} else {0}}),
    }
}
pub fn journal_execution<S: RuntimeStore>(
    store: S,
    prepared: &PreparedNormExecution,
    response: &HttpResponse,
    failed: bool,
) -> crate::RuntimeKernel<S> {
    use crate::exec_http::{settle_exec_http_result, ExecSettleContext};
    use whipplescript_store::{NewEffect, RuleCommit, RunStart};
    let mut kernel = crate::RuntimeKernel::new(store);
    let input = prepared.effect_input().to_string();
    let effects = [NewEffect {
        effect_id: "observe",
        kind: "exec.command",
        target: None,
        input_json: &input,
        status: "queued",
        idempotency_key: "observe",
        required_capabilities_json: "[]",
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: Some(30),
    }];
    let effects = [
        effects[0],
        NewEffect {
            effect_id: "foreign",
            idempotency_key: "foreign",
            ..effects[0]
        },
    ];
    kernel
        .store_mut()
        .commit_rule(RuleCommit {
            instance_id: "instance",
            rule: "observe",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &effects,
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("prepare"),
            marks: &[],
            context_json: None,
        })
        .expect("journal input");
    let digest = prepared.request().body["script_sha256"]
        .as_str()
        .expect("prepared script digest");
    let plan = ExecDispatchPlan::prepare(
        "observer",
        digest,
        prepared.effect_input(),
        prepared.request(),
        "epoch",
        None,
        None,
    );
    kernel
        .start_run(RunStart {
            instance_id: "instance",
            effect_id: "observe",
            run_id: "run",
            provider: "exec",
            worker_id: "whip-exec",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: &json!({"executor_dispatch":plan}).to_string(),
        })
        .expect("start execution");
    let context = ExecSettleContext {
        resolution_event_id: None,
        input_json: &prepared.effect_input().to_string(),
        instance_id: "instance",
        effect_id: "observe",
        run_id: "run",
        capability: "observer",
        script_sha256: digest,
        cache: None,
        ingest_schema: "json",
        executor_response: Some(response),
        executor_transport: "http",
        dispatch_plan: Some(&plan),
    };
    let outcome = if failed {
        Err((
            Some((
                response.body["exit_code"]
                    .as_i64()
                    .expect("fixture exit code"),
                String::new(),
                String::new(),
            )),
            "execution failed".into(),
        ))
    } else {
        Ok((0, String::new(), String::new(), None))
    };
    settle_exec_http_result(&mut kernel, &context, outcome).expect("durable settlement");
    kernel
}

pub fn observation_vocabulary() -> NormVocabulary {
    serde_json::from_value(json!({
        "definition": {
            "name":"local-observation", "version":"1",
            "fields": (["instance", "effect", "run", "invocation_json", "observation_json"].map(|name| json!({"name":name,"required":true,"value_type":{"type":"text"}}))),
            "status":{"values":["recorded"],"initial":"recorded","transitions":[]}
        },
        "creation":{"requires":"authority","scope":"observe.publish"}
    })).expect("valid observation vocabulary fixture")
}
