//! Hosted norm commands with deployment-owned P-256 principal bindings.
//! The trust document is an embedding input, never part of a command body.

use serde::Deserialize;
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_store::norm::{NormActor, NormCheckpoint};
use whipplescript_store::norm_commands::{NormArtifactCapture, NormCommandHost, NormCommandStore};

use whipplescript_kernel::norm_public_key::{NormPublicKeyBinding, NormPublicKeyVerifier};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedNormTrust {
    bindings: Vec<NormActor>,
    creation_grants: Vec<CreationGrant>,
    #[serde(default)]
    public_bindings: Vec<NormPublicKeyBinding>,
    #[serde(default)]
    restorations: Vec<Restoration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restoration {
    object_id: String,
    checkpoint: NormCheckpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationGrant {
    creator: String,
    owner: String,
}

/// The caller has already authenticated full-ledger host access. Public SEC1
/// keys in this separately supplied configuration bind exact norm principals;
/// the product policy issuer is not implicitly a represented norm owner.
pub fn execute_hosted_norm_command<S: NormCommandStore>(
    store: &mut S,
    trusted_configuration: &str,
    command: &str,
) -> Result<String, String> {
    execute_hosted_norm_command_with_artifacts(
        store,
        trusted_configuration,
        command,
        None,
        None,
        None,
        None,
    )
}

/// The embedding additionally authorizes whole-workspace artifact reads. The
/// callback chooses the store and limits; neither is supplied by a command.
/// `gated_refs` leases the workspace's gated refs before a ledger's first
/// event lands (norm-plane §5), and `running` lists the object's running norm
/// effects for an activation to plan (§10).
pub fn execute_hosted_norm_command_with_artifacts<S: NormCommandStore>(
    store: &mut S,
    trusted_configuration: &str,
    command: &str,
    artifacts: Option<&NormArtifactCapture<'_>>,
    gated_refs: Option<&mut whipplescript_store::norm_commands::GatedRefLease<'_>>,
    running: Option<&whipplescript_store::norm_commands::NormRunningEffects<'_>>,
    deployment: Option<&whipplescript_store::norm_commands::NormDeploymentGate<'_>>,
) -> Result<String, String> {
    let trust: HostedNormTrust =
        serde_json::from_str(trusted_configuration).map_err(|error| error.to_string())?;
    trust.with_verifier(|verifier| {
        let mut host = NormCommandHost::new(store, verifier);
        if let Some(artifacts) = artifacts {
            host = host.with_artifacts(artifacts);
        }
        if let Some(gated_refs) = gated_refs {
            host = host.with_gated_refs(gated_refs);
        }
        if let Some(running) = running {
            host = host.with_running_effects(running);
        }
        if let Some(deployment) = deployment {
            host = host.with_deployment_gate(deployment);
        }
        host.execute_json(command)
            .map_err(|error| format!("norm command refused: {error:?}"))
    })
}

impl HostedNormTrust {
    fn with_verifier<T>(
        self,
        execute: impl FnOnce(&NormGovernanceVerifier<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let roots = self
            .bindings
            .into_iter()
            .map(|actor| NormPublicKeyBinding {
                public_key_hex: actor.key_id.clone(),
                actor,
            })
            .chain(self.public_bindings)
            .map(NormPublicKeyVerifier::new)
            .collect::<Result<Vec<_>, _>>()?;
        let verifier = NormGovernanceVerifier::new(
            roots
                .iter()
                .map(|verifier| NormPrincipalBinding {
                    actor: verifier.actor().clone(),
                    verifier,
                })
                .collect(),
            self.creation_grants
                .into_iter()
                .map(|grant| (grant.creator, grant.owner))
                .collect(),
        )?;
        execute(&verifier)
    }
}

#[path = "norm_commands/impact.rs"]
mod impact;
pub use impact::{
    execute_hosted_norm_impact, execute_installed_hosted_norm_impact, HostedImpactConfiguration,
};
#[path = "norm_commands/promotion.rs"]
mod promotion;
pub use promotion::execute_installed_hosted_norm_promotion;

/// The deployment's norm planning configuration for the object's in-language
/// doors onto the mainline (norm-plane §5): the trust document and the
/// installed planning premises `/host/norm/promotions` receives, without a
/// clock. Each evaluation takes its time basis and `now` from the step it runs
/// in, so the gate a door asks is the one the promotion route asks.
#[derive(Clone, Debug)]
pub struct HostedNormGate {
    pub trust: String,
    /// `planning`, `runtime`, `image_binding` and `deployed_image`, as the
    /// promotion route's deployment carries them.
    pub deployment: String,
}

impl HostedNormGate {
    /// Evaluate with the admission host this configuration installs at the
    /// step's injected clock (`now_unix_ms`), never wall time.
    pub(crate) fn with_admission_host<Sql: crate::do_store::DoSql + Clone, T>(
        &self,
        sql: &Sql,
        now_unix_ms: i64,
        evaluate: impl FnOnce(
            whipplescript_kernel::norm_admission::AdmissionHost<
                '_,
                crate::do_store::DoSqliteStore<Sql>,
            >,
        ) -> Result<T, String>,
    ) -> Result<T, String> {
        let deployment = impact::Deployment::at_step(&self.deployment, now_unix_ms)?;
        promotion::with_admission_host(sql, &self.trust, &deployment, evaluate)
    }
}

/// The object's deployment gate (norm-plane §10): the gate the promotion
/// route builds, at `now_unix_ms`, judging a deployment over the ledger its
/// command door captured. A configuration that cannot build a host refuses
/// the deployment, naming why, rather than admitting it unjudged.
pub fn hosted_deployment_gate<'a, Sql: crate::do_store::DoSql + Clone>(
    gate: &'a HostedNormGate,
    sql: &'a Sql,
    now_unix_ms: i64,
    artifacts: &'a NormArtifactCapture<'a>,
) -> impl Fn(
    &whipplescript_store::norm::NormView,
    &[whipplescript_store::items::TrackerEvent],
    &str,
    &[String],
) -> whipplescript_store::StoreResult<Result<(), whipplescript_store::vcs::GateRefusal>>
       + 'a {
    use whipplescript_kernel::norm_admission::{judge_deployment, CapturedLedger};
    move |view, events, release, cuts| {
        let judged = gate.with_admission_host(sql, now_unix_ms, |host| {
            judge_deployment(
                host,
                CapturedLedger { view, events },
                release,
                cuts,
                artifacts,
            )
            .map_err(|error| format!("{error:?}"))
        });
        Ok(judged.unwrap_or_else(|reason| {
            Err(whipplescript_store::vcs::GateRefusal {
                reason: format!(
                    "the deployment's gated requirements cannot be evaluated: {reason}"
                ),
                detail: serde_json::Value::Null,
            })
        }))
    }
}

const ENQUEUE_PROTOCOL: &str = "whipplescript.norm.enqueue/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnqueueRequest {
    protocol: String,
    command: EnqueueCommand,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnqueueCommand {
    instance: String,
    requirement: String,
    cut: String,
    effect: String,
    capability: String,
    publisher: String,
    frontier: Option<Vec<String>>,
    deadline_seconds: Option<std::num::NonZeroU32>,
}

/// Authenticated enqueue using only deployment-owned sources and executor
/// configuration. The caller retains scheduling responsibility after admission.
pub fn execute_hosted_norm_enqueue<S: NormCommandStore + whipplescript_store::RuntimeStore>(
    kernel: &mut whipplescript_kernel::RuntimeKernel<S>,
    trusted_configuration: &str,
    command: &str,
    artifacts: &NormArtifactCapture<'_>,
    executor_url: &str,
    environment_epoch: &str,
    norm_runtime: Option<&str>,
) -> Result<String, String> {
    use whipplescript_kernel::norm_execution::{
        NormEnqueuePreparation, NormRunSelection, PreparedNormExecution,
    };
    use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
    let norm_runtime = norm_runtime.map(crate::norm_runtime::parse).transpose()?;
    let environment_epoch = norm_runtime
        .as_ref()
        .map(|runtime| runtime.environment.as_str())
        .unwrap_or(environment_epoch);
    let request: EnqueueRequest = serde_json::from_str(command).map_err(|e| e.to_string())?;
    if request.protocol != ENQUEUE_PROTOCOL {
        return Err("unsupported norm enqueue protocol".into());
    }
    let trust: HostedNormTrust =
        serde_json::from_str(trusted_configuration).map_err(|e| e.to_string())?;
    let request = request.command;
    let known_publisher = trust
        .bindings
        .iter()
        .any(|actor| actor.principal == request.publisher)
        || trust
            .public_bindings
            .iter()
            .any(|binding| binding.actor.principal == request.publisher);
    if !known_publisher {
        return Err("norm enqueue publisher has no deployment binding".into());
    }
    trust.with_verifier(|verifier| {
        let current = kernel
            .store()
            .norm_state(verifier)
            .map_err(|e| format!("{e:?}"))?;
        let history = CapturedNormHistory::capture(
            &current,
            &kernel
                .store()
                .tracker_history()
                .map_err(|e| format!("{e:?}"))?,
            verifier,
            NormHistoryLimits::default(),
        )
        .map_err(|e| format!("{e:?}"))?;
        let artifact = artifacts(&request.cut).map_err(|e| format!("{e:?}"))?;
        let installed = kernel
            .store()
            .get_script_capability(&request.capability)
            .map_err(|e| format!("{e:?}"))?;
        let prepared = PreparedNormExecution::prepare_enqueue(
            kernel.store(),
            &request.instance,
            NormEnqueuePreparation {
                history: &history,
                verifier,
                artifact: &artifact,
                installed: installed.as_ref(),
                capability: &request.capability,
                selection: NormRunSelection {
                    ledger: &current.ledger,
                    frontier: request.frontier.as_deref(),
                    requirement: &request.requirement,
                    effect_id: &request.effect,
                    publisher: &request.publisher,
                    executor_url,
                    environment_epoch,
                },
            },
        )?;
        let fresh = !kernel
            .store()
            .list_effects(&request.instance)
            .map_err(|e| format!("{e:?}"))?
            .iter()
            .any(|effect| effect.effect_id == request.effect);
        if fresh {
            crate::norm_runtime::validate(prepared.effect_input(), norm_runtime.as_ref())?;
        }
        let acknowledged = prepared
            .enqueue(
                kernel,
                &request.instance,
                request.deadline_seconds.map(std::num::NonZeroU32::get),
            )
            .map_err(|e| format!("{e:?}"))?;
        serde_json::to_string(&serde_json::json!({"protocol":ENQUEUE_PROTOCOL,"result":{
            "acknowledgment":{"event_id":acknowledged.event_id,"sequence":acknowledged.sequence},
            "effect_id":prepared.intent().effect_id,"anchor":prepared.intent().anchor,
            "artifact":prepared.intent().artifact,
        }}))
        .map_err(|e| e.to_string())
    })
}

const PUBLICATION_PROTOCOL: &str = "whipplescript.norm.publication/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRequest {
    protocol: String,
    command: PublicationCommand,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PublicationCommand {
    Prepare {
        instance: String,
        run: String,
        vocabulary: String,
        actor: NormActor,
        created_at: String,
    },
    Publish {
        instance: String,
        run: String,
        event: Box<whipplescript_store::norm::SignedNormEvent>,
    },
}

/// Authenticated whole-ledger/workspace host operation. The deployment supplies
/// verification bindings and artifact access; the client supplies no trust.
pub fn execute_hosted_norm_publication<
    S: NormCommandStore + whipplescript_store::norm_publication::NormPublicationJournal,
>(
    store: &mut S,
    trusted_configuration: &str,
    command: &str,
    artifacts: &NormArtifactCapture<'_>,
) -> Result<String, String> {
    use whipplescript_core::vocabulary::Vocabulary;
    use whipplescript_kernel::norm_execution::PreparedNormExecution;
    use whipplescript_kernel::norm_publication::{
        ObservationSigning, PreparedObservationPublication,
    };
    use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
    let request: PublicationRequest = serde_json::from_str(command).map_err(|e| e.to_string())?;
    if request.protocol != PUBLICATION_PROTOCOL {
        return Err("unsupported norm publication protocol".into());
    }
    let trust: HostedNormTrust =
        serde_json::from_str(trusted_configuration).map_err(|e| e.to_string())?;
    trust.with_verifier(|verifier| {
        let current = store.norm_state(verifier).map_err(|e| format!("{e:?}"))?;
        let history = CapturedNormHistory::capture(&current, &store.tracker_history().map_err(|e| format!("{e:?}"))?, verifier, NormHistoryLimits::default()).map_err(|e| format!("{e:?}"))?;
        let (instance, run) = match &request.command {
            PublicationCommand::Prepare { instance, run, .. } | PublicationCommand::Publish { instance, run, .. } => (instance, run),
        };
        let execution = PreparedNormExecution::recover_with_artifacts(&history, verifier, artifacts, store, instance, run)?;
        let result = match request.command {
            PublicationCommand::Prepare { vocabulary, actor, created_at, .. } => {
                let entry = current.charter.vocabularies.iter().find(|entry| format!("{}@{}", entry.definition.name, entry.definition.version) == vocabulary).ok_or_else(|| format!("charter has no vocabulary {vocabulary}"))?;
                let vocabulary = Vocabulary::new(entry.definition.clone()).map_err(|e| e.to_string())?.reference().clone();
                serde_json::to_value(PreparedObservationPublication::draft(&execution,
&history, store, verifier, ObservationSigning { vocabulary: &vocabulary, authority: Some(&current.authority_head), actor:&actor, created_at:&created_at })?).map_err(|e| e.to_string())?
            }
            PublicationCommand::Publish { event, .. } => {
                let publication = PreparedObservationPublication::prepare_signed(&execution,
&history, store, verifier, &event)?;
                let receipt = publication.submit(store, verifier)?;
                let acknowledged = receipt.acknowledge(store)?;
                serde_json::json!({"event_id":receipt.event_id(), "acknowledgment":{"event_id":acknowledged.event_id,"sequence":acknowledged.sequence}, "observation":execution.observation()})
            }
        };
        serde_json::to_string(&serde_json::json!({"protocol":PUBLICATION_PROTOCOL,"result":result})).map_err(|e| e.to_string())
    })
}

/// Install only a deployment-configured checkpoint for this actual DO identity.
/// This administrative operation is separate from the norm command protocol;
/// imported history and HTTP request fields cannot select restoration trust.
pub fn provision_hosted_norm<D: crate::do_store::DoSql>(
    store: &mut crate::do_store::DoSqliteStore<D>,
    object_id: &str,
    trusted_configuration: &str,
    request: &str,
) -> Result<String, String> {
    let request: std::collections::BTreeMap<String, serde::de::IgnoredAny> =
        serde_json::from_str(request).map_err(|error| error.to_string())?;
    if !request.is_empty() {
        return Err("norm provisioning request must be an empty object".into());
    }
    let trust: HostedNormTrust =
        serde_json::from_str(trusted_configuration).map_err(|error| error.to_string())?;
    let mut destinations = std::collections::BTreeMap::new();
    for restoration in trust.restorations {
        let repeated = destinations
            .insert(restoration.object_id, restoration.checkpoint)
            .is_some();
        if repeated {
            return Err("norm restoration configuration repeats an object identity".into());
        }
    }
    // The refusal names the object, since its id is how an operator writes
    // the restoration that provisions it, and nothing else reports it.
    let checkpoint = destinations.get(object_id).ok_or_else(|| {
        format!("no norm restoration checkpoint is configured for object {object_id}")
    })?;
    store
        .pin_norm_checkpoint(checkpoint)
        .map_err(|error| format!("norm provisioning refused: {error:?}"))?;
    serde_json::to_string(&serde_json::json!({"checkpoint": checkpoint}))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn norm_hosted_provision_uses_only_the_exact_configured_destination() {
        let checkpoint = NormCheckpoint {
            ledger: "a".repeat(64),
            authority_head: "b".repeat(64),
        };
        let entry = json!({"object_id":"destination", "checkpoint":checkpoint});
        let configuration = |entries: Vec<serde_json::Value>| {
            json!({
                "bindings":[], "creation_grants":[], "restorations":entries,
            })
            .to_string()
        };
        let valid = configuration(vec![entry.clone()]);
        let mut store = crate::do_store::test_support::store();
        for body in [
            r#"{"checkpoint":{}}"#,
            r#"{"object_id":"destination"}"#,
            "[]",
            "null",
            "{} {}",
        ] {
            assert!(provision_hosted_norm(&mut store, "destination", &valid, body).is_err());
            assert_eq!(store.norm_checkpoint().unwrap(), None);
        }
        assert_eq!(
            provision_hosted_norm(&mut store, "another-object", &valid, "{}").unwrap_err(),
            "no norm restoration checkpoint is configured for object another-object",
            "an unconfigured object is refused naming its id"
        );
        for (object, config) in [
            ("another-object", valid.clone()),
            ("destination", configuration(vec![])),
            ("destination", configuration(vec![entry.clone(), entry])),
        ] {
            assert!(provision_hosted_norm(&mut store, object, &config, "{}").is_err());
            assert_eq!(store.norm_checkpoint().unwrap(), None);
        }
        let response = provision_hosted_norm(&mut store, "destination", &valid, "{}").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap(),
            json!({"checkpoint":checkpoint})
        );
        assert_eq!(store.norm_checkpoint().unwrap(), Some(checkpoint.clone()));
        assert!(provision_hosted_norm(&mut store, "destination", &valid, "{}").is_ok());
        let rollback = configuration(vec![json!({"object_id":"destination", "checkpoint": {
            "ledger":checkpoint.ledger,"authority_head":checkpoint.ledger,
        }})]);
        assert!(provision_hosted_norm(&mut store, "destination", &rollback, "{}").is_err());
        assert_eq!(store.norm_checkpoint().unwrap(), Some(checkpoint));
        assert!(
            store.export_events().unwrap().is_empty(),
            "a pin does not fabricate evidence"
        );
    }

    /// NC-01 on the hosted command route: a request cannot carry host
    /// configuration. Bindings, creation grants and a restoration checkpoint
    /// in a command body are refused before anything is admitted.
    #[test]
    fn norm_hosted_commands_refuse_request_supplied_host_configuration() {
        let trust = json!({"bindings":[], "creation_grants":[]}).to_string();
        let mut store = crate::do_store::test_support::store();
        for injected in [
            json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"snapshot"},
                "creation_grants":[{"creator":"worker","owner":"owner"}]}),
            json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"snapshot"},
                "bindings":[]}),
            json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"import","events":[],
                "checkpoint":{"ledger":"a".repeat(64),"authority_head":"a".repeat(64)}}}),
        ] {
            let refused = execute_hosted_norm_command(&mut store, &trust, &injected.to_string());
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|error| error.contains("unknown field")),
                "{injected}: {refused:?}"
            );
        }
        assert_eq!(store.norm_checkpoint().unwrap(), None);
        assert!(store.export_events().unwrap().is_empty());
    }

    // --- the production norm-ledger canary ----------------------------------
    //
    // `worker/scripts/production-wiring-canary.mjs#norm-ledger` signs nothing:
    // it forwards one stable signed act and the host's retained observation,
    // and every other body it sends is built by `normLedgerRequests`, which the
    // runner's own test pins to this vector. These tests are the Rust half: the
    // bodies decode at the real doors, the refusals it expects are refused for
    // the reason it names, and re-appending an act the ledger holds is the same
    // receipt even after the ledger moved. That last is what makes a re-run of
    // the canary an exact retry rather than new history.

    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use serde_json::Value;
    use whipplescript_store::norm::{NormStatement, SignedNormEvent};

    const CANARY_REQUESTS: &str =
        include_str!("../worker/scripts/fixtures/norm-ledger-canary-requests.json");
    const CANARY_OBJECT: &str = "norm-ledger-canary-object";

    fn canary_vector() -> Value {
        let vector: Value = serde_json::from_str(CANARY_REQUESTS).expect("canary vector");
        assert_eq!(
            vector["protocol"],
            "whipplescript.production-canary.norm-ledger-requests/v1"
        );
        vector
    }

    fn canary_actor(principal: &str, key: &SigningKey) -> Value {
        json!({"principal":principal,"algorithm":"p256-sha256","key_id":hex::encode(
            key.verifying_key().as_affine().to_sec1_point(false).as_bytes(),
        )})
    }

    /// Signed the way the Rust signer that provisions the ledger signs.
    fn canary_signed(actor: &Value, key: &SigningKey, nonce: &str, action: Value) -> Value {
        let statement: NormStatement = serde_json::from_value(json!({
            "protocol":"whipplescript.norm/v1","actor":actor,"nonce":nonce,
            "created_at":"2026-09-28T00:00:00Z","action":action,
        }))
        .expect("statement");
        let signature: Signature = key.sign(&statement.signing_bytes().expect("bytes"));
        json!({"statement":statement,"signature":hex::encode(signature.to_bytes())})
    }

    fn event_id(event: &Value) -> String {
        serde_json::from_value::<SignedNormEvent>(event.clone())
            .expect("signed event")
            .tracker_event()
            .expect("tracker event")
            .event_id
    }

    /// The request with `event` in place of the vector's `null`: the runner
    /// forwards a signed event verbatim inside exactly this envelope.
    fn carrying(request: &Value, event: &Value) -> String {
        let mut request = request.clone();
        assert_eq!(request["command"]["event"], Value::Null);
        request["command"]["event"] = event.clone();
        request.to_string()
    }

    /// A synthetic ledger as provisioning leaves it: an owner-signed genesis
    /// with a vocabulary the worker may create under, the deployment's trust
    /// binding owner, worker and the vector's publisher, and a restoration for
    /// this object at the genesis checkpoint.
    struct CanaryLedger {
        sql: crate::do_store::test_support::RusqliteDoSql,
        trust: String,
        genesis: Value,
        worker: (Value, SigningKey),
        vocabulary: Value,
    }

    impl CanaryLedger {
        fn provisioned(vector: &Value) -> Self {
            let (owner_key, worker_key) = (
                SigningKey::from_slice(&[3; 32]).unwrap(),
                SigningKey::from_slice(&[5; 32]).unwrap(),
            );
            let owner = canary_actor("canary-owner", &owner_key);
            let worker = canary_actor("canary-worker", &worker_key);
            let charter = json!({"vocabularies":[{
                "definition":{"name":"canary-note","version":"1",
                    "fields":[{"name":"title","required":true,"value_type":{"type":"text"}}],
                    "status":{"values":["draft"],"initial":"draft","transitions":[]}},
                "creation":{"requires":"public"},"editing":{"requires":"public"},
            }],"owner_scopes":[]});
            let definition =
                serde_json::from_value(charter["vocabularies"][0]["definition"].clone())
                    .expect("definition");
            let vocabulary = serde_json::to_value(
                whipplescript_core::vocabulary::Vocabulary::new(definition)
                    .expect("vocabulary")
                    .reference(),
            )
            .unwrap();
            let genesis = canary_signed(
                &owner,
                &owner_key,
                "production-norm-ledger-canary:genesis:v1",
                json!({"act":"bootstrap","creator":"canary-worker","charter":charter}),
            );
            let ledger = event_id(&genesis);
            let trust = json!({
                "bindings":[owner, worker, vector["workspace"]["publisher"]],
                "creation_grants":[{"creator":"canary-worker","owner":"canary-owner"}],
                "restorations":[{"object_id":CANARY_OBJECT,
                    "checkpoint":{"ledger":ledger,"authority_head":ledger}}],
            })
            .to_string();
            let hosted = Self {
                sql: crate::do_store::test_support::RusqliteDoSql::from_store_schema(),
                trust,
                genesis,
                worker: (worker, worker_key),
                vocabulary,
            };
            let append = json!({"protocol":"whipplescript.norm.commands/v1",
                "command":{"kind":"append","event":hosted.genesis}});
            hosted.command(&append.to_string()).expect("genesis");
            hosted
        }

        fn store(
            &self,
        ) -> crate::do_store::DoSqliteStore<crate::do_store::test_support::RusqliteDoSql> {
            crate::do_store::DoSqliteStore::new(self.sql.clone())
        }

        fn command(&self, body: &str) -> Result<String, String> {
            execute_hosted_norm_command(&mut self.store(), &self.trust, body)
        }

        fn provision(&self, body: &Value) -> Result<String, String> {
            provision_hosted_norm(
                &mut self.store(),
                CANARY_OBJECT,
                &self.trust,
                &body.to_string(),
            )
        }

        /// One more worker record: the ledger moving between two canary runs.
        fn advance(&self, nonce: &str) -> String {
            let (worker, key) = &self.worker;
            let record = canary_signed(
                worker,
                key,
                nonce,
                json!({"act":"create","ledger":event_id(&self.genesis),
                    "vocabulary":self.vocabulary,"fields_json":r#"{"title":"moved"}"#}),
            );
            self.command(
                &json!({"protocol":"whipplescript.norm.commands/v1",
                    "command":{"kind":"append","event":record}})
                .to_string(),
            )
            .expect("advance")
        }

        /// The ledger's event ids, sorted: export orders concurrent acts
        /// canonically rather than by arrival, and the claim is about the set.
        fn history(&self) -> Vec<String> {
            let exported: Value = serde_json::from_str(
                &self
                    .command(&canary_vector()["requests"]["export"].to_string())
                    .expect("export"),
            )
            .unwrap();
            exported["result"]["events"]
                .as_array()
                .expect("events")
                .iter()
                .map(|event| event["event_id"].as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        }
    }

    /// The deployment premises the planning doors are installed with.
    fn canary_deployment() -> String {
        let runtime = json!({
            "engine":{"kind":"cpython3147_wasi","artifact_path":"/opt/reactor.wasm",
                "artifact_sha256":"a".repeat(64)},
            "executable":"/usr/local/bin/whip","python_version":"3.14.7","environment":"epoch",
        });
        let image = format!("sha256:{}", "c".repeat(64));
        json!({
            "planning":json!({"capability":"observer","roles":[]}).to_string(),
            "runtime":runtime.to_string(),
            "deployed_image":image,
            "image_binding":json!({"protocol":"whipplescript.exec.runtime-image/v1",
                "image_id":image,"runtime":runtime}).to_string(),
            "time_basis":"hosted-impact/0/canary",
            "now":"2026-09-28T00:00:00Z",
        })
        .to_string()
    }

    /// What serde and the protocol checks say when a body does not decode.
    const UNDECODED: [&str; 7] = [
        "unknown field",
        "missing field",
        "invalid type",
        "unknown variant",
        "EOF while parsing",
        "trailing characters",
        "protocol",
    ];

    fn assert_decoded(door: &str, answer: &Result<String, String>) {
        if let Err(error) = answer {
            assert!(
                !UNDECODED.iter().any(|marker| error.contains(marker)),
                "{door}: the canary's request did not decode: {error}"
            );
        }
    }

    /// The same request with a field the door does not know: the control that
    /// shows `assert_decoded` would have seen a decoding failure at this door.
    fn with_unknown_field(request: &Value) -> String {
        let mut request = request.clone();
        request["command"]["canary_unexpected"] = json!(true);
        request.to_string()
    }

    #[test]
    fn norm_ledger_canary_requests_decode_at_every_hosted_door() {
        let vector = canary_vector();
        let requests = &vector["requests"];
        let refused = &requests["refused"];
        let ledger = CanaryLedger::provisioned(&vector);
        let deployment = canary_deployment();
        let sql = ledger.sql.clone();
        let artifacts = |cut: &str| {
            crate::do_branches::compose_vcs(&sql)?.capture_norm_artifact(
                cut,
                whipplescript_store::norm_artifact::ArtifactLimits::default(),
            )
        };
        let unknown = |door: &str, answer: Result<String, String>| {
            assert!(
                answer
                    .as_ref()
                    .is_err_and(|error| error.contains("unknown field")),
                "{door}: an unknown field was not refused as one: {answer:?}"
            );
        };

        // Commands and provision, which answer outright on this ledger.
        assert!(ledger.command(&requests["export"].to_string()).is_ok());
        assert!(ledger
            .command(&carrying(&requests["append"], &ledger.genesis))
            .is_ok());
        unknown(
            "commands",
            ledger.command(&with_unknown_field(&requests["export"])),
        );
        unknown("commands", ledger.command(&refused["commands"].to_string()));
        assert!(ledger.provision(&requests["provision"]).is_ok());
        assert!(ledger
            .provision(&refused["provision"])
            .is_err_and(|error| error.contains("must be an empty object")));

        // Impacts: past the installed deployment, into the request.
        let impact = |body: String| {
            execute_installed_hosted_norm_impact(
                &ledger.store(),
                &ledger.trust,
                &body,
                &artifacts,
                &deployment,
            )
        };
        assert_decoded("impacts", &impact(requests["impact"].to_string()));
        unknown("impacts", impact(with_unknown_field(&requests["impact"])));
        unknown("impacts", impact(refused["impact"].to_string()));

        // Enqueues: the publisher the vector names is bound; the refusal's is not.
        let enqueue = |body: String| {
            execute_hosted_norm_enqueue(
                &mut whipplescript_kernel::RuntimeKernel::new(ledger.store()),
                &ledger.trust,
                &body,
                &artifacts,
                "https://executor.invalid",
                "epoch",
                None,
            )
        };
        assert_decoded("enqueues", &enqueue(requests["enqueue"].to_string()));
        unknown(
            "enqueues",
            enqueue(with_unknown_field(&requests["enqueue"])),
        );
        assert!(enqueue(refused["enqueue"].to_string())
            .is_err_and(|error| error.contains("deployment binding")));

        // Publications: prepare, and publish around a signed event.
        let publication = |body: String| {
            execute_hosted_norm_publication(&mut ledger.store(), &ledger.trust, &body, &artifacts)
        };
        assert_decoded(
            "publications",
            &publication(requests["prepare"].to_string()),
        );
        unknown(
            "publications",
            publication(with_unknown_field(&requests["prepare"])),
        );
        let publish = carrying(&requests["publish"], &ledger.genesis);
        assert_decoded("publications", &publication(publish));
        let mut forged = ledger.genesis.clone();
        forged["signature"] = json!("invalid");
        assert_decoded(
            "publications",
            &publication(carrying(&refused["publish"], &forged)),
        );

        // Promotions.
        let promotion = |body: String| {
            execute_installed_hosted_norm_promotion(&sql, &ledger.trust, &body, &deployment)
        };
        assert_decoded("promotions", &promotion(requests["promotion"].to_string()));
        unknown(
            "promotions",
            promotion(with_unknown_field(&requests["promotion"])),
        );
        unknown("promotions", promotion(refused["promotion"].to_string()));

        // None of it appended anything but the genesis the ledger began with.
        assert_eq!(ledger.history(), vec![event_id(&ledger.genesis)]);
    }

    #[test]
    fn norm_ledger_canary_retry_of_a_held_act_is_the_same_receipt() {
        let vector = canary_vector();
        let requests = &vector["requests"];
        let ledger = CanaryLedger::provisioned(&vector);
        let genesis = event_id(&ledger.genesis);
        ledger.advance("provisioned-record");

        // The canary's stable act, first run: admitted once, retried the same.
        let (worker, key) = &ledger.worker;
        let act = canary_signed(
            worker,
            key,
            "production-norm-ledger-canary:act:v1",
            json!({"act":"create","ledger":genesis,"vocabulary":ledger.vocabulary,
                "fields_json":r#"{"title":"canary"}"#}),
        );
        let provisioned = ledger.provision(&requests["provision"]).expect("provision");
        let appended = ledger
            .command(&carrying(&requests["append"], &act))
            .expect("append");
        assert_eq!(
            ledger.command(&carrying(&requests["append"], &act)),
            Ok(appended.clone())
        );
        let after_first_run = ledger.history();
        assert_eq!(after_first_run.len(), 3);

        // The ledger moves between runs. The next run re-provisions, and
        // re-appends the same act and the genesis: each is its first receipt,
        // and the history gains nothing but what moved it.
        let moved = ledger.advance("between-runs");
        assert_eq!(
            ledger.provision(&requests["provision"]),
            Ok(provisioned.clone())
        );
        assert_eq!(
            ledger.command(&carrying(&requests["append"], &act)),
            Ok(appended)
        );
        let genesis_receipt = ledger
            .command(&carrying(&requests["append"], &ledger.genesis))
            .expect("genesis retry");
        assert_eq!(
            serde_json::from_str::<Value>(&genesis_receipt).unwrap()["result"]["event_id"],
            genesis.as_str()
        );
        let mut expected = after_first_run;
        expected.push(
            serde_json::from_str::<Value>(&moved).unwrap()["result"]["event_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        expected.sort();
        assert_eq!(ledger.history(), expected);
        assert_eq!(
            serde_json::from_str::<Value>(&provisioned).unwrap()["checkpoint"]["ledger"],
            genesis.as_str()
        );

        // The runner's forged copy of the act is refused and appends nothing.
        let mut forged = act.clone();
        forged["signature"] = json!("00");
        assert!(ledger
            .command(&carrying(&requests["refused"]["append"], &forged))
            .is_err());
        assert_eq!(ledger.history(), expected);
    }
}
