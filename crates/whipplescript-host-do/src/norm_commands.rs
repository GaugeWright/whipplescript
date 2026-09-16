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
    execute_hosted_norm_command_with_artifacts(store, trusted_configuration, command, None)
}

/// The embedding additionally authorizes whole-workspace artifact reads. The
/// callback chooses the store and limits; neither is supplied by a command.
pub fn execute_hosted_norm_command_with_artifacts<S: NormCommandStore>(
    store: &mut S,
    trusted_configuration: &str,
    command: &str,
    artifacts: Option<&NormArtifactCapture<'_>>,
) -> Result<String, String> {
    let trust: HostedNormTrust =
        serde_json::from_str(trusted_configuration).map_err(|error| error.to_string())?;
    trust.with_verifier(|verifier| {
        let mut host = NormCommandHost::new(store, verifier);
        if let Some(artifacts) = artifacts {
            host = host.with_artifacts(artifacts);
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
    let checkpoint = destinations
        .get(object_id)
        .ok_or("no norm restoration checkpoint is configured for this object")?;
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
}
