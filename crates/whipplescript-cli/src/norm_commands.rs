//! Native norm authoring and admission. The invoking host owns the process
//! environment and custody socket; neither workspace documents nor command
//! bodies may supply principal bindings or restoration trust.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::Value;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::{CredentialName, CustodyTransport};
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_kernel::norm_public_key::{NormPublicKeyBinding, NormPublicKeyVerifier};
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{
    NormAct, NormCharter, NormCheckpoint, NormPremises, NormStatement, NormVerifier,
    SignedNormEvent,
};
use whipplescript_store::norm_commands::{
    NormCommand, NormCommandHost, NormCommandRequest, NormResourcePoint,
};

#[path = "norm_commands/impact.rs"]
mod impact;

const TRUST_ENV: &str = "WHIPPLESCRIPT_NORM_TRUST";
pub(crate) const USAGE: &str = "usage: whip [--json] norm <command>\n\
  snapshot [--frontier <file>] | inventory [--frontier <file>] | export\n\
  resources <cut> [--frontier <file>]\n\
  compare-resources <before-cut> <after-cut> [--before-frontier <file>] [--after-frontier <file>]\n\
  impact <before-cut> <after-cut> [--before-frontier <file>] [--after-frontier <file>]\n\
  render <id-or-alias> [--frontier <file>] | explain <id-or-alias> [--frontier <file>]\n\
  diff --before-frontier <file> [--after-frontier <file>]\n\
  bootstrap --as <binding> --creator <principal> [--charter <file>]\n\
  create <vocabulary@version> --as <binding> --fields <file>\n\
  enqueue-observation <instance> <requirement> <cut> --effect <id> --capability <name> --as <binding> [--frontier <file>] [--deadline <seconds>]\n\
  publish-observation <instance> <run> <vocabulary@version> --as <binding> [--at <time>]\n\
  edit <id-or-alias> --as <binding> --fields <file>\n\
  transition <id-or-alias> <status> --as <binding>\n\
  retire <id-or-alias> <status> --as <binding>\n\
  rotate --as <binding> --successor <binding>\n\
  sign --as <binding> --statement <file>\n\
  cosign --as <binding> --event <file>\n\
  dispatch --request <file> | import --events <file>\n\
  provision (uses only the checkpoint in trusted host configuration)\n\
  Authoring accepts --nonce and --at; exact retries reuse signed events via dispatch.\n\
  Host configuration: WHIPPLESCRIPT_NORM_TRUST and WHIPPLESCRIPT_CUSTODIAN_SOCKET.\n\
  Impact configuration: WHIPPLESCRIPT_NORM_PLANNING and WHIPPLESCRIPT_NATIVE_NORM_RUNTIME.\n\
  Ledger: WHIPPLESCRIPT_ITEMS_STORE (defaults to .whipplescript/items.sqlite).";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trust {
    bindings: Vec<Binding>,
    creation_grants: Vec<CreationGrant>,
    #[serde(default)]
    public_bindings: Vec<NormPublicKeyBinding>,
    checkpoint: Option<NormCheckpoint>,
    /// The labeled regions of every cut the Home builds (DR-0124 §14.2):
    /// who may read a region is the Home's policy, never the build cell's.
    #[serde(default)]
    regions: Vec<super::build_scope::Region>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    name: String,
    principal: String,
    credential: CredentialName,
    version: KeyVersion,
    /// The region labels this binding's principal holds; none by default.
    #[serde(default)]
    labels: Vec<String>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum KeyVersion {
    ImmutableLocal {},
    Version { version: NonZeroU32 },
}
impl From<KeyVersion> for NormCustodyVersion {
    fn from(value: KeyVersion) -> Self {
        match value {
            KeyVersion::ImmutableLocal {} => Self::ImmutableLocal,
            KeyVersion::Version { version } => Self::Version(version),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationGrant {
    creator: String,
    owner: String,
}

struct Arguments<'a> {
    verb: &'a str,
    positional: Vec<&'a str>,
    flags: BTreeMap<&'a str, &'a str>,
}
impl<'a> Arguments<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let verb = args.first().map(String::as_str).unwrap_or("snapshot");
        let (arity, allowed): (usize, &[&str]) = match verb {
            "snapshot" | "inventory" => (0, &["--frontier"]),
            "render" | "explain" => (1, &["--frontier"]),
            "diff" => (0, &["--before-frontier", "--after-frontier"]),
            "export" | "provision" => (0, &[]),
            "resources" => (1, &["--frontier"]),
            "compare-resources" | "impact" => (2, &["--before-frontier", "--after-frontier"]),
            "dispatch" => (0, &["--request"]),
            "import" => (0, &["--events"]),
            "sign" => (0, &["--as", "--statement"]),
            "cosign" => (0, &["--as", "--event"]),
            "bootstrap" => (0, &["--as", "--creator", "--charter", "--nonce", "--at"]),
            "create" | "edit" => (
                1,
                &[
                    "--as",
                    "--fields",
                    "--family-basis",
                    "--references",
                    "--nonce",
                    "--at",
                ],
            ),
            "publish-observation" => (3, &["--as", "--at"]),
            "enqueue-observation" => (
                3,
                &[
                    "--effect",
                    "--capability",
                    "--as",
                    "--frontier",
                    "--deadline",
                ],
            ),
            "transition" | "retire" => (
                2,
                &["--as", "--family-basis", "--references", "--nonce", "--at"],
            ),
            "rotate" => (0, &["--as", "--successor", "--nonce", "--at"]),
            _ => {
                // MUTATION-SUCCESS-EXPR: Ok(Self { verb: "snapshot", positional: Vec::new(), flags: BTreeMap::new() })
                return Err(format!("unknown norm command {verb}"));
            }
        };
        let mut parsed = Self {
            verb,
            positional: Vec::new(),
            flags: BTreeMap::new(),
        };
        let mut remaining = args.iter().skip(1);
        while let Some(arg) = remaining.next() {
            if arg.starts_with("--") {
                if !allowed.contains(&arg.as_str()) || parsed.flags.contains_key(arg.as_str()) {
                    return Err(format!("unknown or repeated norm option {arg}"));
                }
                let value = remaining
                    .next()
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| format!("norm option {arg} needs a value"))?;
                parsed.flags.insert(arg, value);
            } else {
                parsed.positional.push(arg);
            }
        }
        if parsed.positional.len() != arity {
            return Err(format!("norm {verb} requires {arity} positional arguments"));
        }
        Ok(parsed)
    }
    fn required(&self, name: &str) -> Result<&str, String> {
        self.flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("norm {} requires {name}", self.verb))
    }
    fn file(&self, name: &str) -> Result<String, String> {
        std::fs::read_to_string(self.required(name)?).map_err(|error| error.to_string())
    }
    fn frontier(&self, name: &str) -> Result<Option<Vec<String>>, String> {
        if self.flags.contains_key(name) {
            serde_json::from_str(&self.file(name)?)
                .map(Some)
                .map_err(|error| error.to_string())
        } else {
            Ok(None)
        }
    }
}

pub(crate) fn command(options: &super::CliOptions) -> ExitCode {
    match execute(&options.args, &options.store_path) {
        Ok(value) => {
            if options.json {
                super::emit_json(value)
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON value")
                );
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("norm: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The host's trusted norm signers and verification roots, loaded from
/// `WHIPPLESCRIPT_NORM_TRUST`. Shared by every command that signs a norm
/// act: `norm` itself and the build engine's `build` (DR-0124 §14.6).
pub(crate) struct NormTrust<'a> {
    keys: BTreeMap<String, NormCustodyKey<'a>>,
    public_keys: Vec<NormPublicKeyVerifier>,
    creation_grants: Vec<(String, String)>,
    pub(crate) checkpoint: Option<NormCheckpoint>,
    /// The Home's label policy and the labels each binding holds.
    pub(crate) policy: super::build_scope::LabelPolicy,
    principals: BTreeMap<String, super::build_scope::Principal>,
}

/// The host's trust document, from the environment only.
pub(crate) fn trust_document() -> Result<Trust, String> {
    let trusted =
        std::env::var(TRUST_ENV).map_err(|_| format!("host must configure {TRUST_ENV}"))?;
    let trust: Trust = serde_json::from_str(&trusted).map_err(|error| error.to_string())?;
    check_binding_names(trust.bindings.iter().map(|binding| binding.name.as_str()))?;
    Ok(trust)
}

/// The custody transport the document's bindings need; none when it has no
/// bindings. The caller owns it for as long as the keys that borrow it.
pub(crate) fn custody_transport_for(
    document: &Trust,
) -> Result<Option<Box<dyn CustodyTransport>>, String> {
    if document.bindings.is_empty() {
        return Ok(None);
    }
    Ok(Some(super::custody_egress_transport()?.ok_or(
        "norm custody bindings require the configured custodian; no local checksum fallback",
    )?))
}

impl<'a> NormTrust<'a> {
    pub(crate) fn from_document(
        trust: Trust,
        transport: Option<&'a dyn CustodyTransport>,
    ) -> Result<Self, String> {
        let public_keys = trust
            .public_bindings
            .into_iter()
            .map(NormPublicKeyVerifier::new)
            .collect::<Result<Vec<_>, _>>()?;
        let policy = super::build_scope::LabelPolicy::new(trust.regions)?;
        let mut keys = BTreeMap::new();
        let mut principals = BTreeMap::new();
        for binding in trust.bindings {
            let key = NormCustodyKey::new(
                binding.principal,
                binding.credential,
                binding.version.into(),
                transport.ok_or("norm custody binding has no transport")?,
            )?;
            principals.insert(
                binding.name.clone(),
                super::build_scope::Principal {
                    name: binding.name.clone(),
                    labels: binding.labels.into_iter().collect(),
                },
            );
            keys.insert(binding.name, key);
        }
        Ok(Self {
            keys,
            public_keys,
            creation_grants: trust
                .creation_grants
                .into_iter()
                .map(|grant| (grant.creator, grant.owner))
                .collect(),
            checkpoint: trust.checkpoint,
            policy,
            principals,
        })
    }

    pub(crate) fn verifier(&self) -> Result<NormGovernanceVerifier<'_>, String> {
        NormGovernanceVerifier::new(
            self.keys
                .values()
                .map(|key| NormPrincipalBinding {
                    actor: key.actor().clone(),
                    verifier: key as &dyn whipplescript_kernel::gov::GovernanceAttestationVerifier,
                })
                .chain(self.public_keys.iter().map(|key| NormPrincipalBinding {
                    actor: key.actor().clone(),
                    verifier: key,
                }))
                .collect(),
            self.creation_grants.iter().cloned().collect(),
        )
    }

    pub(crate) fn key(&self, name: &str) -> Result<&NormCustodyKey<'a>, String> {
        self.keys
            .get(name)
            .ok_or_else(|| format!("no trusted norm binding named {name}"))
    }

    /// Every binding's principal, for an endpoint that admits them all.
    pub(crate) fn principals(&self) -> impl Iterator<Item = &super::build_scope::Principal> {
        self.principals.values()
    }

    /// The principal a binding acts as, with the labels the document grants it.
    pub(crate) fn principal(&self, name: &str) -> Result<&super::build_scope::Principal, String> {
        self.principals
            .get(name)
            .ok_or_else(|| format!("no trusted norm binding named {name}"))
    }
}

/// Binding names select signers, so an empty or repeated one is refused
/// before any key is minted.
fn check_binding_names<'a>(names: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for name in names {
        if name.trim().is_empty() || !seen.insert(name) {
            return Err("norm binding names must be nonempty and unique".into());
        }
    }
    Ok(())
}

fn execute(args: &[String], runtime_path: &std::path::Path) -> Result<Value, String> {
    let args = Arguments::parse(args)?;
    let document = trust_document()?;
    let transport = custody_transport_for(&document)?;
    let trust = NormTrust::from_document(document, transport.as_deref())?;
    let verifier = trust.verifier()?;
    let key = |name: &str| trust.key(name);
    // Signing has no store side effects and cannot import a request's binding.
    if args.verb == "sign" {
        let statement: NormStatement =
            serde_json::from_str(&args.file("--statement")?).map_err(|error| error.to_string())?;
        let signature = key(args.required("--as")?)?.sign(&statement)?;
        return serde_json::to_value(SignedNormEvent {
            statement,
            signature,
            successor_signature: None,
        })
        .map_err(|error| error.to_string());
    }
    if args.verb == "cosign" {
        let mut event: SignedNormEvent =
            serde_json::from_str(&args.file("--event")?).map_err(|error| error.to_string())?;
        verifier.verify(
            &event.statement.actor,
            &event.statement.signing_bytes().map_err(debug_error)?,
            &event.signature,
        )?;
        event.successor_signature =
            Some(key(args.required("--as")?)?.cosign_rotation(&event.statement)?);
        return serde_json::to_value(event).map_err(|error| error.to_string());
    }
    let mut store = WorkItemStore::open(super::items_store_path()).map_err(debug_error)?;
    if args.verb == "provision" {
        let checkpoint = trust
            .checkpoint
            .ok_or("host configuration has no restoration checkpoint")?;
        store
            .pin_norm_checkpoint(&checkpoint)
            .map_err(debug_error)?;
        return Ok(serde_json::json!({"checkpoint": checkpoint}));
    }
    let artifacts = |cut: &str| -> whipplescript_store::StoreResult<
        whipplescript_store::norm_artifact::CapturedArtifact,
    > {
        let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open(
            super::branch_store_path(),
            super::vcs_content_store_path(),
        )?;
        vcs.capture_norm_artifact(
            cut,
            whipplescript_store::norm_artifact::ArtifactLimits::default(),
        )
    };
    if args.verb == "impact" {
        return impact::execute(&args, &store, &verifier, runtime_path, &artifacts);
    }
    if args.verb == "enqueue-observation" {
        use whipplescript_kernel::norm_execution::{
            NormEnqueuePreparation, NormRunSelection, PreparedNormExecution,
        };
        use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
        let publisher = key(args.required("--as")?)?;
        let capability = args.required("--capability")?;
        let effect_id = args.required("--effect")?;
        let deadline = args
            .flags
            .get("--deadline")
            .map(|value| {
                value
                    .parse::<NonZeroU32>()
                    .map(NonZeroU32::get)
                    .map_err(|_| {
                        "norm enqueue deadline must be positive seconds fitting u32".to_owned()
                    })
            })
            .transpose()?;
        let frontier = args.frontier("--frontier")?;
        let view = store.norm_view(&verifier).map_err(debug_error)?;
        let history = CapturedNormHistory::capture(
            &view,
            &store.export_events().map_err(debug_error)?,
            &verifier,
            NormHistoryLimits::default(),
        )
        .map_err(debug_error)?;
        let artifact = artifacts(args.positional[2]).map_err(debug_error)?;
        let runtime = super::open_store(runtime_path)?;
        let installed = runtime
            .get_script_capability(capability)
            .map_err(debug_error)?;
        let native_host = super::norm_exec_managed::configuration().map_err(debug_error)?;
        let environment_epoch = native_host
            .as_ref()
            .map(|host| host.installed.runtime.environment.clone())
            .unwrap_or_else(super::compute_environment_hash);
        let prepared = PreparedNormExecution::prepare_enqueue(
            &runtime,
            args.positional[0],
            NormEnqueuePreparation {
                history: &history,
                verifier: &verifier,
                artifact: &artifact,
                installed: installed.as_ref(),
                capability,
                selection: NormRunSelection {
                    ledger: &view.ledger,
                    frontier: frontier.as_deref(),
                    requirement: args.positional[1],
                    effect_id,
                    publisher: &publisher.actor().principal,
                    executor_url: "whip-executor://native",
                    environment_epoch: &environment_epoch,
                },
            },
        )?;
        // A retry of the same enqueue reconstructs its original selection;
        // only a fresh effect must match the current installed host profile.
        if !runtime
            .list_effects(args.positional[0])
            .map_err(debug_error)?
            .iter()
            .any(|effect| effect.effect_id == effect_id)
        {
            super::norm_exec_managed::validate_enqueue(
                prepared.effect_input(),
                native_host.as_ref(),
            )
            .map_err(debug_error)?;
        }
        let mut kernel = whipplescript_kernel::RuntimeKernel::new(runtime);
        let acknowledged = prepared
            .enqueue(&mut kernel, args.positional[0], deadline)
            .map_err(debug_error)?;
        return Ok(serde_json::json!({
            "acknowledgment": {"event_id":acknowledged.event_id,"sequence":acknowledged.sequence},
            "effect_id":prepared.intent().effect_id,
            "anchor":prepared.intent().anchor,
            "artifact":prepared.intent().artifact,
        }));
    }
    if args.verb == "publish-observation" {
        use whipplescript_kernel::norm_execution::PreparedNormExecution;
        use whipplescript_kernel::norm_publication::{
            ObservationSigning, PreparedObservationPublication,
        };
        use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
        let signer = key(args.required("--as")?)?;
        let view = store.norm_view(&verifier).map_err(debug_error)?;
        let selector = args.positional[2];
        let entry = view
            .charter
            .vocabularies
            .iter()
            .find(|entry| {
                format!("{}@{}", entry.definition.name, entry.definition.version) == selector
            })
            .ok_or_else(|| format!("charter has no vocabulary {selector}"))?;
        let vocabulary = Vocabulary::new(entry.definition.clone())
            .map_err(|e| e.to_string())?
            .reference()
            .clone();
        let history = CapturedNormHistory::capture(
            &view,
            &store.export_events().map_err(debug_error)?,
            &verifier,
            NormHistoryLimits::default(),
        )
        .map_err(debug_error)?;
        let runtime = super::open_store(runtime_path)?;
        let execution = PreparedNormExecution::recover_with_artifacts(
            &history,
            &verifier,
            &artifacts,
            &runtime,
            args.positional[0],
            args.positional[1],
        )?;
        let created_at = args
            .flags
            .get("--at")
            .map(|value| (*value).to_owned())
            .unwrap_or_else(super::now_stamp);
        let publication = PreparedObservationPublication::prepare(
            &execution,
            &history,
            &runtime,
            &verifier,
            ObservationSigning {
                vocabulary: &vocabulary,
                authority: Some(&view.authority_head),
                actor: signer.actor(),
                created_at: &created_at,
            },
            |statement| signer.sign(statement),
        )?;
        let receipt = publication.submit(&mut store, &verifier)?;
        let acknowledged = receipt.acknowledge(&runtime)?;
        return Ok(serde_json::json!({
            "event_id": receipt.event_id(),
            "acknowledgment": {"event_id": acknowledged.event_id, "sequence": acknowledged.sequence},
            "observation": execution.observation(),
        }));
    }
    if args.verb == "dispatch" {
        let response = NormCommandHost::new(&mut store, &verifier)
            .with_artifacts(&artifacts)
            .execute_json(&args.file("--request")?)
            .map_err(debug_error)?;
        return serde_json::from_str(&response).map_err(|error| error.to_string());
    }
    let command = match args.verb {
        "snapshot" => match args.frontier("--frontier")? {
            Some(frontier) => NormCommand::SnapshotAt { frontier },
            None => NormCommand::Snapshot {},
        },
        "inventory" => match args.frontier("--frontier")? {
            Some(frontier) => NormCommand::InventoryAt { frontier },
            None => NormCommand::Inventory {},
        },
        "resources" => NormCommand::Resources {
            point: NormResourcePoint {
                cut: args.positional[0].into(),
                frontier: args.frontier("--frontier")?,
            },
        },
        "compare-resources" => NormCommand::CompareResources {
            before: NormResourcePoint {
                cut: args.positional[0].into(),
                frontier: args.frontier("--before-frontier")?,
            },
            after: NormResourcePoint {
                cut: args.positional[1].into(),
                frontier: args.frontier("--after-frontier")?,
            },
        },
        "render" | "explain" => {
            let record = store
                .resolve_norm_record(args.positional[0])
                .map_err(debug_error)?
                .ok_or("unknown norm record or alias")?;
            let frontier = args.frontier("--frontier")?;
            if args.verb == "render" {
                NormCommand::Render {
                    manifest: record,
                    frontier,
                }
            } else {
                NormCommand::Explain { record, frontier }
            }
        }
        "diff" => {
            args.required("--before-frontier")?;
            NormCommand::Diff {
                before: args.frontier("--before-frontier")?.unwrap_or_default(),
                after: args.frontier("--after-frontier")?,
            }
        }
        "export" => NormCommand::Export {},
        "import" => NormCommand::Import {
            events: serde_json::from_str(&args.file("--events")?)
                .map_err(|error| error.to_string())?,
        },
        _ => {
            let signer = key(args.required("--as")?)?;
            let action = if args.verb == "bootstrap" {
                let charter = match args.flags.get("--charter") {
                    Some(_) => serde_json::from_str(&args.file("--charter")?)
                        .map_err(|error| error.to_string())?,
                    None => NormCharter::bundled().map_err(debug_error)?,
                };
                NormAct::Bootstrap {
                    creator: args.required("--creator")?.into(),
                    charter,
                }
            } else {
                let view = store.norm_view(&verifier).map_err(debug_error)?;
                let ledger = view.ledger.clone();
                let authority = Some(view.authority_head.clone());
                match args.verb {
                    "create" => {
                        let selector = args.positional[0];
                        let entry = view
                            .charter
                            .vocabularies
                            .iter()
                            .find(|entry| {
                                format!("{}@{}", entry.definition.name, entry.definition.version)
                                    == selector
                            })
                            .ok_or_else(|| format!("charter has no vocabulary {selector}"))?;
                        NormAct::Create {
                            ledger,
                            authority,
                            vocabulary: Vocabulary::new(entry.definition.clone())
                                .map_err(|error| error.to_string())?
                                .reference()
                                .clone(),
                            fields_json: args.file("--fields")?,
                        }
                    }
                    "rotate" => NormAct::Rotate {
                        ledger,
                        previous: view.authority_head,
                        successor: key(args.required("--successor")?)?.actor().clone(),
                        frontier: view.frontier.into_iter().collect(),
                    },
                    "edit" | "transition" | "retire" => {
                        let id = store
                            .resolve_norm_record(args.positional[0])
                            .map_err(debug_error)?
                            .ok_or("unknown norm record or alias")?;
                        let record = view
                            .records
                            .get(&id)
                            .ok_or("norm alias has no verified record")?;
                        if args.verb == "edit" {
                            NormAct::Edit {
                                ledger,
                                authority,
                                vocabulary: record.vocabulary.clone(),
                                record: id,
                                previous: record.head.clone(),
                                fields_json: args.file("--fields")?,
                            }
                        } else if args.verb == "retire" {
                            let effective = view
                                .effective_records
                                .get(&id)
                                .ok_or("norm record has no active acceptance to retire")?;
                            NormAct::Retire {
                                ledger,
                                authority,
                                vocabulary: record.vocabulary.clone(),
                                record: id,
                                previous: record.head.clone(),
                                revision: effective.content_head.clone(),
                                activation: effective.head.clone(),
                                status: args.positional[1].into(),
                            }
                        } else {
                            NormAct::Transition {
                                ledger,
                                authority,
                                vocabulary: record.vocabulary.clone(),
                                record: id,
                                previous: record.head.clone(),
                                status: args.positional[1].into(),
                            }
                        }
                    }
                    _ => unreachable!("arguments validated above"),
                }
            };
            let statement = NormStatement {
                protocol: "whipplescript.norm/v1".into(),
                actor: signer.actor().clone(),
                nonce: match args.flags.get("--nonce") {
                    Some(value) => (*value).into(),
                    None => super::credential_proxy_token()?,
                },
                created_at: args
                    .flags
                    .get("--at")
                    .map(|value| (*value).into())
                    .unwrap_or_else(super::now_stamp),
                action,
                // DR-0122: an act on a relation binds the family basis the
                // caller captured from a snapshot and validated against. The
                // door refuses a moved basis; nothing here substitutes a fresh one.
                premises: match (
                    args.flags.get("--family-basis"),
                    args.flags.get("--references"),
                    args.flags.get("--inventory-frontier"),
                ) {
                    (None, None, None) => None,
                    (basis, references, frontier) => Some(NormPremises {
                        family_basis: basis.map(|basis| (*basis).into()),
                        references: references
                            .map(|list| list.split(',').map(str::to_owned).collect())
                            .unwrap_or_default(),
                        inventory_frontier: frontier
                            .map(|list| list.split(',').map(str::to_owned).collect())
                            .unwrap_or_default(),
                    }),
                },
            };
            let signature = signer.sign(&statement)?;
            let successor_signature = if args.verb == "rotate" {
                Some(key(args.required("--successor")?)?.cosign_rotation(&statement)?)
            } else {
                None
            };
            NormCommand::append(SignedNormEvent {
                statement,
                signature,
                successor_signature,
            })
        }
    };
    let response = NormCommandHost::new(&mut store, &verifier)
        .with_artifacts(&artifacts)
        .execute(NormCommandRequest::new(command))
        .map_err(debug_error)?;
    serde_json::to_value(response).map_err(|error| error.to_string())
}

fn debug_error(error: whipplescript_store::StoreError) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod query_tests {
    use super::{check_binding_names, KeyVersion};
    #[test]
    fn norm_binding_names_must_be_nonempty_and_unique() {
        assert!(check_binding_names(["owner", "worker"].into_iter()).is_ok());
        assert_eq!(
            check_binding_names(["owner", "owner"].into_iter()).unwrap_err(),
            "norm binding names must be nonempty and unique"
        );
        assert_eq!(
            check_binding_names([" "].into_iter()).unwrap_err(),
            "norm binding names must be nonempty and unique"
        );
    }
    #[test]
    fn norm_query_local_key_version_refuses_silently_ignored_options() {
        assert!(matches!(
            serde_json::from_str::<KeyVersion>(r#"{"kind":"immutable_local"}"#),
            Ok(KeyVersion::ImmutableLocal {})
        ));
        assert!(
            serde_json::from_str::<KeyVersion>(r#"{"kind":"immutable_local","version":9}"#)
                .is_err()
        );
    }
}
