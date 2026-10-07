//! Governed host actions through the Durable Object's Worker transport (HA-5).
//!
//! The native embedding and the DO share one public kernel API for action
//! admission, ordinary execution and result reads (`spec/host-actions.md`).
//! This module is the hosted adapter's half of that API: it binds a command's
//! proof to an authority key the deployment pins, never to a key the request
//! names, and it executes only the exact program the recorded admission names.
//!
//! The functions are generic over the store so the same code runs over the
//! Worker's `DoSqlBridge` in production and over real SQLite in these tests.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use whipplescript_kernel::host_action::CompiledHostAction;
use whipplescript_kernel::host_facade::GovernedHostFacade;
use whipplescript_kernel::host_protocol::action::{ActionAdmissionVerifier, HostActionCommand};
use whipplescript_kernel::host_protocol::action_result::{ActionResultVerifier, ReadActionResult};
use whipplescript_kernel::host_protocol::ProtocolError;
use whipplescript_store::coordination::Coordination;
use whipplescript_store::items::WorkItems;
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::vcs::FrontierRead;
use whipplescript_store::RuntimeStore;

/// The only proof algorithm a hosted action authority may be pinned with.
pub const ACTION_PROOF_ALGORITHM: &str = "p256-sha256";

/// The deployment's pinned action authorities: which P-256 keys may sign a
/// command or a result read on behalf of which authority. It comes from a
/// Worker binding, so a request can neither add a key nor choose one.
#[derive(Clone, Debug)]
pub struct HostedActionTrust {
    bindings: Vec<ActionTrustBinding>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionTrustDocument {
    bindings: Vec<ActionTrustBinding>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionTrustBinding {
    authority: String,
    algorithm: String,
    key_id: String,
}

impl HostedActionTrust {
    pub fn parse(json: &str) -> Result<Self, String> {
        let document: ActionTrustDocument = serde_json::from_str(json)
            .map_err(|error| format!("action trust is not a trust document: {error}"))?;
        if document.bindings.is_empty() {
            return Err("action trust pins no authority".to_owned());
        }
        for binding in &document.bindings {
            if binding.authority.trim().is_empty() {
                return Err("action trust binding names no authority".to_owned());
            }
            if binding.algorithm != ACTION_PROOF_ALGORITHM {
                return Err(format!(
                    "action trust binding for `{}` uses unsupported algorithm `{}`",
                    binding.authority, binding.algorithm
                ));
            }
            let key = hex::decode(&binding.key_id)
                .map_err(|_| format!("action trust key for `{}` is not hex", binding.authority))?;
            VerifyingKey::from_sec1_bytes(&key).map_err(|_| {
                format!(
                    "action trust key for `{}` is not a P-256 point",
                    binding.authority
                )
            })?;
        }
        Ok(Self {
            bindings: document.bindings,
        })
    }

    /// A proof is the hex of a raw P-256 signature over the exact signing
    /// bytes. It verifies only under a key pinned for this authority; a valid
    /// signature by another authority's key is not standing.
    fn verify_for(
        &self,
        authority: &str,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        let signature = std::str::from_utf8(proof)
            .ok()
            .and_then(|text| hex::decode(text).ok())
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or(ProtocolError::Invalid(
                "action proof is not a hex P-256 signature",
            ))?;
        let verified = self
            .bindings
            .iter()
            .filter(|binding| binding.authority == authority)
            .filter_map(|binding| hex::decode(&binding.key_id).ok())
            .filter_map(|key| VerifyingKey::from_sec1_bytes(&key).ok())
            .any(|key| key.verify(signing_bytes, &signature).is_ok());
        if !verified {
            return Err(ProtocolError::Mismatch(
                "action proof is not signed by a key pinned for its authority",
            ));
        }
        Ok(())
    }
}

impl ActionAdmissionVerifier for HostedActionTrust {
    fn verify(
        &self,
        command: &HostActionCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        self.verify_for(&command.issuer, signing_bytes, proof)
    }
}

impl ActionResultVerifier for HostedActionTrust {
    fn verify(
        &self,
        request: &ReadActionResult,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        // V1 reads under the original issuer; V2 names its current read
        // authority, and the signing bytes already bind which one it is.
        let authority = request.read_authority.as_deref().unwrap_or(&request.issuer);
        self.verify_for(authority, signing_bytes, proof)
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

/// The immutable identity a caller signs into its command. Pure: it compiles
/// the source and reads nothing from any store.
pub fn action_identity(operation: &str, source: &str) -> Result<String, String> {
    let action = CompiledHostAction::compile(operation, source, None)?;
    json(&serde_json::json!({
        "operation": operation,
        "program_version_ref": action.version_ref(),
        "input_schema_ref": action.input_schema_ref(),
    }))
}

/// The exact bytes a proof signs, hex-encoded, for a `command` or a `read`.
/// Pure: a caller can sign without reimplementing the canonical encoding.
pub fn signing_bytes_hex(kind: &str, body: &str) -> Result<String, String> {
    let bytes = match kind {
        "command" => serde_json::from_str::<HostActionCommand>(body)
            .map_err(|error| error.to_string())?
            .signing_bytes(),
        "read" => serde_json::from_str::<ReadActionResult>(body)
            .map_err(|error| error.to_string())?
            .signing_bytes(),
        _ => return Err(format!("unknown action signing kind `{kind}`")),
    }
    .map_err(|error| error.to_string())?;
    Ok(hex::encode(bytes))
}

/// Admit one signed action command. A duplicate delivery of the same command
/// returns the original receipt and appends nothing.
pub fn admit<S: RuntimeStore + LogAppend>(
    facade: &mut GovernedHostFacade<S>,
    trust: &HostedActionTrust,
    command: &str,
    source: &str,
    proof: &str,
) -> Result<String, String> {
    let command: HostActionCommand =
        serde_json::from_str(command).map_err(|error| error.to_string())?;
    let action = CompiledHostAction::compile(&command.operation, source, None)?;
    let receipt = facade
        .admit_action(command, &action, trust, proof.as_bytes())
        .map_err(|error| error.to_string())?;
    json(&receipt)
}

#[derive(Deserialize)]
struct RecordedCommand {
    command: HostActionCommand,
}

/// Run the ordinary rule pass for an admitted action. The program must be the
/// one the recorded admission names; a terminal action is not stepped again,
/// so a retried execute after an interruption appends nothing.
pub fn execute<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    facade: &mut GovernedHostFacade<S>,
    instance_ref: &str,
    source: &str,
) -> Result<String, String> {
    let store = facade.kernel().store();
    let admitted = store
        .list_events(instance_ref)
        .map_err(|error| format!("{error:?}"))?
        .into_iter()
        .find(|event| event.event_type == "host.action.admitted" && event.source == "host-runtime")
        .ok_or_else(|| format!("no admitted action `{instance_ref}`"))?;
    let recorded: RecordedCommand =
        serde_json::from_str(&admitted.payload_json).map_err(|error| error.to_string())?;
    let action = CompiledHostAction::compile(&recorded.command.operation, source, None)?;
    if action.version_ref() != recorded.command.program_version_ref {
        return Err("action program differs from the admitted program".to_owned());
    }
    let status = |facade: &GovernedHostFacade<S>| -> Result<String, String> {
        facade
            .kernel()
            .store()
            .get_instance(instance_ref)
            .map_err(|error| format!("{error:?}"))?
            .map(|instance| instance.status)
            .ok_or_else(|| format!("no admitted action `{instance_ref}`"))
    };
    if status(facade)? == "running" {
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            instance_ref,
            action.program(),
            None,
            None,
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    json(&serde_json::json!({
        "instance_ref": instance_ref,
        "status": status(facade)?,
    }))
}

/// Read recorded action evidence under a current, separately signed read.
pub fn read_result<S: RuntimeStore + LogAppend>(
    facade: &GovernedHostFacade<S>,
    trust: &HostedActionTrust,
    query: &str,
    proof: &str,
) -> Result<String, String> {
    let query: ReadActionResult = serde_json::from_str(query).map_err(|error| error.to_string())?;
    let snapshot = facade
        .read_action_result(query, trust, proof.as_bytes())
        .map_err(|error| error.to_string())?;
    json(&snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::{test_support::RusqliteDoSql, DoSqliteStore};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use std::collections::BTreeMap;
    use whipplescript_kernel::gov::{
        ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope,
    };
    use whipplescript_kernel::host_protocol::action::{
        ActionAdmissionReceipt, ActionInput, ActionProvenance, HOST_ACTION_PROTOCOL,
    };
    use whipplescript_kernel::host_protocol::action_result::ACTION_RESULT_PROTOCOL;
    use whipplescript_kernel::ifc::VerifiedEnvelope;

    const SOURCE: &str = r#"
workflow HostedAction
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.handle } }
"#;
    const OTHER_SOURCE: &str = r#"
workflow HostedAction
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.version_ref } }
"#;

    struct Policy;
    impl GovernanceAttestationVerifier for Policy {
        fn verify(&self, _: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
            (attestation.signature == "fixture-attestation")
                .then_some(())
                .ok_or_else(|| "fixture governance proof mismatch".into())
        }
    }

    fn key(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_slice(&[seed; 32]).expect("test key");
        let public = hex::encode(
            key.verifying_key()
                .as_affine()
                .to_sec1_point(true)
                .as_bytes(),
        );
        (key, public)
    }

    fn trust(bindings: &[(&str, &str)]) -> String {
        serde_json::json!({
            "bindings": bindings.iter().map(|(authority, key_id)| serde_json::json!({
                "authority": authority, "algorithm": ACTION_PROOF_ALGORITHM, "key_id": key_id,
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }

    fn sign(key: &SigningKey, kind: &str, body: &str) -> String {
        let bytes = hex::decode(signing_bytes_hex(kind, body).expect("signing bytes")).unwrap();
        let signature: Signature = key.sign(&bytes);
        hex::encode(signature.to_bytes())
    }

    fn facade() -> GovernedHostFacade<DoSqliteStore<RusqliteDoSql>> {
        let signed = SignedEnvelope::from_external_signature_v2(
            "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
            "fixture-signer",
            "fixture",
            "fixture-key",
            "fixture-attestation",
            7,
            "product",
        )
        .expect("policy fixture");
        let envelope =
            VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &Policy).expect("policy");
        GovernedHostFacade::from_verified_store(
            DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            7,
            envelope,
        )
        .expect("facade")
        .with_compiler_artifact_digest("c".repeat(64))
        .with_embedded_std_manifests(crate::do_packages::EMBEDDED_STD_MANIFESTS)
    }

    fn command(facade: &GovernedHostFacade<DoSqliteStore<RusqliteDoSql>>, actor: &str) -> String {
        let identity: serde_json::Value =
            serde_json::from_str(&action_identity("reference.echo", SOURCE).unwrap()).unwrap();
        json(&HostActionCommand {
            anchor: None,
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: "product".into(),
            scope: "workspace:1".into(),
            request_id: format!("action:{actor}"),
            operation: "reference.echo".into(),
            program_version_ref: identity["program_version_ref"].as_str().unwrap().into(),
            input_schema_ref: identity["input_schema_ref"].as_str().unwrap().into(),
            policy: facade.policy_ref().clone(),
            provenance: ActionProvenance {
                initiator: actor.into(),
                executor: actor.into(),
                delegation: vec![],
                origin: "tool.call".into(),
                causes: vec![],
            },
            inputs: BTreeMap::from([(
                "content".into(),
                ActionInput {
                    handle: "ledger".into(),
                    version_ref: "content:version:1".into(),
                    label_ref: "label:private".into(),
                },
            )]),
            resources: BTreeMap::new(),
        })
        .unwrap()
    }

    fn read(command: &str, receipt: &str) -> String {
        let command: HostActionCommand = serde_json::from_str(command).unwrap();
        let admission: ActionAdmissionReceipt = serde_json::from_str(receipt).unwrap();
        json(&ReadActionResult {
            protocol: ACTION_RESULT_PROTOCOL.into(),
            read_authority: None,
            issuer: command.issuer,
            scope: command.scope,
            policy: command.policy,
            provenance: command.provenance,
            admission,
            evidence_handle: "ledger".into(),
            evidence_label_ref: "label:private".into(),
            through: None,
        })
        .unwrap()
    }

    #[test]
    fn hosted_action_admits_executes_and_reads_under_pinned_authority() {
        let (product, product_key) = key(3);
        let trust = HostedActionTrust::parse(&trust(&[("product", &product_key)])).unwrap();
        let mut facade = facade();
        for actor in ["person:1", "agent:1"] {
            let command = command(&facade, actor);
            let proof = sign(&product, "command", &command);
            let receipt = admit(&mut facade, &trust, &command, SOURCE, &proof).expect("admit");
            assert_eq!(
                admit(&mut facade, &trust, &command, SOURCE, &proof).expect("replay"),
                receipt
            );
            let instance: serde_json::Value = serde_json::from_str(&receipt).unwrap();
            let instance = instance["instance_ref"].as_str().unwrap().to_owned();
            let executed = execute(&mut facade, &instance, SOURCE).expect("execute");
            assert!(executed.contains("\"completed\""), "{executed}");
            let events = facade.kernel().store().list_events(&instance).unwrap();
            assert_eq!(execute(&mut facade, &instance, SOURCE).unwrap(), executed);
            assert_eq!(
                facade.kernel().store().list_events(&instance).unwrap(),
                events
            );
            let query = read(&command, &receipt);
            let snapshot =
                read_result(&facade, &trust, &query, &sign(&product, "read", &query)).unwrap();
            assert!(snapshot.contains("\"completed\""), "{snapshot}");
        }
    }

    #[test]
    fn hosted_action_refuses_a_proof_by_another_authoritys_key() {
        let (_, product_key) = key(3);
        let (stranger, stranger_key) = key(4);
        let trust = HostedActionTrust::parse(&trust(&[
            ("product", &product_key),
            ("other", &stranger_key),
        ]))
        .unwrap();
        let mut facade = facade();
        let command = command(&facade, "person:1");
        let error = admit(
            &mut facade,
            &trust,
            &command,
            SOURCE,
            &sign(&stranger, "command", &command),
        )
        .unwrap_err();
        assert!(
            error.contains("not signed by a key pinned for its authority"),
            "{error}"
        );
        assert!(facade.kernel().store().list_instances().unwrap().is_empty());
        let error = admit(&mut facade, &trust, &command, SOURCE, "not hex").unwrap_err();
        assert!(error.contains("not a hex P-256 signature"), "{error}");
    }

    #[test]
    fn hosted_action_refuses_a_read_without_current_read_proof() {
        let (product, product_key) = key(3);
        let (stranger, _) = key(4);
        let trust = HostedActionTrust::parse(&trust(&[("product", &product_key)])).unwrap();
        let mut facade = facade();
        let command = command(&facade, "agent:1");
        let receipt = admit(
            &mut facade,
            &trust,
            &command,
            SOURCE,
            &sign(&product, "command", &command),
        )
        .unwrap();
        let query = read(&command, &receipt);
        let error = read_result(
            &facade,
            &trust,
            &query,
            &sign(&product, "command", &command),
        )
        .unwrap_err();
        assert!(error.contains("not signed by a key pinned"), "{error}");
        let error =
            read_result(&facade, &trust, &query, &sign(&stranger, "read", &query)).unwrap_err();
        assert!(error.contains("not signed by a key pinned"), "{error}");
    }

    #[test]
    fn hosted_action_executes_only_the_admitted_program() {
        let (product, product_key) = key(3);
        let trust = HostedActionTrust::parse(&trust(&[("product", &product_key)])).unwrap();
        let mut facade = facade();
        let command = command(&facade, "person:1");
        let receipt = admit(
            &mut facade,
            &trust,
            &command,
            SOURCE,
            &sign(&product, "command", &command),
        )
        .unwrap();
        let instance: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        let instance = instance["instance_ref"].as_str().unwrap();
        let before = facade.kernel().store().list_events(instance).unwrap();
        let error = execute(&mut facade, instance, OTHER_SOURCE).unwrap_err();
        assert!(
            error.contains("differs from the admitted program"),
            "{error}"
        );
        assert_eq!(
            facade.kernel().store().list_events(instance).unwrap(),
            before
        );
        let error = execute(&mut facade, "ins_action_absent", SOURCE).unwrap_err();
        assert!(error.contains("no admitted action"), "{error}");
    }

    #[test]
    fn action_trust_refuses_what_it_cannot_pin() {
        let (_, product_key) = key(3);
        let error = HostedActionTrust::parse(r#"{"bindings":[]}"#).unwrap_err();
        assert!(error.contains("pins no authority"), "{error}");
        let error = HostedActionTrust::parse(&trust(&[(" ", &product_key)])).unwrap_err();
        assert!(error.contains("names no authority"), "{error}");
        let error = HostedActionTrust::parse(
            &trust(&[("product", &product_key)]).replace(ACTION_PROOF_ALGORITHM, "ed25519"),
        )
        .unwrap_err();
        assert!(error.contains("unsupported algorithm"), "{error}");
        let error = HostedActionTrust::parse(&trust(&[("product", "zz")])).unwrap_err();
        assert!(error.contains("is not hex"), "{error}");
        let error = HostedActionTrust::parse(&trust(&[("product", "0011")])).unwrap_err();
        assert!(error.contains("not a P-256 point"), "{error}");
        let error = HostedActionTrust::parse("{}").unwrap_err();
        assert!(error.contains("not a trust document"), "{error}");
        let error = signing_bytes_hex("other", "{}").unwrap_err();
        assert!(error.contains("unknown action signing kind"), "{error}");
    }
}
