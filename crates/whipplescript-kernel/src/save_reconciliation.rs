//! Current authority plus the actual retained target result, over the existing
//! reconciliation protocol. This door never writes a target or advances rules.
use serde_json::Value;
use sha2::{Digest, Sha256};
use whipplescript_store::branches::Branches;
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::effect_recovery::{DispatchMarker, EvidenceDisposition};
use whipplescript_store::event_chain::OwnedChainEntry;
use whipplescript_store::vcs::WorkspaceVcs;
use whipplescript_store::vcs_file_save::{read_committed_save, SaveAttempt, SaveResultBinding};

use crate::host_facade::HostFacadeError;
use crate::host_protocol::action::{
    ActionAdmissionReceipt, ActionBasis, ActionInput, ActionResource, HostActionCommand,
};
use crate::host_protocol::execution::ExecuteActionEffect;
use crate::host_protocol::recovery::{EffectEvidenceVerifier, ReconcileEffectCommand};
use crate::host_protocol::ProtocolError;

/// Trusted host configuration, resolved from the registered operation and its
/// target store. These references are observations, never grants or wire input.
pub struct VersionedSaveEvidenceSource<'a, B: Branches, C: ContentBlobs> {
    pub admission: &'a ActionAdmissionReceipt,
    pub workspace: &'a WorkspaceVcs<B, C>,
    pub binding: &'a SaveResultBinding,
    pub input_name: &'a str,
    pub resource_name: &'a str,
    pub authority_ref: &'a str,
}

/// The embedding host supplies pinned authentication/authorization roots. The
/// runtime owns target verification; the host cannot replace it with a label.
pub trait SaveReconciliationAuthority {
    /// Authenticate current permission to inspect this exact instance's
    /// metadata, all principal/delegation claims and the complete signing bytes.
    fn authenticate(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;

    /// Authorize current reconciliation and receipt access (including the
    /// evidence label, target authority and store binding) within the original
    /// command's ceiling. Resolve the original opaque selector to the actual
    /// branch/path and its immutable input version to `binding.draft_hash`; an
    /// input version may identify a labeled envelope rather than its raw bytes.
    /// Verify these exact mappings before target content is read. Original
    /// admission or execution is not current access.
    fn authorize(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
    ) -> Result<(), ProtocolError>;
}

/// Private and non-clonable. Only a freshly authorized, checked target read
/// constructs this context; a serialized receipt cannot reconstruct it.
pub(crate) struct VerifiedSaveEvidence {
    command: ReconcileEffectCommand,
    signing: Vec<u8>,
    authorization: Vec<u8>,
    target: String,
}
impl VerifiedSaveEvidence {
    pub(crate) fn target_proof(&self) -> &[u8] {
        self.target.as_bytes()
    }
}
impl EffectEvidenceVerifier for VerifiedSaveEvidence {
    fn verify(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != &self.command
            || signing_bytes != self.signing
            || authorization_proof != self.authorization
            || target_proof != self.target.as_bytes()
        {
            return Err(ProtocolError::Mismatch(
                "versioned save verified evidence context",
            ));
        }
        Ok(())
    }
}

// The original admission and dispatch have already been verified. This is
// the runtime-owned ceiling; opaque identity interpretation remains the host's
// current-authority obligation before any retained target content is read.
fn require_original_save_ceiling(
    input: Option<&ActionInput>,
    target: Option<&ActionResource>,
    binding: &SaveResultBinding,
    evidence_ref: &str,
) -> Result<(), ProtocolError> {
    let target_matches = target.is_some_and(|target| {
        target.resource.handle == evidence_ref
            && target.resource.kind == "file_store"
            && target.resource.writable == Some(true)
            && target.label_ref == binding.evidence_label
            && target.basis
                == ActionBasis::Version {
                    version_ref: binding.base_cut_id.clone(),
                }
    });
    if !target_matches || input.is_none() {
        return Err(ProtocolError::Mismatch(
            "versioned save original resource and input ceiling",
        ));
    }
    Ok(())
}

fn require_original_save_execution(
    execution: &ExecuteActionEffect,
    original: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    effect_id: &str,
    executing_principal: &str,
    fingerprint: &str,
    recorded_fingerprint: &Value,
) -> Result<(), ProtocolError> {
    if execution.admission != *admission
        || execution.effect_id != effect_id
        || execution.issuer != original.issuer
        || execution.scope != original.scope
        || execution.provenance.executor != executing_principal
        || recorded_fingerprint != fingerprint
    {
        return Err(ProtocolError::Mismatch(
            "versioned save original executing authority",
        ));
    }
    Ok(())
}

pub(crate) fn prepare<B: Branches, C: ContentBlobs>(
    command: &ReconcileEffectCommand,
    source: &VersionedSaveEvidenceSource<'_, B, C>,
    prefix: &[OwnedChainEntry],
    authority: &dyn SaveReconciliationAuthority,
    authorization: &[u8],
) -> Result<VerifiedSaveEvidence, HostFacadeError> {
    let frame = &command.evidence.frame;
    let (original, admission_index) = crate::host_action::recorded_action_command(
        source.admission,
        &command.issuer,
        &command.scope,
        prefix,
    )?;
    let pin = whipplescript_store::host_actions::dispatch_admission_binding(
        &source.admission.instance_ref,
        &prefix[..=admission_index],
    )
    .map_err(HostFacadeError::Store)?;
    if frame.instance_id != source.admission.instance_ref
        || frame.action_admission != pin
        || frame.kind != "file.write"
        || frame.provider != "files"
        || command.evidence.disposition != EvidenceDisposition::Applied
        || command.evidence.authority_ref != source.authority_ref
        || command.evidence_label_ref != source.binding.evidence_label
    {
        return Err(
            ProtocolError::Mismatch("versioned save reconciliation scope and disposition").into(),
        );
    }
    let mut started = None;
    for event in prefix.iter().filter(|event| {
        event.source.as_deref() == Some("kernel") && event.event_type == "effect.run_started"
    }) {
        let payload: Value =
            serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
        if payload.get("run_id").and_then(Value::as_str) != Some(frame.run_id.as_str()) {
            continue;
        }
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())
            .map_err(HostFacadeError::Json)?;
        if marker.frame != *frame || started.is_some() {
            return Err(ProtocolError::Mismatch("versioned save exact recorded dispatch").into());
        }
        started = Some((event, payload));
    }
    let Some((event, payload)) = started else {
        return Err(ProtocolError::Mismatch("versioned save dispatch is unavailable").into());
    };
    let execution: ExecuteActionEffect =
        serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
            .map_err(HostFacadeError::Json)?;
    let fingerprint = Sha256::digest(execution.signing_bytes()?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    require_original_save_execution(
        &execution,
        &original,
        source.admission,
        &frame.effect_id,
        &source.binding.executing_principal,
        &fingerprint,
        &payload["metadata"]["action_execution"]["fingerprint"],
    )?;
    require_original_save_ceiling(
        original.inputs.get(source.input_name),
        original.resources.get(source.resource_name),
        source.binding,
        &command.evidence.evidence_ref,
    )?;
    authority.authorize(command, &original, &execution, source.binding)?;
    let attempt = SaveAttempt {
        instance_id: frame.instance_id.clone(),
        effect_id: frame.effect_id.clone(),
        run_id: frame.run_id.clone(),
        started_event_id: event.event_id.clone(),
    };
    let result = read_committed_save(source.workspace, source.binding, &attempt).map_err(|_| {
        ProtocolError::Mismatch("versioned save retained target evidence is unavailable")
    })?;
    let Some(result) = result else {
        return Err(
            ProtocolError::Mismatch("versioned save target has no committed result").into(),
        );
    };
    Ok(VerifiedSaveEvidence {
        command: command.clone(),
        signing: command.signing_bytes()?,
        authorization: authorization.to_vec(),
        target: result.receipt_json,
    })
}

/// Read-only negative controls over a fixture's actual retained target and
/// copied runtime prefix. This never exports a verified context or appends.
#[cfg(any(test, feature = "test-support"))]
pub mod conformance {
    use super::*;

    pub fn check<B: Branches, C: ContentBlobs>(
        command: &ReconcileEffectCommand,
        source: &VersionedSaveEvidenceSource<'_, B, C>,
        prefix: &[OwnedChainEntry],
        authority: &dyn SaveReconciliationAuthority,
        proof: &[u8],
    ) {
        let verified =
            prepare(command, source, prefix, authority, proof).expect("valid fixture evidence");
        let signing = command.signing_bytes().expect("signing");
        verified
            .verify(command, &signing, proof, verified.target_proof())
            .expect("exact context");
        for field in ["command", "signing", "authorization", "target"] {
            let mut changed = command.clone();
            if field == "command" {
                changed.request_id.push_str("-changed");
            }
            let error = verified
                .verify(
                    &changed,
                    if field == "signing" {
                        b"changed"
                    } else {
                        &signing
                    },
                    if field == "authorization" {
                        b"changed"
                    } else {
                        proof
                    },
                    if field == "target" {
                        b"changed"
                    } else {
                        verified.target_proof()
                    },
                )
                .expect_err("verified context must remain exact");
            assert_eq!(
                error,
                ProtocolError::Mismatch("versioned save verified evidence context")
            );
        }
        let index = prefix
            .iter()
            .position(|event| {
                event.event_type == "effect.run_started"
                    && serde_json::from_str::<Value>(&event.payload_json).expect("start")["run_id"]
                        == command.evidence.frame.run_id
            })
            .expect("exact fixture start");
        for field in ["effect_id", "issuer", "scope", "fingerprint", "executor"] {
            let mut changed = prefix.to_vec();
            let mut payload: Value =
                serde_json::from_str(&changed[index].payload_json).expect("payload");
            if field == "fingerprint" {
                payload["metadata"]["action_execution"]["fingerprint"] = "changed".into();
            } else if field == "executor" {
                payload["metadata"]["action_execution"]["request"]["provenance"]["executor"] =
                    "changed".into();
                payload["metadata"]["action_execution"]["request"]["provenance"]["initiator"] =
                    "changed".into();
            } else {
                payload["metadata"]["action_execution"]["request"][field] = "changed".into();
            }
            changed[index].payload_json = payload.to_string();
            let error = match prepare(command, source, &changed, authority, proof) {
                Err(error) => error,
                Ok(_) => panic!("changed {field} must refuse"),
            };
            assert!(
                format!("{error:?}").contains("versioned save original executing authority"),
                "{field}: {error:?}"
            );
        }
        let mut duplicate = prefix.to_vec();
        duplicate.push(prefix[index].clone());
        let error = match prepare(command, source, &duplicate, authority, proof) {
            Err(error) => error,
            Ok(_) => panic!("duplicate start must refuse"),
        };
        assert!(format!("{error:?}").contains("versioned save exact recorded dispatch"));
    }
}

#[cfg(test)]
mod ceiling_tests {
    use super::*;
    use crate::host_protocol::ResourceRef;

    #[test]
    fn original_save_execution_requires_exact_admission_scope_actor_and_fingerprint() {
        let (execution, original, effect) =
            crate::host_protocol::execution::tests::fixture("file.write");
        let fingerprint = "recorded-execution-fingerprint";
        let recorded = Value::String(fingerprint.into());
        let check = |request: &ExecuteActionEffect, recorded: &Value| {
            require_original_save_execution(
                request,
                &original,
                &execution.admission,
                &effect.effect_id,
                &execution.provenance.executor,
                fingerprint,
                recorded,
            )
        };
        check(&execution, &recorded).expect("exact original executing authority");
        let expected = ProtocolError::Mismatch("versioned save original executing authority");
        for field in ["admission", "effect", "issuer", "scope", "executor"] {
            let mut changed = execution.clone();
            match field {
                "admission" => changed.admission.fingerprint.push_str("-other"),
                "effect" => changed.effect_id.push_str("-other"),
                "issuer" => changed.issuer.push_str("-other"),
                "scope" => changed.scope.push_str("-other"),
                "executor" => changed.provenance.executor.push_str("-other"),
                _ => unreachable!(),
            }
            assert_eq!(check(&changed, &recorded), Err(expected.clone()), "{field}");
        }
        for recorded in [Value::Null, Value::String("other-fingerprint".into())] {
            assert_eq!(check(&execution, &recorded), Err(expected.clone()));
        }
    }

    #[test]
    fn original_save_ceiling_requires_its_input_and_exact_writable_target() {
        let binding = SaveResultBinding {
            branch_id: "branch".into(),
            path: "note.txt".into(),
            base_cut_id: "base".into(),
            draft_hash: "raw-draft-hash".into(),
            executing_principal: "actor".into(),
            evidence_label: "private".into(),
        };
        let input = ActionInput {
            handle: "admitted_input".into(),
            version_ref: "labeled-envelope-version".into(),
            label_ref: "input-private".into(),
        };
        let target = ActionResource {
            resource: ResourceRef {
                handle: "admitted_target".into(),
                kind: "file_store".into(),
                selector: Some(r#"["target", "branch", "note.txt"]"#.into()),
                writable: Some(true),
            },
            basis: ActionBasis::Version {
                version_ref: "base".into(),
            },
            label_ref: "private".into(),
        };
        require_original_save_ceiling(Some(&input), Some(&target), &binding, "admitted_target")
            .expect("opaque input and selector have host-owned interpretations");
        let expected =
            ProtocolError::Mismatch("versioned save original resource and input ceiling");
        assert_eq!(
            require_original_save_ceiling(None, Some(&target), &binding, "admitted_target"),
            Err(expected.clone())
        );
        assert_eq!(
            require_original_save_ceiling(Some(&input), None, &binding, "admitted_target"),
            Err(expected.clone())
        );
        for field in [
            "handle",
            "kind",
            "read-only",
            "unspecified-write",
            "label",
            "base",
        ] {
            let mut changed = target.clone();
            match field {
                "handle" => changed.resource.handle = "other".into(),
                "kind" => changed.resource.kind = "other".into(),
                "read-only" => changed.resource.writable = Some(false),
                "unspecified-write" => changed.resource.writable = None,
                "label" => changed.label_ref = "other".into(),
                "base" => {
                    changed.basis = ActionBasis::Version {
                        version_ref: "other".into(),
                    }
                }
                _ => unreachable!(),
            }
            assert_eq!(
                require_original_save_ceiling(
                    Some(&input),
                    Some(&changed),
                    &binding,
                    "admitted_target"
                ),
                Err(expected.clone()),
                "{field}"
            );
        }
    }
}
