//! Actual admission and dispatch, with synthetic host authority. These tests
//! qualify runtime ordering/flow checks, not a product's scope interpretation.
use super::*;
use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope};
use crate::host_protocol::action::{
    tests::ExactAdmission, ActionInput, ActionProvenance, ActionResource, HOST_ACTION_PROTOCOL,
};
use crate::host_protocol::execution::{effect_observation_fingerprint, ACTION_EXECUTION_PROTOCOL};
use crate::host_protocol::ResourceRef;
use crate::ifc::VerifiedEnvelope;
use serde_json::{json, Value};
use std::{cell::Cell, collections::BTreeMap, io, path::Path};
use whipplescript_store::{
    branches::BranchStore, content::ContentStore, native_stores::NativeStores, vcs::WorkspaceVcs,
    vcs_file_save::VersionedSaveFileStore,
};

const SOURCE: &str = r#"use std.files
workflow ScopedExecutionFixture
input content InputReference
output result Saved
failure error Failed
class InputReference { handle string version_ref string label_ref string }
class Saved { content_hash string }
class Failed { reason string }
class Extra { text string }
file store admitted_input { root "/action/input" allow read ["content"] }
file store admitted_target { root "/action/output" allow write ["target"] }
rule save
  when InputReference as reference
=> {
  read text from admitted_input at "content" as loaded
  after loaded succeeds as draft {
    write text to admitted_target at "target" { body draft.content mode upsert } as written
    after written succeeds as saved { complete result { content_hash saved.content_hash } }
    after written fails as failed { fail error { reason failed.reason } }
  }
  after loaded fails as failed { fail error { reason failed.reason } }
}
"#;

struct PolicyFixture;
impl GovernanceAttestationVerifier for PolicyFixture {
    fn verify(&self, _: &[u8], _: &ExternalAttestation) -> Result<(), String> {
        Ok(())
    }
}

struct Authority {
    bytes: Vec<u8>,
    original: HostActionCommand,
    scope: ResolutionMemoryScope,
    deny_auth: bool,
    deny_target: bool,
    deny_scope: bool,
    scoped_calls: Cell<usize>,
}
impl ActionExecutionVerifier for Authority {
    fn authenticate(
        &self,
        _: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.deny_auth || bytes != self.bytes || proof != b"execute" {
            return Err(ProtocolError::Mismatch(
                "fixture execution authentication denied",
            ));
        }
        Ok(())
    }
    fn authorize(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        if self.deny_target || original != &self.original {
            return Err(ProtocolError::Mismatch("fixture target execution denied"));
        }
        Ok(())
    }
}
impl ScopedSaveExecutionAuthority for Authority {
    fn authorize_scoped_save(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
        _: &VersionedSaveBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError> {
        self.scoped_calls.set(self.scoped_calls.get() + 1);
        if self.deny_scope || scope != &self.scope || original != &self.original {
            return Err(ProtocolError::Mismatch("fixture memory execution denied"));
        }
        Ok(())
    }
}

struct Files {
    inner: VersionedSaveFileStore<BranchStore, ContentStore>,
    calls: Cell<usize>,
}
impl FileStore for Files {
    fn scoped_save_binding(&self) -> Option<(&VersionedSaveBinding, &ResolutionMemoryScope)> {
        self.inner.scoped_save_binding()
    }
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.calls.set(self.calls.get() + 1);
        self.inner.read_to_string(path)
    }
    fn exists(&self, path: &Path) -> bool {
        self.calls.set(self.calls.get() + 1);
        self.inner.exists(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.create_dir_all(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.write(path, bytes)
    }
    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.append(path, bytes)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.remove(path)
    }
}

fn setup(
    case: &str,
    actor: &str,
) -> (
    GovernedHostFacade<NativeStores>,
    CompiledHostAction,
    ExecuteActionEffect,
    Authority,
    Files,
) {
    let store = NativeStores::open_in_memory().expect("runtime");
    for capability in ["file.read", "file.write"] {
        store
            .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
                capability,
                description: "fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register file capability");
        store
            .bind_capability(whipplescript_store::CapabilityBinding {
                binding_id: capability,
                program_id: None,
                capability,
                provider: "files",
                config_json: "{}",
            })
            .expect("bind file capability");
        store
            .register_effect_provider(whipplescript_store::EffectProviderRegistration {
                provider_id: capability,
                effect_kind: capability,
                provider: "files",
                capability,
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register file provider");
    }
    let mut policy = json!({"resources": {
        "file:/action/input": {}, "file:/action/output": {}, "memory:/action/resolutions": {}, "result": {}, "error": {}, "fact:Extra": {}
    }, "bindings": {"admitted_input": "file:/action/input", "admitted_target": "file:/action/output", "admitted_resolutions": "memory:/action/resolutions"}});
    match case {
        "memory-to-file" => {
            policy["resources"]["memory:/action/resolutions"]["reader"] = json!(["Private"])
        }
        "memory-to-result" | "memory-to-error" => {
            for name in [
                "memory:/action/resolutions",
                "file:/action/output",
                "result",
                "error",
            ] {
                policy["resources"][name]["reader"] = json!(["Private"]);
            }
            policy["resources"][if case == "memory-to-result" {
                "result"
            } else {
                "error"
            }]["reader"] = json!([]);
        }
        "target-to-result" | "target-to-error" => {
            for name in ["file:/action/output", "result", "error"] {
                policy["resources"][name]["reader"] = json!(["Private"]);
            }
            policy["resources"][if case == "target-to-result" {
                "result"
            } else {
                "error"
            }]["reader"] = json!([]);
        }
        "memory-integrity" => {
            for name in ["file:/action/input", "file:/action/output"] {
                policy["resources"][name]["writer"] = json!(["Trusted"]);
            }
        }
        "target-integrity" => {
            for name in ["file:/action/input", "memory:/action/resolutions"] {
                policy["resources"][name]["writer"] = json!(["Trusted"]);
            }
            policy["resources"]["file:/action/output"]["writer_sink"] = json!(["Trusted"]);
        }
        "private-allowed" => {
            for name in [
                "memory:/action/resolutions",
                "file:/action/output",
                "result",
                "error",
            ] {
                policy["resources"][name]["reader"] = json!(["Private"]);
            }
        }
        _ => {}
    }
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "fixture",
        "fixture",
        "fixture",
        "fixture",
        7,
        "product",
    )
    .expect("sign fixture policy");
    let envelope = VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &PolicyFixture)
        .expect("verify fixture policy");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope)
        .expect("construct governed facade");
    let source = match case {
        "record" => SOURCE.replace(
            "complete result",
            "record Extra { text \"extra\" } complete result",
        ),
        "foreign-file" => SOURCE.replace("admitted_target", "other_target"),
        _ => SOURCE.into(),
    };
    let action = CompiledHostAction::compile("file.save", &source, None).expect("compiled profile");
    let scope = ResolutionMemoryScope::new("home".into(), "target:path".into(), "Private".into())
        .expect("construct fixture scope");
    let binding = VersionedSaveBinding {
        branch_id: "mainline".into(),
        path: "file.txt".into(),
        base_cut_id: "base".into(),
        draft: "draft".into(),
        draft_hash: whipplescript_store::stable_hash_hex("draft"),
        input_label: "draft-label".into(),
        executing_principal: actor.into(),
        evidence_label: "file-label".into(),
        recorded_at: "t1".into(),
    };
    let mut command = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace".into(),
        request_id: "request".into(),
        operation: "file.save".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "fixture".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "admitted_input".into(),
                version_ref: binding.draft_hash.clone(),
                label_ref: binding.input_label.clone(),
            },
        )]),
        resources: BTreeMap::from([
            (
                "target".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "admitted_target".into(),
                        kind: "file_store".into(),
                        selector: Some("fixture-target".into()),
                        writable: Some(true),
                    },
                    basis: ActionBasis::Version {
                        version_ref: "base".into(),
                    },
                    label_ref: "file-label".into(),
                },
            ),
            (
                "resolutions".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "admitted_resolutions".into(),
                        kind: "resolution_memory".into(),
                        selector: Some(
                            serde_json::to_string(&scope).expect("serialize scope selector"),
                        ),
                        writable: Some(false),
                    },
                    basis: ActionBasis::Version {
                        version_ref: scope.version_ref(),
                    },
                    label_ref: "memory-label".into(),
                },
            ),
        ]),
    };
    match case {
        "missing-memory" => {
            command.resources.remove("resolutions");
        }
        "wrong-selector" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("resolution resource")
                .resource
                .selector = Some("{}".into())
        }
        "wrong-scope" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("resolution resource")
                .resource
                .selector = Some(
                serde_json::to_string(
                    &ResolutionMemoryScope::new(
                        "other".into(),
                        "target:path".into(),
                        "Private".into(),
                    )
                    .expect("construct foreign scope"),
                )
                .expect("serialize foreign scope"),
            )
        }
        "wrong-version" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("resolution resource")
                .basis = ActionBasis::Version {
                version_ref: "other-scope".into(),
            }
        }
        "write-memory" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("resolution resource")
                .resource
                .writable = Some(true)
        }
        "wrong-kind" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("resolution resource")
                .resource
                .kind = "file_store".into()
        }
        "wrong-target-label" => {
            command
                .resources
                .get_mut("target")
                .expect("target resource")
                .label_ref = "another-label".into()
        }
        "wrong-base" => {
            command
                .resources
                .get_mut("target")
                .expect("target resource")
                .basis = ActionBasis::Version {
                version_ref: "another-base".into(),
            }
        }
        _ => {}
    }
    let admission = facade
        .admit_action(
            command.clone(),
            &action,
            &ExactAdmission(command.signing_bytes().expect("sign admission command")),
            b"authenticated fixture",
        )
        .expect("actual admission");
    crate::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &admission.instance_ref,
        action.program(),
        None,
        None,
    )
    .expect("ordinary rule pass");
    let effect = facade
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .expect("read claimable effects")
        .into_iter()
        .find(|effect| effect.kind == "file.read")
        .expect("actual read effect");
    let request = ExecuteActionEffect {
        protocol: ACTION_EXECUTION_PROTOCOL.into(),
        issuer: command.issuer.clone(),
        scope: command.scope.clone(),
        admission,
        policy: facade.policy_ref().clone(),
        provenance: command.provenance.clone(),
        effect_id: effect.effect_id.clone(),
        effect_fingerprint: effect_observation_fingerprint(&effect)
            .expect("fingerprint actual effect"),
    };
    let authority = Authority {
        bytes: request.signing_bytes().expect("sign execution request"),
        original: command,
        scope: scope.clone(),
        deny_auth: case == "authentication",
        deny_target: case == "target-authority",
        deny_scope: case == "memory-authority",
        scoped_calls: Cell::new(0),
    };
    let workspace = WorkspaceVcs::from_parts(
        BranchStore::open(":memory:").expect("open branch store"),
        ContentStore::open(":memory:").expect("open content store"),
    );
    let inner = if case == "unscoped-adapter" {
        VersionedSaveFileStore::new(workspace, binding)
    } else {
        VersionedSaveFileStore::new_in_resolution_scope(workspace, binding, scope)
    }
    .expect("construct file adapter");
    (
        facade,
        action,
        request,
        authority,
        Files {
            inner,
            calls: Cell::new(0),
        },
    )
}

#[test]
fn scoped_execution_refusals_precede_all_adapter_access_and_dispatch() {
    for actor in ["human:one", "agent:one"] {
        for (case, diagnostic) in [
            ("authentication", "fixture execution authentication denied"),
            ("target-authority", "fixture target execution denied"),
            ("memory-authority", "fixture memory execution denied"),
            (
                "unscoped-adapter",
                "scoped save execution requires a scoped adapter",
            ),
            (
                "missing-memory",
                "scoped save requires admitted draft, target and resolutions",
            ),
            (
                "wrong-selector",
                "scoped save command does not bind the adapter",
            ),
            (
                "wrong-scope",
                "scoped save command does not bind the adapter",
            ),
            (
                "wrong-version",
                "scoped save command does not bind the adapter",
            ),
            (
                "write-memory",
                "scoped save command does not bind the adapter",
            ),
            (
                "wrong-kind",
                "scoped save command does not bind the adapter",
            ),
            (
                "wrong-target-label",
                "scoped save command does not bind the adapter",
            ),
            (
                "wrong-base",
                "scoped save command does not bind the adapter",
            ),
            (
                "record",
                "scoped save requires the confined replacement profile",
            ),
            (
                "foreign-file",
                "scoped save requires the confined replacement profile",
            ),
            ("memory-to-file", "resource flow violates confidentiality"),
            ("memory-to-result", "resource flow violates confidentiality"),
            ("memory-to-error", "resource flow violates confidentiality"),
            ("target-to-result", "resource flow violates confidentiality"),
            ("target-to-error", "resource flow violates confidentiality"),
            ("memory-integrity", "resource flow violates integrity"),
            ("target-integrity", "resource flow violates integrity"),
        ] {
            let (mut facade, action, request, authority, files) = setup(case, actor);
            let before = facade
                .kernel()
                .store()
                .chain_head(&request.admission.instance_ref)
                .expect("head before refused execution");
            let error = facade
                .execute_scoped_save_file_effect(
                    request.clone(),
                    &action,
                    &authority,
                    b"execute",
                    &files,
                )
                .expect_err(case);
            assert!(
                format!("{error:?}").contains(diagnostic),
                "{case}: {error:?}"
            );
            assert_eq!(files.calls.get(), 0, "{case}");
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(&request.admission.instance_ref)
                    .expect("head after refused execution"),
                before,
                "{case}"
            );
        }
    }
}

#[test]
fn scoped_execution_requires_the_new_door_and_enters_only_after_authority() {
    for actor in ["human:one", "agent:one"] {
        for case in ["allowed", "private-allowed"] {
            let (mut facade, action, request, authority, files) = setup(case, actor);
            let error = facade
                .execute_action_file_effect(
                    request.clone(),
                    &action,
                    &authority,
                    b"execute",
                    &files,
                )
                .expect_err("legacy door");
            assert!(format!("{error:?}")
                .contains("scoped save requires verified memory execution authority"));
            assert_eq!(files.calls.get(), 0);
            facade
                .execute_scoped_save_file_effect(
                    request.clone(),
                    &action,
                    &authority,
                    b"execute",
                    &files,
                )
                .expect("scoped read dispatch");
            assert_eq!(authority.scoped_calls.get(), 1);
            assert!(files.calls.get() > 0);
            let calls = files.calls.get();
            let error = facade
                .execute_scoped_save_file_effect(request, &action, &authority, b"execute", &files)
                .expect_err("settled read is not claimable again");
            assert!(format!("{error:?}").contains("execution effect is not claimable"));
            assert_eq!(files.calls.get(), calls);
        }
    }
}

#[test]
fn scope_reference_pins_every_component_and_survives_strict_decoding() {
    let base = ResolutionMemoryScope::new("a".into(), "b".into(), "c".into())
        .expect("construct reference scope");
    let decoded: ResolutionMemoryScope =
        serde_json::from_value(serde_json::to_value(&base).expect("serialize reference scope"))
            .expect("decode reference scope");
    assert_eq!(base.version_ref(), decoded.version_ref());
    assert_eq!(
        base.version_ref(),
        "resolution-scope:v1:0fbfd3e6f1a136e5acdb0a8bdf61701560636f49f16cdd2063e29dc0cf06bcba"
    );
    for (a, r, c) in [
        ("other", "b", "c"),
        ("a", "other", "c"),
        ("a", "b", "other"),
        ("a:b", "b", "c"),
    ] {
        let other = ResolutionMemoryScope::new(a.into(), r.into(), c.into())
            .expect("construct distinct scope");
        assert_ne!(base.version_ref(), other.version_ref());
    }
    assert_ne!(
        ResolutionMemoryScope::new("a:b".into(), "c".into(), "d".into())
            .expect("construct first framed scope")
            .version_ref(),
        ResolutionMemoryScope::new("a".into(), "b:c".into(), "d".into())
            .expect("construct second framed scope")
            .version_ref()
    );
    let value: Value =
        serde_json::from_str(r#"{"authority":"a","resource":"b","compartment":"c","extra":true}"#)
            .expect("decode invalid-field fixture");
    assert!(serde_json::from_value::<ResolutionMemoryScope>(value).is_err());
}
