//! WS-683 journeys through signed host admission and the real DO driver/tools.
use super::*;
use crate::do_store::SqlValue;
use crate::skill_catalogue::{HostedSkillCatalogue, HostedSkillEntry};
use whipplescript_kernel::host_protocol::ResourceRef;
const AUTHOR: &str =
    "---\nname: author\ndescription: Write workflows.\n---\n# Author\nRead [guide](guide.md).";
const DRAFT: &str = "---\nname: draft\ndescription: Draft agent instructions.\n---\n# Draft";
fn skill_policy() -> (GaugeDeskGovernanceRoot, String) {
    let principal = ResourcePolicy {
        principal: true,
        ..ResourcePolicy::default()
    };
    let policy = HostGovernancePolicy {
        resources: BTreeMap::from([
            ("provider:openai".to_owned(), principal.clone()),
            ("placement:do".to_owned(), principal),
            (
                "workspace".to_owned(),
                ResourcePolicy {
                    reader: BTreeSet::from(["public".into()]),
                    writer: BTreeSet::from(["public".into()]),
                    ..ResourcePolicy::default()
                },
            ),
        ]),
        bindings: BTreeMap::from([
            ("model".to_owned(), "provider:openai".to_owned()),
            ("do".to_owned(), "placement:do".to_owned()),
            ("files".to_owned(), "workspace".to_owned()),
        ]),
        parties: BTreeMap::from([("operator".to_owned(), "public".to_owned())]),
        provider_bindings: BTreeMap::from([(
            "model".to_owned(),
            ProviderBindingPolicy {
                provider: "openai".to_owned(),
                model: "gpt-test".to_owned(),
                base_url: "https://provider.invalid".to_owned(),
                credential_ref: "credential:model".to_owned(),
                wire: None,
            },
        )]),
        placements: BTreeMap::from([(
            "do".to_owned(),
            PlacementPolicy {
                kind: "durable_object".to_owned(),
                provider_bindings: BTreeSet::from(["model".to_owned()]),
                command_network: false,
            },
        )]),
        ..HostGovernancePolicy::default()
    };
    let signer = "authority:gaugedesk";
    let key = SigningKey::from_slice(&[7u8; 32]).expect("test key");
    let public_key = hex::encode(
        key.verifying_key()
            .as_affine()
            .to_sec1_point(true)
            .as_bytes(),
    );
    let unsigned = policy.to_json().expect("policy");
    // `:v2`, because the hosted path reads its epoch from the signature
    // (DR-0063 §5).
    let signing_bytes = external_signing_bytes_v2(
        &unsigned,
        signer,
        GAUGEDESK_ATTESTATION_ALGORITHM,
        &public_key,
        7,
        "gaugedesk",
    )
    .expect("bytes");
    let signature: Signature = key.sign(&signing_bytes);
    let signed = SignedEnvelope::from_external_signature_v2(
        &unsigned,
        signer,
        GAUGEDESK_ATTESTATION_ALGORITHM,
        &public_key,
        &hex::encode(signature.to_bytes()),
        7,
        "gaugedesk",
    )
    .expect("signed")
    .to_json();
    (GaugeDeskGovernanceRoot::new(signer, public_key), signed)
}

fn resource(root: &str, writable: bool) -> ResourceRef {
    ResourceRef {
        handle: "files".into(),
        kind: "file_store".into(),
        selector: Some(root.into()),
        writable: Some(writable),
        presented_as: None,
    }
}
fn entry(path: &str, body: &str, source: &str) -> HostedSkillEntry {
    let frontmatter =
        whipplescript_store::skill_frontmatter::parse_skill_frontmatter(body).expect("frontmatter");
    HostedSkillEntry {
        path: path.into(),
        body_sha256: whipplescript_kernel::exec_http::sha256_hex(body.as_bytes()),
        name: frontmatter.name,
        description: frontmatter.description,
        source: ModelContentProvenance {
            source_handles: vec![source.into()],
            complete: true,
        },
    }
}
fn run_selected(
    work: bool,
    edit: impl FnOnce(&mut HostedSkillCatalogue),
) -> (
    DurableStepOutcome,
    Rc<test_support::RusqliteDoSql>,
    String,
    Vec<ResourceRef>,
) {
    let (root, signed) = skill_policy();
    let verified = root.verify(&signed).expect("signed host policy");
    let sql = Rc::new(test_support::store().sql);
    for statement in [
        "INSERT INTO capability_schemas (capability,description,schema_json) VALUES ('agent.tell','Run agent','{}')",
        "INSERT INTO effect_providers (provider_id,effect_kind,provider,capability,config_json) VALUES ('provider_agent_tell_builtin','agent.tell','builtin-agent-harness','agent.tell','{}')",
        "INSERT INTO capability_bindings (binding_id,program_id,capability,provider,config_json) VALUES ('binding_agent_tell_builtin',NULL,'agent.tell','builtin-agent-harness','{}')",
        "INSERT INTO profiles (profile_id,name,description,enforcement_mode,allowed_capabilities,config_json) VALUES ('profile_repo_reader','repo-reader','reads','enforce','[\"agent.tell\"]','{}')",
    ] { sql.execute(statement,&[]).expect("same production agent registrations as the existing host journey"); }

    let mut host = GovernedHostFacade::from_verified_store(
        DoSqliteStore::new(sql.clone()),
        7,
        verified.envelope,
    )
    .expect("governed host")
    .with_compiler_artifact_digest("d".repeat(64))
    .with_embedded_std_manifests(crate::do_packages::EMBEDDED_STD_MANIFESTS);
    let package = package();
    let opened = host
        .open_instance(
            &OpenInstanceCommand {
                protocol: HOST_PROTOCOL.into(),
                request_id: "open-skills".into(),
                package_version_ref: package.version_ref().into(),
                policy: host.policy_ref().clone(),
            },
            &package,
        )
        .expect("opened governed instance");
    let resources = vec![resource("editor", false), resource("agent", true)];
    let command = StartTurnCommand {
        protocol: HOST_PROTOCOL.into(),
        command_id: "offered-skills".into(),
        run_ref: "run-skills".into(),
        instance_ref: opened.instance_ref.clone(),
        package_version_ref: package.version_ref().into(),
        policy: host.policy_ref().clone(),
        actor_ref: "operator".into(),
        input: TurnInput {
            text: "Review the selected skill.".into(),
            images: vec![],
        },
        resources: resources.clone(),
        provider_binding: ProviderBindingRef {
            binding_id: "model".into(),
            credential: CredentialRef {
                credential_id: "credential:model".into(),
            },
        },
        placement_ceiling_ref: "do".into(),
    };
    host.begin_turn(
        &command,
        &package,
        ProviderRealization {
            provider: "openai",
            model: "gpt-test",
            base_url: "https://provider.invalid",
        },
    )
    .expect("real governed turn admission");
    for (path, body) in [
        ("editor/author/SKILL.md", AUTHOR),
        ("editor/author/guide.md", "Exact linked guide."),
        ("agent/draft/SKILL.md", DRAFT),
        ("secret/author/SKILL.md", AUTHOR),
    ] {
        sql.execute(
            "INSERT INTO files(key,content) VALUES(?1,?2)",
            &[
                SqlValue::Text(format!("{}/{path}", opened.instance_ref)),
                SqlValue::Text(body.into()),
            ],
        )
        .expect("retained instance file");
    }
    let mut catalogue = HostedSkillCatalogue {
        instance_id: opened.instance_ref.clone(),
        command_id: command.command_id.clone(),
        actor_ref: command.actor_ref.clone(),
        entries: vec![if work {
            entry(
                "agent/draft/SKILL.md",
                DRAFT,
                "discipline-skill:chat:exact:draft",
            )
        } else {
            entry("editor/author/SKILL.md", AUTHOR, "runtime")
        }],
    };
    edit(&mut catalogue);
    let resolved = package
        .resolve_package(package.version_ref())
        .expect("resolved package");
    let mut instance = DurableInstance::attach(
        sql.clone(),
        resolved.program,
        &opened.instance_ref,
        resolved.system_prompt,
        16,
        DurableEffectPorts {
            skill_catalogue: Some(catalogue),
            agent_workspace_resources: Some(resources.clone()),
            initial_model_provenance: Some(InitialModelProvenance {
                system: ModelContentProvenance {
                    source_handles: vec!["runtime".into()],
                    complete: true,
                },
                workspace_content: ModelContentProvenance {
                    source_handles: vec!["workspace:chat".into()],
                    complete: true,
                },
                ..InitialModelProvenance::default()
            }),
            agent_model: Some(Box::new(MessagesApiClient::new(
                CoerceProvider::OpenAi,
                "test",
                "gpt-test",
                "https://provider.invalid",
                1024,
                None,
            ))),
            ..DurableEffectPorts::default()
        },
    )
    .expect("attach actual driver");
    let outcome = instance.step(None, 1_790_000_000_000);
    (outcome, sql, opened.instance_ref, resources)
}

#[test]
fn hosted_selected_catalogue_offers_only_verified_editor_or_agent_identity() {
    use whipplescript_kernel::harness_loop::{ToolCall, ToolExecutor, ToolStatus};
    for work in [false, true] {
        let (outcome, sql, instance, resources) = run_selected(work, |_| {});
        let DurableStepOutcome::NeedsHttp(request) = outcome else {
            panic!("actual model assembly: {outcome:?}")
        };
        let body = request.body.to_string();
        let offered = if work {
            "agent/draft/SKILL.md"
        } else {
            "editor/author/SKILL.md"
        };
        let absent = if work {
            "editor/author/SKILL.md"
        } else {
            "agent/draft/SKILL.md"
        };
        assert!(body.contains(offered), "{body}");
        assert!(
            !body.contains(absent),
            "unselected skill was offered: {body}"
        );
        let handles = request
            .model_provenance
            .expect("exact live provenance")
            .messages
            .into_iter()
            .flat_map(|part| part.source_handles)
            .collect::<Vec<_>>();
        assert!(
            handles.contains(&if work {
                "discipline-skill:chat:exact:draft".into()
            } else {
                "runtime".into()
            }),
            "{handles:?}"
        );
        let tools = crate::do_tools::DoToolExecutor::for_instance(sql.clone(), &instance)
            .with_workspace_source(Some("workspace:chat".into()))
            .with_resources(&resources)
            .expect("current admitted roots");
        let read = |path: &str| {
            tools.execute(&ToolCall {
                id: "read-skill".into(),
                name: "read".into(),
                arguments: json!({"path":path}),
            })
        };
        let body = read(offered);
        assert_eq!(body.status, ToolStatus::Ok, "{body:?}");
        assert_eq!(
            body.content,
            if work { DRAFT } else { AUTHOR },
            "exact selected body"
        );
        let read_source = tools.model_output_provenance(&ToolCall {
            id: "read-skill".into(),
            name: "read".into(),
            arguments: json!({"path":offered}),
        });
        assert!(read_source.complete);
        assert_eq!(
            read_source.source_handles,
            [format!(
                "workspace-file:chat:{}:{offered}",
                whipplescript_store::stable_hash_bytes_hex(
                    if work { DRAFT } else { AUTHOR }.as_bytes()
                )
            )],
            "read witnesses current bytes separately from the offered catalogue source"
        );
        assert_eq!(read("editor/author/guide.md").status, ToolStatus::Ok);
        assert_eq!(
            read(absent).status,
            ToolStatus::Ok,
            "unselected draft data remains readable"
        );
        assert_eq!(
            read("secret/author/SKILL.md").status,
            ToolStatus::Error,
            "selection grants no reads"
        );
    }
}

#[test]
fn hosted_selected_catalogue_refuses_forged_bytes_metadata_and_request_identity_before_model() {
    let edits: [fn(&mut HostedSkillCatalogue); 10] = [
        |c| c.entries[0].body_sha256 = "0".repeat(64),
        |c| c.entries[0].description = "forged".into(),
        |c| c.entries[0].name = "other".into(),
        |c| c.entries[0].path = "secret/author/SKILL.md".into(),
        |c| c.entries[0].path = "editor/missing/SKILL.md".into(),
        |c| c.instance_id = "another-instance".into(),
        |c| c.command_id = "another-caller-command".into(),
        |c| c.actor_ref = "another-caller".into(),
        |c| c.entries.push(c.entries[0].clone()),
        |c| c.entries[0].source.source_handles.clear(),
    ];
    for edit in edits {
        let (outcome, _, _, _) = run_selected(false, edit);
        assert!(
            matches!(outcome,DurableStepOutcome::Failed(ref detail) if detail.contains("hosted skill catalogue")),
            "{outcome:?}"
        );
    }
}

#[test]
fn hosted_selected_empty_catalogue_keeps_draft_files_readable_without_offering_them() {
    let (outcome, sql, instance, resources) =
        run_selected(false, |catalogue| catalogue.entries.clear());
    let DurableStepOutcome::NeedsHttp(request) = outcome else {
        panic!("model dispatch: {outcome:?}")
    };
    let body = request.body.to_string();
    assert!(!body.contains("editor/author/SKILL.md"));
    assert!(!body.contains("agent/draft/SKILL.md"));
    let tools = crate::do_tools::DoToolExecutor::for_instance(sql.clone(), &instance)
        .with_resources(&resources)
        .expect("current file view");
    use whipplescript_kernel::harness_loop::{ToolCall, ToolExecutor, ToolStatus};
    let write = tools.execute(&ToolCall {
        id: "edit-draft".into(),
        name: "write".into(),
        arguments: json!({"path":"agent/draft/SKILL.md","content":"edited draft data"}),
    });
    assert_eq!(write.status, ToolStatus::Ok, "{write:?}");
    let read = tools.execute(&ToolCall {
        id: "read-edited".into(),
        name: "read".into(),
        arguments: json!({"path":"agent/draft/SKILL.md"}),
    });
    assert_eq!(read.content, "edited draft data");
    let narrowed = crate::do_tools::DoToolExecutor::for_instance(sql, &instance)
        .with_resources(&[resource("agent", true)])
        .expect("later narrowed grant");
    let removed = narrowed.execute(&ToolCall {
        id: "read-revoked".into(),
        name: "read".into(),
        arguments: json!({"path":"editor/author/SKILL.md"}),
    });
    assert_eq!(
        removed.status,
        ToolStatus::Error,
        "current reader grant still applies"
    );
}
