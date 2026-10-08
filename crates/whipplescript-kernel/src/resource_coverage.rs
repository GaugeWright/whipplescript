//! Compiler-owned resource-field inventory for checked admission (RC-1).
//!
//! These are exact source spellings with field-specific meanings. A path,
//! endpoint, destination, credential or agent selector is not an external
//! revision pin or live update edge without its host binding and admitting
//! operation.

use whipplescript_parser::{
    IrAgent, IrChannel, IrEffectKind, IrEffectNode, IrFileStore, IrHttpRequest, IrProgram,
    IrRequestHeaderValue, IrSource,
};
use whipplescript_store::program_imports::{
    ProgramResourceField, ProgramResourceFieldCapture, ProgramResourceFieldScope,
    ProgramResourceFieldUse,
};

use crate::exec_http::sha256_hex;

fn marked_header_credentials(request: &IrHttpRequest) -> Vec<String> {
    request
        .headers
        .iter()
        .filter_map(|header| match &header.value {
            IrRequestHeaderValue::Credential { handle, .. } => Some(handle.clone()),
            IrRequestHeaderValue::Expr(_) => None,
        })
        .collect()
}

pub fn capture(program: &IrProgram) -> Result<ProgramResourceFieldCapture, String> {
    // Exhaustive IR destructuring makes a new top-level population a review
    // event before the compiler can keep claiming this resource-field scope.
    let IrProgram {
        execution_semantics: _,
        workflow: _,
        source_tags: _,
        source_descriptions: _,
        includes: _,
        pattern_applications: _,
        workflow_contracts: _,
        uses: _,
        declaration_constructs: _,
        harnesses: _,
        trackers: _,
        streams: _,
        regions: _,
        channels,
        credentials: _,
        vaults: _,
        gauges: _,
        marks: _,
        campaigns: _,
        file_stores,
        memory_pools: _,
        events: _,
        sources,
        tests: _,
        leases: _,
        ledgers: _,
        counters: _,
        shared_coordination_usage: _,
        schemas: _,
        agents,
        coerces: _,
        assertions: _,
        rules,
        rule_dependencies: _,
        measure_declarations: _,
        measures: _,
    } = program;
    let mut examined = Vec::new();
    let mut push = |owner: &str, field: ProgramResourceField, values: Vec<String>| {
        examined.push(ProgramResourceFieldUse {
            occurrence: examined.len(),
            owner: owner.to_owned(),
            field,
            meaning: field.meaning(),
            values,
        });
    };
    for channel in channels {
        let IrChannel {
            name,
            provider: _,
            workspace,
            destination,
            span: _,
        } = channel;
        push(
            name,
            ProgramResourceField::ChannelWorkspace,
            workspace.iter().cloned().collect(),
        );
        push(
            name,
            ProgramResourceField::ChannelDestination,
            destination.iter().cloned().collect(),
        );
    }
    for store in file_stores {
        let IrFileStore {
            name,
            root,
            read_globs,
            write_globs,
            provider: _,
        } = store;
        push(
            name,
            ProgramResourceField::FileStoreRoot,
            vec![root.clone()],
        );
        push(
            name,
            ProgramResourceField::FileStoreReadGlobs,
            read_globs.clone(),
        );
        push(
            name,
            ProgramResourceField::FileStoreWriteGlobs,
            write_globs.clone(),
        );
    }
    for source in sources {
        let IrSource {
            name,
            provider: _,
            is_clock: _,
            is_file: _,
            is_http: _,
            recurrence: _,
            timezone: _,
            missed: _,
            path,
            watch,
            url,
            dedup_field: _,
            endpoint,
            auth_mode: _,
            auth_secret,
            verified_credential,
            correlate_field: _,
            observe_binding: _,
            emit_signal: _,
            emit_from: _,
            emit_fields: _,
            span: _,
        } = source;
        for (field, value) in [
            (ProgramResourceField::SourcePath, path),
            (ProgramResourceField::SourceWatch, watch),
            (ProgramResourceField::SourceUrl, url),
            (ProgramResourceField::SourceEndpoint, endpoint),
            (ProgramResourceField::SourceAuthSecret, auth_secret),
            (
                ProgramResourceField::SourceVerifiedCredential,
                verified_credential,
            ),
        ] {
            push(name, field, value.iter().cloned().collect());
        }
    }
    for agent in agents {
        let IrAgent {
            name,
            span: _,
            harness: _,
            provider: _,
            profile,
            capacity: _,
            skills,
            capabilities,
            requires,
            tools,
            compaction: _,
            thread: _,
            settings: _,
            returns,
            harness_class: _,
        } = agent;
        push(
            name,
            ProgramResourceField::AgentProfile,
            profile.iter().cloned().collect(),
        );
        push(name, ProgramResourceField::AgentSkills, skills.clone());
        push(
            name,
            ProgramResourceField::AgentCapabilities,
            capabilities.clone(),
        );
        push(name, ProgramResourceField::AgentRequires, requires.clone());
        push(name, ProgramResourceField::AgentTools, tools.clone());
        push(
            name,
            ProgramResourceField::AgentReturns,
            returns.iter().cloned().collect(),
        );
    }
    for rule in rules {
        for effect in &rule.metadata.effects {
            // The claim is field-specific: a newly added effect field must be
            // classified here before this compiler can issue another V4
            // witness, even when its current lowering leaves that field empty.
            let IrEffectNode {
                id: _,
                kind: _,
                binding: _,
                after_arm: _,
                required_capabilities: _,
                construct_use: _,
                package_call: _,
                idempotency_key: _,
                span: _,
                timeout_seconds: _,
                access_grants: _,
                prompt_result_type: _,
                turn_skills: _,
                on_stream: _,
                selection_source: _,
                transport_onto: _,
                resources: _,
                agent: _,
                coerce_target: _,
                prompt_provider: _,
                workflow_target: _,
                endorsed: _,
                declassified: _,
                selected_by: _,
                exec_target: _,
                http_request: _,
                mint_credential: _,
            } = effect;
            let http = effect.http_request.as_ref();
            let mint = effect.mint_credential.as_ref();
            match effect.kind {
                IrEffectKind::HttpRequest if http.is_some() && mint.is_none() => {}
                IrEffectKind::MintCredential if mint.is_some() && http.is_none() => {}
                IrEffectKind::HttpRequest | IrEffectKind::MintCredential => {
                    return Err(format!(
                        "effect `{}` has an incomplete HTTP or credential-mint payload",
                        effect.id
                    ));
                }
                _ if http.is_some() || mint.is_some() => {
                    return Err(format!(
                        "effect `{}` has an HTTP or credential-mint payload on another kind",
                        effect.id
                    ));
                }
                _ => {}
            }
            match effect.kind {
                IrEffectKind::AgentTell
                    if effect.workflow_target.is_none() && effect.exec_target.is_none() => {}
                IrEffectKind::WorkflowInvoke
                    if effect.workflow_target.is_some()
                        && effect.exec_target.is_none()
                        && effect.on_stream.is_none() => {}
                IrEffectKind::ExecCommand
                    if effect.exec_target.is_some()
                        && effect.workflow_target.is_none()
                        && effect.on_stream.is_none() => {}
                IrEffectKind::AgentTell
                | IrEffectKind::WorkflowInvoke
                | IrEffectKind::ExecCommand => {
                    return Err(format!(
                        "effect `{}` has an incomplete target selector",
                        effect.id
                    ));
                }
                _ if effect.workflow_target.is_some()
                    || effect.exec_target.is_some()
                    || effect.on_stream.is_some() =>
                {
                    return Err(format!(
                        "effect `{}` has a target selector on another kind",
                        effect.id
                    ));
                }
                _ => {}
            }
            if (effect.kind != IrEffectKind::AgentTell && !effect.turn_skills.is_empty())
                || (effect.kind != IrEffectKind::SchemaCoerce
                    && effect.prompt_result_type.is_some())
                || (effect.kind != IrEffectKind::CapabilityCall
                    && (effect.selection_source.is_some() || effect.transport_onto.is_some()))
            {
                return Err(format!(
                    "effect `{}` has an unclassified effect selector",
                    effect.id
                ));
            }
            if !effect.access_grants.is_empty()
                && !matches!(
                    effect.kind,
                    IrEffectKind::AgentTell
                        | IrEffectKind::SchemaCoerce
                        | IrEffectKind::WorkflowInvoke
                        | IrEffectKind::ExecCommand
                )
            {
                return Err(format!(
                    "effect `{}` has a turn access grant on another kind",
                    effect.id
                ));
            }
            // A tuple encoding keeps rule/effect identity unambiguous even if
            // either source spelling contains punctuation.
            let owner = serde_json::to_string(&(rule.name.as_str(), effect.id.as_str()))
                .map_err(|error| error.to_string())?;
            push(
                &owner,
                ProgramResourceField::EffectHttpUrl,
                http.map(|request| request.url.clone())
                    .into_iter()
                    .collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectHttpHeaderCredentials,
                http.map(marked_header_credentials).unwrap_or_default(),
            );
            push(
                &owner,
                ProgramResourceField::EffectHttpSignedWith,
                http.and_then(|request| request.signed_with.clone())
                    .into_iter()
                    .collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectMintParent,
                mint.map(|request| request.parent.clone())
                    .into_iter()
                    .collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectMintExchangeUrl,
                mint.map(|request| request.exchange.url.clone())
                    .into_iter()
                    .collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectMintExchangeHeaderCredentials,
                mint.map(|request| marked_header_credentials(&request.exchange))
                    .unwrap_or_default(),
            );
            push(
                &owner,
                ProgramResourceField::EffectMintExchangeSignedWith,
                mint.and_then(|request| request.exchange.signed_with.clone())
                    .into_iter()
                    .collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectRequiredCapabilities,
                effect.required_capabilities.clone(),
            );
            push(
                &owner,
                ProgramResourceField::EffectPromptResultType,
                effect.prompt_result_type.iter().cloned().collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectTurnSkills,
                effect.turn_skills.clone(),
            );
            push(
                &owner,
                ProgramResourceField::EffectOnStream,
                effect.on_stream.iter().cloned().collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectSelectionSource,
                effect.selection_source.iter().cloned().collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectTransportOnto,
                effect.transport_onto.iter().cloned().collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectResources,
                effect.resources.clone(),
            );
            push(
                &owner,
                ProgramResourceField::EffectWorkflowTarget,
                effect.workflow_target.iter().cloned().collect(),
            );
            push(
                &owner,
                ProgramResourceField::EffectExecPrincipal,
                effect
                    .exec_target
                    .as_ref()
                    .map(|target| target.principal())
                    .into_iter()
                    .collect(),
            );
            let grants = effect
                .access_grants
                .iter()
                .map(|grant| {
                    serde_json::to_string(&(
                        grant.resource.as_str(),
                        grant
                            .operations
                            .iter()
                            .map(|op| (op.operation.as_str(), op.target.as_deref(), &op.globs))
                            .collect::<Vec<_>>(),
                    ))
                    .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            push(&owner, ProgramResourceField::EffectTurnAccessGrants, grants);
        }
    }
    let json = serde_json::to_vec(&examined).map_err(|error| error.to_string())?;
    Ok(ProgramResourceFieldCapture {
        scope: ProgramResourceFieldScope::DeclaredFieldsAgentEffectAndTurnAccessV5,
        examined,
        digest: sha256_hex(&json),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_store::program_imports::ProgramResourceFieldMeaning;

    fn checked(source: &str) -> ProgramResourceFieldCapture {
        let compiled = whipplescript_parser::compile_program(source);
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        capture(&compiled.ir.unwrap()).unwrap()
    }

    #[test]
    fn resource_fields_keep_omitted_clauses_and_field_meanings() {
        let channel = checked(include_str!("../../../examples/messaging-demo.whip"));
        assert!(channel.examined.iter().any(|use_site| {
            use_site.owner == "ops_room"
                && use_site.field == ProgramResourceField::ChannelDestination
                && use_site.meaning == ProgramResourceFieldMeaning::ProviderDestinationSelector
                && use_site.values == ["#ops"]
        }));
        assert!(channel.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::ChannelWorkspace && use_site.values.is_empty()
        }));
        let files = checked(include_str!("../../../examples/file-store-demo.whip"));
        assert!(files.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::FileStoreRoot
                && use_site.meaning == ProgramResourceFieldMeaning::LocalRootPath
                && use_site.values == ["./.whipplescript/filestore-demo"]
        }));
        assert_eq!(
            files
                .examined
                .iter()
                .filter(|use_site| use_site.owner == "notes_store")
                .count(),
            3
        );
        let source = checked(include_str!("../../../examples/ingress-http-source.whip"));
        assert!(source.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::SourceUrl
                && use_site.meaning == ProgramResourceFieldMeaning::HttpFetchEndpoint
                && use_site.values == ["http://127.0.0.1:8080/feed.json"]
        }));
        assert!(source.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::SourceAuthSecret && use_site.values.is_empty()
        }));
        let file_source = checked(include_str!("../../../examples/ingress-file-source.whip"));
        assert!(file_source.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::SourcePath
                && use_site.meaning == ProgramResourceFieldMeaning::LocalFileInput
                && use_site.values == ["./inbox.txt"]
        }));
        assert!(file_source.examined.iter().any(|use_site| {
            use_site.field == ProgramResourceField::SourceWatch && use_site.values.is_empty()
        }));
    }

    #[test]
    fn agent_selector_fields_are_inventoried_without_claiming_live_edges() {
        let compiled = whipplescript_parser::compile_program(include_str!(
            "../../../examples/subworkflow-tool-consumer.whip"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let mut program = compiled.ir.unwrap();
        let worker = program
            .agents
            .iter_mut()
            .find(|agent| agent.name == "worker")
            .unwrap();
        worker.skills = vec!["code-reviewer".into()];
        worker.capabilities = vec!["repo.read".into()];
        worker.requires = vec!["session.resume".into()];
        worker.returns = Some("ReviewResult".into());
        let capture = capture(&program).unwrap();
        assert_eq!(
            capture.scope,
            ProgramResourceFieldScope::DeclaredFieldsAgentEffectAndTurnAccessV5
        );
        let worker_fields = capture
            .examined
            .iter()
            .filter(|field| field.owner == "worker")
            .collect::<Vec<_>>();
        assert_eq!(worker_fields.len(), 6);
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentTools
                && field.meaning == ProgramResourceFieldMeaning::WorkflowToolSelector
                && field.values == ["EchoText"]
        }));
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentSkills
                && field.meaning == ProgramResourceFieldMeaning::SkillSelector
                && field.values == ["code-reviewer"]
        }));
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentRequires
                && field.meaning == ProgramResourceFieldMeaning::ProviderFeatureSelector
                && field.values == ["session.resume"]
        }));
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentReturns
                && field.meaning == ProgramResourceFieldMeaning::ResultSchemaSelector
                && field.values == ["ReviewResult"]
        }));
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentProfile
                && field.meaning == ProgramResourceFieldMeaning::ProviderProfileSelector
                && field.values == ["repo-writer"]
        }));
        assert!(worker_fields.iter().any(|field| {
            field.field == ProgramResourceField::AgentCapabilities
                && field.meaning == ProgramResourceFieldMeaning::CapabilitySelector
                && field.values == ["repo.read"]
        }));
    }

    #[test]
    fn effect_http_and_mint_fields_keep_urls_and_marked_credential_handles() {
        use whipplescript_parser::{IrMintCredential, IrRequestHeader};

        let compiled = whipplescript_parser::compile_program(include_str!(
            "../../../examples/subworkflow-tool-consumer.whip"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let mut program = compiled.ir.unwrap();
        let rule_index = program
            .rules
            .iter()
            .position(|rule| !rule.metadata.effects.is_empty())
            .unwrap();
        let owner = serde_json::to_string(&(
            program.rules[rule_index].name.as_str(),
            program.rules[rule_index].metadata.effects[0].id.as_str(),
        ))
        .unwrap();
        let effect = &mut program.rules[rule_index].metadata.effects[0];
        effect.kind = IrEffectKind::HttpRequest;
        effect.http_request = Some(IrHttpRequest {
            method: "POST".into(),
            url: "endpoint_expression".into(),
            headers: vec![IrRequestHeader {
                name: "Authorization".into(),
                value: IrRequestHeaderValue::Credential {
                    presentation: "bearer".into(),
                    handle: "request_key".into(),
                },
            }],
            body: None,
            signed_with: Some("signing_key".into()),
        });
        let http = capture(&program).unwrap();
        let fields = http
            .examined
            .iter()
            .filter(|field| field.owner == owner)
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 17);
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectHttpUrl
                && field.meaning == ProgramResourceFieldMeaning::HttpRequestUrlExpression
                && field.values == ["endpoint_expression"]
        }));
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectHttpHeaderCredentials
                && field.values == ["request_key"]
        }));
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectHttpSignedWith
                && field.values == ["signing_key"]
        }));

        let effect = &mut program.rules[rule_index].metadata.effects[0];
        effect.kind = IrEffectKind::MintCredential;
        let exchange = effect.http_request.take().unwrap();
        effect.mint_credential = Some(IrMintCredential {
            parent: "parent_key".into(),
            exchange,
            token_path: "$.token".into(),
            public_paths: vec![],
        });
        let mint = capture(&program).unwrap();
        let fields = mint
            .examined
            .iter()
            .filter(|field| field.owner == owner)
            .collect::<Vec<_>>();
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectMintParent && field.values == ["parent_key"]
        }));
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectMintExchangeUrl
                && field.values == ["endpoint_expression"]
        }));
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectMintExchangeHeaderCredentials
                && field.values == ["request_key"]
        }));
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectMintExchangeSignedWith
                && field.values == ["signing_key"]
        }));

        let effect = &mut program.rules[rule_index].metadata.effects[0];
        let exchange = effect.mint_credential.take().unwrap().exchange;
        assert!(capture(&program).unwrap_err().contains("incomplete HTTP"));
        let effect = &mut program.rules[rule_index].metadata.effects[0];
        effect.kind = IrEffectKind::AgentTell;
        effect.http_request = Some(exchange);
        assert!(capture(&program).unwrap_err().contains("another kind"));
    }

    #[test]
    fn effect_selectors_keep_exact_source_values_and_refuse_wrong_kinds() {
        use whipplescript_parser::IrExecTarget;

        let compiled = whipplescript_parser::compile_program(include_str!(
            "../../../examples/subworkflow-tool-consumer.whip"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let base = compiled.ir.unwrap();
        let rule = base
            .rules
            .iter()
            .position(|rule| !rule.metadata.effects.is_empty())
            .unwrap();
        let owner = serde_json::to_string(&(
            base.rules[rule].name.as_str(),
            base.rules[rule].metadata.effects[0].id.as_str(),
        ))
        .unwrap();
        let values = |capture: &ProgramResourceFieldCapture, field| {
            capture
                .examined
                .iter()
                .find(|use_site| use_site.owner == owner && use_site.field == field)
                .unwrap()
                .values
                .clone()
        };

        let mut tell = base.clone();
        let effect = &mut tell.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::AgentTell;
        effect.workflow_target = None;
        effect.exec_target = None;
        effect.prompt_result_type = None;
        effect.selection_source = None;
        effect.transport_onto = None;
        effect.required_capabilities = vec!["repo.read".into()];
        effect.turn_skills = vec!["reviewer".into()];
        effect.on_stream = Some("review-branch".into());
        effect.resources = vec!["repo".into(), "ticket".into()];
        let tell_capture = capture(&tell).unwrap();
        assert_eq!(
            values(
                &tell_capture,
                ProgramResourceField::EffectRequiredCapabilities
            ),
            ["repo.read"]
        );
        assert_eq!(
            values(&tell_capture, ProgramResourceField::EffectTurnSkills),
            ["reviewer"]
        );
        assert_eq!(
            values(&tell_capture, ProgramResourceField::EffectOnStream),
            ["review-branch"]
        );
        assert_eq!(
            values(&tell_capture, ProgramResourceField::EffectResources),
            ["repo", "ticket"]
        );

        let mut granted = tell.clone();
        granted.rules[rule].metadata.effects[0].access_grants =
            vec![whipplescript_parser::IrAccessGrant {
                resource: "credential key".into(),
                operations: vec![whipplescript_parser::IrAccessGrantOp {
                    operation: "unwrap".into(),
                    target: Some("Record".into()),
                    globs: vec![],
                }],
            }];
        let granted_capture = capture(&granted).unwrap();
        let exact_grant = serde_json::to_string(&(
            "credential key",
            vec![("unwrap", Some("Record"), Vec::<String>::new())],
        ))
        .unwrap();
        assert_eq!(
            values(
                &granted_capture,
                ProgramResourceField::EffectTurnAccessGrants
            ),
            [exact_grant]
        );
        granted.rules[rule].metadata.effects[0].access_grants[0].operations[0].target =
            Some("OtherRecord".into());
        assert_ne!(granted_capture.digest, capture(&granted).unwrap().digest);

        let effect = &mut granted.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::TimerWait;
        effect.turn_skills.clear();
        effect.on_stream = None;
        assert!(capture(&granted)
            .unwrap_err()
            .contains("turn access grant on another kind"));

        let mut invoke = tell.clone();
        let effect = &mut invoke.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::WorkflowInvoke;
        effect.turn_skills.clear();
        effect.on_stream = None;
        effect.workflow_target = Some("ReviewChild".into());
        let invoke_capture = capture(&invoke).unwrap();
        assert_eq!(
            values(&invoke_capture, ProgramResourceField::EffectWorkflowTarget),
            ["ReviewChild"]
        );

        let mut exec = invoke.clone();
        let effect = &mut exec.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::ExecCommand;
        effect.workflow_target = None;
        effect.exec_target = Some(IrExecTarget::Capability {
            name: "deploy".into(),
        });
        let exec_capture = capture(&exec).unwrap();
        assert_eq!(
            values(&exec_capture, ProgramResourceField::EffectExecPrincipal),
            ["script:deploy"]
        );
        exec.rules[rule].metadata.effects[0].exec_target = Some(IrExecTarget::Raw);
        let raw_capture = capture(&exec).unwrap();
        assert_eq!(
            values(&raw_capture, ProgramResourceField::EffectExecPrincipal),
            ["exec:raw"]
        );
        assert_ne!(exec_capture.digest, raw_capture.digest);

        let mut selective = tell.clone();
        let effect = &mut selective.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::CapabilityCall;
        effect.turn_skills.clear();
        effect.on_stream = None;
        effect.selection_source = Some("selected_units".into());
        effect.transport_onto = Some("mainline".into());
        let selective_capture = capture(&selective).unwrap();
        assert_eq!(
            values(
                &selective_capture,
                ProgramResourceField::EffectSelectionSource
            ),
            ["selected_units"]
        );
        assert_eq!(
            values(
                &selective_capture,
                ProgramResourceField::EffectTransportOnto
            ),
            ["mainline"]
        );

        let mut prompt = tell.clone();
        let effect = &mut prompt.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::SchemaCoerce;
        effect.turn_skills.clear();
        effect.on_stream = None;
        effect.prompt_result_type = Some("ReviewResult".into());
        let prompt_capture = capture(&prompt).unwrap();
        assert_eq!(
            values(
                &prompt_capture,
                ProgramResourceField::EffectPromptResultType
            ),
            ["ReviewResult"]
        );

        tell.rules[rule].metadata.effects[0].exec_target = Some(IrExecTarget::Raw);
        assert!(capture(&tell)
            .unwrap_err()
            .contains("incomplete target selector"));
        invoke.rules[rule].metadata.effects[0].workflow_target = None;
        assert!(capture(&invoke)
            .unwrap_err()
            .contains("incomplete target selector"));

        let mut unrelated = base;
        let effect = &mut unrelated.rules[rule].metadata.effects[0];
        effect.kind = IrEffectKind::TimerWait;
        effect.workflow_target = None;
        effect.on_stream = None;
        effect.turn_skills.clear();
        effect.prompt_result_type = None;
        effect.selection_source = None;
        effect.transport_onto = None;
        effect.exec_target = Some(IrExecTarget::Raw);
        assert!(capture(&unrelated)
            .unwrap_err()
            .contains("target selector on another kind"));
        let effect = &mut unrelated.rules[rule].metadata.effects[0];
        effect.exec_target = None;
        effect.turn_skills = vec!["unrelated-skill".into()];
        assert!(capture(&unrelated)
            .unwrap_err()
            .contains("unclassified effect selector"));
    }

    #[test]
    fn checked_workflow_grants_keep_resource_operations_and_globs() {
        let expected = serde_json::to_string(&(
            "project_files",
            vec![
                ("read", None::<&str>, vec!["docs/**"]),
                ("write", None::<&str>, vec!["reports/**"]),
            ],
        ))
        .unwrap();
        for root in ["ParentReview", "ReviewDocs"] {
            let compiled = whipplescript_parser::compile_program_with_root(
                include_str!("../../../examples/least-privilege-subagent.whip"),
                Some(root),
            );
            assert!(
                compiled.diagnostics.is_empty(),
                "{:?}",
                compiled.diagnostics
            );
            let capture = capture(&compiled.ir.unwrap()).unwrap();
            assert_eq!(
                capture.scope,
                ProgramResourceFieldScope::DeclaredFieldsAgentEffectAndTurnAccessV5
            );
            let grants = capture
                .examined
                .iter()
                .filter(|field| field.field == ProgramResourceField::EffectTurnAccessGrants)
                .flat_map(|field| &field.values)
                .collect::<Vec<_>>();
            assert_eq!(grants, [&expected], "root {root}");
        }
    }
}
