//! Compiler-owned provider selector inventory for checked admission (RC-1).
//!
//! These are local selectors and use-site links. No selector by itself proves
//! the external provider identity, a live update edge, or a closed Home roster.

use whipplescript_parser::{
    IrAgent, IrChannel, IrCoerce, IrEffectKind, IrEffectNode, IrFileStore, IrHarness, IrProgram,
    IrSource, IrTracker, IrVault,
};
use whipplescript_store::program_imports::{
    ProgramProviderBindingCapture, ProgramProviderBindingScope, ProgramProviderBindingSite,
    ProgramProviderBindingUse, ProgramProviderTargetResolution,
};

use crate::exec_http::sha256_hex;

pub fn capture(program: &IrProgram) -> Result<ProgramProviderBindingCapture, String> {
    // An added top-level IR population must be classified before this witness
    // can continue to claim that it examined the compiler's provider paths.
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
        harnesses,
        trackers,
        streams: _,
        regions: _,
        channels,
        credentials: _,
        vaults,
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
        coerces,
        assertions: _,
        rules,
        rule_dependencies: _,
        measure_declarations: _,
        measures: _,
    } = program;
    let mut examined = Vec::new();
    let mut push = |site| {
        examined.push(ProgramProviderBindingUse {
            occurrence: examined.len(),
            site,
        });
    };
    for declaration in harnesses {
        let IrHarness {
            name,
            kind,
            span: _,
        } = declaration;
        push(ProgramProviderBindingSite::Harness {
            name: name.clone(),
            kind: kind.clone(),
        });
    }
    for declaration in trackers {
        let IrTracker {
            name,
            provider,
            span: _,
        } = declaration;
        push(ProgramProviderBindingSite::Tracker {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for declaration in channels {
        let IrChannel {
            name,
            provider,
            workspace: _,
            destination: _,
            span: _,
        } = declaration;
        push(ProgramProviderBindingSite::Channel {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for declaration in vaults {
        let IrVault {
            name,
            kind: _,
            allow: _,
            retain: _,
            provider,
            span: _,
        } = declaration;
        push(ProgramProviderBindingSite::Vault {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for declaration in file_stores {
        let IrFileStore {
            name,
            root: _,
            read_globs: _,
            write_globs: _,
            provider,
        } = declaration;
        push(ProgramProviderBindingSite::FileStore {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for declaration in sources {
        let IrSource {
            name,
            provider,
            is_clock: _,
            is_file: _,
            is_http: _,
            recurrence: _,
            timezone: _,
            missed: _,
            path: _,
            watch: _,
            url: _,
            dedup_field: _,
            endpoint: _,
            auth_mode: _,
            auth_secret: _,
            verified_credential: _,
            correlate_field: _,
            observe_binding: _,
            emit_signal: _,
            emit_from: _,
            emit_fields: _,
            span: _,
        } = declaration;
        push(ProgramProviderBindingSite::Source {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for declaration in agents {
        let IrAgent {
            name,
            span: _,
            harness,
            provider,
            profile: _,
            capacity: _,
            skills: _,
            capabilities: _,
            requires: _,
            tools: _,
            compaction: _,
            thread: _,
            settings: _,
            returns: _,
            harness_class: _,
        } = declaration;
        if let Some(binding) = harness {
            if !harnesses.iter().any(|candidate| candidate.name == *binding) {
                return Err(format!(
                    "agent `{}` names an unregistered harness `{}`",
                    name, binding
                ));
            }
        }
        if provider.is_some() && harness.is_some() {
            return Err(format!(
                "agent `{}` names both a provider and a harness",
                name
            ));
        }
        push(ProgramProviderBindingSite::Agent {
            name: name.clone(),
            provider: provider.clone(),
            harness: harness.clone(),
        });
    }
    for declaration in coerces {
        let IrCoerce {
            name,
            span: _,
            params: _,
            output: _,
            body: _,
            provider,
        } = declaration;
        push(ProgramProviderBindingSite::Coerce {
            name: name.clone(),
            provider: provider.clone(),
        });
    }
    for rule in rules {
        for effect in &rule.metadata.effects {
            let IrEffectNode {
                id,
                kind,
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
                agent,
                coerce_target,
                prompt_provider,
                workflow_target: _,
                endorsed: _,
                declassified: _,
                selected_by: _,
                exec_target: _,
                http_request: _,
                mint_credential: _,
            } = effect;
            match kind {
                IrEffectKind::AgentTell => {
                    let target = agent.as_ref().ok_or_else(|| {
                        format!("agent.tell effect `{}` has no provider-binding target", id)
                    })?;
                    let target_resolution =
                        if agents.iter().any(|declaration| declaration.name == *target) {
                            ProgramProviderTargetResolution::StaticDeclaration
                        } else {
                            ProgramProviderTargetResolution::DynamicExpression
                        };
                    if coerce_target.is_some() || prompt_provider.is_some() {
                        return Err(format!(
                            "agent.tell effect `{}` has an unrelated provider binding",
                            id
                        ));
                    }
                    push(ProgramProviderBindingSite::AgentTell {
                        rule: rule.name.clone(),
                        effect: id.clone(),
                        agent: target.clone(),
                        target_resolution,
                    });
                }
                IrEffectKind::SchemaCoerce => {
                    if agent.is_some() || (coerce_target.is_some() && prompt_provider.is_some()) {
                        return Err(format!(
                            "schema.coerce effect `{}` has conflicting provider bindings",
                            id
                        ));
                    }
                    if let Some(target) = coerce_target {
                        if !coerces
                            .iter()
                            .any(|declaration| declaration.name == *target)
                        {
                            return Err(format!(
                                "schema.coerce effect `{}` names an unregistered coerce `{}`",
                                id, target
                            ));
                        }
                    }
                    push(ProgramProviderBindingSite::SchemaCoerce {
                        rule: rule.name.clone(),
                        effect: id.clone(),
                        declaration: coerce_target.clone(),
                        prompt_provider: prompt_provider.clone(),
                    });
                }
                IrEffectKind::CapabilityCall
                | IrEffectKind::EventEmit
                | IrEffectKind::WorkflowInvoke
                | IrEffectKind::TimerWait
                | IrEffectKind::ExecCommand
                | IrEffectKind::HttpRequest
                | IrEffectKind::MintCredential
                | IrEffectKind::RotateCredential
                | IrEffectKind::RevokeCredential
                | IrEffectKind::TrackerFile
                | IrEffectKind::TrackerClaim
                | IrEffectKind::TrackerRenew
                | IrEffectKind::TrackerRelease
                | IrEffectKind::TrackerFinish
                | IrEffectKind::TrackerMembership
                | IrEffectKind::TrackerInspect
                | IrEffectKind::LeaseAcquire
                | IrEffectKind::LeaseRenew
                | IrEffectKind::LedgerAppend
                | IrEffectKind::CounterConsume
                | IrEffectKind::SignalEmit
                | IrEffectKind::FileRead
                | IrEffectKind::FileWrite
                | IrEffectKind::FileImport
                | IrEffectKind::FileExport => {
                    if agent.is_some() || coerce_target.is_some() || prompt_provider.is_some() {
                        return Err(format!(
                            "effect `{}` has an unclassified provider binding",
                            id
                        ));
                    }
                }
            }
        }
    }
    let json = serde_json::to_vec(&examined).map_err(|error| error.to_string())?;
    Ok(ProgramProviderBindingCapture {
        scope: ProgramProviderBindingScope::DeclarationsAndEffectsV1,
        examined,
        digest: sha256_hex(&json),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled_capture(source: &str) -> ProgramProviderBindingCapture {
        let compiled = whipplescript_parser::compile_program(source);
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        capture(&compiled.ir.unwrap()).unwrap()
    }

    #[test]
    fn provider_inventory_covers_every_current_declaration_family() {
        let harness = compiled_capture(
            "workflow HarnessSelector\nharness coder: codex\nagent writer using coder {\n  profile \"repo-writer\"\n  capacity 1\n}\n",
        );
        assert!(harness.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Harness { name, kind }
                if name == "coder" && kind == "codex"
        )));
        assert!(harness.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Agent { name, harness: Some(binding), provider: None }
                if name == "writer" && binding == "coder"
        )));
        let mut duplicated = whipplescript_parser::compile_program(
            "workflow HarnessSelector\nharness coder: codex\nagent writer using coder {\n  profile \"repo-writer\"\n  capacity 1\n}\n",
        )
        .ir
        .unwrap();
        duplicated.agents[0].provider = Some("codex".into());
        assert!(capture(&duplicated)
            .unwrap_err()
            .contains("names both a provider and a harness"));
        duplicated.agents[0].provider = None;
        duplicated.agents[0].harness = Some("missing".into());
        assert!(capture(&duplicated)
            .unwrap_err()
            .contains("names an unregistered harness"));

        let channel = compiled_capture(include_str!("../../../examples/messaging-demo.whip"));
        assert!(channel.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Channel { name, provider }
                if name == "ops_room" && provider == "fixture"
        )));

        let files = compiled_capture(include_str!("../../../examples/file-store-demo.whip"));
        assert!(files.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::FileStore { name, provider: None }
                if name == "notes_store"
        )));

        let source = compiled_capture(include_str!("../../../examples/clock-source.whip"));
        assert!(source.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Source { name, provider }
                if name == "daily_triage" && provider == "clock"
        )));

        let coerce = compiled_capture(include_str!(
            "../../../examples/reactive-ticket-review.whip"
        ));
        assert!(coerce.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Coerce { name, provider: None }
                if name == "parseInvestigation"
        )));
        assert!(coerce.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::SchemaCoerce {
                declaration: Some(name),
                prompt_provider: None,
                ..
            } if name == "parseInvestigation"
        )));
        let mut conflicted = whipplescript_parser::compile_program(include_str!(
            "../../../examples/reactive-ticket-review.whip"
        ))
        .ir
        .unwrap();
        conflicted
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::SchemaCoerce)
            .unwrap()
            .agent = Some("invented-agent".into());
        assert!(capture(&conflicted)
            .unwrap_err()
            .contains("conflicting provider bindings"));
        conflicted
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::SchemaCoerce)
            .unwrap()
            .agent = None;
        conflicted
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::SchemaCoerce)
            .unwrap()
            .coerce_target = Some("missing".into());
        assert!(capture(&conflicted)
            .unwrap_err()
            .contains("names an unregistered coerce"));

        let vault = compiled_capture(
            "use std.custody\nworkflow VaultSelector\nvault tenant_keys {\n  kind raw\n  allow [wrap, unwrap]\n  retain durable\n  provider openbao\n}\n",
        );
        assert!(vault.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Vault { name, provider: Some(provider) }
                if name == "tenant_keys" && provider == "openbao"
        )));

        let inline_prompt = compiled_capture(
            "workflow PromptText\noutput result string\nclass Ticket { title string }\nrule ask\n  when Ticket as ticket\n=> {\n  prompt \"Summarize {{ ticket.title }}\" using fixture as answer\n  after answer succeeds as text { complete result text }\n}\n",
        );
        assert!(inline_prompt.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::SchemaCoerce {
                declaration: None,
                prompt_provider: Some(provider),
                ..
            } if provider == "fixture"
        )));
    }

    #[test]
    fn provider_inventory_captures_declarations_and_use_sites_and_refuses_strays() {
        let compiled = whipplescript_parser::compile_program(include_str!(
            "../../../examples/package-memory.whip"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let mut program = compiled.ir.unwrap();
        let captured = capture(&program).unwrap();
        assert_eq!(
            captured.scope,
            ProgramProviderBindingScope::DeclarationsAndEffectsV1
        );
        assert!(captured.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Agent { name, provider: Some(provider), .. }
                if name == "worker" && provider == "codex"
        )));
        assert!(captured.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::AgentTell {
                rule,
                agent,
                target_resolution: ProgramProviderTargetResolution::StaticDeclaration,
                ..
            } if rule == "recall_before_work" && agent == "worker"
        )));
        let dynamic = compiled_capture(include_str!("../../../examples/incident-router.whip"));
        assert!(dynamic.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::AgentTell {
                agent,
                target_resolution: ProgramProviderTargetResolution::DynamicExpression,
                ..
            } if agent == "incident.assignee"
        )));
        assert!(captured.examined.iter().any(|entry| matches!(
            &entry.site,
            ProgramProviderBindingSite::Tracker { name, .. } if name == "backlog"
        )));

        let mut missing = program.clone();
        missing
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::AgentTell)
            .unwrap()
            .agent = None;
        assert!(capture(&missing)
            .unwrap_err()
            .contains("has no provider-binding target"));
        missing
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::AgentTell)
            .unwrap()
            .agent = Some("missing".into());
        assert!(capture(&missing)
            .unwrap()
            .examined
            .iter()
            .any(|entry| matches!(
                &entry.site,
                ProgramProviderBindingSite::AgentTell {
                    agent,
                    target_resolution: ProgramProviderTargetResolution::DynamicExpression,
                    ..
                } if agent == "missing"
            )));

        let mut unrelated = program.clone();
        unrelated
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::AgentTell)
            .unwrap()
            .prompt_provider = Some("invented-provider".into());
        assert!(capture(&unrelated)
            .unwrap_err()
            .contains("unrelated provider binding"));

        program
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::CapabilityCall)
            .unwrap()
            .prompt_provider = Some("invented".into());
        assert!(capture(&program)
            .unwrap_err()
            .contains("unclassified provider binding"));
    }
}
