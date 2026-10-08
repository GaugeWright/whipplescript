//! Compiler-owned resource-field inventory for checked admission (RC-1).
//!
//! These are exact source spellings with field-specific meanings. A path,
//! endpoint, destination, credential or agent selector is not an external
//! revision pin or live update edge without its host binding and admitting
//! operation.

use whipplescript_parser::{IrAgent, IrChannel, IrFileStore, IrProgram, IrSource};
use whipplescript_store::program_imports::{
    ProgramResourceField, ProgramResourceFieldCapture, ProgramResourceFieldScope,
    ProgramResourceFieldUse,
};

use crate::exec_http::sha256_hex;

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
        rules: _,
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
    let json = serde_json::to_vec(&examined).map_err(|error| error.to_string())?;
    Ok(ProgramResourceFieldCapture {
        scope: ProgramResourceFieldScope::DeclaredFieldsAndAgentSelectorsV2,
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
            ProgramResourceFieldScope::DeclaredFieldsAndAgentSelectorsV2
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
}
