//! Shared declaration dispatch. The private builder is not a complete program:
//! body lowering and whole-program checks must run before an executable exists.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingBody {
    Rule(RuleDecl),
    Table(TableDecl),
    Action(ActionDecl),
}

pub(super) struct Context<'a> {
    pub schema_names: &'a BTreeSet<String>,
    pub agent_names: &'a BTreeSet<String>,
    pub harness_kinds: &'a BTreeMap<String, String>,
    pub semantic: &'a SemanticContext,
}

pub(super) fn new_program(
    program: &Program,
    execution_semantics: ExecutionSemantics,
    pattern_applications: Vec<IrPatternApplication>,
    shared_coordination_usage: Vec<IrSharedCoordinationUsage>,
) -> IrProgram {
    // Both callers require a selected root; declaration analysis checks that
    // precondition before constructing this private builder.
    let workflow = program
        .workflow
        .as_ref()
        .expect("select_root_workflow admits only a program that has a root workflow")
        .name
        .clone();

    let mut ir = IrProgram {
        execution_semantics,
        workflow,
        source_tags: Vec::new(),
        source_descriptions: Vec::new(),
        includes: Vec::new(),
        pattern_applications,
        workflow_contracts: Vec::new(),
        uses: Vec::new(),
        harnesses: Vec::new(),
        trackers: Vec::new(),
        streams: Vec::new(),
        regions: Vec::new(),
        channels: Vec::new(),
        credentials: Vec::new(),
        vaults: Vec::new(),
        gauges: Vec::new(),
        marks: Vec::new(),
        campaigns: Vec::new(),
        file_stores: Vec::new(),
        memory_pools: Vec::new(),
        events: Vec::new(),
        sources: Vec::new(),
        tests: Vec::new(),
        leases: Vec::new(),
        ledgers: Vec::new(),
        counters: Vec::new(),
        shared_coordination_usage,
        schemas: Vec::new(),
        agents: Vec::new(),
        coerces: Vec::new(),
        assertions: Vec::new(),
        rules: Vec::new(),
        rule_dependencies: Vec::new(),
        measures: Vec::new(),
        measure_declarations: Vec::new(),
    };
    let workflow_tag_target = ir.workflow.clone();
    lower_source_tags(
        &program.workflow_tags,
        "workflow",
        &workflow_tag_target,
        &mut ir,
    );
    lower_source_description(
        program.workflow_description.as_ref(),
        "workflow",
        &workflow_tag_target,
        &mut ir,
    );

    ir
}

pub(super) fn lower_item(
    item: Item,
    context: &Context<'_>,
    ir: &mut IrProgram,
    diagnostics: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) -> Option<PendingBody> {
    match item {
        Item::Include(include) => lower_include(include, ir),
        Item::Measure(measure) => ir.measure_declarations.push(IrMeasureDeclaration {
            class: measure.class.name,
            field: measure.field.name,
            rising: measure.rising,
            bound: measure.bound,
            span: measure.span,
        }),
        Item::WorkflowContract(contract) => lower_workflow_contract(
            contract,
            ir,
            context.schema_names,
            context.agent_names,
            context.semantic,
            diagnostics,
        ),
        Item::Use(use_decl) => lower_use(use_decl, ir, diagnostics),
        // Legacy expansion has consumed actions; composition retains definitions.
        Item::Action(action) => return Some(PendingBody::Action(action)),
        // Pure parameterized views are captured in each managed plan. They do
        // not lower to independently scheduled IR declarations.
        Item::View(_) => {}
        Item::Pattern(pattern) => diagnostics.push(Diagnostic {
            code: diagnostic_code!("construct.invalid_declaration_scope"),
            severity: Severity::Error,
            related: Vec::new(),
            fixits: Vec::new(),
            span: pattern.span,
            message: format!(
                "pattern `{}` is not allowed inside this declaration scope",
                pattern.name.name
            ),
            suggestion: suggest("declare patterns at source top level".to_owned()),
        }),
        // `main` factored this refusal out so a test could pin it directly;
        // the extraction this module came from predates that, and inlining it
        // again left two copies of one diagnostic and the named one unused.
        Item::Apply(apply) => super::refuse_unexpanded_application(&apply, diagnostics),
        Item::Harness(harness) => lower_harness(harness, ir, diagnostics),
        Item::Tracker(queue) => lower_tracker(queue, ir, diagnostics),
        Item::Channel(channel) => lower_channel(channel, ir, diagnostics),
        Item::Credential(credential) => lower_credential(credential, ir, diagnostics),
        Item::Stream(stream) => lower_stream(stream, ir, diagnostics),
        Item::Region(region) => lower_region(region, ir, diagnostics),
        Item::Gauge(gauge) => lower_gauge(gauge, ir, diagnostics),
        Item::Mark(mark) => lower_mark(mark, ir, diagnostics),
        Item::Campaign(campaign) => lower_campaign(campaign, ir, diagnostics),
        // The `file store` declaration (capability-scoped store identity)
        // lowers to its name + literal root; the runtime file provider reads
        // `<root>/<path>` for `read` effects against this store.
        Item::Vault(vault) => lower_vault(vault, ir, diagnostics),
        Item::FileStore(file_store) => {
            // Conditioned check (spec/std-files.md "Static checks"): the
            // optional `provider <name>` clause must name a known file
            // provider. v1 ships exactly one — `local`, the FileStore
            // host-projection seam — and it is also the default when the
            // clause is absent. Unknown providers would lower to a store
            // no runtime seam backs, so they are rejected at check time.
            if let Some(provider) = &file_store.provider {
                if !FILE_STORE_PROVIDERS.contains(&provider.name.as_str()) {
                    diagnostics.push(Diagnostic {
                        code: diagnostic_code!("construct.unknown_provider"),
                        severity: Severity::Error,
                        related: Vec::new(),
                        fixits: Vec::new(),
                        span: provider.span,
                        message: format!(
                            "file store `{}` names unknown provider `{}`",
                            file_store.name.name, provider.name
                        ),
                        suggestion: suggest(crate::suggest_then_keyword(
                            &provider.name,
                            FILE_STORE_PROVIDERS.iter().copied(),
                            format!(
                                "declare one of the v1 file providers: {}",
                                FILE_STORE_PROVIDERS.join(", ")
                            ),
                        )),
                    });
                    // Fall through: the store still lowers so read/write
                    // sites do not cascade an unknown-store error on top.
                }
            }
            ir.file_stores.push(IrFileStore {
                name: file_store.name.name,
                root: file_store.root,
                read_globs: file_store.read_globs,
                write_globs: file_store.write_globs,
                provider: file_store.provider.map(|provider| provider.name),
            });
        }
        // The `memory pool` declaration (std.memory, MEM-1) lowers to its
        // name + optional recall context-limit budget; providers read the
        // limit from the `capability.call` effect input.
        Item::MemoryPool(pool) => {
            ir.memory_pools.push(IrMemoryPool {
                name: pool.name.name,
                context_limit: pool.context_limit,
            });
        }
        Item::Agent(agent) => lower_agent(
            agent,
            ir,
            context.harness_kinds,
            &context.semantic.schemas,
            diagnostics,
        ),
        Item::Enum(enum_decl) => lower_enum(enum_decl, ir, diagnostics),
        Item::Event(event) => lower_event(event, ir, diagnostics),
        Item::Source(source) => {
            validate_source_emit_signal_declared(
                &source,
                &context.semantic.schemas.events,
                diagnostics,
            );
            validate_source_verified_credential(
                &source,
                &context.semantic.credentials,
                diagnostics,
            );
            lower_source(*source, ir, diagnostics, warnings)
        }
        Item::Test(test) => lower_test(test, ir, diagnostics),
        Item::Lease(lease) => {
            if !context.schema_names.contains(&lease.key_type.name) {
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("type.unknown_schema"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    fixits: Vec::new(),
                    span: lease.key_type.span,
                    message: format!(
                        "lease `{}` keys on undeclared type `{}`",
                        lease.name.name, lease.key_type.name
                    ),
                    suggestion: suggest(crate::suggest_otherwise(
                        &lease.key_type.name,
                        context.schema_names.iter(),
                        "key a lease on an entity class the workflow already models",
                    )),
                });
            }
            ir.leases.push(IrLease {
                name: lease.name.name,
                key_type: lease.key_type.name,
                slots: lease.slots.max(1),
                ttl_seconds: lease.ttl_seconds,
                shared: lease.shared,
                span: lease.span,
            });
        }
        Item::Ledger(ledger) => {
            if !context.schema_names.contains(&ledger.entry_schema.name) {
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("type.unknown_schema"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    fixits: Vec::new(),
                    span: ledger.entry_schema.span,
                    message: format!(
                        "ledger `{}` records undeclared entry type `{}`",
                        ledger.name.name, ledger.entry_schema.name
                    ),
                    suggestion: suggest(crate::suggest_otherwise(
                        &ledger.entry_schema.name,
                        context.schema_names.iter(),
                        "declare the entry class before the ledger",
                    )),
                });
            }
            ir.ledgers.push(IrLedger {
                name: ledger.name.name,
                entry_schema: ledger.entry_schema.name,
                partition_field: ledger.partition_field.name,
                retain_seconds: ledger.retain_seconds,
                shared: ledger.shared,
                span: ledger.span,
            });
        }
        Item::Counter(counter) => {
            if !context.schema_names.contains(&counter.key_type.name) {
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("type.unknown_schema"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    fixits: Vec::new(),
                    span: counter.key_type.span,
                    message: format!(
                        "counter `{}` keys on undeclared type `{}`",
                        counter.name.name, counter.key_type.name
                    ),
                    suggestion: suggest(crate::suggest_otherwise(
                        &counter.key_type.name,
                        context.schema_names.iter(),
                        "key a counter on an entity class the workflow already models",
                    )),
                });
            }
            ir.counters.push(IrCounter {
                name: counter.name.name,
                key_type: counter.key_type.name,
                cap: counter.cap,
                reset: counter.reset,
                timezone: counter.timezone,
                shared: counter.shared,
                span: counter.span,
            });
        }
        Item::Class(class_decl) => lower_class(
            class_decl,
            ir,
            context.schema_names,
            context.agent_names,
            diagnostics,
        ),
        Item::Table(table) => {
            lower_source_tags(&table.tags, "table", &table.name.name, ir);
            lower_source_description(table.description.as_ref(), "table", &table.name.name, ir);
            return Some(PendingBody::Table(table));
        }
        Item::Coerce(coerce) => lower_coerce(
            coerce,
            ir,
            context.schema_names,
            context.agent_names,
            diagnostics,
        ),
        Item::Assert(assertion) => {
            let assertion_target = stable_hash(&assertion.expr);
            lower_source_tags(&assertion.tags, "assertion", &assertion_target, ir);
            lower_source_description(
                assertion.description.as_ref(),
                "assertion",
                &assertion_target,
                ir,
            );
            lower_assert(assertion, context.semantic, ir, diagnostics)
        }
        Item::Rule(rule) => {
            lower_source_tags(&rule.tags, "rule", &rule.name.name, ir);
            lower_source_description(rule.description.as_ref(), "rule", &rule.name.name, ir);
            return Some(PendingBody::Rule(rule));
        }
    }
    None
}

/// Actual lowered declarations and authored pending bodies. No program/IR
/// accessor, serialization, execution tag or body-validation claim is exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclarationAnalysis {
    ir: IrProgram,
    bodies: Vec<PendingBody>,
    warnings: Vec<Diagnostic>,
}
macro_rules! declaration_accessors {
    ($($name:ident: $ty:ty),* $(,)?) => {
        impl DeclarationAnalysis {
            $(pub fn $name(&self) -> &[$ty] { &self.ir.$name })*
        }
        #[cfg(test)]
        impl DeclarationAnalysis {
            fn assert_same_declarations(&self, ir: &IrProgram) {
                $(assert_eq!(self.$name(), ir.$name, "{}", stringify!($name));)*
                assert_eq!(self.workflow(), ir.workflow);
            }
        }
    };
}
declaration_accessors! {
    source_tags: IrSourceTag,
    source_descriptions: IrSourceDescription,
    includes: IrInclude,
    workflow_contracts: IrWorkflowContract,
    uses: IrUse,
    harnesses: IrHarness,
    trackers: IrTracker,
    streams: IrStream,
    regions: IrRegionDecl,
    channels: IrChannel,
    credentials: IrCredential,
    vaults: IrVault,
    gauges: IrGauge,
    marks: IrMark,
    campaigns: IrCampaign,
    file_stores: IrFileStore,
    memory_pools: IrMemoryPool,
    events: IrEvent,
    sources: IrSource,
    tests: IrTest,
    leases: IrLease,
    ledgers: IrLedger,
    counters: IrCounter,
    schemas: IrSchema,
    agents: IrAgent,
    coerces: IrCoerce,
    assertions: IrAssertion,
    measure_declarations: IrMeasureDeclaration,
}

impl DeclarationAnalysis {
    pub fn workflow(&self) -> &str {
        &self.ir.workflow
    }
    pub fn bodies(&self) -> &[PendingBody] {
        &self.bodies
    }
    pub fn warnings(&self) -> &[Diagnostic] {
        &self.warnings
    }
}

pub(crate) fn analyze(
    program: &Program,
    semantic: &SemanticContext,
) -> Result<DeclarationAnalysis, Vec<Diagnostic>> {
    if program.workflow.is_none() || !program.workflows.is_empty() {
        // Reuse missing/ambiguous-root diagnostics before reporting a violated
        // selection precondition; do not silently analyze another workflow.
        select_root_workflow(program.clone(), None)?;
        return Err(vec![Diagnostic::error(
            diagnostic_code!("construct.invalid_declaration_scope"),
            SourceSpan { start: 0, end: 0 },
            "composition analysis requires a selected root workflow".to_owned(),
        )]);
    }
    let mut diagnostics = Vec::new();
    let mut warnings = Vec::new();
    let schema_names = collect_schema_names(program, &mut diagnostics);
    let harness_kinds = collect_harness_kinds(program, &mut diagnostics);
    let agent_names = collect_agent_names(program, &mut diagnostics);
    collect_workflow_contract_names(program, &mut diagnostics);
    let context = Context {
        schema_names: &schema_names,
        agent_names: &agent_names,
        harness_kinds: &harness_kinds,
        semantic,
    };
    // This private work-in-progress IR is never exposed as an executable. Its
    // rule vector stays empty; complete body assembly retains its own contract.
    let mut ir = new_program(
        program,
        ExecutionSemantics::LegacyActionChainsV1,
        Vec::new(),
        Vec::new(),
    );
    let bodies = program
        .items
        .iter()
        .cloned()
        .filter_map(|item| lower_item(item, &context, &mut ir, &mut diagnostics, &mut warnings))
        .collect();
    validate_stream_memberships(&ir, &mut diagnostics);
    validate_regions(&ir, &mut diagnostics);
    expand_source_emit_from(&mut ir, &mut diagnostics);
    warn_counter_without_timezone(&ir, &mut warnings);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    debug_assert!(ir.rules.is_empty());
    Ok(DeclarationAnalysis {
        ir,
        bodies,
        warnings,
    })
}

#[cfg(test)]
mod tests;
