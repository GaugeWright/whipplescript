//! Source joins and local flow checks over the actual composition bodies.
//! Includes additive field clearance; complete admission remains separate.
use super::fact_producers;
use super::output_integrity::managed::incomplete;
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::NodeId;
use whipplescript_parser::SourceSpan;

type Reads = BTreeMap<String, BTreeSet<String>>;
pub(super) struct ImportedReads {
    pub by_rule: Reads,
    pub sites: BTreeMap<String, BTreeMap<NodeId, BTreeSet<String>>>,
}

pub(super) fn check(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
    imports: &[IrProgram],
) -> Vec<Diagnostic> {
    let context = ProgramContext::Composition(bodies.source());
    let extra = match imported_reads(bodies, context, imports) {
        Ok(reads) => reads,
        Err(errors) => return errors,
    };
    let facts = match fact_producers::reach_with_reads(bodies, verified, &extra.by_rule) {
        Ok(facts) => facts,
        Err(errors) => return errors,
    };
    let claims = match claim_endorsement::check(bodies, verified) {
        Ok(claims) => claims,
        Err(errors) => return errors,
    };
    let envelope = verified.envelope();
    let derived = signal_integrity(bodies, context, envelope, imports, &extra.by_rule);
    let mut diagnostics = Vec::new();
    for body in bodies.rules() {
        let name = body.rule.root.name.name.as_str();
        let marked_claims = &claims[name];
        let mut reads = fact_producers::own_reads(context, body);
        reads.extend(extra.by_rule.get(name).into_iter().flatten().cloned());
        for schema in fact_reads(body) {
            reads.extend(facts.get(&schema).into_iter().flatten().cloned());
        }
        let sinks = local_destinations(body, context);
        composition_selectors::check(body, context, envelope, &sinks, &mut diagnostics);
        for ((node, destination), sink) in sinks {
            let selection: Vec<_> = body
                .inventory
                .effects
                .get(&node)
                .map(|effect| effect.controls.iter().cloned().collect())
                .unwrap_or_default();
            let result = match sink {
                Some(sink) => {
                    fact_producers::carried(body, context, &facts, &sink.as_sink(), marked_claims)
                        .map(Some)
                }
                // Validate selection without certifying the absent payload or
                // allowing it to support marked-input narrowing.
                None => fact_producers::carried(
                    body,
                    context,
                    &facts,
                    &ManagedExecutorSink {
                        node,
                        resource: &destination,
                        payload: &[],
                        selection: &selection,
                    },
                    marked_claims,
                )
                .map(|_| None),
            };
            let carried = match result {
                Ok(carried) => carried,
                Err(error) => {
                    diagnostics.push(at_sink(*error, body, node));
                    continue;
                }
            };
            composition_fields::check(
                body,
                context,
                envelope,
                node,
                &destination,
                sink,
                &mut diagnostics,
            );
            let narrowed = carried
                .as_ref()
                .filter(|carried| carried.attributed && carried.marked);
            let sources = narrowed.map_or(&reads, |carried| &carried.sources);
            let declassified = carried.as_ref().is_some_and(|carried| carried.declassified);
            let endorsed = carried.as_ref().is_some_and(|carried| carried.endorsed);
            let mut leak = None;
            let mut inject = None;
            for source in sources {
                if leak.is_none()
                    && source_flow::leaks(envelope, source, &destination, declassified)
                {
                    leak = Some(source);
                }
                let carried_integrity =
                    if source.starts_with("signal:") && envelope.is_internal_signal(source) {
                        Some(
                            derived
                                .get(source)
                                .cloned()
                                .unwrap_or_else(|| Some(envelope.integrity_set(source))),
                        )
                    } else {
                        None
                    };
                if inject.is_none()
                    && source_flow::injects(
                        envelope,
                        source,
                        &destination,
                        carried_integrity.as_ref(),
                        endorsed,
                    )
                {
                    let label = carried_integrity.unwrap_or_else(|| {
                        Some(
                            envelope
                                .integrity_set(source.strip_prefix("output:").unwrap_or(source)),
                        )
                    });
                    inject = Some((source, carried_label(&label)));
                }
            }
            let span = body.rule.typed.plan.nodes[node.0].span;
            if let Some(source) = leak {
                diagnostics.push(at_sink(
                    source_flow::leak_diagnostic(
                        name,
                        span,
                        source,
                        &destination,
                        narrowed.is_some(),
                        envelope,
                    ),
                    body,
                    node,
                ));
            }
            if let Some((source, label)) = inject {
                diagnostics.push(at_sink(
                    source_flow::injection_diagnostic(
                        name,
                        span,
                        source,
                        &destination,
                        &label,
                        envelope,
                    ),
                    body,
                    node,
                ));
            }
        }
        for (node, effect) in &body.rule.typed.effects {
            if effect.contract.kind != IrEffectKind::SchemaCoerce {
                continue;
            }
            let declaration = effect.contract.coerce_target.as_deref().and_then(|target| {
                context
                    .coerces()
                    .iter()
                    .find(|declaration| declaration.name == target)
            });
            let start = diagnostics.len();
            provider_egress::coerce(
                name,
                body.rule.typed.plan.nodes[node.0].span,
                super::coerce_principal(effect.contract.prompt_provider.as_deref(), declaration),
                declaration,
                reads.iter().map(String::as_str),
                envelope,
                &mut diagnostics,
            );
            for diagnostic in &mut diagnostics[start..] {
                managed_call_context(diagnostic, &body.rule.typed.plan, *node);
            }
        }
    }
    diagnostics
}

pub(super) fn local_destinations<'a>(
    body: &'a RuleBodyAnalysis<'_>,
    context: ProgramContext<'_>,
) -> BTreeMap<(NodeId, String), Option<&'a ManagedOwnedSink>> {
    let shared = shared_coordination_resources_in(context);
    let declared = declared_resources_in(context);
    // A source-flow write need not carry an explicit value payload: opaque
    // tool grants and credential/coordination effects still cross a door.
    let mut sinks: BTreeMap<_, Option<&ManagedOwnedSink>> = body
        .inventory
        .local
        .iter()
        .map(|sink| ((sink.node, sink.resource.clone()), Some(sink)))
        .collect();
    for (id, effect) in &body.inventory.effects {
        let flow = effect_flow(&effect.kind);
        if flow.writes_resource {
            for resource in &effect.resources {
                if let Some(resource) = resource_for_ifc(&effect.kind, resource, &shared) {
                    sinks.entry((*id, resource.into())).or_default();
                }
            }
        }
        if flow.emits_stream {
            sinks.entry((*id, "stream".into())).or_default();
        }
        for grant in &body.rule.typed.effects[id].contract.access_grants {
            if grant
                .operations
                .iter()
                .any(|op| classify_op(&op.operation, declared.contains(grant.resource.as_str())).1)
            {
                sinks.entry((*id, grant.resource.clone())).or_default();
            }
        }
    }
    sinks
}

pub(super) fn at_sink(
    mut error: Diagnostic,
    body: &RuleBodyAnalysis<'_>,
    node: NodeId,
) -> Diagnostic {
    let plan = &body.rule.typed.plan;
    let span = plan.nodes.get(node.0).map_or(error.span, |node| node.span);
    if error.span != (SourceSpan { start: 0, end: 0 }) && error.span != span {
        error.related.push(RelatedInfo {
            span: error.span,
            message: "source value originates here".into(),
        });
    }
    error.span = span;
    if plan.nodes.get(node.0).is_some() && plan.validate_structure().is_ok() {
        managed_call_context(&mut error, plan, node);
    }
    error
}

pub(super) fn fact_reads(body: &RuleBodyAnalysis<'_>) -> BTreeSet<String> {
    body.rule
        .root
        .fact_reads
        .iter()
        .filter_map(|read| read.strip_prefix("schema:").map(str::to_owned))
        .chain(
            body.rule
                .root
                .projection_reads
                .iter()
                .filter(|read| read.kind == QueryKind::Fact)
                .map(|read| read.head.clone()),
        )
        .collect()
}

fn unique<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

pub(super) fn imported_reads(
    bodies: &CompositionBodies<'_>,
    context: ProgramContext<'_>,
    imports: &[IrProgram],
) -> Result<ImportedReads, Vec<Diagnostic>> {
    let mut reads = Reads::new();
    let mut sites: BTreeMap<String, BTreeMap<NodeId, BTreeSet<String>>> = BTreeMap::new();
    let mut errors = Vec::new();
    for body in bodies.rules() {
        let rule_reads = reads.entry(body.rule.root.name.name.clone()).or_default();
        for (node, effect) in &body.rule.typed.effects {
            for target in effect.agent_targets.iter().flatten() {
                let Some(agent) = unique(
                    context
                        .agents()
                        .iter()
                        .filter(|agent| agent.name == *target),
                ) else {
                    errors.push(at_sink(
                        *incomplete(&format!(
                            "source-flow target `{target}` requires one actual agent declaration"
                        )),
                        body,
                        *node,
                    ));
                    continue;
                };
                for name in &agent.tools {
                    let Some(tool) = unique(imports.iter().filter(|tool| tool.workflow == *name))
                    else {
                        errors.push(at_sink(
                            *incomplete(&format!(
                                "source-flow tool `{name}` requires one complete imported program"
                            )),
                            body,
                            *node,
                        ));
                        continue;
                    };
                    let imported = result_dependency_reads(tool);
                    rule_reads.extend(imported.iter().cloned());
                    sites
                        .entry(body.rule.root.name.name.clone())
                        .or_default()
                        .entry(*node)
                        .or_default()
                        .extend(imported);
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(ImportedReads {
        by_rule: reads,
        sites,
    })
}

fn signal_integrity(
    bodies: &CompositionBodies<'_>,
    context: ProgramContext<'_>,
    envelope: &Envelope,
    imports: &[IrProgram],
    extra: &Reads,
) -> BTreeMap<String, CarriedIntegrity> {
    let mut derived = derived_signal_integrity(&imports.iter().collect::<Vec<_>>(), envelope);
    for body in bodies.rules() {
        let mut reads = fact_producers::own_reads(context, body);
        reads.extend(
            extra
                .get(&body.rule.root.name.name)
                .into_iter()
                .flatten()
                .cloned(),
        );
        reads.extend(
            fact_reads(body)
                .iter()
                .filter_map(|schema| fact_producers::governed_token(schema, envelope)),
        );
        let carried = reads.iter().fold(None, |acc, source| {
            meet_integrity(acc, Some(envelope.integrity_set(source)))
        });
        for effect in body
            .inventory
            .effects
            .values()
            .filter(|effect| effect_flow(&effect.kind).emits_stream)
        {
            for port in effect
                .resources
                .iter()
                .filter(|resource| resource.starts_with("signal:"))
            {
                let merged = match derived.remove(port) {
                    None => carried.clone(),
                    Some(previous) => meet_integrity(previous, carried.clone()),
                };
                derived.insert(port.clone(), merged);
            }
        }
    }
    derived
}
