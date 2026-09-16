//! Authority ceilings over the real composition context and imported producers.
use super::program_context::ProgramContext;
use super::source_reads::ReadSite;
use super::*;

pub(super) fn principal(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
    identity: &str,
    imports: &[IrProgram],
) -> Vec<Diagnostic> {
    let envelope = verified.envelope();
    if !envelope.has_parties() {
        return Vec::new();
    }
    let role = envelope.role_for_principal(identity);
    let context = ProgramContext::Composition(bodies.source());
    let extra = match source_inputs::imported_reads(bodies, context, imports) {
        Ok(extra) => extra,
        Err(errors) => return errors,
    };
    let facts = match fact_producers::reach_with_reads(bodies, verified, &extra.by_rule) {
        Ok(facts) => facts,
        Err(errors) => return errors,
    };
    let mut errors = Vec::new();
    for body in bodies.rules() {
        let name = body.rule.root.name.name.as_str();
        let mut reads = source_reads::own(context, body);
        for schema in source_inputs::fact_reads(body) {
            let span = body
                .rule
                .root
                .whens
                .iter()
                .find(|when| when.pattern.split_whitespace().next() == Some(schema.as_str()))
                .or(body.rule.root.whens.first())
                .map(|when| when.span)
                .unwrap_or(body.rule.root.name.span);
            reads.extend(
                facts
                    .get(&schema)
                    .into_iter()
                    .flatten()
                    .map(|source| ReadSite {
                        source: source.clone(),
                        span,
                        node: None,
                    }),
            );
        }
        for (node, sources) in extra.sites.get(name).into_iter().flatten() {
            reads.extend(sources.iter().map(|source| ReadSite {
                source: source.clone(),
                span: body.rule.typed.plan.nodes[node.0].span,
                node: Some(*node),
            }));
        }
        // Deduplicate one read site without erasing distinct expanded calls.
        let mut seen = BTreeSet::new();
        for read in reads {
            if !seen.insert((
                read.node,
                read.span.start,
                read.span.end,
                read.source.clone(),
            )) {
                continue;
            }
            if let Some(mut error) =
                authority_policy::principal_read(name, read.span, &read.source, role, envelope)
            {
                if let Some(node) = read.node {
                    managed_call_context(&mut error, &body.rule.typed.plan, node);
                }
                errors.push(error);
            }
        }
    }
    errors
}

pub(super) fn unwrap(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
) -> Vec<Diagnostic> {
    let mut errors = Vec::new();
    for body in bodies.rules() {
        for (node, effect) in &body.rule.typed.effects {
            let start = errors.len();
            authority_policy::unwrap_grants(
                &body.rule.root.name.name,
                body.rule.typed.plan.nodes[node.0].span,
                &effect.contract.access_grants,
                verified.envelope(),
                &mut errors,
            );
            for error in &mut errors[start..] {
                managed_call_context(error, &body.rule.typed.plan, *node);
            }
        }
    }
    errors
}
