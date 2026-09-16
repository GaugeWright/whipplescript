//! Trigger analysis shared by legacy rules and managed composition. Root facts
//! and projections are only one component of complete program metadata.
use crate::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleRoot {
    pub name: Ident,
    pub kind: RuleKind,
    pub whens: Vec<IrWhen>,
    pub binding_schemas: BTreeMap<String, String>,
    pub fact_reads: Vec<String>,
    pub resource_reads: Vec<String>,
    pub projection_reads: Vec<IrProjectionRead>,
}

pub(crate) fn bindings(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, String> {
    let mut binding_types = BTreeMap::new();
    for when in &rule.whens {
        // A pattern that binds (`... as x`) but maps to no known readiness
        // form would otherwise be a silently-dead rule.
        let (pattern_text, _) = split_when_guard(&when.text);
        if binding_after_as(pattern_text).is_some()
            && binding_from_when(&when.text).is_none()
            && !pattern_text.ends_with(" is available")
        {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("parse.unsupported_when_pattern"),
                severity: Severity::Error,
                related: Vec::new(),
                fixits: Vec::new(),
                span: when.span,
                message: format!(
                    "rule `{}` has unknown readiness pattern `{pattern_text}`",
                    rule.name.name
                ),
                suggestion: suggest(
                    "match a class (`when Class as x`) or a runtime fact (`when fact <name> as x`)"
                        .to_owned(),
                ),
            });
        }
        if let Some((binding, schema)) = binding_from_when(&when.text) {
            validate_binding_name(rule, &binding, when.span, diagnostics);
            if !schema.contains('.') && !semantic.schemas.class_exists(&schema) {
                let suggestion = suggest_otherwise(
                    &schema,
                    semantic.schemas.classes.keys(),
                    format!("declare `class {schema}` before matching it"),
                );
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("type.unknown_schema"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    fixits: Vec::new(),
                    span: when.span,
                    message: format!("rule `{}` matches unknown class `{schema}`", rule.name.name),
                    suggestion: suggest(suggestion),
                });
            }
            // The bare dotted form is the typed signal reaction
            // (spec/event-ingress.md): it requires a declared `signal`;
            // undeclared dotted facts keep the untyped `when fact` form.
            if schema.contains('.')
                && !pattern_text.trim_start().starts_with("fact ")
                && !semantic.schemas.events.contains(&schema)
            {
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("type.unknown_signal"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    fixits: Vec::new(),
                    span: when.span,
                    message: format!(
                        "rule `{}` reacts to undeclared signal `{schema}`",
                        rule.name.name
                    ),
                    suggestion: suggest(suggest_otherwise(
                        &schema,
                        semantic.schemas.events.iter(),
                        format!(
                            "declare `signal {schema} {{ ... }}` for a typed reaction, or use `when fact {schema} as ...` for an untyped one"
                        ),
                    )),
                });
            }
            binding_types.insert(binding, schema);
        }
    }
    binding_types
}

pub(crate) fn guards(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<IrProjectionRead> {
    let mut projection_reads = Vec::new();
    for when in &rule.whens {
        if let (_, Some(guard)) = split_when_guard(&when.text) {
            // The guard is a slice of the `when` clause, and the clause is a
            // verbatim slice of the file when the parser cut it from one, so a
            // finding inside the guard can name the guard rather than the whole
            // clause (D10). A synthesized clause records no origin and every
            // finding lands on the clause, exactly as before.
            let guard_anchor = when_guard_anchor(when, guard);
            validate_expression(
                rule,
                guard,
                guard_anchor,
                semantic,
                binding_types,
                "guard",
                diagnostics,
            );
            validate_known_field_paths(
                rule,
                guard,
                guard_anchor,
                semantic,
                binding_types,
                known_roots,
                diagnostics,
            );
            if let Some(expr) = lower_expression(guard, when.span) {
                projection_reads.extend(collect_projection_reads(&expr.expr));
            }
        }
        validate_availability_when(
            rule,
            &when.text,
            when.span,
            semantic,
            binding_types,
            diagnostics,
        );
    }
    projection_reads
}

pub(crate) fn analyze(
    rule: &RuleDecl,
    semantic: &SemanticContext,
) -> Result<RuleRoot, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let binding_schemas = bindings(rule, semantic, &mut diagnostics);
    let inputs = inputs(rule);
    crate::action_plan::validate_rule_inputs(&inputs, &mut diagnostics);
    let roots = binding_schemas.keys().cloned().collect();
    let mut projection_reads = guards(rule, semantic, &binding_schemas, &roots, &mut diagnostics);
    // Availability targets are value paths, not Boolean guard expressions.
    // The shared type check alone returns early for an unresolved dotted path.
    for when in &rule.whens {
        let (pattern, _) = split_when_guard(&when.text);
        if let Some(target) = pattern.strip_suffix(" is available").map(str::trim) {
            validate_known_field_paths(
                rule,
                target,
                when_guard_anchor(when, target),
                semantic,
                &binding_schemas,
                &roots,
                &mut diagnostics,
            );
        }
    }
    validate_message_from_channels(rule, semantic, &mut diagnostics);
    validate_evidence_fact_not_matched(rule, &mut diagnostics);
    collapse_general_unknown_bindings(&mut diagnostics, 0);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    sort_projection_reads(&mut projection_reads);
    let mut fact_reads: Vec<_> = rule
        .whens
        .iter()
        .map(|when| fact_read_from_when(&when.text))
        .collect();
    fact_reads.sort();
    fact_reads.dedup();
    Ok(RuleRoot {
        name: rule.name.clone(),
        kind: rule.kind,
        whens: rule.whens.iter().cloned().map(lower_when_clause).collect(),
        binding_schemas,
        fact_reads,
        resource_reads: tracker_resource_reads(rule, semantic),
        projection_reads,
    })
}

pub(crate) fn inputs(rule: &RuleDecl) -> Vec<Ident> {
    rule.whens
        .iter()
        .filter_map(|when| {
            binding_from_when(&when.text).map(|(name, _)| {
                let (pattern, _) = split_when_guard(&when.text);
                let start = pattern
                    .rfind(&name)
                    .expect("matched alias occurs in trigger");
                let span = when_guard_span(when, &pattern[start..start + name.len()]);
                Ident { name, span }
            })
        })
        .collect()
}

/// Derives trigger binding/guard metadata after workflow and pattern selection.
/// The compiler still owns declaration and full source validation. This is not
/// body metadata, an executable program, or an admission certificate.
pub fn resolve_rule_root(program: &Program, name: &str) -> Result<RuleRoot, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let mut names = BTreeMap::new();
    let mut selected = None;
    for item in &program.items {
        if let Item::Rule(rule) = item {
            register_rule_name(&rule.name, &mut names, &mut diagnostics);
            if rule.name.name == name {
                selected = Some(rule);
            }
        }
    }
    let Some(rule) = selected else {
        return Err(vec![crate::action_plan::error(
            SourceSpan { start: 0, end: 0 },
            format!("unknown rule `{name}` for managed root"),
        )]);
    };
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    analyze(
        rule,
        &SemanticContext::from_program(program, BTreeMap::new()),
    )
}

#[cfg(test)]
mod tests;
