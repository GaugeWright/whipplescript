//! A may-footprint shared through the same once-per-definition summaries as
//! subject requirements. It deliberately carries no fabricated pacing flag.
use super::*;

#[derive(Clone)]
struct Witness {
    span: SourceSpan,
    calls: Vec<RelatedInfo>,
}
impl Witness {
    fn at(span: SourceSpan) -> Self {
        Self {
            span,
            calls: Vec::new(),
        }
    }
    fn through(&self, call: &graph::Call) -> Self {
        let mut witness = self.clone();
        witness.calls.push(RelatedInfo {
            span: call.span,
            message: format!("call to action `{}`", call.name),
        });
        witness
    }
}

#[derive(Clone, Default)]
pub(super) struct Flow {
    writes: BTreeMap<String, Witness>,
    effect: Option<Witness>,
}
impl Flow {
    pub fn observe(&mut self, statement: &body::BodyStmt) {
        if let Some(record) = fact_flow::record(statement) {
            self.writes
                .entry(format!("schema:{}", record.schema))
                .or_insert_with(|| Witness::at(record.span));
        }
        if let body::BodyStmt::Effect(effect) = statement {
            self.effect.get_or_insert_with(|| Witness::at(effect.span));
            if let Some(schema) = fact_flow::ingest_schema(effect) {
                self.writes
                    .entry(format!("schema:{schema}"))
                    .or_insert_with(|| Witness::at(effect.span));
            }
        }
    }
    pub fn inherit(&mut self, callee: &Self, call: &graph::Call) {
        for (schema, witness) in &callee.writes {
            self.writes
                .entry(schema.clone())
                .or_insert_with(|| witness.through(call));
        }
        if self.effect.is_none() {
            self.effect = callee.effect.as_ref().map(|witness| witness.through(call));
        }
    }
    pub fn metadata(&self, requirements: &[Requirement]) -> RuleFactFlow {
        RuleFactFlow {
            writes: self
                .writes
                .iter()
                .map(|(schema, witness)| FactWrite {
                    fact: schema.clone(),
                    span: witness.span,
                    calls: witness.calls.clone(),
                })
                .collect(),
            consumes: consumed_schemas(requirements),
            effectful: self.effect.is_some(),
        }
    }
    pub fn validate(
        &self,
        rule: &RuleDecl,
        requirements: &[Requirement],
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        // Use the dependency graph's canonical interpretation of actual when
        // clauses, including explicit `fact Class`, rather than callee types.
        let reads: Vec<_> = rule
            .whens
            .iter()
            .map(|when| fact_flow::normalize_read(&fact_read_from_when(&when.text)))
            .collect();
        let consumes = consumed_schemas(requirements);
        let consumes: Vec<_> = consumes.into_iter().collect();
        for (schema, witness) in &self.writes {
            let span = witness.calls.last().map_or(witness.span, |call| call.span);
            let before = diagnostics.len();
            fact_flow::validate_self_trigger(
                &rule.name.name,
                span,
                self.effect.is_some(),
                &reads,
                std::slice::from_ref(schema),
                &consumes,
                diagnostics,
            );
            for diagnostic in &mut diagnostics[before..] {
                if witness.span != span {
                    diagnostic.related.push(RelatedInfo {
                        span: witness.span,
                        message: "this helper statement writes the triggering fact".into(),
                    });
                }
                diagnostic.related.extend(
                    witness
                        .calls
                        .iter()
                        .filter(|call| call.span != span)
                        .cloned(),
                );
                if let Some(effect) = &self.effect {
                    diagnostic.related.push(RelatedInfo {
                        span: effect.span,
                        message: "this operation makes the calling rule effectful".into(),
                    });
                    for call in &effect.calls {
                        if call.span != span && !diagnostic.related.contains(call) {
                            diagnostic.related.push(call.clone());
                        }
                    }
                }
                diagnostic.related.push(RelatedInfo {
                    span: rule.name.span,
                    message: "calling rule declared here".into(),
                });
            }
        }
    }
}

fn consumed_schemas(requirements: &[Requirement]) -> BTreeSet<String> {
    requirements
        .iter()
        .filter_map(|requirement| match requirement.subject.as_ref() {
            Shape::Fact { schema, .. } => Some(format!("schema:{schema}")),
            _ => None,
        })
        .collect()
}
