//! Termination measures over an effect-bearing rule cycle (DR-0081 §2).
//!
//! A ranking function proves **well-foundedness**: the cycle cannot turn
//! forever, because some `int` field strictly moves toward a bound it cannot
//! pass. That is a different property from a bound on how long the cycle runs,
//! and the difference is the whole point of the record — `n < 10` seeded from a
//! table runs ten times and the number is knowable, while `n < p.budget` from an
//! input terminates with no number available at compile time. Both are proven
//! here; only the first is `step_bounded`.
//!
//! The analysis is a syntactic match over structure the compiler already has —
//! guards are `Expr`, a record's field value is an `Expr`, `int` is distinct
//! from `float` — and it introduces no solver. It is deliberately incomplete:
//! anything it cannot read leaves the cycle with whatever verdict it had, so an
//! unproven measure never becomes a refusal that did not already exist.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    binding_from_when, BinaryOp, Expr, ExprLiteral, IrPrimitiveType, IrProgram, IrRecordShape,
    IrSchema, IrType,
};

/// What bounds the measure field: a literal ceiling, or a field the ring never
/// changes (a budget carried in the data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MeasureBound {
    Literal(i64),
    InvariantField(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Measure {
    pub field: String,
    /// Positive when the field rises toward an upper bound, negative when it
    /// falls toward a lower one. The smallest step around the ring.
    pub step: i64,
    pub bound: MeasureBound,
    /// The rule whose guard carries the bound; the ring stops turning there.
    pub bounding_rule: String,
    /// The bound is a literal AND every producer outside the ring seeds the
    /// field with a literal, so the number of turns follows from the source.
    pub step_bounded: bool,
}

impl Measure {
    /// The measure alone, for prose: ``t.n rises by 1 toward 10``.
    pub fn describe(&self, binding: &str) -> String {
        let direction = if self.step > 0 { "rises" } else { "falls" };
        let bound = match &self.bound {
            MeasureBound::Literal(value) => value.to_string(),
            MeasureBound::InvariantField(field) => format!("{binding}.{field}"),
        };
        format!(
            "`{binding}.{}` {direction} by {} toward {bound}",
            self.field,
            self.step.abs()
        )
    }

    /// The snapshot rendering, which adds what the measure proves and where.
    pub fn to_snapshot(&self, binding: &str) -> String {
        let direction = if self.step > 0 { "rises" } else { "falls" };
        let bound = match &self.bound {
            MeasureBound::Literal(value) => value.to_string(),
            MeasureBound::InvariantField(field) => format!("{binding}.{field}"),
        };
        let kind = if self.step_bounded {
            "step-bounded"
        } else {
            "well-founded"
        };
        format!(
            "{binding}.{} {direction} by {} toward {bound} ({kind}, bounded by rule `{}`)",
            self.field,
            self.step.abs(),
            self.bounding_rule
        )
    }
}

/// Why a cycle was not proven, when the analysis got close enough to say
/// something useful (DR-0081 §8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MeasureMiss {
    /// A field advances on every hop, but no rule on the cycle bounds it.
    Unbounded { field: String, step: i64 },
}

pub(crate) enum MeasureOutcome {
    Proven(Box<Measure>),
    Missed(MeasureMiss),
    None,
}

/// One rule's place in the ring.
struct Hop<'a> {
    rule: &'a str,
    /// The class this rule matches and the binding it matches it under.
    in_schema: String,
    binding: String,
    /// The class it records, which the next rule matches.
    out_schema: String,
    guard: Vec<&'a Expr>,
    records: Vec<&'a IrRecordShape>,
}

/// Attempt DR-0081 §2 over one strongly connected component.
pub(crate) fn prove_cycle_measure(ir: &IrProgram, component: &[usize]) -> MeasureOutcome {
    let Some(hops) = build_hops(ir, component) else {
        return MeasureOutcome::None;
    };
    let classes = class_index(ir);

    // Candidate fields: `int` on every class the ring carries. `float` is
    // excluded because `n := n + 0.5` under `n < 1` converges and is not
    // well-founded; `duration` and `time` are integer-backed and deferred.
    let mut candidates: Option<BTreeSet<String>> = None;
    for hop in &hops {
        let Some(fields) = classes.get(hop.in_schema.as_str()) else {
            return MeasureOutcome::None;
        };
        let ints = fields
            .iter()
            .filter(|(_, ty)| matches!(ty, IrType::Primitive(IrPrimitiveType::Int)))
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        candidates = Some(match candidates {
            Some(previous) => previous.intersection(&ints).cloned().collect(),
            None => ints,
        });
    }
    let candidates = candidates.unwrap_or_default();

    let mut missed = None;
    for field in candidates {
        match prove_field(ir, &hops, &field, component) {
            MeasureOutcome::Proven(measure) => return MeasureOutcome::Proven(measure),
            MeasureOutcome::Missed(miss) => missed = Some(miss),
            MeasureOutcome::None => {}
        }
    }
    match missed {
        Some(miss) => MeasureOutcome::Missed(miss),
        None => MeasureOutcome::None,
    }
}

fn prove_field(
    ir: &IrProgram,
    hops: &[Hop<'_>],
    field: &str,
    component: &[usize],
) -> MeasureOutcome {
    // Every hop advances the field by a positive integer literal, all in one
    // direction.
    let mut steps = Vec::new();
    for hop in hops {
        let mut records = hop
            .records
            .iter()
            .filter(|shape| shape.schema == hop.out_schema);
        let (Some(record), None) = (records.next(), records.next()) else {
            // Two records of the same class in one rule: which one continues the
            // ring is not a question this analysis answers.
            return MeasureOutcome::None;
        };
        let Some((_, assigned)) = record.fields.iter().find(|(name, _)| name == field) else {
            return MeasureOutcome::None;
        };
        let Some(step) = advance_step(assigned, &hop.binding, field) else {
            return MeasureOutcome::None;
        };
        steps.push(step);
    }
    // A hop that carries the field through unchanged is fine; what matters is
    // the round trip. Every hop that DOES move it must move it the same way, and
    // at least one must, so the sum around the ring is a real advance.
    let rising = steps.iter().any(|step| *step > 0);
    let falling = steps.iter().any(|step| *step < 0);
    if rising == falling {
        return MeasureOutcome::None;
    }
    let step: i64 = steps.iter().sum();
    if (step > 0) != rising {
        return MeasureOutcome::None;
    }

    // One bound anywhere on the ring is enough: the rule that carries it stops
    // firing once the field passes it, and a simple ring cannot turn without
    // every rule on it.
    let mut bound = None;
    for hop in hops {
        for conjunct in &hop.guard {
            if let Some(found) = guard_bound(conjunct, &hop.binding, field, rising) {
                if let MeasureBound::InvariantField(ref name) = found {
                    if !field_is_invariant(hops, name) {
                        continue;
                    }
                }
                bound = Some((found, hop.rule.to_owned(), hop.binding.clone()));
                break;
            }
        }
        if bound.is_some() {
            break;
        }
    }
    let Some((bound, bounding_rule, _)) = bound else {
        return MeasureOutcome::Missed(MeasureMiss::Unbounded {
            field: field.to_owned(),
            step,
        });
    };

    let step_bounded = matches!(bound, MeasureBound::Literal(_))
        && outside_producers_seed_literally(ir, hops, field, component);

    MeasureOutcome::Proven(Box::new(Measure {
        field: field.to_owned(),
        step,
        bound,
        bounding_rule,
        step_bounded,
    }))
}

/// How one hop moves the field: `<binding>.<field> + k`, `- k`, or the bare
/// `<binding>.<field>`, which carries it through unchanged and moves it by zero.
/// Anything else — a call, another fact's field, an arithmetic shape this does
/// not read — is not an update the analysis can speak about.
fn advance_step(expr: &Expr, binding: &str, field: &str) -> Option<i64> {
    if is_field_path(expr, binding, field) {
        return Some(0);
    }
    let Expr::Binary { op, left, right } = expr else {
        return None;
    };
    if !is_field_path(left, binding, field) {
        return None;
    }
    let step = integer_literal(right)?;
    if step <= 0 {
        return None;
    }
    match op {
        BinaryOp::Add => Some(step),
        BinaryOp::Sub => Some(-step),
        _ => None,
    }
}

/// A guard conjunct that bounds `<binding>.<field>` from the direction of
/// travel: `< K` / `<= K` for a rising field, `> K` / `>= K` for a falling one.
fn guard_bound(expr: &Expr, binding: &str, field: &str, rising: bool) -> Option<MeasureBound> {
    let Expr::Binary { op, left, right } = expr else {
        return None;
    };
    if !is_field_path(left, binding, field) {
        return None;
    }
    let bounds = matches!(
        (op, rising),
        (BinaryOp::Lt | BinaryOp::Le, true) | (BinaryOp::Gt | BinaryOp::Ge, false)
    );
    if !bounds {
        return None;
    }
    if let Some(value) = integer_literal(right) {
        return Some(MeasureBound::Literal(value));
    }
    match right.as_ref() {
        Expr::Path(path) if path.len() == 2 && path[0] == binding && path[1] != field => {
            Some(MeasureBound::InvariantField(path[1].clone()))
        }
        _ => None,
    }
}

/// A field the ring carries around unchanged — every hop copies it — so a bound
/// stated against it holds on every turn.
fn field_is_invariant(hops: &[Hop<'_>], field: &str) -> bool {
    hops.iter().all(|hop| {
        hop.records
            .iter()
            .filter(|shape| shape.schema == hop.out_schema)
            .all(|shape| {
                shape
                    .fields
                    .iter()
                    .find(|(name, _)| name == field)
                    .is_some_and(|(_, expr)| is_field_path(expr, &hop.binding, field))
            })
    })
}

/// Every producer of a ring class that is NOT on the ring seeds the measure
/// field with a literal, so the entry value is known from the source too. A
/// table lowers to a rule whose body records its rows, so a seeded ring passes
/// here; a stream or an effect result does not.
fn outside_producers_seed_literally(
    ir: &IrProgram,
    hops: &[Hop<'_>],
    field: &str,
    component: &[usize],
) -> bool {
    let ring_classes = hops
        .iter()
        .map(|hop| format!("schema:{}", hop.in_schema))
        .collect::<BTreeSet<_>>();
    for (index, rule) in ir.rules.iter().enumerate() {
        if component.contains(&index) {
            continue;
        }
        for written in &rule.metadata.fact_writes {
            if !ring_classes.contains(written) {
                continue;
            }
            let schema = written.trim_start_matches("schema:");
            let mut seeds = rule
                .metadata
                .record_shapes
                .iter()
                .filter(|shape| shape.schema == schema)
                .peekable();
            if seeds.peek().is_none() {
                // Written without a `record` — an `exec … -> each` stream or an
                // import, whose row count is data.
                return false;
            }
            for shape in seeds {
                match shape.fields.iter().find(|(name, _)| name == field) {
                    Some((_, expr)) if integer_literal(expr).is_some() => {}
                    _ => return false,
                }
            }
        }
    }
    true
}

fn is_field_path(expr: &Expr, binding: &str, field: &str) -> bool {
    matches!(expr, Expr::Path(path) if path.len() == 2 && path[0] == binding && path[1] == field)
}

fn integer_literal(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Literal(ExprLiteral::Number(text)) => text.parse::<i64>().ok(),
        Expr::Unary {
            op: crate::UnaryOp::Not,
            ..
        } => None,
        _ => None,
    }
}

/// The class fields of every declared class, by name.
fn class_index(ir: &IrProgram) -> BTreeMap<&str, Vec<(String, IrType)>> {
    ir.schemas
        .iter()
        .filter_map(|schema| match schema {
            IrSchema::Class(class) => Some((
                class.name.as_str(),
                class
                    .fields
                    .iter()
                    .map(|field| (field.name.clone(), field.ty.clone()))
                    .collect(),
            )),
            IrSchema::Enum(_) => None,
        })
        .collect()
}

/// The ring, one hop per member: what each rule matches, under which binding,
/// and what it records for the next. `None` when the component is not a simple
/// ring — a member with two ways in or out, or one that does not consume its
/// trigger, is not a shape this analysis reads.
fn build_hops<'a>(ir: &'a IrProgram, component: &[usize]) -> Option<Vec<Hop<'a>>> {
    let mut hops = Vec::new();
    for &index in component {
        let rule = &ir.rules[index];
        let others = component
            .iter()
            .copied()
            .filter(|other| *other != index || component.len() == 1)
            .collect::<Vec<_>>();
        let reads_from_ring = rule
            .metadata
            .fact_reads
            .iter()
            .filter(|fact| {
                others
                    .iter()
                    .any(|other| ir.rules[*other].metadata.fact_writes.contains(*fact))
            })
            .collect::<Vec<_>>();
        let writes_to_ring = rule
            .metadata
            .fact_writes
            .iter()
            .filter(|fact| {
                others
                    .iter()
                    .any(|other| ir.rules[*other].metadata.fact_reads.contains(*fact))
            })
            .collect::<Vec<_>>();
        let ([in_fact], [out_fact]) = (reads_from_ring.as_slice(), writes_to_ring.as_slice())
        else {
            return None;
        };
        // The token must be consumed, or the ring carries a growing population
        // of facts rather than one value a measure can speak about.
        if !rule.metadata.fact_consumes.contains(*in_fact) {
            return None;
        }
        let in_schema = in_fact.trim_start_matches("schema:").to_owned();
        let out_schema = out_fact.trim_start_matches("schema:").to_owned();
        let mut binding = None;
        let mut guard = Vec::new();
        for when in &rule.whens {
            if let Some((bound, schema)) = binding_from_when(&when.source) {
                if schema == in_schema {
                    binding = Some(bound);
                    if let Some(expression) = &when.guard {
                        collect_conjuncts(&expression.expr, &mut guard);
                    }
                }
            }
        }
        hops.push(Hop {
            rule: rule.name.as_str(),
            in_schema,
            binding: binding?,
            out_schema,
            guard,
            records: rule.metadata.record_shapes.iter().collect(),
        });
    }
    Some(hops)
}

fn collect_conjuncts<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => {
            collect_conjuncts(left, out);
            collect_conjuncts(right, out);
        }
        other => out.push(other),
    }
}

/// The binding the measure is rendered against — the first hop's, so the
/// snapshot line reads in the source's own vocabulary.
pub(crate) fn measure_binding(ir: &IrProgram, component: &[usize]) -> Option<String> {
    build_hops(ir, component).and_then(|hops| hops.first().map(|hop| hop.binding.clone()))
}
