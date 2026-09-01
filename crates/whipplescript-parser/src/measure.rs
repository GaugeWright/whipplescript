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
    IrSchema, IrType, MeasureDeclBound,
};

/// What bounds the measure field: a literal ceiling, or a field the ring never
/// changes (a budget carried in the data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MeasureBound {
    Literal(i64),
    InvariantField(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CounterMeasure {
    pub field: String,
    /// The field is a `duration`, so its numbers are seconds and render as the
    /// canonical spelling — "rises by 30 toward 300" on a length says thirty of
    /// what.
    pub duration: bool,
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

/// A ring that terminates by advancing a FINITE DOMAIN rather than a counter.
///
/// The manual teaches this one first and DR-0081 §2 could not express it: a
/// `status` that a rule matches at `"queued"` and records as `"routed"` ends the
/// ring, not because a number descends but because the field moved to a value it
/// will not hold again. Each hop contributes one edge `matched -> recorded` over
/// the field's declared values, and the ring is well-founded exactly when that
/// graph is ACYCLIC: a finite set with no cycle admits no infinite walk.
///
/// It is always step-bounded, and by a number the source fixes — the longest
/// path through the domain, which is at most one turn per value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DomainMeasure {
    pub field: String,
    /// The `matched -> recorded` edges, in ring order.
    pub transitions: Vec<(String, String)>,
    pub domain: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Measure {
    Counter(CounterMeasure),
    Domain(DomainMeasure),
}

impl Measure {
    /// Whether the number of turns follows from the source. A finite domain
    /// always does: the walk cannot be longer than the domain.
    pub fn step_bounded(&self) -> bool {
        match self {
            Self::Counter(counter) => counter.step_bounded,
            Self::Domain(_) => true,
        }
    }

    /// The measure alone, for prose: ``t.n rises by 1 toward 10``.
    pub fn describe(&self, binding: &str) -> String {
        match self {
            Self::Counter(counter) => {
                let direction = if counter.step > 0 { "rises" } else { "falls" };
                let bound = match &counter.bound {
                    MeasureBound::Literal(value) => counter.amount(*value),
                    MeasureBound::InvariantField(field) => format!("{binding}.{field}"),
                };
                format!(
                    "`{binding}.{}` {direction} by {} toward {bound}",
                    counter.field,
                    counter.amount(counter.step.abs())
                )
            }
            Self::Domain(domain) => format!(
                "`{binding}.{}` advances through {}",
                domain.field,
                domain.render_transitions()
            ),
        }
    }

    /// The measure without a binding, for a message that compares it against a
    /// declaration: `rises by 1 toward 10`.
    pub fn describe_bare(&self) -> String {
        match self {
            Self::Counter(counter) => {
                let direction = if counter.step > 0 { "rises" } else { "falls" };
                let bound = match &counter.bound {
                    MeasureBound::Literal(value) => counter.amount(*value),
                    MeasureBound::InvariantField(field) => field.clone(),
                };
                format!(
                    "{direction} by {} toward {bound}",
                    counter.amount(counter.step.abs())
                )
            }
            Self::Domain(domain) => {
                format!("advances through {}", domain.render_transitions())
            }
        }
    }

    /// The snapshot rendering, which adds what the measure proves and where.
    pub fn to_snapshot(&self, binding: &str) -> String {
        match self {
            Self::Counter(counter) => {
                let direction = if counter.step > 0 { "rises" } else { "falls" };
                let bound = match &counter.bound {
                    MeasureBound::Literal(value) => counter.amount(*value),
                    MeasureBound::InvariantField(field) => format!("{binding}.{field}"),
                };
                let kind = if counter.step_bounded {
                    "step-bounded"
                } else {
                    "well-founded"
                };
                format!(
                    "{binding}.{} {direction} by {} toward {bound} ({kind}, bounded by rule `{}`)",
                    counter.field,
                    counter.amount(counter.step.abs()),
                    counter.bounding_rule
                )
            }
            Self::Domain(domain) => format!(
                "{binding}.{} advances through {} (step-bounded, {} step(s) over a domain of {})",
                domain.field,
                domain.render_transitions(),
                domain.transitions.len(),
                domain.domain
            ),
        }
    }
}

impl CounterMeasure {
    fn amount(&self, seconds: i64) -> String {
        if self.duration {
            crate::canonical_duration(seconds)
        } else {
            seconds.to_string()
        }
    }
}

impl DomainMeasure {
    fn render_transitions(&self) -> String {
        self.transitions
            .iter()
            .map(|(from, to)| format!("{from} -> {to}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Why a cycle was not proven, when the analysis got close enough to say
/// something useful (DR-0081 §8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MeasureMiss {
    /// A field advances on every hop, but no rule on the cycle bounds it.
    Unbounded { field: String, step: i64 },
    /// A `measure` declaration covers this cycle and the code does not honour
    /// it. This is what the declaration is FOR: the compiler can say which half
    /// of a stated claim broke, where an inference can only say it found
    /// nothing.
    DeclarationUnmet {
        class: String,
        field: String,
        reason: String,
    },
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
        // `duration` counts alongside `int` since DR-0087 made it a whole
        // number of seconds: the well-foundedness argument is the same one, and
        // it was only excluded while the value was float-backed.
        let ints = fields
            .iter()
            .filter(|(_, ty)| {
                matches!(
                    ty,
                    IrType::Primitive(IrPrimitiveType::Int | IrPrimitiveType::Duration)
                )
            })
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        candidates = Some(match candidates {
            Some(previous) => previous.intersection(&ints).cloned().collect(),
            None => ints,
        });
    }
    let candidates = candidates.unwrap_or_default();

    // A `measure` declaration for a class on this ring is the author's claim
    // about which field carries it, so the analysis stops searching and checks
    // that claim: a stated measure that does not hold should say so, not fall
    // back to a quiet "nothing found".
    if let Some(declared) = ir
        .measure_declarations
        .iter()
        .find(|declaration| hops.iter().any(|hop| hop.in_schema == declaration.class))
    {
        if !candidates.contains(&declared.field) {
            return MeasureOutcome::Missed(MeasureMiss::DeclarationUnmet {
                class: declared.class.clone(),
                field: declared.field.clone(),
                reason: format!(
                    "`{}` is not an `int` field on every class the cycle carries",
                    declared.field
                ),
            });
        }
        return match prove_field(ir, &hops, &declared.field, component) {
            MeasureOutcome::Proven(measure) => {
                // A declaration states a counter; a ring proven by its finite
                // domain does not answer that claim, and says so rather than
                // silently passing.
                let honoured = match measure.as_ref() {
                    Measure::Counter(counter) => {
                        (counter.step > 0) == declared.rising
                            && match (&counter.bound, &declared.bound) {
                                (
                                    MeasureBound::Literal(found),
                                    MeasureDeclBound::Literal(stated),
                                ) => found == stated,
                                (
                                    MeasureBound::InvariantField(found),
                                    MeasureDeclBound::Field(stated),
                                ) => found == stated,
                                _ => false,
                            }
                    }
                    Measure::Domain(_) => false,
                };
                if honoured {
                    MeasureOutcome::Proven(measure)
                } else {
                    MeasureOutcome::Missed(MeasureMiss::DeclarationUnmet {
                        class: declared.class.clone(),
                        field: declared.field.clone(),
                        reason: format!(
                            "the cycle {}, which is not what the declaration states",
                            measure.describe_bare()
                        ),
                    })
                }
            }
            MeasureOutcome::Missed(MeasureMiss::Unbounded { field, step }) => {
                MeasureOutcome::Missed(MeasureMiss::DeclarationUnmet {
                    class: declared.class.clone(),
                    field: declared.field.clone(),
                    reason: format!(
                        "`{field}` {} by {} on every hop, but no rule on the cycle bounds it",
                        if step > 0 { "rises" } else { "falls" },
                        step.abs()
                    ),
                })
            }
            _ => MeasureOutcome::Missed(MeasureMiss::DeclarationUnmet {
                class: declared.class.clone(),
                field: declared.field.clone(),
                reason: format!(
                    "no hop of the cycle advances `{}` by a whole-number step, or a hop does not consume the fact it matched",
                    declared.field
                ),
            }),
        };
    }

    // A finite domain is tried after the counters, and only because a counter is
    // the narrower claim: where both could be read, the arithmetic one says more
    // about how far the ring runs.
    if let Some(measure) = prove_domain(ir, &hops) {
        return MeasureOutcome::Proven(Box::new(Measure::Domain(measure)));
    }

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

    let duration = hops.first().is_some_and(|hop| {
        class_index(ir)
            .get(hop.in_schema.as_str())
            .is_some_and(|fields| {
                fields.iter().any(|(name, ty)| {
                    name == field && matches!(ty, IrType::Primitive(IrPrimitiveType::Duration))
                })
            })
    });
    MeasureOutcome::Proven(Box::new(Measure::Counter(CounterMeasure {
        field: field.to_owned(),
        duration,
        step,
        bound,
        bounding_rule,
        step_bounded,
    })))
}

/// A ring that terminates by advancing a finite domain (DR-0081 §2, finite
/// domains).
///
/// Each hop must match one value of the field and record another: the guard
/// carries `binding.f == "A"` and the record writes `f "B"`. Those are the edges
/// of a walk over the field's declared values, and the ring is well-founded
/// exactly when the walk cannot return to a value it has left — an acyclic graph
/// over a finite set admits no infinite walk.
///
/// This is the argument `docs/manual/04-rules.md` teaches before it teaches a
/// counter: a ticket goes `"queued" -> "routed"` and the ring stops, not because
/// a number descends but because the status will not be `"queued"` again.
fn prove_domain(ir: &IrProgram, hops: &[Hop<'_>]) -> Option<DomainMeasure> {
    let classes = class_index(ir);
    let enums = ir
        .schemas
        .iter()
        .filter_map(|schema| match schema {
            IrSchema::Enum(declared) => Some((declared.name.clone(), declared.variants.len())),
            IrSchema::Class(_) => None,
        })
        .collect::<BTreeMap<_, _>>();

    // The field must be a finite domain on every class the ring carries: a union
    // of string literals, or a reference to a declared enum.
    let domain_size = |ty: &IrType| -> Option<usize> {
        match ty {
            IrType::Union(members)
                if members
                    .iter()
                    .all(|member| matches!(member, IrType::LiteralString(_))) =>
            {
                Some(members.len())
            }
            IrType::Ref(name) => enums.get(name).copied(),
            _ => None,
        }
    };

    let mut candidates: Option<BTreeSet<String>> = None;
    let mut domain = 0usize;
    for hop in hops {
        let fields = classes.get(hop.in_schema.as_str())?;
        let mut finite = BTreeSet::new();
        for (name, ty) in fields {
            if let Some(size) = domain_size(ty) {
                domain = domain.max(size);
                finite.insert(name.clone());
            }
        }
        candidates = Some(match candidates {
            Some(previous) => previous.intersection(&finite).cloned().collect(),
            None => finite,
        });
    }

    for field in candidates.unwrap_or_default() {
        let mut transitions = Vec::new();
        let mut readable = true;
        for hop in hops {
            let Some(matched) = hop
                .guard
                .iter()
                .find_map(|conjunct| equality_value(conjunct, &hop.binding, &field))
            else {
                readable = false;
                break;
            };
            let mut records = hop
                .records
                .iter()
                .filter(|shape| shape.schema == hop.out_schema);
            let (Some(record), None) = (records.next(), records.next()) else {
                readable = false;
                break;
            };
            let Some(recorded) = record.fields.iter().find_map(|(name, expr)| {
                if name != &field {
                    return None;
                }
                match expr {
                    Expr::Literal(ExprLiteral::String(value)) => Some(value.clone()),
                    // A bare identifier is how an enum variant is written.
                    Expr::Literal(ExprLiteral::Ident(value)) => Some(value.clone()),
                    _ => None,
                }
            }) else {
                readable = false;
                break;
            };
            transitions.push((matched, recorded));
        }
        if !readable || transitions.is_empty() {
            continue;
        }
        if walk_is_acyclic(&transitions) {
            return Some(DomainMeasure {
                field,
                transitions,
                domain,
            });
        }
    }
    None
}

/// `<binding>.<field> == "value"` in a guard conjunct, as the value.
fn equality_value(expr: &Expr, binding: &str, field: &str) -> Option<String> {
    let Expr::Binary {
        op: BinaryOp::Eq,
        left,
        right,
    } = expr
    else {
        return None;
    };
    if !is_field_path(left, binding, field) {
        return None;
    }
    match right.as_ref() {
        Expr::Literal(ExprLiteral::String(value)) => Some(value.clone()),
        Expr::Literal(ExprLiteral::Ident(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Whether the walk these edges describe can return to a value it has left. A
/// finite set with no cycle admits no infinite walk, which is the whole of the
/// termination argument.
fn walk_is_acyclic(transitions: &[(String, String)]) -> bool {
    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (from, to) in transitions {
        edges.entry(from.as_str()).or_default().insert(to.as_str());
    }
    let mut reach: BTreeMap<&str, BTreeSet<&str>> = edges
        .iter()
        .map(|(node, targets)| (*node, targets.clone()))
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for node in reach.keys().copied().collect::<Vec<_>>() {
            let onward = reach[node]
                .iter()
                .flat_map(|step| edges.get(step).into_iter().flatten().copied())
                .collect::<Vec<_>>();
            for target in onward {
                if reach.get_mut(node).map(|set| set.insert(target)) == Some(true) {
                    changed = true;
                }
            }
        }
    }
    !reach.iter().any(|(node, targets)| targets.contains(node))
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
        // A duration literal IS its whole number of seconds (DR-0087 §1), so a
        // measure over one is the same descent over a different spelling.
        Expr::Literal(ExprLiteral::Duration(seconds)) => Some(*seconds),
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
