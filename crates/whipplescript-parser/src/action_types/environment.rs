//! Lexical types plus null and finite refinements of individual value paths.
//! Refining a field never rewrites the nominal type of its containing record.
use super::*;
use crate::case_pattern::{optional_presence, PresencePattern};
mod nulls;

#[derive(Default)]
pub(super) struct CaseExclusions {
    values: BTreeSet<String>,
    null: bool,
    present: bool,
}
impl CaseExclusions {
    pub(super) fn record(&mut self, pattern: &str, guarded: bool, ty: Option<&IrType>) {
        if guarded {
            return;
        }
        if nulls::pattern_is_null(pattern, ty) {
            self.null = true;
        } else if ty
            .is_some_and(|ty| optional_presence(ty, pattern) == Some(PresencePattern::Present))
        {
            self.present = true;
        } else if let Some(value) = agent_pattern(pattern) {
            self.values.insert(value);
        }
    }
}

pub(super) enum ReadFailure {
    Unknown,
    Conditional {
        field: String,
        discriminator: String,
        required: String,
        declaration: SourceSpan,
    },
}

#[derive(Clone, Default)]
pub(super) struct Environment {
    bindings: BTreeMap<String, Option<IrType>>,
    refined: BTreeMap<Vec<String>, Option<IrType>>,
    operations: BTreeSet<String>,
    operation_outcomes: BTreeMap<String, OperationOutcomes>,
    terminal_outcomes: BTreeMap<String, OperationOutcomes>,
}

#[derive(Clone, Default)]
pub(super) struct OperationOutcomes {
    pub(super) succeeded: Option<IrType>,
    pub(super) completed: Option<IrType>,
    pub(super) failed: Option<IrType>,
    pub(super) timed_out: Option<IrType>,
    pub(super) cancelled: Option<IrType>,
}

impl FromIterator<(String, Option<IrType>)> for Environment {
    fn from_iter<T: IntoIterator<Item = (String, Option<IrType>)>>(iter: T) -> Self {
        Self {
            bindings: iter.into_iter().collect(),
            refined: BTreeMap::new(),
            operations: BTreeSet::new(),
            operation_outcomes: BTreeMap::new(),
            terminal_outcomes: BTreeMap::new(),
        }
    }
}

impl Environment {
    pub(super) fn new() -> Self {
        Self::default()
    }
    pub(super) fn get(&self, name: &str) -> Option<&Option<IrType>> {
        self.refined
            .get(&vec![name.to_owned()])
            .or_else(|| self.bindings.get(name))
    }
    pub(super) fn insert(&mut self, name: String, ty: Option<IrType>) {
        // Even an unresolved local is a new binding occurrence, not permission
        // to reuse an outer fact field's or agent parameter's refinement.
        self.refined.retain(|path, _| path.first() != Some(&name));
        self.operations.remove(&name);
        self.operation_outcomes.remove(&name);
        self.terminal_outcomes.remove(&name);
        self.bindings.insert(name, ty);
    }
    pub(super) fn mark_operation(&mut self, name: &str, outcomes: OperationOutcomes) {
        self.operations.insert(name.to_owned());
        self.operation_outcomes.insert(name.to_owned(), outcomes);
    }
    pub(super) fn is_operation(&self, name: &str) -> bool {
        self.operations.contains(name)
    }
    pub(super) fn mark_terminal_outcome(&mut self, name: &str, outcomes: OperationOutcomes) {
        self.terminal_outcomes.insert(name.to_owned(), outcomes);
    }
    pub(super) fn terminal_outcome(&self, path: &[String]) -> Option<&OperationOutcomes> {
        (path.len() == 1)
            .then(|| self.terminal_outcomes.get(&path[0]))
            .flatten()
    }
    pub(super) fn operation_outcome(
        &self,
        name: &str,
        predicate: body::AfterPredicate,
    ) -> Option<&IrType> {
        let outcomes = self.operation_outcomes.get(name)?;
        match predicate {
            body::AfterPredicate::Ok | body::AfterPredicate::Over => outcomes.succeeded.as_ref(),
            body::AfterPredicate::Completes => outcomes.completed.as_ref(),
            body::AfterPredicate::Fails => outcomes.failed.as_ref(),
            body::AfterPredicate::TimedOut => outcomes.timed_out.as_ref(),
            body::AfterPredicate::Cancelled => outcomes.cancelled.as_ref(),
            _ => None,
        }
    }
    pub(super) fn outcomes(&self, name: &str) -> Option<&OperationOutcomes> {
        self.operation_outcomes.get(name)
    }
    pub(super) fn inherit_refinements(&mut self, name: &str, source: &[String], from: &Self) {
        for (path, ty) in &from.refined {
            if let Some(suffix) = path.strip_prefix(source) {
                let mut alias_path = vec![name.to_owned()];
                alias_path.extend_from_slice(suffix);
                self.refined.insert(alias_path, ty.clone());
            }
        }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &Option<IrType>)> {
        self.bindings
            .iter()
            .map(|(name, ty)| (name, self.get(name).unwrap_or(ty)))
    }
    pub(super) fn path_type(&self, path: &[String], semantic: &SemanticContext) -> Option<IrType> {
        self.read_path(path, semantic).ok()
    }
    pub(super) fn unknown_member(
        &self,
        path: &[String],
        semantic: &SemanticContext,
    ) -> Option<(String, String, Vec<String>)> {
        for index in (1..path.len()).rev() {
            let Some(parent) = self.path_type(&path[..index], semantic) else {
                continue;
            };
            let mut fields = match parent {
                IrType::Ref(schema) => semantic
                    .schemas
                    .classes
                    .get(&schema)?
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                IrType::Object(fields) => fields.into_iter().map(|field| field.name).collect(),
                _ => return None,
            };
            fields.sort();
            let field = &path[index];
            if fields.contains(field) {
                return None;
            }
            return Some((path[..index].join("."), field.clone(), fields));
        }
        None
    }
    pub(super) fn read_path(
        &self,
        path: &[String],
        semantic: &SemanticContext,
    ) -> Result<IrType, ReadFailure> {
        if let Some(ty) = self.refined.get(path) {
            return ty.clone().ok_or(ReadFailure::Unknown);
        }
        let (root, fields) = path.split_first().ok_or(ReadFailure::Unknown)?;
        let ty = self
            .get(root)
            .and_then(Option::as_ref)
            .ok_or(ReadFailure::Unknown)?;
        self.member_type(ty, &path[..1], fields, semantic)
    }
    pub(super) fn member_type(
        &self,
        ty: &IrType,
        parent: &[String],
        fields: &[String],
        semantic: &SemanticContext,
    ) -> Result<IrType, ReadFailure> {
        let Some((field, rest)) = fields.split_first() else {
            return Ok(ty.clone());
        };
        if let IrType::Union(variants) = ty {
            if variants.is_empty() {
                return Err(ReadFailure::Unknown);
            }
            return variants
                .iter()
                .map(|variant| self.member_type(variant, parent, fields, semantic))
                .collect::<Result<Vec<_>, _>>()
                .map(IrType::Union);
        }
        let mut child = parent.to_vec();
        child.push(field.clone());
        let member = match ty {
            IrType::Ref(schema) => {
                let declared = semantic
                    .schemas
                    .classes
                    .get(schema)
                    .ok_or(ReadFailure::Unknown)?;
                let declaration = declared.get(field).ok_or(ReadFailure::Unknown)?;
                if let Some((discriminator, required)) =
                    semantic.schemas.field_presence(schema, field)
                {
                    let mut discriminator_path = parent.to_vec();
                    discriminator_path.push(discriminator.clone());
                    let evidence = match self.refined.get(&discriminator_path) {
                        Some(ty) => ty.clone(),
                        // Never derive presence recursively from another
                        // conditioned field: cycles cannot supply evidence.
                        None if semantic
                            .schemas
                            .field_presence(schema, discriminator)
                            .is_none() =>
                        {
                            declared.get(discriminator).cloned().map(lower_type)
                        }
                        None => None,
                    };
                    let proven = evidence
                        .as_ref()
                        .and_then(literal_domain)
                        .is_some_and(|values| {
                            !values.is_empty() && values.iter().all(|value| value == required)
                        });
                    if !proven {
                        return Err(ReadFailure::Conditional {
                            field: child.join("."),
                            discriminator: discriminator_path.join("."),
                            required: required.clone(),
                            declaration: declaration.span(),
                        });
                    }
                }
                lower_type(declaration.clone())
            }
            IrType::Object(members) => members
                .iter()
                .find(|m| &m.name == field)
                .ok_or(ReadFailure::Unknown)?
                .ty
                .clone(),
            _ => {
                // The mutation fabricates a readable string from a non-record.
                // MUTATION-SUCCESS-EXPR: Ok(primitive(IrPrimitiveType::String))
                return Err(ReadFailure::Unknown);
            }
        };
        let member = self
            .refined
            .get(&child)
            .cloned()
            .unwrap_or(Some(member))
            .ok_or(ReadFailure::Unknown)?;
        self.member_type(&member, &child, rest, semantic)
    }
    pub(super) fn narrow_case(
        &mut self,
        expr: &Expr,
        pattern: &str,
        excluded: &CaseExclusions,
        semantic: &SemanticContext,
    ) {
        let Some(path) = value_path(expr) else {
            return;
        };
        let Some(ty) = self.path_type(&path, semantic) else {
            return;
        };
        let presence_pattern = optional_presence(&ty, pattern) == Some(PresencePattern::Present);
        let ty = if nulls::pattern_is_null(pattern, Some(&ty)) {
            nulls::select(&ty, true, false)
        } else if is_fallback_pattern(pattern) {
            nulls::select(&ty, !excluded.null, !excluded.present)
        } else {
            nulls::select(&ty, false, true)
        };
        let ty = if let Some(mut values) = finite_domain(&ty) {
            if is_fallback_pattern(pattern) {
                values.retain(|value| !excluded.values.contains(value));
            } else if let Some(value) = agent_pattern(pattern).filter(|_| !presence_pattern) {
                values.retain(|candidate| {
                    candidate == &value && !excluded.values.contains(candidate)
                });
            }
            refined_type(&ty, values)
        } else {
            ty
        };
        self.refined.insert(path, Some(ty));
    }
    pub(super) fn narrow_guard(&mut self, expr: &Expr, semantic: &SemanticContext) {
        fn collect(expr: &Expr, paths: &mut BTreeSet<Vec<String>>) {
            if let Some(path) = value_path(expr) {
                paths.insert(path);
            }
            for child in expr.children() {
                collect(child, paths);
            }
        }
        let mut paths = BTreeSet::new();
        collect(expr, &mut paths);
        // Lexicographic path order visits a parent before its descendants.
        // A proved-present parent can therefore expose a nullable child for
        // another independently justified refinement in this same condition.
        for path in paths {
            let Some(ty) = self.path_type(&path, semantic) else {
                continue;
            };
            let ty = nulls::guard(&ty, expr, &path);
            let ty = if let Some(mut values) = finite_domain(&ty) {
                values.retain(|value| {
                    possible_truth(expr, &path, value, self, semantic) != Some(false)
                });
                refined_type(&ty, values)
            } else {
                ty
            };
            self.refined.insert(path, Some(ty));
        }
    }
}

/// Resolve the closed terminal domain represented by either a lexical
/// completion alias or the direct observation `outcome(operation)`.
pub(super) fn terminal_outcomes<'a>(
    expr: &Expr,
    environment: &'a Environment,
) -> Option<&'a OperationOutcomes> {
    if let Some(path) = value_path(expr) {
        if let Some(outcomes) = environment.terminal_outcome(&path) {
            return Some(outcomes);
        }
    }
    let Expr::Call { name, args } = expr else {
        return None;
    };
    if name != "outcome" {
        return None;
    }
    let [argument] = args.as_slice() else {
        return None;
    };
    let path = value_path(argument)?;
    (path.len() == 1)
        .then(|| environment.outcomes(&path[0]))
        .flatten()
}

pub(super) fn observed_operation(expr: &Expr) -> Option<&str> {
    let Expr::Call { name, args } = expr else {
        return None;
    };
    if name != "outcome" {
        return None;
    }
    let [argument] = args.as_slice() else {
        return None;
    };
    match argument {
        Expr::Literal(ExprLiteral::Ident(name)) => Some(name),
        Expr::Path(path) if path.len() == 1 => Some(&path[0]),
        _ => None,
    }
}

pub(super) fn value_path(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Literal(ExprLiteral::Ident(name)) => Some(vec![name.clone()]),
        Expr::Path(path) => Some(path.clone()),
        _ => None,
    }
}

pub(super) fn agent_pattern(pattern: &str) -> Option<String> {
    match parse_expression(pattern).ok()? {
        Expr::Literal(ExprLiteral::Ident(name) | ExprLiteral::String(name)) => Some(name),
        _ => None,
    }
}

// A partial valuation can disprove a candidate, never assume an unknown
// predicate true. In particular `agent == writer || unknown` keeps reader.
fn possible_truth(
    expr: &Expr,
    path: &[String],
    agent: &str,
    environment: &Environment,
    semantic: &SemanticContext,
) -> Option<bool> {
    guard_truth(expr, &|left, right| {
        let value = |expr: &Expr| -> Option<String> {
            if value_path(expr).as_deref() == Some(path) {
                return Some(agent.to_owned());
            }
            match expr {
                Expr::Literal(ExprLiteral::String(value)) => Some(value.clone()),
                Expr::Literal(ExprLiteral::Ident(value))
                    if environment.get(value).is_none() && semantic.agents.contains(value) =>
                {
                    Some(value.clone())
                }
                _ => None,
            }
        };
        Some(value(left)? == value(right)?)
    })
}

// Both finite-value and null refinements use the same conservative Boolean
// interpretation. Unknown predicates must never silently become false.
fn guard_truth(expr: &Expr, equal: &impl Fn(&Expr, &Expr) -> Option<bool>) -> Option<bool> {
    let recurse = |expr| guard_truth(expr, equal);
    match expr {
        Expr::Literal(ExprLiteral::Bool(value)) => Some(*value),
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
        } => recurse(expr).map(|v| !v),
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => match (recurse(left), recurse(right)) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        },
        Expr::Binary {
            op: BinaryOp::Or,
            left,
            right,
        } => match (recurse(left), recurse(right)) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        },
        Expr::Binary {
            op: op @ (BinaryOp::Eq | BinaryOp::Ne),
            left,
            right,
        } => equal(left, right).map(|value| value == (*op == BinaryOp::Eq)),
        _ => None,
    }
}

/// A union of agent domains is still an agent domain. A union containing a
/// string or absence is not a validated agent value.
pub(super) fn agent_domain(ty: &IrType) -> Option<Vec<String>> {
    match ty {
        IrType::AgentRef(agents) => Some(agents.clone()),
        IrType::Union(variants) if !variants.is_empty() => {
            let domains = variants
                .iter()
                .map(agent_domain)
                .collect::<Option<Vec<_>>>()?;
            Some(
                domains
                    .into_iter()
                    .flatten()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Literal domains carry no agent authority, even when a string names an agent.
pub(super) fn literal_domain(ty: &IrType) -> Option<Vec<String>> {
    match ty {
        IrType::LiteralString(value) => Some(vec![value.clone()]),
        IrType::Union(variants) if !variants.is_empty() => Some(
            variants
                .iter()
                .map(literal_domain)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ),
        _ => None,
    }
}

pub(super) fn finite_domain(ty: &IrType) -> Option<Vec<String>> {
    agent_domain(ty).or_else(|| literal_domain(ty))
}

fn refined_type(original: &IrType, values: Vec<String>) -> IrType {
    if agent_domain(original).is_some() {
        IrType::AgentRef(values)
    } else if values.len() == 1 {
        IrType::LiteralString(values[0].clone())
    } else {
        IrType::Union(values.into_iter().map(IrType::LiteralString).collect())
    }
}
