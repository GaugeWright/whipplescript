//! Directional value contracts for DR-0100. Comparison compatibility is not
//! assignment compatibility: null, optional values and unrelated records cannot
//! satisfy a narrower action result merely because they can be compared.

use super::*;
use body::{BodyEffectKind, BodyStmt, CompositionExpr, CompositionStmt};

// A present unresolved binding still shadows a global enum variant or agent.
mod environment;
mod indexing;
use environment::{agent_domain, agent_pattern, finite_domain, Environment};

mod paths;
mod projections;
mod records;
mod terminals;

pub(super) fn expression_type(ty: &IrType, semantic: &SemanticContext) -> ExprType {
    match ty {
        IrType::Primitive(primitive) => match primitive {
            IrPrimitiveType::String => ExprType::String,
            IrPrimitiveType::Int => ExprType::Int,
            IrPrimitiveType::Float => ExprType::Float,
            IrPrimitiveType::Bool => ExprType::Bool,
            IrPrimitiveType::Null => ExprType::Null,
            IrPrimitiveType::Duration => ExprType::Duration,
            IrPrimitiveType::Time => ExprType::Time,
            IrPrimitiveType::Secret(kind) => ExprType::Secret(*kind),
            _ => ExprType::Unknown,
        },
        IrType::LiteralString(value) => ExprType::Finite {
            label: "literal".into(),
            values: vec![value.clone()],
        },
        IrType::Ref(name) => semantic
            .schemas
            .enums
            .get(name)
            .map_or(ExprType::Object, |values| ExprType::Finite {
                label: name.clone(),
                values: values.iter().cloned().collect(),
            }),
        IrType::AgentRef(agents) => ExprType::Finite {
            label: "AgentRef".into(),
            values: agents.clone(),
        },
        IrType::Object(_) => ExprType::Object,
        IrType::Optional(inner) => ExprType::Optional(Box::new(expression_type(inner, semantic))),
        IrType::Array(inner) => ExprType::Array(Box::new(expression_type(inner, semantic))),
        IrType::Map(inner) => ExprType::Map(Box::new(expression_type(inner, semantic))),
        IrType::Sealed(inner) => ExprType::Sealed(Box::new(expression_type(inner, semantic))),
        IrType::Union(variants) => {
            if let Some(values) = environment::literal_domain(ty) {
                return ExprType::Finite {
                    label: "literal".into(),
                    values,
                };
            }
            let types: Vec<_> = variants
                .iter()
                .map(|ty| expression_type(ty, semantic))
                .collect();
            types
                .first()
                .filter(|first| types.iter().all(|ty| ty == *first))
                .cloned()
                .unwrap_or(ExprType::Unknown)
        }
    }
}

pub(super) fn field_type(
    ty: &IrType,
    path: &[String],
    semantic: &SemanticContext,
) -> Option<IrType> {
    let Some((field, rest)) = path.split_first() else {
        return Some(ty.clone());
    };
    let member = match ty {
        IrType::Ref(name) => {
            if semantic
                .schemas
                .presence
                .get(name)
                .is_some_and(|fields| fields.contains_key(field))
            {
                return None;
            }
            lower_type(semantic.schemas.classes.get(name)?.get(field)?.clone())
        }
        IrType::Object(fields) => fields.iter().find(|f| &f.name == field)?.ty.clone(),
        IrType::Union(variants) => {
            return variants
                .iter()
                .map(|variant| field_type(variant, path, semantic))
                .collect::<Option<Vec<_>>>()
                .map(IrType::Union)
        }
        // Optional records must be narrowed before a field can be read.
        _ => return None,
    };
    field_type(&member, rest, semantic)
}

fn primitive(ty: IrPrimitiveType) -> IrType {
    IrType::Primitive(ty)
}
fn anonymous_field(name: &str, ty: IrType) -> IrClassField {
    IrClassField {
        name: name.to_owned(),
        ty,
        is_key: false,
        presence_condition: None,
        span: SourceSpan { start: 0, end: 0 },
    }
}
fn failure_aggregate(domain: Option<&TypeSyntax>) -> IrType {
    let cause = IrType::Object(vec![
        anonymous_field("origin", primitive(IrPrimitiveType::String)),
        anonymous_field(
            "kind",
            IrType::Union(
                ["Failed", "TimedOut", "Cancelled", "Domain"]
                    .into_iter()
                    .map(|kind| IrType::LiteralString(kind.into()))
                    .collect(),
            ),
        ),
        anonymous_field("summary", primitive(IrPrimitiveType::String)),
        anonymous_field("recovered", primitive(IrPrimitiveType::Bool)),
        anonymous_field(
            "evidence",
            IrType::Array(Box::new(primitive(IrPrimitiveType::String))),
        ),
    ]);
    let domain = domain.map_or_else(
        || primitive(IrPrimitiveType::Null),
        |failure| IrType::Optional(Box::new(lower_type(failure.clone()))),
    );
    IrType::Object(vec![
        anonymous_field("summary", primitive(IrPrimitiveType::String)),
        anonymous_field("operation_id", primitive(IrPrimitiveType::String)),
        anonymous_field("domain", domain),
        anonymous_field("causes", IrType::Array(Box::new(cause))),
    ])
}
fn is_null(ty: &IrType) -> bool {
    matches!(ty, IrType::Primitive(IrPrimitiveType::Null))
}

/// Directional, with no Unknown top type. A union argument must fit in its
/// entirety; matching just one possible variant loses the caller's obligation.
fn assignable(actual: &IrType, expected: &IrType, semantic: &SemanticContext) -> bool {
    value_assignable(actual, expected, semantic, true)
}

/// Record fields have the ordinary record contract, including in containers.
/// Only an explicit action parameter/result boundary admits a named string as
/// an AgentRef; sharing the recursive value checker must not spread that coercion.
fn record_assignable(actual: &IrType, expected: &IrType, semantic: &SemanticContext) -> bool {
    value_assignable(actual, expected, semantic, false)
}

fn value_assignable(
    actual: &IrType,
    expected: &IrType,
    semantic: &SemanticContext,
    agent_literals: bool,
) -> bool {
    if let (Some(actual), Some(expected)) = (agent_domain(actual), agent_domain(expected)) {
        return actual.iter().all(|agent| expected.contains(agent));
    }
    if let IrType::Union(actual) = actual {
        return actual
            .iter()
            .all(|actual| value_assignable(actual, expected, semantic, agent_literals));
    }
    if let IrType::Optional(actual) = actual {
        return value_assignable(actual, expected, semantic, agent_literals)
            && value_assignable(
                &primitive(IrPrimitiveType::Null),
                expected,
                semantic,
                agent_literals,
            );
    }
    if let IrType::Union(expected) = expected {
        return expected
            .iter()
            .any(|expected| value_assignable(actual, expected, semantic, agent_literals));
    }
    if let IrType::Optional(expected) = expected {
        return is_null(actual) || value_assignable(actual, expected, semantic, agent_literals);
    }
    match (actual, expected) {
        (IrType::Primitive(IrPrimitiveType::Int), IrType::Primitive(IrPrimitiveType::Float)) => {
            true
        }
        (
            IrType::Primitive(IrPrimitiveType::Secret(_)),
            IrType::Primitive(IrPrimitiveType::Secret(None)),
        ) => true,
        (IrType::LiteralString(_), IrType::Primitive(IrPrimitiveType::String)) => true,
        (IrType::LiteralString(value), IrType::Primitive(IrPrimitiveType::Time)) => {
            body::is_iso8601_instant(value)
        }
        (IrType::LiteralString(value), IrType::AgentRef(agents)) => {
            agent_literals && agents.contains(value)
        }
        (IrType::LiteralString(value), IrType::Ref(name)) => {
            semantic.schemas.enums.get(name).is_some_and(|variants| {
                variants.contains(value)
                    && !semantic
                        .schemas
                        .classes
                        .contains_key(&format!("{name}.{value}"))
            })
        }
        (IrType::Array(actual), IrType::Array(expected))
        | (IrType::Map(actual), IrType::Map(expected)) => {
            value_assignable(actual, expected, semantic, agent_literals)
        }
        (IrType::Object(fields), IrType::Ref(name)) => {
            semantic.schemas.classes.get(name).is_some_and(|schema| {
                fields.iter().all(|field| {
                    schema.get(&field.name).is_some_and(|expected| {
                        value_assignable(
                            &field.ty,
                            &lower_type(expected.clone()),
                            semantic,
                            agent_literals,
                        )
                    })
                }) && schema.iter().all(|(field, ty)| {
                    !records::required_field(name, field, ty, fields, semantic)
                        || fields.iter().any(|f| &f.name == field)
                }) && fields
                    .iter()
                    .map(|f| &f.name)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == fields.len()
            })
        }
        (IrType::Object(fields), IrType::Map(expected)) => fields
            .iter()
            .all(|field| value_assignable(&field.ty, expected, semantic, agent_literals)),
        // Named records are nominal; sealed payloads are invariant. A helper
        // cannot turn either into another type by exploiting erased Object.
        _ => actual == expected,
    }
}

fn type_label(ty: &IrType) -> String {
    match ty {
        IrType::Ref(name) => name.clone(),
        IrType::LiteralString(value) => format!("{value:?}"),
        IrType::Primitive(ty) => format!("{ty:?}").to_lowercase(),
        IrType::Optional(inner) => format!("{}?", type_label(inner)),
        IrType::Array(inner) => format!("{}[]", type_label(inner)),
        IrType::Map(inner) => format!("map<{}>", type_label(inner)),
        IrType::Sealed(inner) => format!("sealed<{}>", type_label(inner)),
        IrType::Union(variants) => variants
            .iter()
            .map(type_label)
            .collect::<Vec<_>>()
            .join(" | "),
        IrType::AgentRef(names) => format!("AgentRef<{}>", names.join(" | ")),
        IrType::Object(_) => "object".into(),
    }
}

fn builtin_result(name: &str, ty: &IrType, semantic: &SemanticContext) -> Option<IrPrimitiveType> {
    if let IrType::Union(variants) = ty {
        let results = variants
            .iter()
            .map(|ty| builtin_result(name, ty, semantic))
            .collect::<Option<Vec<_>>>()?;
        return results
            .first()
            .filter(|first| results.iter().all(|ty| ty == *first))
            .cloned();
    }
    if let IrType::Optional(inner) = ty {
        if name == "empty" {
            return builtin_result(name, inner, semantic);
        }
    }
    let ty = expression_type(ty, semantic);
    if matches!(ty, ExprType::Unknown) {
        return None;
    }
    match name {
        "count" if is_countable_type(&ty) => Some(IrPrimitiveType::Int),
        "exists" if is_exists_type(&ty) => Some(IrPrimitiveType::Bool),
        "empty" if is_emptiable_type(&ty) => Some(IrPrimitiveType::Bool),
        _ => None,
    }
}

// Expected types flow into constructors, not backwards through arbitrary
// operators or pure helper calls. This keeps action values under the same
// object-literal rule as the expression kernel.
fn object_contexts(expr: &Expr, expected: Option<&IrType>, semantic: &SemanticContext) -> bool {
    if let Some(IrType::Optional(inner)) = expected {
        return object_contexts(expr, Some(inner), semantic);
    }
    if let Some(IrType::Union(variants)) = expected {
        return variants
            .iter()
            .any(|ty| object_contexts(expr, Some(ty), semantic));
    }
    match expr {
        Expr::Object(fields) => match expected {
            Some(IrType::Ref(name)) => semantic.schemas.classes.get(name).is_some_and(|schema| {
                fields.iter().all(|field| {
                    // Unknown fields are rejected by assignment; no invented type
                    // is supplied for an object nested in such a field.
                    let ty = schema.get(&field.key).cloned().map(lower_type);
                    object_contexts(&field.value, ty.as_ref(), semantic)
                })
            }),
            Some(IrType::Map(inner)) => fields
                .iter()
                .all(|field| object_contexts(&field.value, Some(inner), semantic)),
            _ => false,
        },
        Expr::Index { target, key } if matches!(target.as_ref(), Expr::Array(_)) => {
            let Expr::Array(items) = target.as_ref() else {
                unreachable!()
            };
            let selected =
                indexing::literal_index(key).and_then(|index| usize::try_from(index).ok());
            items.iter().enumerate().all(|(index, item)| {
                object_contexts(
                    item,
                    (selected == Some(index)).then_some(expected).flatten(),
                    semantic,
                )
            }) && object_contexts(key, None, semantic)
        }
        Expr::Array(items) => {
            let inner = match expected {
                Some(IrType::Array(inner)) => Some(inner.as_ref()),
                _ => None,
            };
            items
                .iter()
                .all(|item| object_contexts(item, inner, semantic))
        }
        _ => expr
            .children()
            .iter()
            .all(|child| object_contexts(child, None, semantic)),
    }
}

use crate::action_plan::source_site::SourceSite;
pub(super) type CaseSite = SourceSite;
pub(super) type CaseTypes = BTreeMap<CaseSite, IrType>;
#[derive(Default)]
pub(super) struct SourceTypes {
    pub roots: BTreeMap<String, crate::rule_roots::RuleRoot>,
    pub cases: CaseTypes,
    pub values: BTreeMap<SourceSite, IrType>,
    pub tell_targets: BTreeMap<SourceSite, Vec<String>>,
    pub views: BTreeMap<String, crate::action_plan::resolved::TypedView>,
}

struct Checker<'a> {
    types: SourceTypes,
    authority: bool,
    semantic: &'a SemanticContext,
    actions: BTreeMap<&'a str, &'a ActionDecl>,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Copy)]
enum Owner<'a> {
    Action(&'a ActionDecl),
    Rule(&'a RuleDecl),
}

impl Owner<'_> {
    fn site(self) -> SourceSite {
        match self {
            Self::Action(action) => SourceSite::action(&action.name.name),
            Self::Rule(rule) => SourceSite::rule(&rule.name.name),
        }
    }
    fn label(self) -> String {
        match self {
            Self::Action(action) => format!("action `{}`", action.name.name),
            Self::Rule(rule) => format!("rule `{}`", rule.name.name),
        }
    }
    fn span(self) -> SourceSpan {
        match self {
            Self::Action(action) => action.result.as_ref().expect("typed action").success.span(),
            Self::Rule(rule) => rule.name.span,
        }
    }
    fn note(self) -> &'static str {
        match self {
            Self::Action(_) => "action contract declared here",
            Self::Rule(_) => "calling rule declared here",
        }
    }
}

#[cfg(test)]
pub(super) fn validate(actions: &[ActionDecl], semantic: &SemanticContext) -> Vec<Diagnostic> {
    validate_definitions(actions, semantic, false)
}

#[cfg(test)]
fn validate_definitions(
    actions: &[ActionDecl],
    semantic: &SemanticContext,
    authority: bool,
) -> Vec<Diagnostic> {
    definition_types(actions, semantic, authority).0
}
pub(super) fn definition_types(
    actions: &[ActionDecl],
    semantic: &SemanticContext,
    authority: bool,
) -> (Vec<Diagnostic>, SourceTypes) {
    let (view_diagnostics, views) = compile_views(semantic);
    let mut checker = Checker {
        types: SourceTypes {
            views,
            ..SourceTypes::default()
        },
        authority,
        semantic,
        actions: actions.iter().map(|a| (a.name.name.as_str(), a)).collect(),
        diagnostics: view_diagnostics,
    };
    let schema_names = semantic
        .schemas
        .classes
        .keys()
        .chain(semantic.schemas.enums.keys())
        .cloned()
        .collect();
    for action in actions.iter().filter(|a| a.result.is_some()) {
        let before = checker.diagnostics.len();
        let result = action.result.as_ref().expect("typed action");
        for ty in action
            .params
            .iter()
            .map(|p| &p.ty)
            .chain(std::iter::once(&result.success))
            .chain(result.failure.iter())
        {
            validate_type_refs(
                ty,
                &schema_names,
                &semantic.agents,
                &mut checker.diagnostics,
            );
        }
        if checker.diagnostics.len() != before {
            continue;
        }

        let (body, errors) = body::parse_action_body(&action.body.text, action.body.body_base());
        if !errors.is_empty() {
            // Normal compilation has already passed the shared syntax gate.
            // Preserve its errors for direct callers too; an unparsed body is
            // never evidence that its value and return contracts hold.
            checker.diagnostics.extend(errors);
            continue;
        }
        let binding_errors = crate::action_plan::validate_bindings(action, &body);
        if !binding_errors.is_empty() {
            checker.diagnostics.extend(binding_errors);
            continue;
        }
        let environment: Environment = action
            .params
            .iter()
            .map(|param| (param.name.name.clone(), Some(lower_type(param.ty.clone()))))
            .collect();
        let before = checker.diagnostics.len();
        checker.block(
            Owner::Action(action),
            &body.statements,
            environment.clone(),
            &Owner::Action(action).site(),
        );
        if !authority && checker.diagnostics.len() == before {
            paths::validate(&mut checker, action, &body.statements, environment);
        }
    }
    (checker.diagnostics, checker.types)
}

fn compile_views(
    semantic: &SemanticContext,
) -> (
    Vec<Diagnostic>,
    BTreeMap<String, crate::action_plan::resolved::TypedView>,
) {
    let mut diagnostics = semantic.parameterized_view_diagnostics.clone();
    let mut compiled = BTreeMap::new();
    let schema_names = semantic
        .schemas
        .classes
        .keys()
        .chain(semantic.schemas.enums.keys())
        .cloned()
        .collect();
    for view in semantic.parameterized_views.values() {
        for ty in view
            .params
            .iter()
            .map(|parameter| &parameter.ty)
            .chain(std::iter::once(&view.result))
        {
            validate_type_refs(ty, &schema_names, &semantic.agents, &mut diagnostics);
        }
        let mut names = BTreeMap::new();
        for parameter in &view.params {
            if let Some(first) = names.insert(parameter.name.name.clone(), parameter.name.span) {
                diagnostics.push(
                    Diagnostic::error(
                        diagnostic_code!("construct.duplicate_binding"),
                        parameter.name.span,
                        format!(
                            "view `{}` repeats parameter `{}`",
                            view.name.name, parameter.name.name
                        ),
                    )
                    .with_related(first, "first parameter declared here")
                    .with_suggestion("rename or remove the repeated parameter"),
                );
            }
        }
        let (body, errors) = body::parse_action_body(&view.body.text, view.body.body_base());
        diagnostics.extend(errors);
        let [BodyStmt::Composition(CompositionStmt::Return(value))] = body.statements.as_slice()
        else {
            diagnostics.push(
                Diagnostic::error(
                    diagnostic_code!("construct.parameterized_view_body"),
                    view.body.span,
                    format!(
                        "parameterized view `{}` must contain exactly one `return` expression",
                        view.name.name
                    ),
                )
                .with_suggestion("replace the body with one pure `return <expression>`"),
            );
            continue;
        };
        compiled.insert(
            view.name.name.clone(),
            crate::action_plan::resolved::TypedView {
                parameters: view
                    .params
                    .iter()
                    .map(|parameter| parameter.name.name.clone())
                    .collect(),
                expression: value.expr.clone(),
            },
        );
    }

    let mut remaining: BTreeSet<_> = compiled.keys().cloned().collect();
    loop {
        let removable: Vec<_> = remaining
            .iter()
            .filter(|name| {
                let mut pending = vec![&compiled[*name].expression];
                while let Some(expr) = pending.pop() {
                    if let Expr::Call { name: called, .. } = expr {
                        if remaining.contains(called) {
                            return false;
                        }
                    }
                    pending.extend(expr.children());
                }
                true
            })
            .cloned()
            .collect();
        if removable.is_empty() {
            break;
        }
        for name in removable {
            remaining.remove(&name);
        }
    }
    if let Some(name) = remaining.first() {
        let view = &semantic.parameterized_views[name];
        diagnostics.push(
            Diagnostic::error(
                diagnostic_code!("construct.recursive_view"),
                view.name.span,
                format!("recursive parameterized view composition includes `{name}`"),
            )
            .with_suggestion("break the cycle so every view expands to a finite expression"),
        );
    }

    // Reuse the action value checker for the one pure return expression. It
    // supplies named-record construction, directional assignment, query and
    // nested-view argument diagnostics without giving views an effect surface.
    let mut checker = Checker {
        types: SourceTypes::default(),
        authority: false,
        semantic,
        actions: BTreeMap::new(),
        diagnostics: Vec::new(),
    };
    for view in semantic.parameterized_views.values() {
        let Some(typed) = compiled.get(&view.name.name) else {
            continue;
        };
        let value = CompositionExpr {
            source: typed.expression.to_snapshot(),
            expr: typed.expression.clone(),
            span: view.body.span,
        };
        let environment: Environment = view
            .params
            .iter()
            .map(|parameter| {
                (
                    parameter.name.name.clone(),
                    Some(lower_type(parameter.ty.clone())),
                )
            })
            .collect();
        checker.check_value(
            &value,
            &view.result,
            &environment,
            &format!("return from view `{}`", view.name.name),
        );
    }
    diagnostics.extend(checker.diagnostics);
    (diagnostics, compiled)
}

/// Definition/signature validation precedes this phase. Types originate at
/// actual trigger bindings, never at the callee's required parameter types.
#[cfg(test)]
pub(super) fn validate_callers(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
) -> Vec<Diagnostic> {
    validate_rules(actions, rules, semantic, false)
}

#[cfg(test)]
pub(super) fn validate_authority(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
) -> Vec<Diagnostic> {
    authority_types(actions, rules, semantic).0
}
pub(super) fn authority_types(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
) -> (Vec<Diagnostic>, SourceTypes) {
    let (mut diagnostics, mut types) = definition_types(actions, semantic, true);
    if diagnostics.is_empty() {
        let (errors, callers) = rule_types(actions, rules, semantic, true);
        diagnostics.extend(errors);
        types.tell_targets.extend(callers.tell_targets);
    }
    (diagnostics, types)
}

#[cfg(test)]
fn validate_rules(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
    authority: bool,
) -> Vec<Diagnostic> {
    rule_types(actions, rules, semantic, authority).0
}
pub(super) fn rule_types(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
    authority: bool,
) -> (Vec<Diagnostic>, SourceTypes) {
    let mut checker = Checker {
        types: SourceTypes::default(),
        authority,
        semantic,
        actions: actions.iter().map(|a| (a.name.name.as_str(), a)).collect(),
        diagnostics: Vec::new(),
    };
    let mut names = BTreeMap::new();
    for rule in rules {
        register_rule_name(&rule.name, &mut names, &mut checker.diagnostics);
    }
    if !checker.diagnostics.is_empty() {
        return (checker.diagnostics, checker.types);
    }
    for rule in rules {
        let root = match crate::rule_roots::analyze(rule, semantic) {
            Ok(root) => root,
            Err(errors) => {
                checker.diagnostics.extend(errors);
                continue;
            }
        };

        let (body, errors) = body::parse_composed_rule_body(&rule.body.text, rule.body.body_base());
        if !errors.is_empty() {
            checker.diagnostics.extend(errors);
            continue;
        }
        let inputs = crate::rule_roots::inputs(rule);
        let mut environment = Environment::new();
        for (name, schema) in &root.binding_schemas {
            environment.insert(name.clone(), Some(IrType::Ref(schema.clone())));
        }
        let mut errors = crate::action_plan::validate_rule_bindings(&body, &inputs);
        errors.extend(crate::action_plan::validate_failure_handlers(
            &body.statements,
            &format!("rule `{}`", rule.name.name),
        ));
        if !errors.is_empty() {
            checker.diagnostics.extend(errors);
            continue;
        }
        for when in &rule.whens {
            if let (_, Some(guard)) = split_when_guard(&when.text) {
                if let Ok(expr) = parse_expression(guard) {
                    environment.narrow_guard(&expr, semantic);
                }
            }
        }
        checker.block(
            Owner::Rule(rule),
            &body.statements,
            environment,
            &Owner::Rule(rule).site(),
        );
        checker.types.roots.insert(rule.name.name.clone(), root);
    }
    (checker.diagnostics, checker.types)
}

impl Checker<'_> {
    fn collect_region_operations(
        &self,
        statements: &[BodyStmt],
        types: &mut BTreeMap<String, IrType>,
    ) {
        for statement in statements {
            let operation = match statement {
                BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                    operation.as_ref()
                }
                other => other,
            };
            if matches!(
                operation,
                BodyStmt::Effect(_) | BodyStmt::Composition(CompositionStmt::Call { .. })
            ) {
                if let Some(name) = crate::action_plan::binding_name(statement) {
                    types.insert(
                        name.to_owned(),
                        self.operation_type(operation)
                            .unwrap_or_else(|| primitive(IrPrimitiveType::String)),
                    );
                }
            }
            match statement {
                BodyStmt::After(after) => self.collect_region_operations(&after.body, types),
                BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        self.collect_region_operations(&branch.body, types);
                    }
                }
                // An enclosing held prefix includes whichever arm a nested
                // region selected, so its progress vocabulary includes both.
                BodyStmt::Region(region) => {
                    self.collect_region_operations(&region.body, types);
                    self.collect_region_operations(&region.lapse_body, types);
                }
                _ => {}
            }
        }
    }

    fn region_progress_type(&self, statements: &[BodyStmt]) -> IrType {
        let mut operations = BTreeMap::new();
        self.collect_region_operations(statements, &mut operations);
        let status = IrType::Union(
            [
                "completed",
                "failed",
                "timed_out",
                "cancelled",
                "cancelled_by_lapse",
                "not_requested",
            ]
            .into_iter()
            .map(|value| IrType::LiteralString(value.into()))
            .collect(),
        );
        let steps = IrType::Object(
            operations
                .keys()
                .map(|name| anonymous_field(name, status.clone()))
                .collect(),
        );
        let mut fields = operations
            .into_iter()
            .map(|(name, ty)| anonymous_field(&name, IrType::Optional(Box::new(ty))))
            .collect::<Vec<_>>();
        fields.push(anonymous_field("steps", steps));
        IrType::Object(fields)
    }

    fn prompt_sealed_inputs(&mut self, effect: &body::EffectStmt, ty: &IrType, kind: &str) {
        let granted: BTreeSet<_> = effect
            .kind
            .access_grants()
            .iter()
            .flat_map(|grant| &grant.operations)
            .filter(|op| op.operation == "unwrap")
            .filter_map(|op| op.target.as_deref())
            .collect();
        let mut pending = vec![ty.clone()];
        let mut seen = BTreeSet::new();
        let mut required = BTreeSet::new();
        while let Some(ty) = pending.pop() {
            match ty {
                IrType::Sealed(inner) => {
                    required.insert(match *inner {
                        IrType::Ref(name) => name,
                        IrType::Primitive(p) => p.as_str().into(),
                        other => other.display_label(),
                    });
                }
                IrType::Optional(inner) | IrType::Array(inner) | IrType::Map(inner) => {
                    pending.push(*inner)
                }
                IrType::Union(types) => pending.extend(types),
                IrType::Object(fields) => pending.extend(fields.into_iter().map(|field| field.ty)),
                IrType::Ref(name) if seen.insert(name.clone()) => {
                    if let Some(fields) = self.semantic.schemas.classes.get(&name) {
                        pending.extend(fields.values().cloned().map(lower_type));
                    } else if let Some(variants) = self.semantic.schemas.enums.get(&name) {
                        pending.extend(
                            variants
                                .iter()
                                .map(|variant| IrType::Ref(format!("{name}.{variant}"))),
                        );
                    }
                }
                _ => {}
            }
        }
        for payload in required
            .into_iter()
            .filter(|payload| !granted.contains(payload.as_str()))
        {
            self.diagnostics.push(Diagnostic::error(
                diagnostic_code!("security.sealed_value_crossing"),
                effect.span,
                format!("{kind} carries sealed<{payload}> without an `unwrap for {payload}` grant"),
            ));
        }
    }

    fn prompt_contains_media(&self, ty: &IrType) -> bool {
        let mut pending = vec![ty.clone()];
        let mut seen = BTreeSet::new();
        while let Some(ty) = pending.pop() {
            match ty {
                IrType::Primitive(
                    IrPrimitiveType::Image
                    | IrPrimitiveType::Pdf
                    | IrPrimitiveType::Audio
                    | IrPrimitiveType::Video,
                ) => return true,
                IrType::Optional(inner)
                | IrType::Array(inner)
                | IrType::Map(inner)
                | IrType::Sealed(inner) => pending.push(*inner),
                IrType::Union(types) => pending.extend(types),
                IrType::Object(fields) => pending.extend(fields.into_iter().map(|field| field.ty)),
                IrType::Ref(name) if seen.insert(name.clone()) => {
                    if let Some(fields) = self.semantic.schemas.classes.get(&name) {
                        pending.extend(fields.values().cloned().map(lower_type));
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn tell_authority(
        &mut self,
        owner: Owner<'_>,
        effect: &body::EffectStmt,
        environment: &Environment,
        site: &SourceSite,
    ) {
        let BodyEffectKind::Tell { target, .. } = &effect.kind else {
            return;
        };
        let before = self.diagnostics.len();
        let ty = parse_expression(target)
            .ok()
            .and_then(|expr| self.infer_node(&expr, effect.span, environment));
        let Some(agents) = ty.as_ref().and_then(agent_domain) else {
            if self.diagnostics.len() != before {
                return;
            }
            self.diagnostics.push(
                Diagnostic::error(
                    diagnostic_code!("type.mismatch"),
                    effect.span,
                    format!(
                        "{} uses tell target `{target}` without a known AgentRef type",
                        owner.label()
                    ),
                )
                .with_related(owner.span(), owner.note()),
            );
            return;
        };
        let mut agents = agents;
        agents.sort();
        agents.dedup();
        self.types.tell_targets.insert(site.clone(), agents.clone());
        for agent in agents {
            if !self.semantic.agents.contains(&agent) {
                self.diagnostics.push(
                    Diagnostic::error(
                        diagnostic_code!("type.unknown_agent"),
                        effect.span,
                        format!("{} tells unknown agent `{agent}`", owner.label()),
                    )
                    .with_related(owner.span(), owner.note()),
                );
                continue;
            }
            agent_capabilities::validate(
                &owner.label(),
                effect.span,
                &agent,
                &effect.requires,
                self.semantic,
                &mut self.diagnostics,
            );
        }
    }

    fn scope_error(&mut self, span: SourceSpan, message: String, owner: Owner<'_>) {
        self.diagnostics.push(
            Diagnostic::error(diagnostic_code!("type.mismatch"), span, message)
                .with_related(owner.span(), owner.note()),
        );
    }
    fn error(&mut self, span: SourceSpan, message: String, contract: SourceSpan) {
        self.diagnostics.push(
            Diagnostic::error(diagnostic_code!("type.mismatch"), span, message)
                .with_related(contract, "action contract declared here"),
        );
    }

    fn path_error(
        &mut self,
        failure: environment::ReadFailure,
        path: &[String],
        environment: &Environment,
        span: SourceSpan,
    ) {
        match failure {
            environment::ReadFailure::Conditional {
                field,
                discriminator,
                required,
                declaration,
            } => self.diagnostics.push(
                Diagnostic::error(
                    diagnostic_code!("expr.conditional_without_presence"),
                    span,
                    format!(
                        "reading `{field}` requires proof that `{discriminator}` is {required:?}"
                    ),
                )
                .with_related(declaration, "conditionally present field declared here")
                .with_suggestion(format!(
                    "read this field inside a branch proving `{discriminator} == {required:?}`"
                )),
            ),
            environment::ReadFailure::Unknown => {
                let Some((parent, field, candidates)) =
                    environment.unknown_member(path, self.semantic)
                else {
                    return;
                };
                let suggestion = crate::closest_name(&field, candidates.iter()).map_or_else(
                    || format!("use a field available on `{parent}`"),
                    |candidate| {
                        format!(
                            "{} use a field available on `{parent}`",
                            crate::fixit::did_you_mean(&candidate)
                        )
                    },
                );
                self.diagnostics.push(
                    Diagnostic::error(
                        diagnostic_code!("type.unknown_field"),
                        span,
                        format!(
                            "action expression has invalid field path `{}`: `{parent}` has no field `{field}`",
                            path.join(".")
                        ),
                    )
                    .with_suggestion(suggestion),
                );
            }
        }
    }

    fn infer(&mut self, value: &CompositionExpr, environment: &Environment) -> Option<IrType> {
        self.infer_node(&value.expr, value.span, environment)
    }

    fn infer_node(
        &mut self,
        expr: &Expr,
        span: SourceSpan,
        environment: &Environment,
    ) -> Option<IrType> {
        match expr {
            Expr::Literal(ExprLiteral::Ident(name)) => match environment.get(name) {
                Some(ty) => ty.clone(),
                None => self
                    .semantic
                    .agents
                    .contains(name)
                    .then(|| IrType::AgentRef(vec![name.clone()]))
                    .or_else(|| {
                        self.semantic
                            .schemas
                            .enums
                            .values()
                            .any(|values| values.contains(name))
                            .then(|| IrType::LiteralString(name.clone()))
                    }),
            },
            Expr::Path(path) => match environment.read_path(path, self.semantic) {
                Ok(ty) => Some(ty),
                Err(failure) => {
                    self.path_error(failure, path, environment, span);
                    None
                }
            },
            Expr::Literal(literal) => Some(match literal {
                ExprLiteral::String(value) => IrType::LiteralString(value.clone()),
                ExprLiteral::Number(value) => primitive(if value.parse::<i64>().is_ok() {
                    IrPrimitiveType::Int
                } else {
                    IrPrimitiveType::Float
                }),
                ExprLiteral::Bool(_) => primitive(IrPrimitiveType::Bool),
                ExprLiteral::Null => primitive(IrPrimitiveType::Null),
                ExprLiteral::Duration(_) => primitive(IrPrimitiveType::Duration),
                ExprLiteral::Ident(_) => unreachable!(),
            }),
            Expr::Array(items) => Some(IrType::Array(Box::new(IrType::Union(
                items
                    .iter()
                    .map(|item| self.infer_node(item, span, environment))
                    .collect::<Option<Vec<_>>>()?,
            )))),
            Expr::Object(fields) => Some(IrType::Object(
                fields
                    .iter()
                    .map(|field| {
                        Some(IrClassField {
                            name: field.key.clone(),
                            ty: self.infer_node(&field.value, span, environment)?,
                            is_key: false,
                            presence_condition: None,
                            span,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            )),
            Expr::Index { target, key } => self.indexed(target, key, span, environment),
            Expr::Unary { .. } | Expr::Binary { .. } => {
                // Resolve every operand first: the shared operator checker must
                // not treat a missing action binding as its legacy Unknown.
                let null_comparison = matches!(expr, Expr::Binary {
                    op: BinaryOp::Eq | BinaryOp::Ne, left, right,
                } if matches!(left.as_ref(), Expr::Literal(ExprLiteral::Null))
                    || matches!(right.as_ref(), Expr::Literal(ExprLiteral::Null)));
                let mut value_expression_types = Vec::new();
                let mut operand_environment = environment.clone();
                for (index, child) in expr.children().into_iter().enumerate() {
                    let ty = self.infer_node(child, span, &operand_environment)?;
                    // Every operand still needs a real managed type. The shared
                    // scalar representation cannot express all valid unions,
                    // but null equality is valid for every successful value.
                    if !null_comparison
                        && matches!(expression_type(&ty, self.semantic), ExprType::Unknown)
                    {
                        return None;
                    }
                    value_expression_types.push((child.clone(), ty));
                    if index == 0 {
                        match expr {
                            Expr::Binary {
                                op: BinaryOp::And, ..
                            } => {
                                operand_environment.narrow_guard(child, self.semantic);
                            }
                            Expr::Binary {
                                op: BinaryOp::Or, ..
                            } => {
                                operand_environment.narrow_guard(
                                    &Expr::Unary {
                                        op: UnaryOp::Not,
                                        expr: Box::new(child.clone()),
                                    },
                                    self.semantic,
                                );
                            }
                            _ => {}
                        }
                    }
                }
                let mut scope = ExprScope {
                    value_expression_types,
                    value_types: environment
                        .iter()
                        .filter_map(|(name, ty)| ty.clone().map(|ty| (name.clone(), ty)))
                        .collect(),
                    ..ExprScope::default()
                };
                let mut nodes = vec![expr];
                while let Some(node) = nodes.pop() {
                    if let Expr::Path(path) = node {
                        if let Some(ty) = environment.path_type(path, self.semantic) {
                            scope.value_path_types.insert(path.clone(), ty);
                        }
                    }
                    nodes.extend(node.children());
                }
                let context = ExprValidationContext {
                    subject: "action expression".into(),
                    at: BodyAnchor::fixed(span),
                };
                let before = self.diagnostics.len();
                let ty = infer_expr_type(
                    expr,
                    &ExprSpans::unknown(),
                    self.semantic,
                    &scope,
                    &context,
                    &mut self.diagnostics,
                );
                if self.diagnostics.len() != before {
                    return None;
                }
                Some(primitive(match ty {
                    ExprType::Bool => IrPrimitiveType::Bool,
                    ExprType::Int => IrPrimitiveType::Int,
                    ExprType::Float => IrPrimitiveType::Float,
                    ExprType::String => IrPrimitiveType::String,
                    ExprType::Duration => IrPrimitiveType::Duration,
                    ExprType::Time => IrPrimitiveType::Time,
                    _ => return None,
                }))
            }
            Expr::Call { name, args } => {
                if let Some(view) = self.semantic.parameterized_views.get(name) {
                    if args.len() != view.params.len() {
                        self.diagnostics.push(
                            Diagnostic::error(
                                diagnostic_code!("expr.arity_mismatch"),
                                span,
                                format!(
                                    "view `{name}` expects {} arguments, got {}",
                                    view.params.len(),
                                    args.len()
                                ),
                            )
                            .with_related(view.name.span, "view declared here"),
                        );
                        return None;
                    }
                    let mut valid = true;
                    for (argument, parameter) in args.iter().zip(&view.params) {
                        let Some(actual) = self.infer_node(argument, span, environment) else {
                            valid = false;
                            continue;
                        };
                        let expected = lower_type(parameter.ty.clone());
                        if !assignable(&actual, &expected, self.semantic) {
                            self.error(
                                span,
                                format!(
                                    "view `{name}` parameter `{}` expects {}, got {}",
                                    parameter.name.name,
                                    type_label(&expected),
                                    type_label(&actual)
                                ),
                                parameter.span,
                            );
                            valid = false;
                        }
                    }
                    return valid.then(|| lower_type(view.result.clone()));
                }
                if name == "outcome" {
                    let Some(operation) = environment::observed_operation(expr) else {
                        self.diagnostics.push(Diagnostic::error(
                            diagnostic_code!("type.mismatch"),
                            span,
                            "`outcome` requires exactly one named operation",
                        ));
                        return None;
                    };
                    if !environment.is_operation(operation) {
                        self.diagnostics.push(Diagnostic::error(
                            diagnostic_code!("type.mismatch"),
                            span,
                            format!("`{operation}` is a value, not an action operation"),
                        ));
                        return None;
                    }
                    let outcomes = environment.outcomes(operation)?;
                    let Some(ty) = &outcomes.completed else {
                        self.diagnostics.push(Diagnostic::error(
                            diagnostic_code!("type.mismatch"),
                            span,
                            format!(
                                "`outcome({operation})` requires an effect or typed child-action operation"
                            ),
                        ));
                        return None;
                    };
                    return Some(ty.clone());
                }
                if args.len() != 1 {
                    return None;
                }
                if matches!(args[0], Expr::Query { .. })
                    && matches!(name.as_str(), "count" | "exists" | "empty")
                {
                    let mut scope = ExprScope {
                        value_types: environment
                            .iter()
                            .filter_map(|(name, ty)| ty.clone().map(|ty| (name.clone(), ty)))
                            .collect(),
                        ..ExprScope::default()
                    };
                    let mut nodes = vec![expr];
                    while let Some(node) = nodes.pop() {
                        if let Expr::Path(path) = node {
                            if let Some(ty) = environment.path_type(path, self.semantic) {
                                scope.value_path_types.insert(path.clone(), ty);
                            }
                        }
                        nodes.extend(node.children());
                    }
                    let context = ExprValidationContext {
                        subject: "action expression".into(),
                        at: BodyAnchor::fixed(span),
                    };
                    let before = self.diagnostics.len();
                    validate_expr_node(
                        expr,
                        &ExprSpans::unknown(),
                        self.semantic,
                        &scope,
                        &context,
                        &BTreeSet::new(),
                        &mut self.diagnostics,
                    );
                    let ty = infer_expr_type(
                        expr,
                        &ExprSpans::unknown(),
                        self.semantic,
                        &scope,
                        &context,
                        &mut self.diagnostics,
                    );
                    if self.diagnostics.len() != before {
                        return None;
                    }
                    return Some(primitive(match ty {
                        ExprType::Bool => IrPrimitiveType::Bool,
                        ExprType::Int => IrPrimitiveType::Int,
                        _ => return None,
                    }));
                }
                let ty = self.infer_node(&args[0], span, environment)?;
                builtin_result(name, &ty, self.semantic).map(primitive)
            }
            Expr::Query { .. } => None,
        }
    }

    fn check_value(
        &mut self,
        value: &CompositionExpr,
        expected: &TypeSyntax,
        environment: &Environment,
        subject: &str,
    ) {
        let expected_ir = lower_type(expected.clone());
        if !object_contexts(&value.expr, Some(&expected_ir), self.semantic) {
            self.error(
                value.span,
                format!("{subject} constructs an object without an expected class or map type"),
                expected.span(),
            );
            return;
        }
        let before = self.diagnostics.len();
        match self.infer(value, environment) {
            Some(actual) if !assignable(&actual, &expected_ir, self.semantic) => self.error(
                value.span,
                format!(
                    "{subject} expects {}, got {}",
                    type_label(&expected_ir),
                    type_label(&actual)
                ),
                expected.span(),
            ),
            None if before == self.diagnostics.len() => self.error(
                value.span,
                format!(
                    "cannot determine the type of `{}` for {subject}",
                    value.source
                ),
                expected.span(),
            ),
            _ => {}
        }
    }

    fn operation_type(&self, statement: &BodyStmt) -> Option<IrType> {
        match statement {
            BodyStmt::Composition(CompositionStmt::Call { name, .. }) => self
                .actions
                .get(name.as_str())?
                .result
                .as_ref()
                .map(|r| lower_type(r.success.clone())),
            BodyStmt::Declassify { target_type, .. }
                if self.semantic.schemas.class_exists(target_type) =>
            {
                Some(IrType::Ref(target_type.clone()))
            }
            BodyStmt::Effect(effect) => match &effect.kind {
                BodyEffectKind::Coerce { name, .. } => self
                    .semantic
                    .coerce_outputs
                    .get(name)
                    .cloned()
                    .map(lower_type),
                BodyEffectKind::Prompt { .. } | BodyEffectKind::Tell { .. } => {
                    Some(primitive(IrPrimitiveType::String))
                }
                BodyEffectKind::Decide { result_fields } => {
                    Some(crate::inline_decide_output_type(result_fields, effect.span))
                }
                BodyEffectKind::Timer { .. } => Some(primitive(IrPrimitiveType::Null)),
                BodyEffectKind::FileRead { .. } => Some(crate::file_read_output_type(effect.span)),
                BodyEffectKind::FileWrite { .. } => {
                    Some(crate::file_write_output_type(effect.span))
                }
                BodyEffectKind::FileImport { .. } => {
                    Some(crate::file_import_output_type(effect.span))
                }
                BodyEffectKind::Notify { .. } => Some(crate::signal_emit_output_type(effect.span)),
                BodyEffectKind::TrackerFile { .. } => {
                    Some(crate::tracker_file_output_type(effect.span))
                }
                BodyEffectKind::TrackerClaim { .. } => {
                    Some(crate::tracker_claim_output_type(effect.span))
                }
                BodyEffectKind::TrackerRelease { .. } => {
                    Some(crate::tracker_release_output_type(effect.span))
                }
                BodyEffectKind::TrackerFinish { .. } => {
                    Some(crate::tracker_finish_output_type(effect.span))
                }
                BodyEffectKind::LedgerAppend { .. } => {
                    Some(crate::ledger_append_output_type(effect.span))
                }
                BodyEffectKind::CounterConsume { .. } => {
                    Some(crate::counter_consume_output_type(effect.span))
                }
                BodyEffectKind::FileExport { .. } => {
                    Some(crate::file_export_output_type(effect.span))
                }
                BodyEffectKind::Exec {
                    parse_target: Some(target),
                    ..
                } if !target.each => Some(IrType::Ref(target.schema.clone())),
                _ => None,
            },
            _ => None,
        }
    }

    fn operation_outcomes(&self, statement: &BodyStmt) -> environment::OperationOutcomes {
        if let BodyStmt::Composition(CompositionStmt::Call { name, .. }) = statement {
            let Some(action) = self.actions.get(name.as_str()) else {
                return environment::OperationOutcomes::default();
            };
            let Some(result) = &action.result else {
                return environment::OperationOutcomes::default();
            };
            let failure = failure_aggregate(result.failure.as_ref());
            return environment::OperationOutcomes {
                succeeded: Some(lower_type(result.success.clone())),
                completed: Some(IrType::Ref("TerminalOutcome".into())),
                failed: Some(failure),
                timed_out: None,
                cancelled: None,
            };
        }
        let BodyStmt::Effect(effect) = statement else {
            return environment::OperationOutcomes::default();
        };
        let failed = match effect.kind {
            BodyEffectKind::Exec { .. } => "TerminalFailedExec",
            BodyEffectKind::Coerce { .. }
            | BodyEffectKind::Prompt { .. }
            | BodyEffectKind::Decide { .. } => "TerminalFailedCoerce",
            BodyEffectKind::Tell { .. } => "TerminalFailedTell",
            _ => "TerminalFailed",
        };
        environment::OperationOutcomes {
            succeeded: self.operation_type(statement),
            completed: Some(IrType::Ref("TerminalOutcome".into())),
            failed: Some(IrType::Ref(failed.into())),
            timed_out: Some(IrType::Ref("TerminalTimedOut".into())),
            cancelled: Some(IrType::Ref("TerminalCancelled".into())),
        }
    }

    fn block_environment(
        &self,
        statements: &[BodyStmt],
        mut environment: Environment,
    ) -> Environment {
        // Managed value dependencies are not source order. Names in this block
        // are visible throughout it; branch and continuation locals stay inside
        // their own child environment. Dependency-cycle checking is a later pass.
        for statement in statements {
            let Some(binding) = crate::action_plan::binding_name(statement) else {
                continue;
            };
            let operation = match statement {
                BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                    operation.as_ref()
                }
                other => other,
            };
            // Synchronous declarations shadow too. A declared result type is
            // checked separately against its source; an unresolved result never
            // inherits an outer agent's type or field refinement.
            environment.insert(binding.to_owned(), self.operation_type(operation));
            if matches!(
                operation,
                BodyStmt::Effect(_) | BodyStmt::Composition(CompositionStmt::Call { .. })
            ) {
                environment.mark_operation(binding, self.operation_outcomes(operation));
            }
        }
        // Pure projections depend on lexical values just as calls do. Resolve
        // forward chains after every local name has shadowed its outer binding.
        for _ in 0..statements.len() {
            let mut changed = false;
            for statement in statements {
                let operation = match statement {
                    BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                        operation.as_ref()
                    }
                    other => other,
                };
                if let BodyStmt::Redact {
                    source,
                    keep,
                    binding,
                    span,
                } = operation
                {
                    if let Ok(ty) = self.redact_type(source, keep, &environment, *span) {
                        if environment.get(binding).and_then(Option::as_ref) != Some(&ty) {
                            environment.insert(binding.clone(), Some(ty));
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        environment
    }

    fn block(
        &mut self,
        owner: Owner<'_>,
        statements: &[BodyStmt],
        environment: Environment,
        site: &SourceSite,
    ) {
        let environment = self.block_environment(statements, environment);
        for (index, statement) in statements.iter().enumerate() {
            self.statement(owner, statement, &environment, &site.child(index));
        }
    }

    fn statement(
        &mut self,
        owner: Owner<'_>,
        statement: &BodyStmt,
        environment: &Environment,
        site: &SourceSite,
    ) {
        if !self.authority {
            if let Some(ty) = crate::action_plan::binding_name(statement)
                .and_then(|name| environment.get(name))
                .and_then(Option::as_ref)
            {
                self.types.values.insert(site.clone(), ty.clone());
            }
        }
        match statement {
            BodyStmt::Redact {
                source, keep, span, ..
            } if !self.authority => {
                self.check_redact(source, keep, environment, *span);
            }
            BodyStmt::Terminal(terminal) if !self.authority => {
                self.terminal_payload(owner, terminal, environment)
            }
            BodyStmt::Record(record)
            | BodyStmt::Done {
                replacement: Some(record),
                ..
            } if !self.authority => self.record_payload(record, environment),
            BodyStmt::Declassify {
                source,
                target_type,
                span,
                ..
            } if !self.authority => {
                self.record_payload(
                    &crate::body::RecordStmt {
                        schema: target_type.clone(),
                        from: Some(source.clone()),
                        fields: Vec::new(),
                        span: *span,
                    },
                    environment,
                );
            }
            BodyStmt::Cancel { binding, span } if !self.authority => {
                if environment.get(binding).is_none() {
                    self.scope_error(
                        *span,
                        format!("cancel names unknown binding `{binding}`"),
                        owner,
                    );
                } else if !environment.is_operation(binding) {
                    self.scope_error(
                        *span,
                        format!("cancel requires an operation binding; `{binding}` is a value"),
                        owner,
                    );
                }
            }
            BodyStmt::Composition(CompositionStmt::Return(value)) => {
                let Owner::Action(action) = owner else {
                    unreachable!("composed-rule parser refuses action returns")
                };
                let contract = action.result.as_ref().expect("typed action");
                self.check_value(
                    value,
                    &contract.success,
                    environment,
                    &format!("return from action `{}`", action.name.name),
                );
            }
            BodyStmt::Composition(CompositionStmt::Fail(value)) => {
                let Owner::Action(action) = owner else {
                    unreachable!("composed-rule parser preserves workflow failure terminals")
                };
                let contract = action.result.as_ref().expect("typed action");
                match &contract.failure {
                    Some(failure) => {
                        if !self.authority {
                            self.types
                                .values
                                .insert(site.clone(), lower_type(failure.clone()));
                        }
                        self.check_value(
                            value,
                            failure,
                            environment,
                            &format!("failure from action `{}`", action.name.name),
                        );
                    }
                    None => self.error(
                        value.span,
                        format!(
                            "action `{}` declares no domain failure type",
                            action.name.name
                        ),
                        contract.success.span(),
                    ),
                }
            }
            BodyStmt::Composition(CompositionStmt::Call {
                name,
                name_span,
                arguments,
                ..
            }) => {
                let Some(callee) = self.actions.get(name.as_str()).copied() else {
                    self.scope_error(*name_span, format!("unknown action `{name}`"), owner);
                    return;
                };
                if arguments.len() != callee.params.len() {
                    self.error(
                        *name_span,
                        format!(
                            "action `{name}` expects {} argument(s), got {}",
                            callee.params.len(),
                            arguments.len()
                        ),
                        callee.name.span,
                    );
                    return;
                }
                for (value, param) in arguments.iter().zip(&callee.params) {
                    self.check_value(
                        value,
                        &param.ty,
                        environment,
                        &format!("parameter `{}` of action `{name}`", param.name.name),
                    );
                }
            }
            BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                self.statement(owner, operation, environment, site)
            }
            BodyStmt::Composition(CompositionStmt::OnFailure { alias, body, .. }) => {
                let domain = match owner {
                    Owner::Action(action) => action
                        .result
                        .as_ref()
                        .and_then(|result| result.failure.as_ref()),
                    Owner::Rule(_) => None,
                };
                let mut child = environment.clone();
                child.insert(alias.clone(), Some(failure_aggregate(domain)));
                self.block(owner, body, child, &site.child(0));
            }
            BodyStmt::After(after) => {
                if after.predicate == body::AfterPredicate::Succeeds {
                    if let Some(alias) = &after.alias {
                        self.diagnostics.push(
                            Diagnostic::error(
                                diagnostic_code!("construct.redundant_success_alias"),
                                after.span,
                                format!(
                                    "managed operation `{}` already denotes its successful value; success alias `{alias}` is redundant",
                                    after.binding
                                ),
                            )
                            .with_suggestion(format!(
                                "write `after {} succeeds {{ ... }}` and use `{}` directly",
                                after.binding, after.binding
                            )),
                        );
                    }
                }
                if let Some(outcomes) = environment.outcomes(&after.binding) {
                    let unavailable = match after.predicate {
                        body::AfterPredicate::TimedOut => outcomes.timed_out.is_none(),
                        body::AfterPredicate::Cancelled => outcomes.cancelled.is_none(),
                        _ => false,
                    };
                    if unavailable {
                        self.scope_error(
                            after.span,
                            format!(
                                "child action `{}` settles as `Completed` or `Failed`; inspect the aggregate failure causes for leaf {} terminals",
                                after.binding,
                                after.predicate.arm_key_str()
                            ),
                            owner,
                        );
                        return;
                    }
                }
                let mut child = environment.clone();
                if let Some(alias) = &after.alias {
                    let terminal_outcome = (after.predicate == body::AfterPredicate::Completes)
                        .then(|| environment.outcomes(&after.binding).cloned())
                        .flatten();
                    child.insert(alias.clone(), None);
                    if after.predicate == body::AfterPredicate::Succeeds {
                        if let Some(ty) = environment.get(&after.binding) {
                            child.insert(alias.clone(), ty.clone());
                            child.inherit_refinements(
                                alias,
                                std::slice::from_ref(&after.binding),
                                environment,
                            );
                        }
                    } else if let Some(ty) =
                        environment.operation_outcome(&after.binding, after.predicate)
                    {
                        child.insert(alias.clone(), Some(ty.clone()));
                    }
                    if let Some(outcomes) = terminal_outcome {
                        child.mark_terminal_outcome(alias, outcomes);
                    }
                }
                self.block(owner, &after.body, child, &site.child(0));
            }
            BodyStmt::Case(case) => {
                let scrutinee = parse_expression(&case.scrutinee).ok();
                let terminal_outcome = scrutinee
                    .as_ref()
                    .and_then(|expr| environment::terminal_outcomes(expr, environment));
                let scrutinee_type = scrutinee
                    .as_ref()
                    .and_then(|expr| self.infer_node(expr, case.span, environment));
                if !self.authority {
                    if let Some(ty) = &scrutinee_type {
                        // Each declaration is visited once. Structural sites
                        // distinguish sibling blocks even at a shared fallback span.
                        self.types.cases.insert(site.clone(), ty.clone());
                    }
                }
                if let Some(outcomes) = terminal_outcome {
                    let has_fallback = case
                        .branches
                        .iter()
                        .any(|branch| is_fallback_pattern(&branch.pattern));
                    let alternatives = [
                        ("Completed", outcomes.succeeded.as_ref()),
                        ("Failed", outcomes.failed.as_ref()),
                        ("TimedOut", outcomes.timed_out.as_ref()),
                        ("Cancelled", outcomes.cancelled.as_ref()),
                    ];
                    let missing: Vec<_> = alternatives
                        .into_iter()
                        .filter_map(|(terminal, payload)| payload.map(|_| terminal))
                        .filter(|terminal| {
                            !case
                                .branches
                                .iter()
                                .any(|branch| branch.pattern == *terminal)
                        })
                        .collect();
                    if !has_fallback && !missing.is_empty() {
                        self.scope_error(
                            case.span,
                            format!(
                                "case `{}` does not handle terminal outcome{} {}",
                                case.scrutinee,
                                if missing.len() == 1 { "" } else { "s" },
                                missing
                                    .iter()
                                    .map(|terminal| format!("`{terminal}`"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            owner,
                        );
                    }
                }
                let mut excluded = environment::CaseExclusions::default();
                for (index, branch) in case.branches.iter().enumerate() {
                    let invalid_terminal_pattern = terminal_outcome.is_some_and(|outcomes| {
                        !is_fallback_pattern(&branch.pattern)
                            && match branch.pattern.as_str() {
                                "Completed" => outcomes.succeeded.is_none(),
                                "Failed" => outcomes.failed.is_none(),
                                "TimedOut" => outcomes.timed_out.is_none(),
                                "Cancelled" => outcomes.cancelled.is_none(),
                                _ => true,
                            }
                    });
                    if invalid_terminal_pattern {
                        self.scope_error(
                            branch.span,
                            format!(
                                "case pattern `{}` is not a terminal outcome of `{}`",
                                branch.pattern, case.scrutinee
                            ),
                            owner,
                        );
                        continue;
                    }
                    let mut child = environment.clone();
                    if let Some(binding) = &branch.binding {
                        child.insert(binding.clone(), None);
                        let terminal_payload =
                            terminal_outcome.and_then(|outcomes| match branch.pattern.as_str() {
                                "Completed" => outcomes.succeeded.as_ref(),
                                "Failed" => outcomes.failed.as_ref(),
                                "TimedOut" => outcomes.timed_out.as_ref(),
                                "Cancelled" => outcomes.cancelled.as_ref(),
                                _ => None,
                            });
                        if let Some(ty) = terminal_payload {
                            child.insert(binding.clone(), Some(ty.clone()));
                        }
                        let pattern_type = IrType::Ref(branch.pattern.clone());
                        let presence = scrutinee_type.as_ref().and_then(|ty| {
                            crate::case_pattern::optional_presence(ty, &branch.pattern)
                        });
                        if terminal_payload.is_some() {
                            // The canonical terminal union binds the selected
                            // variant payload, not the envelope.
                        } else if presence.is_none()
                            && self.semantic.schemas.class_exists(&branch.pattern)
                            && scrutinee_type
                                .as_ref()
                                .is_some_and(|ty| assignable(&pattern_type, ty, self.semantic))
                        {
                            child.insert(binding.clone(), Some(pattern_type));
                            if let Some(path) = scrutinee.as_ref().and_then(environment::value_path)
                            {
                                child.inherit_refinements(binding, &path, environment);
                            }
                        } else {
                            let message = if presence.is_some() {
                                format!("presence pattern `{}` cannot bind class `{}`; narrow `{}` with a null guard before matching that class", branch.pattern, branch.pattern, case.scrutinee)
                            } else {
                                format!(
                                    "case pattern `{}` cannot bind `{binding}` from `{}`",
                                    branch.pattern, case.scrutinee
                                )
                            };
                            self.scope_error(branch.span, message, owner);
                            // The branch's entrance binding is invalid. Its
                            // dependent expressions cannot add useful typing
                            // evidence until that primary error is repaired.
                            continue;
                        }
                    }
                    if let Some(agents) = scrutinee_type.as_ref().and_then(finite_domain) {
                        if !is_fallback_pattern(&branch.pattern)
                            && !agent_pattern(&branch.pattern)
                                .is_some_and(|agent| agents.contains(&agent))
                        {
                            self.scope_error(
                                branch.span,
                                format!(
                                    "case pattern `{}` is not an alternative of `{}`",
                                    branch.pattern, case.scrutinee
                                ),
                                owner,
                            );
                            continue;
                        }
                    }
                    if let Some(expr) = &scrutinee {
                        child.narrow_case(expr, &branch.pattern, &excluded, self.semantic);
                    }
                    excluded.record(
                        &branch.pattern,
                        branch.guard.is_some(),
                        scrutinee_type.as_ref(),
                    );
                    if let Some(guard) = &branch.guard {
                        match parse_expression(guard) {
                            Ok(expr)
                                if self.infer_node(&expr, branch.span, &child)
                                    == Some(primitive(IrPrimitiveType::Bool)) =>
                            {
                                child.narrow_guard(&expr, self.semantic)
                            }
                            _ => {
                                self.scope_error(
                                    branch.span,
                                    "a case guard must be a known boolean expression".into(),
                                    owner,
                                );
                                continue;
                            }
                        }
                    }
                    self.block(owner, &branch.body, child, &site.child(index));
                }
            }
            BodyStmt::Effect(effect)
                if !self.authority
                    && matches!(
                        effect.kind,
                        BodyEffectKind::Tell { .. }
                            | BodyEffectKind::Prompt { .. }
                            | BodyEffectKind::Decide { .. }
                    ) =>
            {
                let kind = match effect.kind {
                    BodyEffectKind::Tell { .. } => "tell prompt",
                    BodyEffectKind::Prompt { .. } => "inline prompt",
                    BodyEffectKind::Decide { .. } => "inline decide",
                    _ => unreachable!(),
                };
                if let Some(prompt) = &effect.prompt {
                    match crate::managed_template::parse(&prompt.text) {
                        Ok(segments) => {
                            for segment in segments {
                                if let crate::managed_template::Segment::Expression {
                                    source,
                                    expr,
                                    ..
                                } = segment
                                {
                                    let before = self.diagnostics.len();
                                    match self.infer_node(&expr, effect.span, environment) {
                                        Some(ty)
                                            if kind != "tell prompt"
                                                && self.prompt_contains_media(&ty) =>
                                        {
                                            self.scope_error(
                                                effect.span,
                                                format!("{kind} interpolation cannot contain media; pass media through a declared coerce parameter"),
                                                owner,
                                            )
                                        }
                                        Some(ty) => {
                                            self.prompt_sealed_inputs(effect, &ty, kind)
                                        }
                                        None if self.diagnostics.len() == before => self
                                            .scope_error(
                                                effect.span,
                                                format!(
                                                    "{kind} expression `{}` has no resolved value type",
                                                    source.trim()
                                                ),
                                                owner,
                                            ),
                                        None => {}
                                    }
                                }
                            }
                        }
                        Err(issue) => self.scope_error(effect.span, issue, owner),
                    }
                }
            }
            BodyStmt::Effect(effect) if !self.authority => match &effect.kind {
                BodyEffectKind::Exec {
                    target: body::ExecTarget::Capability { stdin_binding, .. },
                    parse_target: Some(parse),
                    ..
                } if !parse.each && environment.get(stdin_binding).is_none_or(Option::is_none) => {
                    self.scope_error(
                        effect.span,
                        format!("script exec stdin `{stdin_binding}` has no resolved value type"),
                        owner,
                    );
                }
                BodyEffectKind::FileRead { path, .. } | BodyEffectKind::FileImport { path, .. } => {
                    match parse_expression(path) {
                        Ok(expr) => {
                            let actual = self.infer_node(&expr, effect.span, environment);
                            if actual.as_ref().is_none_or(|actual| {
                                !assignable(
                                    actual,
                                    &primitive(IrPrimitiveType::String),
                                    self.semantic,
                                )
                            }) {
                                self.scope_error(
                                    effect.span,
                                    format!(
                                        "file {} path `{path}` must be a string value",
                                        if matches!(effect.kind, BodyEffectKind::FileRead { .. }) {
                                            "read"
                                        } else {
                                            "import"
                                        }
                                    ),
                                    owner,
                                )
                            }
                        }
                        Err(issue) => self.scope_error(effect.span, issue, owner),
                    }
                }
                BodyEffectKind::Notify {
                    target_expr,
                    event,
                    from,
                    fields,
                } => {
                    match parse_expression(target_expr) {
                        Ok(expr) => {
                            let actual = self.infer_node(&expr, effect.span, environment);
                            if actual.as_ref().is_none_or(|actual| {
                                !assignable(
                                    actual,
                                    &primitive(IrPrimitiveType::String),
                                    self.semantic,
                                )
                            }) {
                                self.scope_error(
                                    effect.span,
                                    format!("signal target `{target_expr}` must be a string value"),
                                    owner,
                                );
                            }
                        }
                        Err(issue) => self.scope_error(effect.span, issue, owner),
                    }
                    if let Some(schema) = self.semantic.schemas.classes.get(event) {
                        let mut projected = Vec::new();
                        let written: BTreeSet<_> =
                            fields.iter().map(|field| field.name.as_str()).collect();
                        if let Some(from) = from {
                            for name in schema
                                .keys()
                                .filter(|name| !written.contains(name.as_str()))
                            {
                                projected.push(ExprObjectField {
                                    key: name.clone(),
                                    value: Expr::Path(vec![from.clone(), name.clone()]),
                                });
                            }
                        }
                        let mut invalid = false;
                        for field in fields {
                            match field.record_expression(from.as_deref(), &|name| {
                                environment.get(name).is_some()
                            }) {
                                Ok(value) => projected.push(ExprObjectField {
                                    key: field.name.clone(),
                                    value,
                                }),
                                Err(issue) => {
                                    invalid = true;
                                    self.scope_error(effect.span, issue, owner);
                                }
                            }
                        }
                        if !invalid {
                            let actual =
                                self.infer_node(&Expr::Object(projected), effect.span, environment);
                            let expected = IrType::Ref(event.clone());
                            if actual
                                .as_ref()
                                .is_none_or(|actual| !assignable(actual, &expected, self.semantic))
                            {
                                self.scope_error(
                                    effect.span,
                                    format!(
                                        "signal `{event}` payload must match its declared fields"
                                    ),
                                    owner,
                                );
                            }
                        }
                    }
                }
                BodyEffectKind::CounterConsume {
                    counter,
                    key_expr,
                    amount_expr,
                } => {
                    if !self.semantic.counters.contains(counter) {
                        self.scope_error(
                            effect.span,
                            format!("counter `{counter}` is not declared"),
                            owner,
                        );
                    }
                    for (label, source, expected) in [
                        ("key", key_expr, None),
                        ("amount", amount_expr, Some(primitive(IrPrimitiveType::Int))),
                    ] {
                        match parse_expression(source) {
                            Ok(expr) => {
                                let before = self.diagnostics.len();
                                let actual = self.infer_node(&expr, effect.span, environment);
                                if actual.is_none() && self.diagnostics.len() == before {
                                    self.scope_error(
                                        effect.span,
                                        format!(
                                            "counter {label} `{source}` has no resolved value type"
                                        ),
                                        owner,
                                    );
                                } else if expected.as_ref().is_some_and(|expected| {
                                    actual.as_ref().is_some_and(|actual| {
                                        !assignable(actual, expected, self.semantic)
                                    })
                                }) {
                                    self.scope_error(
                                        effect.span,
                                        format!(
                                            "counter amount `{source}` must be an integer value"
                                        ),
                                        owner,
                                    );
                                }
                            }
                            Err(issue) => self.scope_error(effect.span, issue, owner),
                        }
                    }
                }
                BodyEffectKind::TrackerFile { queue, fields } => {
                    if !self.semantic.trackers.contains(queue) {
                        self.scope_error(
                            effect.span,
                            format!("tracker `{queue}` is not declared"),
                            owner,
                        );
                    }
                    let mut names = BTreeSet::new();
                    for field in fields {
                        if !names.insert(field.name.as_str()) {
                            self.scope_error(
                                effect.span,
                                format!("tracker item field `{}` is duplicated", field.name),
                                owner,
                            );
                            continue;
                        }
                        let expected = match field.name.as_str() {
                            "title" | "body" => Some(primitive(IrPrimitiveType::String)),
                            "labels" => {
                                Some(IrType::Array(Box::new(primitive(IrPrimitiveType::String))))
                            }
                            "metadata" => None,
                            unknown => {
                                self.scope_error(
                                    effect.span,
                                    format!("tracker item has no field `{unknown}`"),
                                    owner,
                                );
                                continue;
                            }
                        };
                        let expr = match field
                            .record_expression(None, &|name| environment.get(name).is_some())
                        {
                            Ok(expr) => expr,
                            Err(issue) => {
                                self.scope_error(effect.span, issue, owner);
                                continue;
                            }
                        };
                        let actual = self.infer_node(&expr, effect.span, environment);
                        let valid = if field.name == "metadata" {
                            matches!(actual, Some(IrType::Object(_) | IrType::Map(_)))
                        } else {
                            expected.as_ref().is_some_and(|expected| {
                                actual.as_ref().is_some_and(|actual| {
                                    assignable(actual, expected, self.semantic)
                                })
                            })
                        };
                        if !valid {
                            self.scope_error(
                                effect.span,
                                format!(
                                    "tracker item field `{}` must be {}",
                                    field.name,
                                    match field.name.as_str() {
                                        "title" | "body" => "a string",
                                        "labels" => "a list of strings",
                                        _ => "an object",
                                    }
                                ),
                                owner,
                            );
                        }
                    }
                    if !names.contains("title") {
                        self.scope_error(
                            effect.span,
                            "tracker item requires a `title` field".into(),
                            owner,
                        );
                    }
                }
                BodyEffectKind::TrackerClaim { item, .. }
                | BodyEffectKind::TrackerRelease { item }
                | BodyEffectKind::TrackerFinish { item, .. } => {
                    let known = environment.get(item).is_some();
                    let valid = known
                        && ["queue", "id", "title"].into_iter().all(|field| {
                            let path = [item.clone(), field.into()];
                            environment
                                .path_type(&path, self.semantic)
                                .is_some_and(|actual| {
                                    assignable(
                                        &actual,
                                        &primitive(IrPrimitiveType::String),
                                        self.semantic,
                                    )
                                })
                        });
                    if known && !valid {
                        self.scope_error(
                            effect.span,
                            format!(
                                "tracker item `{item}` must provide string fields `queue`, `id`, and `title`"
                            ),
                            owner,
                        );
                    }
                    if let BodyEffectKind::TrackerFinish { fields, .. } = &effect.kind {
                        let mut names = BTreeSet::new();
                        for field in fields {
                            if !names.insert(field.name.as_str()) {
                                self.scope_error(
                                    effect.span,
                                    format!("tracker finish field `{}` is duplicated", field.name),
                                    owner,
                                );
                                continue;
                            }
                            if field.name != "summary" {
                                self.scope_error(
                                    effect.span,
                                    format!("tracker finish has no field `{}`", field.name),
                                    owner,
                                );
                                continue;
                            }
                            let expr = match field
                                .record_expression(None, &|name| environment.get(name).is_some())
                            {
                                Ok(expr) => expr,
                                Err(issue) => {
                                    self.scope_error(effect.span, issue, owner);
                                    continue;
                                }
                            };
                            let actual = self.infer_node(&expr, effect.span, environment);
                            if actual.as_ref().is_none_or(|actual| {
                                !assignable(
                                    actual,
                                    &primitive(IrPrimitiveType::String),
                                    self.semantic,
                                )
                            }) {
                                self.scope_error(
                                    effect.span,
                                    "tracker finish field `summary` must be a string".into(),
                                    owner,
                                );
                            }
                        }
                    }
                }
                BodyEffectKind::LedgerAppend {
                    ledger,
                    schema,
                    fields,
                } => {
                    let Some(entry_schema) = self.semantic.ledger_entries.get(ledger) else {
                        self.scope_error(
                            effect.span,
                            format!("ledger `{ledger}` is not declared"),
                            owner,
                        );
                        return;
                    };
                    if schema != entry_schema {
                        self.scope_error(
                            effect.span,
                            format!(
                                "ledger `{ledger}` accepts `{entry_schema}` entries, not `{schema}`"
                            ),
                            owner,
                        );
                    }
                    if self.semantic.schemas.classes.contains_key(schema) {
                        let mut projected = Vec::new();
                        let mut invalid = false;
                        for field in fields {
                            match field
                                .record_expression(None, &|name| environment.get(name).is_some())
                            {
                                Ok(value) => projected.push(ExprObjectField {
                                    key: field.name.clone(),
                                    value,
                                }),
                                Err(issue) => {
                                    invalid = true;
                                    self.scope_error(effect.span, issue, owner);
                                }
                            }
                        }
                        if !invalid {
                            let actual =
                                self.infer_node(&Expr::Object(projected), effect.span, environment);
                            let expected = IrType::Ref(schema.clone());
                            if actual
                                .as_ref()
                                .is_none_or(|actual| !assignable(actual, &expected, self.semantic))
                            {
                                self.scope_error(
                                    effect.span,
                                    format!("ledger `{ledger}` entry must match `{schema}`"),
                                    owner,
                                );
                            }
                        }
                    }
                }
                BodyEffectKind::FileWrite { path, body, .. } => {
                    for (label, source) in [("path", path), ("body", body)] {
                        match parse_expression(source) {
                            Ok(expr) => {
                                let actual = self.infer_node(&expr, effect.span, environment);
                                if actual.as_ref().is_none_or(|actual| {
                                    !assignable(
                                        actual,
                                        &primitive(IrPrimitiveType::String),
                                        self.semantic,
                                    )
                                }) {
                                    self.scope_error(
                                        effect.span,
                                        format!(
                                            "file write {label} `{source}` must be a string value"
                                        ),
                                        owner,
                                    )
                                }
                            }
                            Err(issue) => self.scope_error(effect.span, issue, owner),
                        }
                    }
                }
                BodyEffectKind::FileExport {
                    schema,
                    path,
                    predicate,
                    ..
                } => {
                    match parse_expression(path) {
                        Ok(expr) => {
                            let actual = self.infer_node(&expr, effect.span, environment);
                            if actual.as_ref().is_none_or(|actual| {
                                !assignable(
                                    actual,
                                    &primitive(IrPrimitiveType::String),
                                    self.semantic,
                                )
                            }) {
                                self.scope_error(
                                    effect.span,
                                    format!("file export path `{path}` must be a string value"),
                                    owner,
                                )
                            }
                        }
                        Err(issue) => self.scope_error(effect.span, issue, owner),
                    }
                    if let Some(predicate) = predicate {
                        match parse_expression(predicate) {
                            Ok(expr) => {
                                let mut row = environment.clone();
                                if let Some(fields) = self.semantic.schemas.classes.get(schema) {
                                    for (name, ty) in fields {
                                        row.insert(name.clone(), Some(lower_type(ty.clone())));
                                    }
                                }
                                let actual = self.infer_node(&expr, effect.span, &row);
                                if actual.as_ref().is_none_or(|actual| {
                                    !assignable(
                                        actual,
                                        &primitive(IrPrimitiveType::Bool),
                                        self.semantic,
                                    )
                                }) {
                                    self.scope_error(
                                        effect.span,
                                        format!(
                                            "file export predicate `{predicate}` must be boolean for `{schema}`"
                                        ),
                                        owner,
                                    )
                                }
                            }
                            Err(issue) => self.scope_error(effect.span, issue, owner),
                        }
                    }
                }
                _ => {}
            },
            BodyStmt::Effect(effect) if self.authority => {
                self.tell_authority(owner, effect, environment, site)
            }
            BodyStmt::Region(region) => {
                let progress = self.region_progress_type(&region.body);
                self.block(owner, &region.body, environment.clone(), &site.child(0));
                let mut lapse = environment.clone();
                if let Some(binding) = &region.lapse_binding {
                    lapse.insert(binding.clone(), Some(progress));
                }
                let mut introduced = BTreeSet::new();
                crate::collect_all_binding_names(&region.body, &mut introduced);
                let mut roots = BTreeSet::new();
                crate::collect_statement_roots(&region.lapse_body, &mut roots);
                let invalid = roots
                    .intersection(&introduced)
                    .map(|name| name.to_owned())
                    .collect::<Vec<_>>();
                for name in &invalid {
                    self.diagnostics.push(
                        Diagnostic::error(
                            diagnostic_code!("expr.binding_out_of_scope"),
                            region.span,
                            format!(
                                "the `on lapse` arm of {} references `{name}`, a binding the region introduces — it may not exist when the arm runs",
                                owner.label()
                            ),
                        )
                        .with_suggestion(
                            "reference only bindings from before the region, or bind the progress view (`on lapse as got`) and read `got.<binding>`",
                        ),
                    );
                }
                if invalid.is_empty() {
                    self.block(owner, &region.lapse_body, lapse, &site.child(1));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod callers_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod agents_tests;

#[cfg(test)]
mod presence_tests;

#[cfg(test)]
mod records_tests;

#[cfg(test)]
mod null_tests;
