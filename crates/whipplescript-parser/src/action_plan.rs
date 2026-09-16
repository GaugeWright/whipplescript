//! Hygienic, finite source-action expansion. Names resolve through lexical
//! binding sites, not text replacement. This is compiler structure; it does
//! not grant authority, prove readiness, or enable executable typed actions.

use std::collections::BTreeMap;

pub mod analysis;
pub mod effects;
pub mod resolved;
pub mod resources;
pub(crate) mod source_site;
pub mod value_flow;
use source_site::SourceSite;
mod validation;
pub use validation::PlanError;

use crate::body::{self, AfterPredicate, BodyAst, BodyStmt, CompositionExpr, CompositionStmt};
use crate::{
    diagnostic_code, ActionDecl, ActionResult, Diagnostic, Ident, RuleDecl, SourceSpan, TypeSyntax,
};

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ScopeId(pub usize);
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct BlockId(pub usize);
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct NodeId(pub usize);
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct BindingId(pub usize);

/// Name resolution, not a dependency list. Merely being visible imposes no
/// wait; readiness must come from the expressions the node actually reads.
pub type Environment = BTreeMap<String, BindingId>;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPlan {
    pub root: BlockId,
    pub root_rule: Option<Ident>,
    pub root_inputs: Vec<BindingId>,
    pub scopes: Vec<Scope>,
    pub blocks: Vec<Block>,
    pub nodes: Vec<Node>,
    pub bindings: Vec<Binding>,
}

impl ActionPlan {
    /// Direct effect/call nodes owned by one lexical action scope, or by the
    /// calling rule when `scope` is `None`.
    pub fn operation_nodes(&self, scope: Option<ScopeId>) -> Vec<NodeId> {
        match scope {
            Some(scope) => self.scopes[scope.0].operations.clone(),
            None => self
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    self.blocks[node.block.0].scope.is_none()
                        && match &node.kind {
                            NodeKind::Call { .. } => true,
                            NodeKind::Statement(statement) => {
                                matches!(statement.as_ref(), BodyStmt::Effect(_))
                            }
                            _ => false,
                        }
                })
                .map(|(index, _)| NodeId(index))
                .collect(),
        }
    }

    /// Operations whose outcomes may select this lexical handler. Work inside
    /// the handler body cannot contribute to selecting itself, and a handler
    /// in a nested block does not observe operations outside that block.
    pub fn protected_operation_nodes(&self, handler: NodeId) -> Vec<NodeId> {
        let node = &self.nodes[handler.0];
        let NodeKind::OnFailure { body, .. } = node.kind else {
            return Vec::new();
        };
        let protected = self.descendant_blocks(node.block);
        let handler_owned = self.descendant_blocks(body);
        self.operation_nodes(self.blocks[node.block.0].scope)
            .into_iter()
            .filter(|operation| {
                let block = self.nodes[operation.0].block;
                protected.contains(&block) && !handler_owned.contains(&block)
            })
            .collect()
    }

    fn descendant_blocks(&self, root: BlockId) -> std::collections::BTreeSet<BlockId> {
        let mut blocks = std::collections::BTreeSet::from([root]);
        let mut pending = vec![root];
        while let Some(block) = pending.pop() {
            for node in &self.blocks[block.0].nodes {
                let children: Vec<_> = match &self.nodes[node.0].kind {
                    NodeKind::After { body, .. } | NodeKind::OnFailure { body, .. } => vec![*body],
                    NodeKind::Case { branches, .. } => {
                        branches.iter().map(|branch| branch.body).collect()
                    }
                    NodeKind::Region {
                        body, lapse_body, ..
                    } => vec![*body, *lapse_body],
                    _ => Vec::new(),
                };
                for child in children {
                    if blocks.insert(child) {
                        pending.push(child);
                    }
                }
            }
        }
        blocks
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub action: String,
    pub definition_span: SourceSpan,
    /// None only for the externally supplied entry action. Follow parent calls
    /// to reconstruct the whole call stack without duplicating it at each node.
    pub parent_call: Option<NodeId>,
    pub parameters: Vec<BindingId>,
    pub result: ActionResult,
    pub entry: BlockId,
    /// Potential direct children only. The runtime joins the actually started
    /// subset; a nested call contributes its scope boundary, not its leaf list.
    pub operations: Vec<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// None for the calling rule and its lexical continuations.
    pub scope: Option<ScopeId>,
    pub nodes: Vec<NodeId>,
    pub environment: Environment,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub name: Option<String>,
    pub span: SourceSpan,
    pub source: BindingSource,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BindingSource {
    RuleInput {
        index: usize,
    },
    Parameter {
        scope: ScopeId,
        index: usize,
        ty: TypeSyntax,
    },
    Node(NodeId),
    After {
        node: NodeId,
    },
    Case {
        node: NodeId,
        branch: usize,
    },
    FailureHandler {
        node: NodeId,
    },
    Lapse {
        node: NodeId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub block: BlockId,
    pub span: SourceSpan,
    /// A success barrier imposed by `then`, not by ordinary source order.
    pub order_after: Option<NodeId>,
    pub result: Option<BindingId>,
    pub kind: NodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedExpr {
    pub value: CompositionExpr,
    pub environment: Environment,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NodeKind {
    /// Only leaf statements occur here. Their payloads, prose, field names and
    /// grant declarations remain the original AST, interpreted in the block's
    /// environment. This variant is not a bypass of the ordinary validators.
    Statement(Box<BodyStmt>),
    Call {
        scope: ScopeId,
        arguments: Vec<ScopedExpr>,
    },
    Return(CompositionExpr),
    Fail(CompositionExpr),
    OnFailure {
        alias: BindingId,
        body: BlockId,
    },
    After {
        observed: BindingId,
        predicate: AfterPredicate,
        milestone: Option<String>,
        alias: Option<BindingId>,
        body: BlockId,
    },
    Case {
        scrutinee: String,
        branches: Vec<Branch>,
    },
    Region {
        until: bool,
        condition: String,
        body: BlockId,
        lapse_binding: Option<BindingId>,
        lapse_body: BlockId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    pub pattern: String,
    pub binding: Option<BindingId>,
    pub guard: Option<String>,
    /// The guard can see the pattern binder, but not the body's declarations.
    pub guard_environment: Environment,
    pub body: BlockId,
    pub span: SourceSpan,
}

pub(crate) fn error(span: SourceSpan, message: String) -> Diagnostic {
    Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        span,
        message,
    )
}

pub(crate) fn span(statement: &BodyStmt) -> SourceSpan {
    match statement {
        BodyStmt::Composition(value) => value.span(),
        BodyStmt::Effect(value) => value.span,
        BodyStmt::After(value) => value.span,
        BodyStmt::Case(value) => value.span,
        BodyStmt::Region(value) => value.span,
        BodyStmt::Record(value) => value.span,
        BodyStmt::Terminal(value) => value.span,
        BodyStmt::Done { span, .. }
        | BodyStmt::Cancel { span, .. }
        | BodyStmt::Milestone { span, .. }
        | BodyStmt::Redact { span, .. }
        | BodyStmt::Declassify { span, .. } => *span,
    }
}

/// The result name a statement declares in its current block. `then` names
/// its operand's value; it does not introduce an extra operation or scope.
pub(crate) fn binding_name(statement: &BodyStmt) -> Option<&str> {
    match statement {
        BodyStmt::Effect(effect) => effect.binding.as_deref(),
        BodyStmt::Composition(CompositionStmt::Call { binding, .. }) => binding.as_deref(),
        BodyStmt::Composition(CompositionStmt::Then { binding, .. })
        | BodyStmt::Redact { binding, .. }
        | BodyStmt::Declassify { binding, .. } => Some(binding),
        _ => None,
    }
}

fn operation(statement: &BodyStmt) -> (&BodyStmt, bool) {
    match statement {
        BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => (operation, true),
        other => (other, false),
    }
}

fn is_operation(statement: &BodyStmt) -> bool {
    matches!(
        statement,
        BodyStmt::Effect(_) | BodyStmt::Composition(CompositionStmt::Call { .. })
    )
}

/// Shared with typed definition checking. Check declarations in each lexical
/// block once; inherited names may be shadowed, but two local declarations
/// (including parameters/entrance aliases) cannot name the same binding site.
pub(crate) fn validate_bindings(action: &ActionDecl, ast: &BodyAst) -> Vec<Diagnostic> {
    let parameters: BTreeMap<&str, SourceSpan> = action
        .params
        .iter()
        .map(|p| (p.name.name.as_str(), p.name.span))
        .collect();
    let mut diagnostics = validate_lexical_blocks(&ast.statements, parameters);
    diagnostics.extend(validate_failure_handlers(
        &ast.statements,
        &format!("action `{}`", action.name.name),
    ));
    diagnostics
}

pub(crate) fn validate_failure_handlers(statements: &[BodyStmt], owner: &str) -> Vec<Diagnostic> {
    let mut handlers = Vec::new();
    collect_failure_handlers(statements, &mut handlers);
    let mut diagnostics = Vec::new();
    if let Some((first, rest)) = handlers.split_first() {
        for duplicate in rest {
            diagnostics.push(
                error(
                    **duplicate,
                    format!("{owner} has more than one lexical failure handler"),
                )
                .with_related(**first, "first failure handler"),
            );
        }
    }
    diagnostics
}

fn collect_failure_handlers<'a>(statements: &'a [BodyStmt], handlers: &mut Vec<&'a SourceSpan>) {
    for statement in statements {
        match statement {
            BodyStmt::Composition(CompositionStmt::OnFailure { body, span, .. }) => {
                handlers.push(span);
                collect_failure_handlers(body, handlers);
            }
            BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                collect_failure_handlers(std::slice::from_ref(operation), handlers)
            }
            BodyStmt::After(after) => collect_failure_handlers(&after.body, handlers),
            BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_failure_handlers(&branch.body, handlers);
                }
            }
            BodyStmt::Region(region) => {
                collect_failure_handlers(&region.body, handlers);
                collect_failure_handlers(&region.lapse_body, handlers);
            }
            _ => {}
        }
    }
}

/// Shared by caller typing and expansion; no call tree must be expanded just
/// to check a calling rule's lexical declarations.
pub(crate) fn validate_rule_bindings(ast: &BodyAst, inputs: &[Ident]) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let names = validate_rule_inputs(inputs, &mut diagnostics);
    diagnostics.extend(validate_lexical_blocks(&ast.statements, names));
    diagnostics
}

pub(crate) fn validate_rule_inputs<'a>(
    inputs: &'a [Ident],
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<&'a str, SourceSpan> {
    let mut names = BTreeMap::new();
    for input in inputs {
        if let Some(first) = names.insert(input.name.as_str(), input.span) {
            diagnostics.push(
                error(input.span, format!("duplicate rule input `{}`", input.name))
                    .with_related(first, "earlier input declaration"),
            );
        }
    }
    names
}

fn validate_lexical_blocks<'a>(
    statements: &'a [BodyStmt],
    initial: BTreeMap<&'a str, SourceSpan>,
) -> Vec<Diagnostic> {
    let mut work = vec![(statements, initial)];
    let mut diagnostics = Vec::new();
    while let Some((statements, mut names)) = work.pop() {
        for statement in statements {
            if let Some(name) = binding_name(statement) {
                match names.entry(name) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(span(statement));
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        diagnostics.push(
                            error(
                                span(statement),
                                format!("duplicate binding `{name}` in one lexical block"),
                            )
                            .with_related(*entry.get(), "first binding declaration"),
                        );
                    }
                }
            }
            match statement {
                BodyStmt::Composition(CompositionStmt::OnFailure { alias, body, span }) => {
                    work.push((body, BTreeMap::from([(alias.as_str(), *span)])))
                }
                BodyStmt::After(after) => work.push((
                    &after.body,
                    after
                        .alias
                        .as_deref()
                        .map(|name| (name, after.span))
                        .into_iter()
                        .collect(),
                )),
                BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        work.push((
                            &branch.body,
                            branch
                                .binding
                                .as_deref()
                                .map(|name| (name, branch.span))
                                .into_iter()
                                .collect(),
                        ));
                    }
                }
                BodyStmt::Region(region) => {
                    work.push((&region.body, BTreeMap::new()));
                    work.push((
                        &region.lapse_body,
                        region
                            .lapse_binding
                            .as_deref()
                            .map(|name| (name, region.span))
                            .into_iter()
                            .collect(),
                    ));
                }
                _ => {}
            }
        }
    }
    diagnostics
}

/// Expand one entry action's finite call tree. The returned syntax plan is
/// deliberately separate from `IrProgram`: it has not earned caller-context
/// type, authority, resource, scheduling or persistent-execution guarantees.
/// Every visible definition is syntax/cycle/binding checked, even when unused.
pub fn expand_syntax(actions: &[ActionDecl], entry: &str) -> Result<ActionPlan, Vec<Diagnostic>> {
    expand(actions, Entry::Action(entry)).map(|expanded| expanded.plan)
}

/// Expand calls in their real calling rule. Inputs are the names admitted by
/// the rule matcher; this pass does not invent synthetic facts or an action
/// result contract for the rule. Workflow terminals stay ordinary statements.
pub fn expand_rule_syntax(
    actions: &[ActionDecl],
    rule: &RuleDecl,
    inputs: &[Ident],
) -> Result<ActionPlan, Vec<Diagnostic>> {
    expand(actions, Entry::Rule(rule, inputs)).map(|expanded| expanded.plan)
}

#[derive(Clone, Copy)]
enum Entry<'a> {
    Action(&'a str),
    Rule(&'a RuleDecl, &'a [Ident]),
}

struct Expansion {
    plan: ActionPlan,
    sites: BTreeMap<NodeId, SourceSite>,
}
fn expand(actions: &[ActionDecl], entry: Entry<'_>) -> Result<Expansion, Vec<Diagnostic>> {
    let mut diagnostics = crate::action_signature::validate(actions);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let bodies: Vec<BodyAst> = actions
        .iter()
        .map(|action| {
            let (ast, errors) = body::parse_action_body(&action.body.text, action.body.body_base());
            diagnostics.extend(errors);
            diagnostics.extend(validate_bindings(action, &ast));
            ast
        })
        .collect();
    let by_name: BTreeMap<&str, usize> = actions
        .iter()
        .enumerate()
        .map(|(i, a)| (a.name.name.as_str(), i))
        .collect();
    for action in actions {
        if action.result.is_none() {
            diagnostics.push(
                error(
                    action.name.span,
                    format!(
                        "action `{}` needs a result contract for scope expansion",
                        action.name.name
                    ),
                )
                .with_suggestion(format!(
                    "declare a result such as `action {}(...) -> null` and return it on every path",
                    action.name.name
                )),
            );
        }
    }
    let rule_body = if let Entry::Rule(rule, inputs) = entry {
        let (ast, errors) = body::parse_composed_rule_body(&rule.body.text, rule.body.body_base());
        diagnostics.extend(errors);
        diagnostics.extend(validate_rule_bindings(&ast, inputs));
        diagnostics.extend(validate_failure_handlers(
            &ast.statements,
            &format!("rule `{}`", rule.name.name),
        ));
        Some(ast)
    } else {
        None
    };
    // Resolve all body calls before expanding any tree. A typo in an unused
    // definition must not become an unchecked hole in an otherwise finite DAG.
    let mut pending: Vec<&BodyStmt> = bodies.iter().flat_map(|body| &body.statements).collect();
    if let Some(body) = &rule_body {
        pending.extend(&body.statements);
    }
    while let Some(statement) = pending.pop() {
        match statement {
            BodyStmt::Composition(CompositionStmt::Call {
                name,
                arguments,
                span,
                ..
            }) => match by_name.get(name.as_str()) {
                None => diagnostics.push(error(*span, format!("unknown action `{name}`"))),
                Some(&index) if actions[index].params.len() != arguments.len() => diagnostics.push(
                    error(
                        *span,
                        format!(
                            "action `{name}` expects {} argument(s) but got {}",
                            actions[index].params.len(),
                            arguments.len()
                        ),
                    )
                    .with_related(actions[index].name.span, "action definition"),
                ),
                Some(_) => {}
            },
            BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                pending.push(operation)
            }
            BodyStmt::Composition(CompositionStmt::OnFailure { body, .. }) => pending.extend(body),
            BodyStmt::After(after) => pending.extend(&after.body),
            BodyStmt::Case(case) => {
                for branch in &case.branches {
                    pending.extend(&branch.body);
                }
            }
            BodyStmt::Region(region) => {
                pending.extend(&region.body);
                pending.extend(&region.lapse_body);
            }
            _ => {}
        }
    }
    let entry_action = if let Entry::Action(name) = entry {
        let Some(&index) = by_name.get(name) else {
            diagnostics.push(error(
                SourceSpan { start: 0, end: 0 },
                format!("unknown entry action `{name}`"),
            ));
            return Err(diagnostics);
        };
        Some(index)
    } else {
        None
    };
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let mut builder = Builder {
        actions,
        bodies: &bodies,
        by_name,
        plan: ActionPlan {
            root: BlockId(0),
            root_rule: None,
            root_inputs: Vec::new(),
            scopes: Vec::new(),
            blocks: Vec::new(),
            nodes: Vec::new(),
            bindings: Vec::new(),
        },
        nodes: Vec::new(),
        sites: BTreeMap::new(),
        work: Vec::new(),
        diagnostics: Vec::new(),
    };
    if let Some(index) = entry_action {
        let scope = builder.add_scope(index, None);
        builder.plan.root = builder.plan.scopes[scope.0].entry;
        builder.plan.root_inputs = builder.plan.scopes[scope.0].parameters.clone();
    } else if let Entry::Rule(rule, inputs) = entry {
        builder.plan.root_rule = Some(rule.name.clone());
        let mut environment = Environment::new();
        for (index, input) in inputs.iter().enumerate() {
            let id = builder.bind(
                Some(&input.name),
                input.span,
                BindingSource::RuleInput { index },
            );
            environment.insert(input.name.clone(), id);
            builder.plan.root_inputs.push(id);
        }
        builder.plan.root = builder.add_block(
            None,
            &rule_body.as_ref().expect("rule body parsed").statements,
            environment,
            SourceSite::rule(&rule.name.name),
        );
    }
    // Expansion uses an explicit work list: a long finite action-call chain
    // does not consume the Rust call stack or create recursively owned trees.
    while let Some(block) = builder.work.pop() {
        builder.fill_block(block);
    }
    let Builder {
        mut plan,
        nodes,
        sites,
        diagnostics,
        ..
    } = builder;
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    plan.nodes = nodes
        .into_iter()
        .map(|node| node.expect("each reserved node was filled"))
        .collect();
    Ok(Expansion { plan, sites })
}

struct PendingBlock<'a> {
    id: BlockId,
    statements: &'a [BodyStmt],
    site: SourceSite,
}
struct Builder<'a> {
    actions: &'a [ActionDecl],
    bodies: &'a [BodyAst],
    by_name: BTreeMap<&'a str, usize>,
    plan: ActionPlan,
    nodes: Vec<Option<Node>>,
    sites: BTreeMap<NodeId, SourceSite>,
    work: Vec<PendingBlock<'a>>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Builder<'a> {
    fn bind(&mut self, name: Option<&str>, span: SourceSpan, source: BindingSource) -> BindingId {
        let id = BindingId(self.plan.bindings.len());
        self.plan.bindings.push(Binding {
            name: name.map(str::to_owned),
            span,
            source,
        });
        id
    }

    fn add_scope(&mut self, target: usize, parent_call: Option<NodeId>) -> ScopeId {
        let action = &self.actions[target];
        let scope = ScopeId(self.plan.scopes.len());
        let mut environment = Environment::new();
        let mut parameters = Vec::new();
        for (index, parameter) in action.params.iter().enumerate() {
            let id = self.bind(
                Some(&parameter.name.name),
                parameter.name.span,
                BindingSource::Parameter {
                    scope,
                    index,
                    ty: parameter.ty.clone(),
                },
            );
            parameters.push(id);
            environment.insert(parameter.name.name.clone(), id);
        }
        let entry = self.add_block(
            Some(scope),
            &self.bodies[target].statements,
            environment,
            SourceSite::action(&action.name.name),
        );
        self.plan.scopes.push(Scope {
            action: action.name.name.clone(),
            definition_span: action.name.span,
            parent_call,
            parameters,
            result: action.result.clone().expect("typed declarations checked"),
            entry,
            operations: Vec::new(),
        });
        scope
    }

    fn add_block(
        &mut self,
        scope: Option<ScopeId>,
        statements: &'a [BodyStmt],
        environment: Environment,
        site: SourceSite,
    ) -> BlockId {
        let id = BlockId(self.plan.blocks.len());
        self.plan.blocks.push(Block {
            scope,
            nodes: Vec::new(),
            environment,
        });
        self.work.push(PendingBlock {
            id,
            statements,
            site,
        });
        id
    }

    fn fill_block(&mut self, pending: PendingBlock<'a>) {
        let block = pending.id;
        let scope = self.plan.blocks[block.0].scope;
        let mut environment = self.plan.blocks[block.0].environment.clone();
        let mut reserved = Vec::new();
        for (index, statement) in pending.statements.iter().enumerate() {
            let site = pending.site.child(index);
            let id = NodeId(self.nodes.len());
            self.nodes.push(None);
            let name = binding_name(statement);
            let (operand, sequenced) = operation(statement);
            let result = if name.is_some() || is_operation(operand) {
                let binding = self.bind(name, span(statement), BindingSource::Node(id));
                if let Some(name) = name {
                    environment.insert(name.to_owned(), binding);
                }
                Some(binding)
            } else {
                None
            };
            if let Some(scope) = scope.filter(|_| is_operation(operand)) {
                self.plan.scopes[scope.0].operations.push(id);
            }
            reserved.push((id, result, operand, sequenced, span(statement), site));
        }
        self.plan.blocks[block.0].environment = environment.clone();
        self.plan.blocks[block.0].nodes = reserved.iter().map(|(id, ..)| *id).collect();
        let mut order_after = None;
        for (id, result, statement, sequenced, span, site) in reserved {
            self.sites.insert(id, site.clone());
            let kind = match statement {
                BodyStmt::Composition(CompositionStmt::Call {
                    name, arguments, ..
                }) => {
                    let target = self.by_name[name.as_str()];
                    let child = self.add_scope(target, Some(id));
                    NodeKind::Call {
                        scope: child,
                        arguments: arguments
                            .iter()
                            .map(|value| ScopedExpr {
                                value: value.clone(),
                                environment: environment.clone(),
                            })
                            .collect(),
                    }
                }
                BodyStmt::Composition(CompositionStmt::Return(value)) => {
                    NodeKind::Return(value.clone())
                }
                BodyStmt::Composition(CompositionStmt::Fail(value)) => {
                    NodeKind::Fail(value.clone())
                }
                BodyStmt::Composition(CompositionStmt::OnFailure { alias, body, .. }) => {
                    let mut nested = environment.clone();
                    let alias = self.bind(
                        Some(alias),
                        span,
                        BindingSource::FailureHandler { node: id },
                    );
                    nested.insert(
                        self.plan.bindings[alias.0]
                            .name
                            .clone()
                            .expect("handler alias"),
                        alias,
                    );
                    let body = self.add_block(scope, body, nested, site.child(0));
                    NodeKind::OnFailure { alias, body }
                }
                BodyStmt::Composition(CompositionStmt::Then { .. }) => {
                    unreachable!("then operand is an effect or call")
                }
                BodyStmt::After(after) => {
                    let Some(&observed) = environment.get(&after.binding) else {
                        self.diagnostics.push(error(
                            after.span,
                            format!("unknown action binding `{}` in continuation", after.binding),
                        ));
                        continue;
                    };
                    let mut nested = environment.clone();
                    let alias = after.alias.as_deref().map(|name| {
                        let binding =
                            self.bind(Some(name), after.span, BindingSource::After { node: id });
                        nested.insert(name.to_owned(), binding);
                        binding
                    });
                    let body = self.add_block(scope, &after.body, nested, site.child(0));
                    NodeKind::After {
                        observed,
                        predicate: after.predicate,
                        milestone: after.milestone.clone(),
                        alias,
                        body,
                    }
                }
                BodyStmt::Case(case) => {
                    let mut branches = Vec::new();
                    for (index, branch) in case.branches.iter().enumerate() {
                        let mut nested = environment.clone();
                        let binding = branch.binding.as_deref().map(|name| {
                            let binding = self.bind(
                                Some(name),
                                branch.span,
                                BindingSource::Case {
                                    node: id,
                                    branch: index,
                                },
                            );
                            nested.insert(name.to_owned(), binding);
                            binding
                        });
                        let body =
                            self.add_block(scope, &branch.body, nested.clone(), site.child(index));
                        branches.push(Branch {
                            pattern: branch.pattern.clone(),
                            binding,
                            guard: branch.guard.clone(),
                            guard_environment: nested,
                            body,
                            span: branch.span,
                        });
                    }
                    NodeKind::Case {
                        scrutinee: case.scrutinee.clone(),
                        branches,
                    }
                }
                BodyStmt::Region(region) => {
                    let body =
                        self.add_block(scope, &region.body, environment.clone(), site.child(0));
                    let mut lapse = environment.clone();
                    let lapse_binding = region.lapse_binding.as_deref().map(|name| {
                        let binding =
                            self.bind(Some(name), region.span, BindingSource::Lapse { node: id });
                        lapse.insert(name.to_owned(), binding);
                        binding
                    });
                    let lapse_body =
                        self.add_block(scope, &region.lapse_body, lapse, site.child(1));
                    NodeKind::Region {
                        until: region.until,
                        condition: region.condition.clone(),
                        body,
                        lapse_binding,
                        lapse_body,
                    }
                }
                leaf @ (BodyStmt::Effect(_)
                | BodyStmt::Record(_)
                | BodyStmt::Done { .. }
                | BodyStmt::Terminal(_)
                | BodyStmt::Cancel { .. }
                | BodyStmt::Milestone { .. }
                | BodyStmt::Redact { .. }
                | BodyStmt::Declassify { .. }) => NodeKind::Statement(Box::new(leaf.clone())),
            };
            self.nodes[id.0] = Some(Node {
                block,
                span,
                order_after,
                result,
                kind,
            });
            if sequenced {
                order_after = Some(id);
            }
        }
    }
}

#[cfg(test)]
mod tests;
