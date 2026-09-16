//! Validate a captured plan without parsing source or granting execution authority.
use std::collections::BTreeSet;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanError {
    pub path: String,
    pub message: String,
}
impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}
impl std::error::Error for PlanError {}

fn invalid(path: &str, message: &str) -> PlanError {
    PlanError {
        path: path.into(),
        message: message.into(),
    }
}
fn require(condition: bool, path: &str, message: &str) -> Result<(), PlanError> {
    if !condition {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err(invalid(path, message));
    }
    Ok(())
}
fn at<'a, T>(items: &'a [T], index: usize, path: &str) -> Result<&'a T, PlanError> {
    items
        .get(index)
        .ok_or_else(|| invalid(path, "reference is out of range"))
}
fn operation(node: &Node) -> bool {
    matches!(&node.kind, NodeKind::Call { .. })
        || matches!(&node.kind, NodeKind::Statement(s) if matches!(s.as_ref(), BodyStmt::Effect(_)))
}
struct Pending {
    block: BlockId,
    scope: Option<ScopeId>,
    environment: Environment,
    entrance_names: BTreeSet<String>,
}
struct Validator<'a> {
    plan: &'a ActionPlan,
    blocks: BTreeSet<BlockId>,
    nodes: BTreeSet<NodeId>,
    bindings: BTreeSet<BindingId>,
    scopes: BTreeSet<ScopeId>,
    operations: BTreeMap<ScopeId, BTreeSet<NodeId>>,
    handlers: BTreeMap<Option<ScopeId>, NodeId>,
    work: Vec<Pending>,
}
impl ActionPlan {
    /// Structural validity only: no type, authority, conservation, authenticity
    /// or expression/source correspondence proof is implied by success.
    pub fn validate_structure(&self) -> Result<(), PlanError> {
        let mut v = Validator {
            plan: self,
            blocks: BTreeSet::new(),
            nodes: BTreeSet::new(),
            bindings: BTreeSet::new(),
            scopes: BTreeSet::new(),
            operations: BTreeMap::new(),
            handlers: BTreeMap::new(),
            work: Vec::new(),
        };
        if let Some(rule) = &self.root_rule {
            require(
                !rule.name.is_empty(),
                "root_rule.name",
                "rule name is empty",
            )?;
            v.span(rule.span, "root_rule.span")?;
            let mut env = Environment::new();
            for (index, &binding) in self.root_inputs.iter().enumerate() {
                v.claim(binding, &BindingSource::RuleInput { index }, "root_inputs")?;
                v.named(&mut env, binding, "root_inputs")?;
            }
            let names = env.keys().cloned().collect();
            v.work.push(Pending {
                block: self.root,
                scope: None,
                environment: env,
                entrance_names: names,
            });
        } else {
            let root = at(&self.blocks, self.root.0, "root")?;
            let scope = root
                .scope
                .ok_or_else(|| invalid("root", "action root has no scope"))?;
            let target = at(&self.scopes, scope.0, "root.scope")?;
            require(
                target.entry == self.root && target.parameters == self.root_inputs,
                "root_inputs",
                "action root must use its entry and parameters",
            )?;
            v.enter_scope(scope, None)?;
        }
        while let Some(pending) = v.work.pop() {
            v.block(pending)?;
        }
        require(
            v.blocks.len() == self.blocks.len(),
            "blocks",
            "unreachable block",
        )?;
        require(
            v.nodes.len() == self.nodes.len(),
            "nodes",
            "unreachable node",
        )?;
        require(
            v.bindings.len() == self.bindings.len(),
            "bindings",
            "unowned binding",
        )?;
        require(
            v.scopes.len() == self.scopes.len(),
            "scopes",
            "unreachable scope",
        )?;
        for (index, scope) in self.scopes.iter().enumerate() {
            let expected = v.operations.remove(&ScopeId(index)).unwrap_or_default();
            let actual: BTreeSet<_> = scope.operations.iter().copied().collect();
            require(
                actual.len() == scope.operations.len() && actual == expected,
                &format!("scopes[{index}].operations"),
                "owned operations differ from direct effect/call nodes",
            )?;
        }
        Ok(())
    }
}
impl Validator<'_> {
    fn span(&self, span: SourceSpan, path: &str) -> Result<(), PlanError> {
        require(span.start <= span.end, path, "source span is reversed")
    }
    fn claim(
        &mut self,
        id: BindingId,
        source: &BindingSource,
        path: &str,
    ) -> Result<(), PlanError> {
        let binding = at(&self.plan.bindings, id.0, path)?;
        require(
            &binding.source == source,
            path,
            "binding source is not reciprocal",
        )?;
        require(
            self.bindings.insert(id),
            path,
            "binding has more than one owner",
        )?;
        require(
            binding.name.as_ref().is_none_or(|n| !n.is_empty()),
            path,
            "binding name is empty",
        )?;
        self.span(binding.span, path)
    }
    fn name(&self, id: BindingId, path: &str) -> Result<String, PlanError> {
        at(&self.plan.bindings, id.0, path)?
            .name
            .clone()
            .ok_or_else(|| invalid(path, "entrance binding must have a name"))
    }
    fn named(&self, env: &mut Environment, id: BindingId, path: &str) -> Result<(), PlanError> {
        let name = self.name(id, path)?;
        require(
            env.insert(name, id).is_none(),
            path,
            "duplicate entrance name",
        )
    }
    fn enter_scope(&mut self, id: ScopeId, parent: Option<NodeId>) -> Result<(), PlanError> {
        let path = format!("scopes[{}]", id.0);
        let scope = at(&self.plan.scopes, id.0, &path)?;
        require(self.scopes.insert(id), &path, "scope is shared or cyclic")?;
        require(
            scope.parent_call == parent,
            &path,
            "parent call is not reciprocal",
        )?;
        require(!scope.action.is_empty(), &path, "action name is empty")?;
        self.span(scope.definition_span, &path)?;
        let mut env = Environment::new();
        for (index, &binding) in scope.parameters.iter().enumerate() {
            let b = at(&self.plan.bindings, binding.0, &path)?;
            let BindingSource::Parameter { ty, .. } = &b.source else {
                return require(false, &path, "parameter has the wrong binding source");
            };
            let expected = BindingSource::Parameter {
                scope: id,
                index,
                ty: ty.clone(),
            };
            self.claim(binding, &expected, &path)?;
            self.named(&mut env, binding, &path)?;
        }
        let names = env.keys().cloned().collect();
        self.work.push(Pending {
            block: scope.entry,
            scope: Some(id),
            environment: env,
            entrance_names: names,
        });
        Ok(())
    }
    fn child(
        &mut self,
        block: BlockId,
        scope: Option<ScopeId>,
        env: &Environment,
        alias: Option<(BindingId, BindingSource)>,
        path: &str,
    ) -> Result<Environment, PlanError> {
        let mut environment = env.clone();
        let mut names = BTreeSet::new();
        if let Some((binding, source)) = alias {
            self.claim(binding, &source, path)?;
            let name = self.name(binding, path)?;
            names.insert(name.clone());
            environment.insert(name, binding);
        }
        self.work.push(Pending {
            block,
            scope,
            environment: environment.clone(),
            entrance_names: names,
        });
        Ok(environment)
    }
    fn block(&mut self, mut pending: Pending) -> Result<(), PlanError> {
        let path = format!("blocks[{}]", pending.block.0);
        let block = at(&self.plan.blocks, pending.block.0, &path)?;
        require(
            self.blocks.insert(pending.block),
            &path,
            "block is shared or cyclic",
        )?;
        require(
            block.scope == pending.scope,
            &path,
            "block scope differs from its lexical owner",
        )?;
        let mut previous = None;
        let mut barrier = None;
        for &id in &block.nodes {
            let path = format!("nodes[{}]", id.0);
            let node = at(&self.plan.nodes, id.0, &path)?;
            require(
                self.nodes.insert(id) && node.block == pending.block,
                &path,
                "node/block ownership is not reciprocal",
            )?;
            self.span(node.span, &path)?;
            if node.order_after != barrier {
                require(
                    node.order_after.is_some() && node.order_after == previous,
                    &path,
                    "success barrier must begin immediately after its operation",
                )?;
                let predecessor = at(
                    &self.plan.nodes,
                    node.order_after.expect("checked Some").0,
                    &path,
                )?;
                require(
                    operation(predecessor),
                    &path,
                    "success barrier must name an operation",
                )?;
            }
            barrier = node.order_after;
            previous = Some(id);
            let bound_leaf = matches!(&node.kind, NodeKind::Statement(s) if matches!(s.as_ref(), BodyStmt::Redact { .. } | BodyStmt::Declassify { .. }));
            require(
                node.result.is_some() == (operation(node) || bound_leaf),
                &path,
                "result binding does not match node kind",
            )?;
            if let Some(binding) = node.result {
                self.claim(binding, &BindingSource::Node(id), &path)?;
                if let Some(name) = &self.plan.bindings[binding.0].name {
                    require(
                        pending.entrance_names.insert(name.clone()),
                        &path,
                        "duplicate local/entrance binding",
                    )?;
                    pending.environment.insert(name.clone(), binding);
                }
                if let NodeKind::Statement(leaf) = &node.kind {
                    if let Some(name) = binding_name(leaf) {
                        require(
                            self.plan.bindings[binding.0].name.as_deref() == Some(name),
                            &path,
                            "leaf result name differs from binding",
                        )?;
                    }
                }
            }
            if operation(node) {
                if let Some(scope) = block.scope {
                    self.operations.entry(scope).or_default().insert(id);
                }
            }
        }
        require(
            block.environment == pending.environment,
            &path,
            "lexical environment differs from declared bindings",
        )?;
        for &id in &block.nodes {
            let node = &self.plan.nodes[id.0];
            let path = format!("nodes[{}]", id.0);
            match &node.kind {
                NodeKind::Statement(leaf) => {
                    require(
                        !matches!(
                            leaf.as_ref(),
                            BodyStmt::Composition(_)
                                | BodyStmt::After(_)
                                | BodyStmt::Case(_)
                                | BodyStmt::Region(_)
                        ),
                        &path,
                        "leaf embeds unexpanded control flow",
                    )?;
                    require(
                        block.scope.is_none() || !matches!(leaf.as_ref(), BodyStmt::Terminal(_)),
                        &path,
                        "action contains a workflow terminal",
                    )?;
                    self.span(span(leaf), &path)?;
                }
                NodeKind::Call { scope, arguments } => {
                    let target = at(&self.plan.scopes, scope.0, &path)?;
                    require(
                        arguments.len() == target.parameters.len(),
                        &path,
                        "call argument count differs from parameters",
                    )?;
                    for argument in arguments {
                        require(
                            argument.environment == block.environment,
                            &path,
                            "call argument captures another lexical environment",
                        )?;
                        self.span(argument.value.span, &path)?;
                    }
                    self.enter_scope(*scope, Some(id))?;
                }
                NodeKind::Return(expr) | NodeKind::Fail(expr) => {
                    require(
                        block.scope.is_some(),
                        &path,
                        "action result appears outside an action",
                    )?;
                    self.span(expr.span, &path)?;
                }
                NodeKind::After {
                    observed,
                    alias,
                    body,
                    ..
                } => {
                    let name = self.name(*observed, &path)?;
                    require(
                        block.environment.get(&name) == Some(observed),
                        &path,
                        "continuation observes an invisible binding",
                    )?;
                    self.child(
                        *body,
                        block.scope,
                        &block.environment,
                        alias.map(|b| (b, BindingSource::After { node: id })),
                        &path,
                    )?;
                }
                NodeKind::OnFailure { alias, body } => {
                    require(
                        self.handlers.insert(block.scope, id).is_none(),
                        &path,
                        "lexical scope has more than one failure handler",
                    )?;
                    self.child(
                        *body,
                        block.scope,
                        &block.environment,
                        Some((*alias, BindingSource::FailureHandler { node: id })),
                        &path,
                    )?;
                }
                NodeKind::Case { branches, .. } => {
                    for (index, branch) in branches.iter().enumerate() {
                        self.span(branch.span, &path)?;
                        let env = self.child(
                            branch.body,
                            block.scope,
                            &block.environment,
                            branch.binding.map(|b| {
                                (
                                    b,
                                    BindingSource::Case {
                                        node: id,
                                        branch: index,
                                    },
                                )
                            }),
                            &path,
                        )?;
                        require(
                            branch.guard_environment == env,
                            &path,
                            "case guard sees a different lexical environment",
                        )?;
                    }
                }
                NodeKind::Region {
                    body,
                    lapse_body,
                    lapse_binding,
                    ..
                } => {
                    self.child(*body, block.scope, &block.environment, None, &path)?;
                    self.child(
                        *lapse_body,
                        block.scope,
                        &block.environment,
                        lapse_binding.map(|b| (b, BindingSource::Lapse { node: id })),
                        &path,
                    )?;
                }
            }
        }
        Ok(())
    }
}
