//! Resource addresses through original managed values. This is neither byte
//! provenance nor a grant/admission decision; selection controls remain explicit.
use super::analysis::CompositionAnalysis;
use super::resolved::TypedActionPlan;
use super::value_flow::{Control, Graph, Origin, Trace};
use super::{BindingId, BindingSource, NodeId, NodeKind};
use crate::body::{BodyEffectKind, BodyStmt};
use crate::effect_contract::Resource;
use crate::{
    diagnostic_code, Diagnostic, IrEffectKind, IrProgram, IrSchema, IrWhen, RelatedInfo, SourceSpan,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEffect {
    pub kind: IrEffectKind,
    pub resources: BTreeSet<String>,
    pub controls: BTreeSet<Control>,
}

#[derive(Clone, Copy)]
enum ProgramContext<'a> {
    Ir(&'a IrProgram),
    Composition(&'a CompositionAnalysis),
}

#[derive(Clone, Copy)]
struct RuleContext<'a> {
    whens: &'a [IrWhen],
}

impl<'a> ProgramContext<'a> {
    fn agents(self) -> &'a [crate::IrAgent] {
        match self {
            Self::Ir(program) => &program.agents,
            Self::Composition(program) => program.declarations().agents(),
        }
    }

    fn schemas(self) -> &'a [IrSchema] {
        match self {
            Self::Ir(program) => &program.schemas,
            Self::Composition(program) => program.declarations().schemas(),
        }
    }

    fn trackers(self) -> &'a [crate::IrTracker] {
        match self {
            Self::Ir(program) => &program.trackers,
            Self::Composition(program) => program.declarations().trackers(),
        }
    }

    fn leases(self) -> &'a [crate::IrLease] {
        match self {
            Self::Ir(program) => &program.leases,
            Self::Composition(program) => program.declarations().leases(),
        }
    }

    fn root(self, name: &str) -> Option<RuleContext<'a>> {
        match self {
            Self::Ir(program) => {
                let mut roots = program.rules.iter().filter(|rule| rule.name == name);
                let root = roots.next()?;
                roots
                    .next()
                    .is_none()
                    .then_some(RuleContext { whens: &root.whens })
            }
            Self::Composition(program) => {
                let mut roots = program
                    .rules()
                    .iter()
                    .filter(|rule| rule.root.name.name == name);
                let root = roots.next()?;
                roots.next().is_none().then_some(RuleContext {
                    whens: &root.root.whens,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Role {
    Item,
    Claim,
    Lease,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Address {
    role: Role,
    resource: String,
}

#[derive(Clone, Debug, Default)]
struct Proof {
    addresses: BTreeSet<Address>,
    controls: BTreeSet<Control>,
}

fn transform_tracker_address(mut proof: Proof, role: Role) -> Result<Proof, Box<Diagnostic>> {
    if proof
        .addresses
        .iter()
        .any(|address| address.role == Role::Lease)
    {
        let message = "tracker lifecycle requires an original tracker item, not a lease";
        // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
        return Err(invalid(message));
    }
    proof.addresses = proof
        .addresses
        .into_iter()
        .map(|address| Address { role, ..address })
        .collect();
    Ok(proof)
}

impl Proof {
    fn extend(&mut self, other: &Self) {
        self.addresses.extend(other.addresses.iter().cloned());
        self.controls.extend(other.controls.iter().cloned());
    }
}

fn invalid(message: &str) -> Box<Diagnostic> {
    Box::new(Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        SourceSpan { start: 0, end: 0 },
        message,
    ))
}

fn unique<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn tracker_trigger_handle<'a>(pattern: &'a str, trackers: &BTreeSet<&str>) -> Option<&'a str> {
    let pattern = pattern.split(" where ").next().unwrap_or(pattern);
    let mut words = pattern.split_whitespace();
    let handle = words.next()?;
    (words.next() == Some("has")
        && words.next() == Some("ready")
        && words.next() == Some("issue")
        && trackers.contains(handle))
    .then_some(handle)
}

pub fn resolve(
    typed: &TypedActionPlan,
    ir: &IrProgram,
) -> Result<BTreeMap<NodeId, ResolvedEffect>, Box<Diagnostic>> {
    resolve_in(typed, ProgramContext::Ir(ir))
}

pub fn resolve_composition(
    typed: &TypedActionPlan,
    analysis: &CompositionAnalysis,
) -> Result<BTreeMap<NodeId, ResolvedEffect>, Box<Diagnostic>> {
    resolve_in(typed, ProgramContext::Composition(analysis))
}

fn resolve_in(
    typed: &TypedActionPlan,
    program: ProgramContext<'_>,
) -> Result<BTreeMap<NodeId, ResolvedEffect>, Box<Diagnostic>> {
    let constants: BTreeSet<String> = program
        .agents()
        .iter()
        .map(|agent| agent.name.clone())
        .chain(
            program
                .schemas()
                .iter()
                .filter_map(|schema| match schema {
                    IrSchema::Enum(e) => Some(e),
                    _ => None,
                })
                .flat_map(|e| e.variants.clone()),
        )
        .collect();
    let graph = Graph::new(typed, &constants)?;
    let Some(root) = typed.plan.root_rule.as_ref() else {
        // MUTATION-SUCCESS-EXPR: Ok(BTreeMap::new())
        return Err(invalid("managed resource resolution requires a root rule"));
    };
    let Some(rule) = program.root(&root.name) else {
        let message = "managed resource resolution requires one matching rule declaration";
        // MUTATION-SUCCESS-EXPR: Ok(BTreeMap::new())
        return Err(invalid(message));
    };
    let mut walker = Walker {
        typed,
        program,
        rule,
        graph,
        memo: BTreeMap::new(),
    };
    let mut result = BTreeMap::new();
    for (id, effect) in &typed.effects {
        let resolved = resolve_one(typed, &mut walker, *id, effect).map_err(|mut error| {
            let span = typed.plan.nodes[id.0].span;
            if error.span != (SourceSpan { start: 0, end: 0 }) && error.span != span {
                error.related.push(RelatedInfo {
                    span: error.span,
                    message: "resource operand originates here".into(),
                });
            }
            error.span = span;
            managed_call_context(&mut error, &typed.plan, *id);
            error
        })?;
        result.insert(*id, resolved);
    }
    Ok(result)
}

fn resolve_one(
    typed: &TypedActionPlan,
    walker: &mut Walker<'_>,
    id: NodeId,
    effect: &super::effects::Effect,
) -> Result<ResolvedEffect, Box<Diagnostic>> {
    let mut resolved = ResolvedEffect {
        kind: effect.contract.kind.clone(),
        resources: BTreeSet::new(),
        controls: BTreeSet::new(),
    };
    match &effect.contract.resource {
        Resource::None => {}
        Resource::Named(resource) => {
            resolved.resources.insert(resource.clone());
        }
        Resource::Binding(_) => {
            let proof =
                walker.binding(effect.resource_subject.expect("validated resource subject"))?;
            let NodeKind::Statement(statement) = &typed.plan.nodes[id.0].kind else {
                unreachable!("validated effect")
            };
            let BodyStmt::Effect(statement) = statement.as_ref() else {
                unreachable!("validated effect")
            };
            return operand(&statement.kind, proof, resolved);
        }
    }
    Ok(resolved)
}

fn operand(
    kind: &BodyEffectKind,
    proof: Proof,
    mut resolved: ResolvedEffect,
) -> Result<ResolvedEffect, Box<Diagnostic>> {
    resolved.controls = proof.controls;
    let mut selected_kind = None;
    for address in proof.addresses {
        let kind = match (kind, address.role) {
            (BodyEffectKind::TrackerClaim { .. }, Role::Item | Role::Claim) => {
                IrEffectKind::TrackerClaim
            }
            (BodyEffectKind::TrackerRelease { .. }, Role::Item | Role::Claim) => {
                IrEffectKind::TrackerRelease
            }
            (BodyEffectKind::TrackerFinish { .. }, Role::Item | Role::Claim) => {
                IrEffectKind::TrackerFinish
            }
            (BodyEffectKind::LeaseRenew { .. }, Role::Claim) => IrEffectKind::TrackerRenew,
            (BodyEffectKind::LeaseRenew { .. }, Role::Lease) => IrEffectKind::LeaseRenew,
            _ => {
                let message =
                    "resource operand is not an original value of the required operation kind";
                // MUTATION-SUCCESS-EXPR: Ok(resolved)
                return Err(invalid(message));
            }
        };
        if selected_kind
            .as_ref()
            .is_some_and(|previous| previous != &kind)
        {
            let message = "resource alternatives require incompatible operation kinds";
            // MUTATION-SUCCESS-EXPR: Ok(resolved)
            return Err(invalid(message));
        }
        selected_kind = Some(kind);
        resolved.resources.insert(address.resource);
    }
    if let Some(kind) = selected_kind {
        resolved.kind = kind;
    }
    Ok(resolved)
}

struct Walker<'a> {
    typed: &'a TypedActionPlan,
    program: ProgramContext<'a>,
    rule: RuleContext<'a>,
    graph: Graph<'a>,
    memo: BTreeMap<Origin, Proof>,
}

impl Walker<'_> {
    fn roots(
        &self,
        binding: BindingId,
    ) -> Result<(Vec<Origin>, BTreeSet<Control>), Box<Diagnostic>> {
        let Trace {
            sources, controls, ..
        } = self.graph.identity_binding(binding)?;
        let mut roots = Vec::new();
        for source in sources {
            if !source.fields.is_empty() {
                let message =
                    "a field of an original resource value is not the whole resource operand";
                // MUTATION-SUCCESS-EXPR: Ok((Vec::new(), BTreeSet::new()))
                return Err(invalid(message));
            }
            roots.push(source.origin);
        }
        Ok((roots, controls))
    }

    fn declared(&self, role: Role, name: &str) -> Result<Proof, Box<Diagnostic>> {
        let present = match role {
            Role::Item | Role::Claim => unique(
                self.program
                    .trackers()
                    .iter()
                    .filter(|item| item.name == name),
            )
            .is_some(),
            Role::Lease => unique(
                self.program
                    .leases()
                    .iter()
                    .filter(|item| item.name == name),
            )
            .is_some(),
        };
        if !present {
            let message = format!("resource origin requires one matching declaration for `{name}`");
            // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
            return Err(invalid(&message));
        }
        let resource = if role == Role::Lease {
            format!("resource:{name}")
        } else {
            name.into()
        };
        Ok(Proof {
            addresses: BTreeSet::from([Address { role, resource }]),
            controls: BTreeSet::new(),
        })
    }

    fn input(&self, id: BindingId) -> Result<Proof, Box<Diagnostic>> {
        let binding = &self.typed.plan.bindings[id.0];
        let name = binding.name.as_deref().unwrap_or("");
        let trackers: BTreeSet<&str> = self
            .program
            .trackers()
            .iter()
            .map(|tracker| tracker.name.as_str())
            .collect();
        let when = unique(self.rule.whens.iter().filter(|when| {
            let mut words = when.pattern.split_whitespace();
            words.any(|word| word == "as") && words.next() == Some(name)
        }));
        let tracker = when.and_then(|when| tracker_trigger_handle(&when.pattern, &trackers));
        let Some(tracker) =
            tracker.filter(|_| matches!(binding.source, BindingSource::RuleInput { .. }))
        else {
            let message = format!("resource input `{name}` requires one matching tracker trigger");
            // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
            return Err(invalid(&message));
        };
        self.declared(Role::Item, tracker)
    }

    fn binding(&mut self, binding: BindingId) -> Result<Proof, Box<Diagnostic>> {
        enum Work {
            Enter(Origin),
            Transform(Origin, Vec<Origin>, BTreeSet<Control>, Role),
        }
        let (roots, controls) = self.roots(binding)?;
        let mut pending: Vec<_> = roots.iter().cloned().map(Work::Enter).collect();
        let mut active = BTreeSet::new();
        while let Some(work) = pending.pop() {
            match work {
                Work::Transform(origin, inputs, controls, role) => {
                    let mut proof = Proof {
                        controls,
                        ..Proof::default()
                    };
                    for input in inputs {
                        proof.extend(&self.memo[&input]);
                    }
                    let proof = transform_tracker_address(proof, role)?;
                    active.remove(&origin);
                    self.memo.insert(origin, proof);
                }
                Work::Enter(origin) => {
                    if active.contains(&origin) {
                        let message = "managed resource identity contains a cycle";
                        // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
                        return Err(invalid(message));
                    }
                    if self.memo.contains_key(&origin) {
                        continue;
                    }
                    let proof = match &origin {
                        Origin::Input(binding) => self.input(*binding)?,
                        Origin::Operation(node) => {
                            let NodeKind::Statement(statement) =
                                &self.typed.plan.nodes[node.0].kind
                            else {
                                unreachable!("validated operation")
                            };
                            let BodyStmt::Effect(effect) = statement.as_ref() else {
                                unreachable!("validated operation")
                            };
                            match &effect.kind {
                                BodyEffectKind::TrackerFile { queue, .. } => {
                                    self.declared(Role::Item, queue)?
                                }
                                BodyEffectKind::LeaseAcquire { resource, .. } => {
                                    self.declared(Role::Lease, resource)?
                                }
                                BodyEffectKind::TrackerClaim { .. }
                                | BodyEffectKind::TrackerRelease { .. }
                                | BodyEffectKind::TrackerFinish { .. } => {
                                    let subject = self.typed.effects[node]
                                        .resource_subject
                                        .expect("validated tracker subject");
                                    let (inputs, controls) = self.roots(subject)?;
                                    let role = if matches!(
                                        effect.kind,
                                        BodyEffectKind::TrackerClaim { .. }
                                    ) {
                                        Role::Claim
                                    } else {
                                        Role::Item
                                    };
                                    active.insert(origin.clone());
                                    pending.push(Work::Transform(
                                        origin,
                                        inputs.clone(),
                                        controls,
                                        role,
                                    ));
                                    pending.extend(inputs.into_iter().map(Work::Enter));
                                    continue;
                                }
                                _ => {
                                    let message = "this operation result carries no original tracker or lease identity";
                                    // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
                                    return Err(invalid(message));
                                }
                            }
                        }
                        Origin::Crossing(_) | Origin::Outcome { .. } | Origin::Lapse(_) => {
                            let message = "a crossing or non-success observation cannot supply original resource identity";
                            // MUTATION-SUCCESS-EXPR: Ok(Proof::default())
                            return Err(invalid(message));
                        }
                    };
                    self.memo.insert(origin, proof);
                }
            }
        }
        let mut result = Proof {
            controls,
            ..Proof::default()
        };
        for root in roots {
            result.extend(&self.memo[&root]);
        }
        Ok(result)
    }
}

fn managed_call_context(diagnostic: &mut Diagnostic, plan: &super::ActionPlan, id: NodeId) {
    let node = &plan.nodes[id.0];
    let mut scope = match node.kind {
        NodeKind::Call { scope, .. } => Some(scope),
        _ => plan.blocks[node.block.0].scope,
    };
    while let Some(id) = scope {
        let owner = &plan.scopes[id.0];
        diagnostic.related.push(RelatedInfo {
            span: owner.definition_span,
            message: format!("action `{}` defined here", owner.action),
        });
        let Some(call) = owner.parent_call else {
            break;
        };
        let caller = &plan.nodes[call.0];
        diagnostic.related.push(RelatedInfo {
            span: caller.span,
            message: format!("call to action `{}`", owner.action),
        });
        scope = plan.blocks[caller.block.0].scope;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_plan::resolved::resolve_rule_types;

    const HEADER: &str = r#"workflow Demo
tracker jobs { provider builtin }
tracker other { provider builtin }
lease slots { key Ticket slots 1 ttl 5m }
class Ticket { id string }
class Box { item WorkItem }
class TrackerAddress { queue string id string title string }
"#;

    fn typed(source: &str) -> TypedActionPlan {
        let parsed = crate::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        resolve_rule_types(&parsed.program, "run").unwrap()
    }

    fn context(trigger: &str) -> IrProgram {
        let source = format!("{HEADER}rule run when {trigger} => {{ timer 1s as wait }}");
        let compiled = crate::compile_program(&source);
        compiled
            .ir
            .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics))
    }

    fn named<'a>(
        typed: &TypedActionPlan,
        map: &'a BTreeMap<NodeId, ResolvedEffect>,
        name: &str,
    ) -> &'a ResolvedEffect {
        let binding = typed.plan.blocks[typed.plan.root.0].environment[name];
        let BindingSource::Node(node) = typed.plan.bindings[binding.0].source else {
            panic!("not a node")
        };
        &map[&node]
    }

    #[test]
    fn resources_follow_original_items_through_helpers_and_keep_selection_controls() {
        let source = format!(
            r#"{HEADER}
action wrap(item WorkItem) -> Box {{ return {{ item item }} }}
action unwrap(boxed Box) -> WorkItem {{ return boxed.item }}
action finish_it(item WorkItem) -> null {{ finish item {{ summary "done" }} as finished
 return null }}
rule run when jobs has ready issue as item => {{ wrap(item) as boxed
 unwrap(boxed) as original
 finish_it(original) as first
 finish_it(original) as second
 claim original as held
 renew held as renewed
 release original }}"#
        );
        let plan = typed(&source);
        let resolved = resolve(&plan, &context("jobs has ready issue as item")).unwrap();
        assert_eq!(resolved.len(), 5);
        assert!(resolved
            .values()
            .all(|effect| effect.resources == BTreeSet::from(["jobs".into()])));
        assert_eq!(
            named(&plan, &resolved, "renewed").kind,
            IrEffectKind::TrackerRenew
        );
        assert!(resolved.values().all(|effect| !effect.controls.is_empty()));
    }

    #[test]
    fn resources_resolve_file_claim_chains_and_lease_renewal() {
        let source = format!(
            r#"{HEADER}
rule run when Ticket as key => {{ file issue into jobs {{ title "task" }} as item
 claim item as held
 claim held as held_again
 release held_again as reopened
 claim reopened as reclaimed
 finish reclaimed as finished
 acquire slots for key until ttl as slot
 renew slot as lease_renewed }}"#
        );
        let plan = typed(&source);
        let resolved = resolve(&plan, &context("Ticket as key")).unwrap();
        assert_eq!(resolved.len(), 8);
        assert_eq!(
            named(&plan, &resolved, "reopened").kind,
            IrEffectKind::TrackerRelease
        );
        assert_eq!(
            named(&plan, &resolved, "reclaimed").resources,
            BTreeSet::from(["jobs".into()])
        );
        assert_eq!(
            named(&plan, &resolved, "finished").resources,
            BTreeSet::from(["jobs".into()])
        );
        assert_eq!(
            named(&plan, &resolved, "lease_renewed").kind,
            IrEffectKind::LeaseRenew
        );
        assert_eq!(
            named(&plan, &resolved, "lease_renewed").resources,
            BTreeSet::from(["resource:slots".into()])
        );
    }

    #[test]
    fn resources_refuse_data_fields_crossings_and_non_success_values() {
        for body in [
            "declassify item into TrackerAddress as field_holder\nfinish field_holder as done",
            "declassify item into TrackerAddress as data\nfinish data as done",
            "renew item as done",
            "claim second as first\nclaim first as second\nrenew second as done",
        ] {
            let source = format!(
                "{HEADER}rule run when jobs has ready issue as item\n when Ticket as key => {{ {body} }}"
            );
            let plan = typed(&source);
            assert!(
                resolve(
                    &plan,
                    &context("jobs has ready issue as item\n when Ticket as key")
                )
                .is_err(),
                "{body}"
            );
        }

        for body in [
            "timer 1s as wait\nfinish wait as done",
            "timer 1s as wait\nafter wait fails as failure { finish failure as done }",
            "during true { timer 1s as wait } on lapse as progress { finish progress as done }",
            "acquire slots for key until ttl as slot\nfinish slot as done",
        ] {
            let source = format!(
                "{HEADER}rule run when jobs has ready issue as item\n when Ticket as key => {{ {body} }}"
            );
            let errors = resolve_rule_types(&crate::parse_program(&source).program, "run")
                .expect_err("non-address tracker operand");
            assert!(
                errors.iter().any(|error| error
                    .message
                    .contains("must provide string fields `queue`, `id`, and `title`")),
                "{body}: {errors:?}"
            );
        }

        let error = transform_tracker_address(
            Proof {
                addresses: BTreeSet::from([Address {
                    role: Role::Lease,
                    resource: "resource:slots".into(),
                }]),
                controls: BTreeSet::new(),
            },
            Role::Claim,
        )
        .unwrap_err();
        assert!(
            error
                .message
                .contains("tracker lifecycle requires an original tracker item, not a lease"),
            "{error:?}"
        );
    }

    #[test]
    fn resources_refuse_missing_or_ambiguous_context() {
        let source = format!(
            "{HEADER}rule run when jobs has ready issue as item => {{ finish item as done }}"
        );
        let plan = typed(&source);
        for case in 0..5 {
            let mut ir = context("jobs has ready issue as item");
            match case {
                0 => ir.rules.clear(),
                1 => ir.rules.push(
                    ir.rules
                        .iter()
                        .find(|rule| rule.name == "run")
                        .unwrap()
                        .clone(),
                ),
                2 => ir.trackers.clear(),
                3 => ir.trackers.push(
                    ir.trackers
                        .iter()
                        .find(|tracker| tracker.name == "jobs")
                        .unwrap()
                        .clone(),
                ),
                _ => {
                    let rule = ir.rules.iter_mut().find(|rule| rule.name == "run").unwrap();
                    rule.whens.push(rule.whens[0].clone());
                }
            }
            assert!(resolve(&plan, &ir).is_err(), "case {case}");
        }
        assert!(resolve(&plan, &context("Ticket as item")).is_err());

        let lease = typed(&format!(
            "{HEADER}rule run when Ticket as key => {{ acquire slots for key until ttl as slot\nrenew slot as again }}"
        ));
        for duplicate in [false, true] {
            let mut ir = context("Ticket as key");
            if duplicate {
                ir.leases.push(ir.leases[0].clone());
            } else {
                ir.leases.clear();
            }
            assert!(resolve(&lease, &ir).is_err());
        }
    }

    #[test]
    fn resources_diagnose_consuming_helper_and_preserve_empty_effect_entries() {
        let source = format!(
            r#"{HEADER}
action finish_it(item WorkItem) -> null {{ finish item as done
 return null }}
rule run when jobs has ready issue as item => {{ finish_it(item) as result
 timer 1s as wait }}"#
        );
        let plan = typed(&source);
        let ir = context("jobs has ready issue as item");
        let resolved = resolve(&plan, &ir).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(named(&plan, &resolved, "wait").resources.is_empty());
        let error = resolve(&plan, &context("Ticket as item")).unwrap_err();
        assert!(source[error.span.start..error.span.end].contains("finish item"));
        assert!(error
            .related
            .iter()
            .any(|related| related.message == "call to action `finish_it`"));
    }

    #[test]
    fn resources_keep_every_returned_queue_and_no_success_is_not_a_default_target() {
        let trigger = "jobs has ready issue as left\n when other has ready issue as right";
        let source = format!(
            r#"{HEADER}
action choose(left WorkItem, right WorkItem, flag bool) -> WorkItem {{
 case flag {{ true => {{ return left }} false => {{ return right }} }} }}
rule run when {trigger} => {{ choose(left,right,true) as selected
 finish selected as finished }}"#
        );
        let plan = typed(&source);
        let resolved = resolve(&plan, &context(trigger)).unwrap();
        let effect = named(&plan, &resolved, "finished");
        assert_eq!(
            effect.resources,
            BTreeSet::from(["jobs".into(), "other".into()])
        );
        assert!(effect
            .controls
            .iter()
            .any(|control| matches!(control, Control::Case { branch: 0, .. })));
        assert!(effect
            .controls
            .iter()
            .any(|control| matches!(control, Control::Case { branch: 1, .. })));

        let source = format!(
            r#"{HEADER}
action unavailable() -> WorkItem ! string {{ fail "no item" }}
rule run when started => {{ unavailable() as item
 finish item as finished }}"#
        );
        let plan = typed(&source);
        let resolved = resolve(&plan, &context("started")).unwrap();
        let effect = named(&plan, &resolved, "finished");
        assert_eq!(effect.kind, IrEffectKind::TrackerFinish);
        assert!(effect.resources.is_empty());
        assert!(!effect.controls.is_empty());
    }

    #[test]
    fn resources_do_not_promote_data_influence_to_item_identity() {
        for action in [
            "action project(item WorkItem) -> TrackerAddress { return { queue item.queue id item.id title item.title } }",
            "action project(item WorkItem) -> TrackerAddress { return { queue \"jobs\" id item.id title item.title } }",
        ] {
            let source = format!(
                "{HEADER}{action}\nrule run when jobs has ready issue as item => {{ project(item) as data\nfinish data as finished }}"
            );
            let plan = typed(&source);
            let error = resolve(&plan, &context("jobs has ready issue as item")).unwrap_err();
            assert!(error.message.contains("original value"), "{error:?}");
            assert!(source[error.span.start..error.span.end].contains("finish data"));
            assert!(error
                .related
                .iter()
                .any(|related| related.message == "resource operand originates here"));
        }
    }

    #[test]
    fn resources_require_a_rule_root_even_without_effects() {
        let program =
            crate::parse_program("workflow Demo\naction empty() -> null { return null }").program;
        let actions = program
            .items
            .iter()
            .filter_map(|item| match item {
                crate::Item::Action(action) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let plan = TypedActionPlan {
            plan: super::super::expand_syntax(&actions, "empty").unwrap(),
            case_types: BTreeMap::new(),
            effects: BTreeMap::new(),
            views: BTreeMap::new(),
        };
        assert!(resolve(&plan, &context("started"))
            .unwrap_err()
            .message
            .contains("requires a root rule"));
    }

    #[test]
    fn resource_join_refuses_mixed_renewal_kinds_and_keeps_tracker_alternatives() {
        let kind = BodyEffectKind::LeaseRenew {
            acquire_binding: "subject".into(),
            ttl_seconds: None,
        };
        let initial = ResolvedEffect {
            kind: IrEffectKind::LeaseRenew,
            resources: BTreeSet::new(),
            controls: BTreeSet::new(),
        };
        let address = |role, resource: &str| Address {
            role,
            resource: resource.into(),
        };
        let mixed = Proof {
            addresses: BTreeSet::from([
                address(Role::Claim, "jobs"),
                address(Role::Lease, "resource:slots"),
            ]),
            ..Proof::default()
        };
        assert!(operand(&kind, mixed, initial.clone())
            .unwrap_err()
            .message
            .contains("incompatible operation kinds"));

        let claims = Proof {
            addresses: BTreeSet::from([
                address(Role::Claim, "jobs"),
                address(Role::Claim, "other"),
            ]),
            ..Proof::default()
        };
        let resolved = operand(&kind, claims, initial).unwrap();
        assert_eq!(resolved.kind, IrEffectKind::TrackerRenew);
        assert_eq!(
            resolved.resources,
            BTreeSet::from(["jobs".into(), "other".into()])
        );
    }
}
