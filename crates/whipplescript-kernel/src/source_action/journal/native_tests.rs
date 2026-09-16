use super::*;
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{context_record_json, RuleContext};
use crate::rule_pass::{commit_lowering, step_active_program_generic, step_instance_generic};
use crate::{ProgramVersionInput, RuntimeKernel};
use serde_json::json;
use whipplescript_parser::{compile_program, IrProgram};
use whipplescript_store::native_stores::NativeStores;
use whipplescript_store::{
    NewEvent, RuleCommit, RuleCommitRevisionGuard, RuntimeStore, SqliteStore,
};

fn wrap(runtime: SqliteStore) -> NativeStores {
    NativeStores {
        runtime,
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory()
            .expect("coord store"),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().expect("items store"),
        frontier: None,
    }
}

struct Fixture {
    kernel: RuntimeKernel<NativeStores>,
    ir: IrProgram,
    instance: String,
    frame: Frame,
    context: RuleContext,
}
impl Fixture {
    fn new(store: SqliteStore) -> Self {
        Self::with_source(store, "workflow Captures\noutput result Result\nclass Result { ok bool }\nrule finish when started => { complete result { ok true } }")
    }
    fn with_source(store: SqliteStore, source: &str) -> Self {
        let ir = compile_program(source).ir.expect("legacy fixture compiles");
        let mut kernel = RuntimeKernel::new(wrap(store));
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "source",
                    ir_hash: "ir",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &ir,
            )
            .expect("version created");
        let instance = kernel
            .create_instance(&version, "{}")
            .expect("instance created");
        let started = kernel
            .ingest_external_event(&instance, "external.started", "{}", Some("started"))
            .expect("start event");
        let frame = Frame {
            version: version.version_id,
            revision: "0".into(),
            rule: "finish".into(),
            identity: None,
            trigger_event: Some(started.event_id.clone()),
        };
        Self {
            kernel,
            ir,
            instance,
            frame,
            context: RuleContext {
                trigger_event_id: Some(started.event_id),
                ..Default::default()
            },
        }
    }
    fn events(&self) -> Vec<EventView> {
        self.kernel
            .store()
            .list_events(&self.instance)
            .expect("events readable")
    }
    fn journal(&self) -> Journal {
        let mut journal = Journal::default();
        for event in self.events() {
            journal.apply(&event).expect("capture journal readable");
        }
        journal
    }
    fn commit(
        &mut self,
        lowering: &OwnedLowering,
        journal: &Journal,
    ) -> Result<whipplescript_store::StoredEvent, whipplescript_store::StoreError> {
        let frontier = self
            .events()
            .last()
            .expect("instance has creation event")
            .sequence;
        commit_lowering(
            &mut self.kernel,
            &self.instance,
            &self.ir,
            &self.context,
            &self.frame,
            lowering,
            journal,
            frontier,
            RuleCommitRevisionGuard {
                evaluated_frontier: None,
                program_version_id: &self.frame.version,
                revision_epoch: 0,
            },
        )
    }
    fn capture(&self, call: u64) -> CallCapture {
        CallCapture {
            call,
            arguments: vec![Value::Null.into(), json!({"ticket": call}).into()],
            reads: BTreeSet::new(),
            frontier: self.events().last().expect("event frontier").sequence,
        }
    }
}

#[test]
fn action_capture_only_commits_reopen_and_replay_without_facts_or_effects() {
    let path = std::env::temp_dir().join(format!(
        "whip-action-capture-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    let first = OwnedLowering {
        action_captures: vec![f.capture(1)],
        ..Default::default()
    };
    assert!(first.has_commit_work());
    assert!(!OwnedLowering::default().has_commit_work());
    let first_event = f.commit(&first, &Journal::default()).unwrap();
    let second = OwnedLowering {
        action_captures: vec![f.capture(2)],
        ..Default::default()
    };
    f.commit(&second, &f.journal()).unwrap();
    let expected = f.journal();
    assert_eq!(expected.calls(&f.frame).unwrap().len(), 2);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut reopened = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    assert_eq!(reopened.journal(), expected);
    let before = reopened.events().len();
    let replay = reopened.commit(&first, &reopened.journal()).unwrap();
    assert_eq!(replay.event_id, first_event.event_id);
    assert_eq!(reopened.events().len(), before);
    assert!(reopened
        .kernel
        .store()
        .list_facts(&reopened.instance)
        .unwrap()
        .is_empty());
    assert!(reopened
        .kernel
        .store()
        .list_effects(&reopened.instance)
        .unwrap()
        .is_empty());
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn parameterized_view_runs_through_native_recorded_dispatch_and_reopens_purely() {
    const SOURCE: &str = r#"workflow NativeViews
output result Answer
class Ticket { owner string }
class Answer { present bool }
view owned(wanted string) -> bool {
  return exists(Ticket where owner == wanted)
}
view readiness(wanted string) -> Answer {
  return { present owned(wanted) }
}
action inspect(wanted string) -> Answer { return readiness(wanted) }
rule finish when Ticket as ticket => {
  inspect(ticket.owner) as answer
  complete result { present answer.present }
}
"#;
    let path = std::env::temp_dir().join(format!(
        "whip-parameterized-view-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let compiled = compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.unwrap();
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&ir, &plans).unwrap();
    let mut kernel = RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap()));
    let source_hash = kernel.store().put_content(SOURCE).unwrap();
    let version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &source_hash,
                ir_hash: &whipplescript_parser::snapshot::identity_hash(&identity),
                compiler_version: "test",
                ir_snapshot: Some(&identity),
            },
            &ir,
            &plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .derive_fact(
            &instance,
            "Ticket",
            "ticket",
            r#"{"owner":"alice"}"#,
            None,
            Some("ticket"),
        )
        .unwrap();
    let report = step_active_program_generic(&mut kernel, &instance, None, None, None).unwrap();
    assert_eq!(report.committed_rules, 1);
    let terminal = kernel
        .store()
        .list_events(&instance)
        .unwrap()
        .into_iter()
        .find(|event| event.event_type == "workflow.completed")
        .unwrap();
    let payload: Value = serde_json::from_str(&terminal.payload_json).unwrap();
    assert_eq!(payload["payload"], json!({"present":true}));
    assert_eq!(payload["validity"][0]["head"], "Ticket");
    assert!(payload["validity"][0]["members"][0]["fact_id"]
        .as_str()
        .is_some_and(|identity| !identity.is_empty()));
    assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
    let before = kernel.store().list_events(&instance).unwrap().len();
    drop(kernel);

    let mut reopened = RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap()));
    let replay = step_active_program_generic(&mut reopened, &instance, None, None, None).unwrap();
    assert_eq!(replay.committed_rules, 0);
    assert_eq!(
        reopened.store().list_events(&instance).unwrap().len(),
        before
    );
    assert!(reopened.store().list_effects(&instance).unwrap().is_empty());
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn action_arguments_from_source_commit_and_reopen_with_fact_origins() {
    use crate::source_action::arguments::{prepare_call, Argument, Bindings, Slot, ValueSource};
    use whipplescript_parser::action_plan::{expand_rule_syntax, NodeId, NodeKind};
    use whipplescript_parser::{parse_program, Ident, Item, SourceSpan};

    // This exercises source-plan argument production and the real durable
    // commit helper. It does not claim the gated source rule driver is built.
    let source = "workflow Captures\naction leaf(x string, y string?) -> string { return x }\nrule finish when Ticket as input => { leaf(input.title, input.optional) as result }";
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    let plan = expand_rule_syntax(
        &actions,
        rule,
        &[Ident {
            name: "input".into(),
            span: SourceSpan { start: 0, end: 0 },
        }],
    )
    .unwrap();
    let call = NodeId(
        plan.nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Call { .. }))
            .unwrap(),
    );
    let path = std::env::temp_dir().join(format!(
        "whip-action-arguments-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "ticket",
            r#"{"title":"original"}"#,
            None,
            Some("ticket"),
        )
        .unwrap();
    let fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Ticket")
        .unwrap();
    let sources = BTreeSet::from([ValueSource::Fact {
        fact_id: fact.fact_id.clone(),
        admission_event: fact.source_event_id.clone(),
    }]);
    let bindings = Bindings::from([(
        plan.root_inputs[0],
        Slot::Ready(Argument {
            subjects: Default::default(),
            value: serde_json::from_str(&fact.value_json).unwrap(),
            sources: sources.clone(),
            validity: Default::default(),
        }),
    )]);
    f.context.bindings.push(("input".into(), fact.clone()));
    f.context.trigger_event_id = Some(fact.source_event_id.clone());
    f.frame.trigger_event = Some(fact.source_event_id);
    let prepared = prepare_call(
        &plan,
        call,
        &bindings,
        &f.journal(),
        &f.frame,
        f.events().last().unwrap().sequence,
    )
    .unwrap();
    assert_eq!(prepared.capture.arguments[0].value, json!("original"));
    assert_eq!(prepared.capture.arguments[1].value, Value::Null);
    assert!(prepared
        .capture
        .arguments
        .iter()
        .all(|arg| arg.sources == sources));
    let lowering = OwnedLowering {
        action_captures: vec![prepared.capture.clone()],
        ..Default::default()
    };
    let committed = f.commit(&lowering, &f.journal()).unwrap();
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut reopened = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let replay = prepare_call(
        &plan,
        call,
        &Bindings::new(),
        &reopened.journal(),
        &reopened.frame,
        reopened.events().last().unwrap().sequence,
    )
    .unwrap();
    assert!(!replay.fresh);
    assert_eq!(replay.capture, prepared.capture);
    assert_eq!(replay.parameters, prepared.parameters);
    assert_eq!(
        reopened
            .commit(&lowering, &reopened.journal())
            .unwrap()
            .event_id,
        committed.event_id
    );
    assert_eq!(
        reopened
            .kernel
            .store()
            .list_facts(&reopened.instance)
            .unwrap()
            .len(),
        1
    );
    assert!(reopened
        .kernel
        .store()
        .list_effects(&reopened.instance)
        .unwrap()
        .is_empty());
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

mod timer_fixture {
    use super::*;
    use crate::source_action::arguments::Bindings;
    use crate::source_action::progression::{advance, Progression, ProgressionError};
    use whipplescript_parser::action_plan::ActionPlan;

    pub(super) fn project(f: &Fixture, plan: &ActionPlan) -> Progression {
        project_with_inputs(f, plan, &Bindings::new())
    }
    pub(super) fn project_with_inputs(
        f: &Fixture,
        plan: &ActionPlan,
        inputs: &Bindings,
    ) -> Progression {
        project_cases(f, plan, inputs, None).expect("fixture progression succeeds")
    }
    pub(super) fn project_typed(
        f: &Fixture,
        typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ) -> Progression {
        try_project_typed(f, typed).expect("fixture progression succeeds")
    }
    pub(super) fn try_project_typed(
        f: &Fixture,
        typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ) -> Result<Progression, ProgressionError> {
        project_cases(f, &typed.plan, &Bindings::new(), Some(typed))
    }
    fn project_cases(
        f: &Fixture,
        plan: &ActionPlan,
        inputs: &Bindings,
        typed: Option<&whipplescript_parser::action_plan::resolved::TypedActionPlan>,
    ) -> Result<Progression, ProgressionError> {
        let events = f.events();
        let frontier = events.last().expect("fixture frontier exists").sequence;
        let prefix = f
            .kernel
            .store()
            .projection_prefix(&f.instance, frontier)
            .expect("fixture projection prefix readable");
        let effects = prefix.effects;
        let facts = prefix.facts;
        let project_statement = |statement: crate::source_action::progression::Statement<'_>| {
            if matches!(
                statement.body,
                whipplescript_parser::body::BodyStmt::Record(_)
                    | whipplescript_parser::body::BodyStmt::Done {
                        replacement: Some(_),
                        ..
                    }
            ) {
                crate::source_action::records::project(
                    statement,
                    crate::source_action::records::Context {
                        ir: &f.ir,
                        instance: &f.instance,
                        frame: &f.frame,
                        events: &events,
                        active: &facts,
                        source_path: None,
                    },
                )
            } else if matches!(
                statement.body,
                whipplescript_parser::body::BodyStmt::Done { .. }
            ) {
                crate::source_action::facts::project(statement, &f.frame, &facts)
            } else if matches!(statement.body,
                    whipplescript_parser::body::BodyStmt::Effect(effect)
                    if matches!(effect.kind, whipplescript_parser::body::BodyEffectKind::Tell { .. }))
            {
                crate::source_action::tell::project(
                    statement,
                    crate::source_action::tell::Context {
                        ir: &f.ir,
                        frame: &f.frame,
                        effects: &effects,
                        events: &events,
                        source_path: None,
                    },
                )
            } else if matches!(statement.body,
                    whipplescript_parser::body::BodyStmt::Effect(effect)
                    if matches!(effect.kind, whipplescript_parser::body::BodyEffectKind::Coerce { .. }))
            {
                crate::source_action::coerce::project(
                    statement,
                    crate::source_action::coerce::Context {
                        ir: &f.ir,
                        frame: &f.frame,
                        effects: &effects,
                        events: &events,
                        coercion_config_fingerprint: "fixture",
                        source_path: None,
                    },
                )
            } else {
                crate::source_action::timer::project(statement, &f.frame, &effects, &events, None)
            }
        };
        match typed {
            Some(typed) => {
                crate::source_action::rule::project(crate::source_action::rule::Context {
                    typed,
                    ir: &f.ir,
                    instance: &f.instance,
                    frame: &f.frame,
                    frontier,
                    admission: &f.context,
                    journal: &f.journal(),
                    effects: &effects,
                    events: &events,
                    facts: &facts,
                    coercion_fingerprint: "fixture",
                    source_path: None,
                })
            }
            None => advance(
                plan,
                &f.instance,
                &f.frame,
                frontier,
                inputs,
                &f.journal(),
                project_statement,
            ),
        }
    }
    pub(super) fn commit(
        f: &mut Fixture,
        progress: &Progression,
    ) -> whipplescript_store::StoredEvent {
        let journal = f.journal();
        commit_lowering(
            &mut f.kernel,
            &f.instance,
            &f.ir,
            &f.context,
            &f.frame,
            &progress.lowering,
            &journal,
            progress.frontier,
            RuleCommitRevisionGuard {
                evaluated_frontier: Some(progress.frontier),
                program_version_id: &f.frame.version,
                revision_epoch: 0,
            },
        )
        .expect("fixture progression succeeds")
    }
    pub(super) fn settle(f: &mut Fixture, effect: &str) {
        let report = crate::time_pass::resolve_due_time_effects(
            &mut f.kernel,
            &f.instance,
            "2099-01-01T00:00:00Z",
        )
        .expect("real time pass settles timer");
        assert_eq!(report.timers_fired, 1);
        let effects = f
            .kernel
            .store()
            .list_effects(&f.instance)
            .expect("fixture effects readable");
        assert_eq!(
            effects
                .iter()
                .find(|item| item.effect_id == effect)
                .expect("timer exists")
                .status,
            "completed"
        );
    }
}

#[test]
fn action_progression_native_after_scope_commits_reopens_and_joins_real_settlement() {
    use crate::source_action::Boundary;
    use timer_fixture::{commit, project, settle};
    use whipplescript_parser::{parse_program, Item};
    let source = "workflow Captures\naction child() -> int { timer 2s as inside\nreturn 2 }\naction root() -> int { timer 1s as start\nafter start succeeds { child() }\nreturn 1 }";
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty());
    let actions: Vec<_> = parsed
        .program
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action),
            _ => None,
        })
        .collect();
    let plan = whipplescript_parser::action_plan::expand_syntax(&actions, "root").unwrap();
    let path = std::env::temp_dir().join(format!(
        "whip-action-progression-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    let first = project(&f, &plan);
    assert!(matches!(first.root.boundary, Boundary::Waiting(_)));
    assert_eq!(first.lowering.effects.len(), 1);
    let start = first.lowering.effects[0].effect_id.clone();
    let admitted = commit(&mut f, &first);
    assert_eq!(commit(&mut f, &first).event_id, admitted.event_id);
    settle(&mut f, &start);
    let next = project(&f, &plan);
    assert!(matches!(next.root.boundary, Boundary::Waiting(_)));
    assert_eq!(next.lowering.action_captures.len(), 1);
    assert_eq!(next.lowering.effects.len(), 1);
    let child = next.lowering.effects[0].effect_id.clone();
    assert_ne!(start, child);
    commit(&mut f, &next);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut reopened = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let pending = project(&reopened, &plan);
    assert!(!pending.lowering.has_commit_work());
    assert!(matches!(pending.root.boundary, Boundary::Waiting(_)));
    settle(&mut reopened, &child);
    let done = project(&reopened, &plan);
    assert!(matches!(done.root.boundary, Boundary::Succeeded(())));
    assert!(!done.lowering.has_commit_work());
    assert_eq!(
        reopened
            .kernel
            .store()
            .list_effects(&reopened.instance)
            .unwrap()
            .len(),
        2
    );
    let facts = reopened
        .kernel
        .store()
        .list_facts(&reopened.instance)
        .unwrap();
    assert_eq!(facts.len(), 2);
    assert!(
        facts.iter().all(|fact| fact.name == "timer.fired"),
        "only time-pass settlement facts, no composition bridge facts"
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn action_timer_native_absolute_argument_uses_real_time_pass_and_unit_contract() {
    use crate::source_action::arguments::{Bindings, Slot};
    use crate::source_action::Boundary;
    use whipplescript_parser::{parse_program, Item};
    let parsed = parse_program("workflow Captures\naction root(deadline time) -> null { timer until deadline as waited\nreturn waited }");
    assert!(parsed.diagnostics.is_empty());
    let actions: Vec<_> = parsed
        .program
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action),
            _ => None,
        })
        .collect();
    let plan = whipplescript_parser::action_plan::expand_syntax(&actions, "root").unwrap();
    let inputs = Bindings::from([(
        plan.root_inputs[0],
        Slot::Ready(json!("2035-01-01T00:00:00Z").into()),
    )]);
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    let first = timer_fixture::project_with_inputs(&f, &plan, &inputs);
    assert_eq!(first.lowering.effects.len(), 1);
    assert!(matches!(first.root.boundary, Boundary::Waiting(_)));
    let effect = first.lowering.effects[0].effect_id.clone();
    timer_fixture::commit(&mut f, &first);
    let before = crate::time_pass::resolve_due_time_effects(
        &mut f.kernel,
        &f.instance,
        "2034-12-31T23:59:59Z",
    )
    .unwrap();
    assert_eq!(before.timers_fired, 0);
    let replay = timer_fixture::project(&f, &plan);
    assert!(!replay.lowering.has_commit_work());
    assert!(matches!(replay.root.boundary, Boundary::Waiting(_)));
    let due = crate::time_pass::resolve_due_time_effects(
        &mut f.kernel,
        &f.instance,
        "2035-01-01T00:00:00Z",
    )
    .unwrap();
    assert_eq!(due.timers_fired, 1);
    let done = timer_fixture::project(&f, &plan);
    assert!(matches!(done.root.boundary, Boundary::Succeeded(())));
    assert!(!done.lowering.has_commit_work());
    let Boundary::Succeeded(value) =
        &done.scopes[&whipplescript_parser::action_plan::ScopeId(0)].boundary
    else {
        panic!("timer's unit result must reach action return");
    };
    assert_eq!(value.value, Value::Null);
    assert!(value
        .sources
        .contains(&crate::source_action::arguments::ValueSource::Operation {
            operation_id: effect.clone()
        }));
    let events = f.events();
    let terminal = events
        .iter()
        .find(|event| event.event_id == due.terminal_events[0])
        .unwrap();
    let payload: Value = serde_json::from_str(&terminal.payload_json).unwrap();
    assert_eq!(payload["effect_id"], effect);
    assert!(
        payload["metadata"].get("value").is_none(),
        "the actual timer contract has no provider output value"
    );
    assert_eq!(
        crate::time_pass::resolve_due_time_effects(
            &mut f.kernel,
            &f.instance,
            "2036-01-01T00:00:00Z"
        )
        .unwrap()
        .timers_fired,
        0
    );
    assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 1);
}

fn effect() -> OwnedEffect {
    OwnedEffect {
        effect_id: "owned-effect".into(),
        kind: "timer.wait".into(),
        target: None,
        input_json: "{}".into(),
        status: "queued".into(),
        idempotency_key: "owned-effect-key".into(),
        required_capabilities_json: "[]".into(),
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: None,
    }
}

#[test]
fn action_capture_conflict_refuses_before_any_external_work_is_committed() {
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    let mut lowering = OwnedLowering {
        action_captures: vec![f.capture(1)],
        ..Default::default()
    };
    f.commit(&lowering, &Journal::default()).unwrap();
    let before = f.events();
    lowering.action_captures[0].arguments[0] = json!("changed").into();
    lowering.effects.push(effect());
    let error = f.commit(&lowering, &f.journal()).unwrap_err();
    assert!(format!("{error:?}").contains("captured differently"));
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
}

#[test]
fn action_capture_overlapping_writers_cannot_commit_different_arguments() {
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    let first = f.capture(1);
    let frontier = first.frontier;
    let mut competing = first.clone();
    competing.arguments[0] = json!("second writer").into();
    let losing = OwnedLowering {
        action_captures: vec![competing, f.capture(2)],
        effects: vec![effect()],
        ..Default::default()
    };
    f.commit(
        &OwnedLowering {
            action_captures: vec![first.clone()],
            ..Default::default()
        },
        &Journal::default(),
    )
    .unwrap();
    let before = f.events();
    let error = commit_lowering(
        &mut f.kernel,
        &f.instance,
        &f.ir,
        &f.context,
        &f.frame,
        &losing,
        &Journal::default(),
        frontier,
        RuleCommitRevisionGuard {
            program_version_id: &f.frame.version,
            revision_epoch: 0,
            evaluated_frontier: None,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        whipplescript_store::StoreError::GuardRefused { .. }
    ));
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
    let journal = f.journal();
    assert_eq!(journal.calls(&f.frame).unwrap().len(), 1);
    assert_eq!(journal.calls(&f.frame).unwrap()[&1], first);
}

#[test]
fn action_capture_and_effect_share_the_revision_guard_and_commit() {
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    let lowering = OwnedLowering {
        action_captures: vec![f.capture(1)],
        effects: vec![effect()],
        ..Default::default()
    };
    let before = f.events();
    let error = commit_lowering(
        &mut f.kernel,
        &f.instance,
        &f.ir,
        &f.context,
        &f.frame,
        &lowering,
        &Journal::default(),
        before.last().unwrap().sequence,
        RuleCommitRevisionGuard {
            evaluated_frontier: None,
            program_version_id: &f.frame.version,
            revision_epoch: 99,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        whipplescript_store::StoreError::Conflict(_)
    ));
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
    let committed = f.commit(&lowering, &Journal::default()).unwrap();
    let record = f
        .events()
        .into_iter()
        .find(|e| e.event_id == committed.event_id)
        .unwrap();
    let payload: Value = serde_json::from_str(&record.payload_json).unwrap();
    assert_eq!(payload["context"][FIELD]["calls"][0]["call"], json!(1));
    assert_eq!(payload["effects"][0]["effect_id"], json!("owned-effect"));
    assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 1);
}

#[test]
fn action_capture_corruption_stops_the_real_rule_pass_but_discarded_history_does_not() {
    for field in [FIELD, "action_root"] {
        let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
        let keep = f.events().last().unwrap().sequence;
        let mut bad_context: Value =
            serde_json::from_str(&context_record_json(&f.context)).unwrap();
        bad_context[field] = Value::Null;
        f.kernel
            .commit_rule(RuleCommit {
                instance_id: &f.instance,
                rule: &f.frame.rule,
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("malformed-capture-test"),
                marks: &[],
                context_json: Some(&bad_context.to_string()),
            })
            .unwrap();
        let before = f.events().len();
        let error =
            step_instance_generic(&mut f.kernel, &f.instance, &f.ir, None, None).unwrap_err();
        assert!(format!("{error:?}").contains("malformed action"));
        assert_eq!(f.events().len(), before);
        f.kernel
            .store_mut()
            .append_event(NewEvent {
                instance_id: &f.instance,
                event_type: "context.restored",
                payload_json: &json!({"restored_to_sequence": keep}).to_string(),
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("restore-capture-test"),
            })
            .unwrap();
        let report = step_instance_generic(&mut f.kernel, &f.instance, &f.ir, None, None).unwrap();
        assert_eq!(report.committed_rules, 1);
    }
}

#[test]
fn action_root_native_delayed_first_read_after_reopen_keeps_admitted_fact_and_event() {
    use crate::source_action::arguments::Bindings;
    use crate::source_action::journal::root::admitted_rule_inputs;
    use crate::source_action::Boundary;
    use whipplescript_parser::{parse_program, Ident, Item};
    let source = "workflow Captures\nclass Ticket { title string }\naction title(ticket Ticket) -> string { return ticket.title }\nrule finish when Ticket as ticket => { timer 1s as delay\nafter delay succeeds { title(ticket) as title } }";
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty());
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    let plan = whipplescript_parser::action_plan::expand_rule_syntax(
        &actions,
        rule,
        &[Ident {
            name: "ticket".into(),
            span: rule.whens[0].span,
        }],
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "whip-action-root-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "ticket",
            r#"{"title":"original"}"#,
            None,
            Some("original"),
        )
        .unwrap();
    let original = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Ticket")
        .unwrap();
    f.context.bindings.push(("ticket".into(), original.clone()));
    f.context.trigger_event_id = Some(original.source_event_id.clone());
    f.frame.trigger_event = Some(original.source_event_id.clone());
    let frontier = f.events().last().unwrap().sequence;
    let inputs = admitted_rule_inputs(&plan, &f.context, frontier).unwrap();
    let first = timer_fixture::project_with_inputs(&f, &plan, &inputs);
    assert!(
        first.lowering.action_captures.is_empty(),
        "the first call has not been reached"
    );
    assert!(first.lowering.action_root.is_some());
    assert_eq!(first.lowering.effects.len(), 1);
    let delay = first.lowering.effects[0].effect_id.clone();
    let committed = timer_fixture::commit(&mut f, &first);
    let record = f
        .events()
        .into_iter()
        .find(|event| event.event_id == committed.event_id)
        .unwrap();
    let payload: Value = serde_json::from_str(&record.payload_json).unwrap();
    let restored_context = crate::rule_lowering::context_from_record(&payload["context"]).unwrap();
    assert!(
        restored_context.bindings[0].1.source_event_id.is_empty(),
        "historical context shape is unchanged"
    );
    let replacement = crate::lowering::OwnedFact {
        fact_id: "replacement-ticket".into(),
        name: "Ticket".into(),
        key: "ticket-next-generation".into(),
        value_json: r#"{"title":"newer"}"#.into(),
        schema_id: None,
        provenance_class: "external".into(),
        correlation_id: None,
        source_span_json: None,
        validity_json: None,
    };
    f.kernel
        .commit_rule(RuleCommit {
            instance_id: &f.instance,
            rule: "replace_ticket",
            trigger_event_id: None,
            facts: &[replacement.as_new_fact()],
            consumed_fact_ids: &[&original.fact_id],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("replace-ticket"),
            marks: &[],
            context_json: None,
        })
        .unwrap();
    let current = f.kernel.store().list_facts(&f.instance).unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].fact_id, replacement.fact_id);
    assert_ne!(current[0].source_event_id, original.source_event_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        ..
    } = f;
    drop(kernel);
    let mut reopened = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context: restored_context,
    };
    assert!(
        admitted_rule_inputs(
            &plan,
            &reopened.context,
            reopened.events().last().unwrap().sequence,
        )
        .is_err(),
        "legacy reconstruction cannot invent the missing admission"
    );
    let waiting = timer_fixture::project_with_inputs(&reopened, &plan, &Bindings::new());
    assert!(!waiting.lowering.has_commit_work());
    assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
    timer_fixture::settle(&mut reopened, &delay);
    let done = timer_fixture::project_with_inputs(&reopened, &plan, &Bindings::new());
    assert!(done.lowering.action_root.is_none());
    assert_eq!(done.lowering.action_captures.len(), 1);
    let argument = &done.lowering.action_captures[0].arguments[0];
    assert_eq!(argument.value, json!({"title":"original"}));
    assert_eq!(
        argument.sources,
        BTreeSet::from([crate::source_action::arguments::ValueSource::Fact {
            fact_id: original.fact_id,
            admission_event: original.source_event_id
        }])
    );
    assert!(matches!(done.root.boundary, Boundary::Succeeded(())));
    timer_fixture::commit(&mut reopened, &done);
    let replay = timer_fixture::project_with_inputs(&reopened, &plan, &Bindings::new());
    assert!(!replay.lowering.has_commit_work());
    assert_eq!(replay.scopes, done.scopes);
    assert_eq!(
        reopened
            .kernel
            .store()
            .list_effects(&reopened.instance)
            .unwrap()
            .len(),
        1
    );
    let active = reopened
        .kernel
        .store()
        .list_facts(&reopened.instance)
        .unwrap();
    assert_eq!(
        active.len(),
        2,
        "the current input and actual timer settlement exist"
    );
    assert_eq!(
        active
            .iter()
            .filter(|fact| fact.name == "timer.fired")
            .count(),
        1
    );
    let current = active.iter().find(|fact| fact.name == "Ticket").unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&current.value_json).unwrap(),
        json!({"title":"newer"})
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn action_root_only_commit_uses_the_atomic_frontier_guard_and_exact_replay() {
    use crate::source_action::journal::root::RootCapture;
    fn commit_at(
        f: &mut Fixture,
        lowering: &OwnedLowering,
        frontier: i64,
    ) -> Result<whipplescript_store::StoredEvent, whipplescript_store::StoreError> {
        let journal = f.journal();
        commit_lowering(
            &mut f.kernel,
            &f.instance,
            &f.ir,
            &f.context,
            &f.frame,
            lowering,
            &journal,
            frontier,
            RuleCommitRevisionGuard {
                evaluated_frontier: None,
                program_version_id: &f.frame.version,
                revision_epoch: 0,
            },
        )
    }
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    let frontier = f.events().last().unwrap().sequence;
    let first = OwnedLowering {
        action_root: Some(RootCapture {
            inputs: vec![],
            frontier,
        }),
        ..Default::default()
    };
    f.kernel
        .ingest_external_event(&f.instance, "external.later", "{}", Some("later"))
        .unwrap();
    let before = f.events();
    let error = commit_at(&mut f, &first, frontier).unwrap_err();
    assert!(matches!(
        error,
        whipplescript_store::StoreError::GuardRefused { .. }
    ));
    assert_eq!(
        f.events(),
        before,
        "stale root-only admission appends nothing"
    );
    let frontier = f.events().last().unwrap().sequence;
    let current = OwnedLowering {
        action_root: Some(RootCapture {
            inputs: vec![],
            frontier,
        }),
        ..Default::default()
    };
    let committed = commit_at(&mut f, &current, frontier).unwrap();
    f.kernel
        .ingest_external_event(&f.instance, "external.more", "{}", Some("more"))
        .unwrap();
    assert_eq!(
        commit_at(&mut f, &current, frontier).unwrap().event_id,
        committed.event_id
    );
    let before = f.events();
    let frontier = before.last().unwrap().sequence;
    let changed = OwnedLowering {
        action_root: Some(RootCapture {
            inputs: vec![],
            frontier,
        }),
        ..Default::default()
    };
    let error = commit_at(&mut f, &changed, frontier).unwrap_err();
    assert!(format!("{error:?}").contains("captured differently"));
    assert_eq!(
        f.events(),
        before,
        "an immutable-root conflict cannot append a corrupt delta"
    );
    assert!(f.kernel.store().list_facts(&f.instance).unwrap().is_empty());
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
}

#[test]
fn action_fact_subject_native_nested_done_reopens_guards_and_spares_revival() {
    use crate::source_action::journal::root::admitted_rule_inputs;
    use crate::source_action::Boundary;
    use whipplescript_parser::{parse_program, Ident, Item};
    let parsed = parse_program("workflow Captures\nclass Ticket { title string }\nclass Box { ticket Ticket }\naction box(ticket Ticket) -> Box { return {ticket ticket} }\naction finish(ticket Ticket?) -> null { case ticket { Some as original => { done original\nreturn null } None => { return null } } }\nrule finish when Ticket as ticket => { box(ticket) as bundle\ntimer 1s as delay\nafter delay succeeds { finish(bundle.ticket) as first\nfinish(bundle.ticket) as second } }");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    let plan = whipplescript_parser::action_plan::expand_rule_syntax(
        &actions,
        rule,
        &[Ident {
            name: "ticket".into(),
            span: rule.whens[0].span,
        }],
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "whip-action-subject-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "ticket",
            r#"{"title":"original"}"#,
            None,
            Some("admit-original"),
        )
        .unwrap();
    let original = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Ticket")
        .unwrap();
    f.context.bindings.push(("ticket".into(), original.clone()));
    f.context.trigger_event_id = Some(original.source_event_id.clone());
    f.frame.trigger_event = Some(original.source_event_id.clone());
    let frontier = f.events().last().unwrap().sequence;
    let inputs = admitted_rule_inputs(&plan, &f.context, frontier).unwrap();
    let first = timer_fixture::project_with_inputs(&f, &plan, &inputs);
    assert!(matches!(first.root.boundary, Boundary::Waiting(_)));
    assert_eq!(first.lowering.action_captures.len(), 1);
    assert!(first.lowering.consumed_fact_ids.is_empty());
    let delay = first.lowering.effects[0].effect_id.clone();
    let committed = timer_fixture::commit(&mut f, &first);
    let record = f
        .events()
        .into_iter()
        .find(|event| event.event_id == committed.event_id)
        .unwrap();
    let payload: Value = serde_json::from_str(&record.payload_json).unwrap();
    let restored_context = crate::rule_lowering::context_from_record(&payload["context"]).unwrap();
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        ..
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context: restored_context,
    };
    assert!(!timer_fixture::project(&f, &plan).lowering.has_commit_work());
    timer_fixture::settle(&mut f, &delay);
    let ready = timer_fixture::project(&f, &plan);
    assert!(matches!(ready.root.boundary, Boundary::Succeeded(())));
    assert_eq!(
        ready.lowering.consumed_fact_ids,
        std::slice::from_ref(&original.fact_id),
        "two aliases compose into one atomic consumption"
    );
    assert_eq!(ready.lowering.action_captures.len(), 2);
    for call in &ready.lowering.action_captures {
        assert_eq!(call.arguments[0].value, json!({"title":"original"}));
        let subject = &call.arguments[0].subjects[""];
        assert_eq!(subject.fact_id, original.fact_id);
        assert_eq!(subject.admission_event, original.source_event_id);
    }
    f.kernel
        .ingest_external_event(&f.instance, "external.concurrent", "{}", Some("concurrent"))
        .unwrap();
    let before = f.events();
    let journal = f.journal();
    let error = commit_lowering(
        &mut f.kernel,
        &f.instance,
        &f.ir,
        &f.context,
        &f.frame,
        &ready.lowering,
        &journal,
        ready.frontier,
        RuleCommitRevisionGuard {
            evaluated_frontier: Some(ready.frontier),
            program_version_id: &f.frame.version,
            revision_epoch: 0,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        whipplescript_store::StoreError::GuardRefused { .. }
    ));
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .contains(&original));
    let current = timer_fixture::project(&f, &plan);
    timer_fixture::commit(&mut f, &current);
    assert!(!f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .iter()
        .any(|fact| fact.fact_id == original.fact_id));
    let replay = timer_fixture::project(&f, &plan);
    assert!(!replay.lowering.has_commit_work());
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "ticket",
            r#"{"title":"original"}"#,
            None,
            Some("admit-revival"),
        )
        .unwrap();
    let revived = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Ticket")
        .unwrap();
    assert_eq!(revived.fact_id, original.fact_id);
    assert_eq!(revived.value_json, original.value_json);
    assert_ne!(revived.source_event_id, original.source_event_id);
    let before = f.events();
    let replay = timer_fixture::project(&f, &plan);
    assert!(
        !replay.lowering.has_commit_work(),
        "old firing cannot consume revival"
    );
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .contains(&revived));
    let facts = f.kernel.store().list_facts(&f.instance).unwrap();
    assert_eq!(facts.len(), 2);
    assert!(
        facts
            .iter()
            .all(|fact| fact.name == "Ticket" || fact.name == "timer.fired"),
        "composition introduces no bridge facts"
    );
    drop(f);
    std::fs::remove_file(path).unwrap();
}

fn record_plan(source: &str, inputs: &[&str]) -> whipplescript_parser::action_plan::ActionPlan {
    use whipplescript_parser::{parse_program, Ident, Item};
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .expect("record fixture has a calling rule");
    whipplescript_parser::action_plan::expand_rule_syntax(
        &actions,
        rule,
        &inputs
            .iter()
            .map(|name| Ident {
                name: (*name).into(),
                span: rule.whens[0].span,
            })
            .collect::<Vec<_>>(),
    )
    .expect("record fixture expands")
}
fn consume_record(f: &mut Fixture, fact: &str) {
    f.kernel
        .commit_rule(RuleCommit {
            instance_id: &f.instance,
            rule: "consume-output",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[fact],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: None,
            marks: &[],
            context_json: None,
        })
        .expect("record fixture consumes its output");
}

#[test]
fn managed_record_native_helper_data_reopens_guards_and_preserves_assertion_receipts() {
    use crate::source_action::Boundary;
    use timer_fixture::{commit, project, settle};
    let plan=record_plan("workflow Captures\nclass Result { ok bool }\naction build() -> Result { timer 1s as wait\nreturn {ok true} }\naction save() -> null { build() as value\nrecord Result from value { }\nrecord Result from value { }\nreturn null }\nrule finish when started => { save() }",&[]);
    let path = std::env::temp_dir().join(format!(
        "whip-managed-record-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    let first = project(&f, &plan);
    assert!(first.lowering.facts.is_empty());
    assert_eq!(first.lowering.action_captures.len(), 2);
    let timer = first.lowering.effects[0].effect_id.clone();
    commit(&mut f, &first);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    assert!(!project(&f, &plan).lowering.has_commit_work());
    settle(&mut f, &timer);
    let ready = project(&f, &plan);
    assert!(matches!(ready.root.boundary, Boundary::Succeeded(())));
    assert!(ready.lowering.action_root.is_none());
    assert!(ready.lowering.action_captures.is_empty());
    assert_eq!(
        ready.lowering.facts.len(),
        1,
        "equal sibling constructions coalesce"
    );
    let output = ready.lowering.facts[0].fact_id.clone();
    f.kernel
        .ingest_external_event(&f.instance, "external.noise", "{}", Some("noise"))
        .unwrap();
    let before = f.events();
    let journal = f.journal();
    let error = commit_lowering(
        &mut f.kernel,
        &f.instance,
        &f.ir,
        &f.context,
        &f.frame,
        &ready.lowering,
        &journal,
        ready.frontier,
        RuleCommitRevisionGuard {
            evaluated_frontier: Some(ready.frontier),
            program_version_id: &f.frame.version,
            revision_epoch: 0,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        whipplescript_store::StoreError::GuardRefused { .. }
    ));
    assert_eq!(f.events(), before);
    let ready = project(&f, &plan);
    let asserted = commit(&mut f, &ready);
    let event = f
        .events()
        .into_iter()
        .find(|event| event.event_id == asserted.event_id)
        .unwrap();
    let body: Value = serde_json::from_str(&event.payload_json).unwrap();
    assert!(body["context"].get("action_root").is_none());
    assert!(body["context"].get("action_captures").is_none());
    assert_eq!(body["facts"].as_array().unwrap().len(), 1);
    assert!(!project(&f, &plan).lowering.has_commit_work());
    consume_record(&mut f, &output);
    assert!(
        !project(&f, &plan).lowering.has_commit_work(),
        "replay cannot revive consumed output"
    );
    // A distinct admitting event can reassert the content, and another firing
    // while it is live contributes evidence without creating another live row.
    for name in ["second", "third"] {
        let event = f
            .kernel
            .ingest_external_event(&f.instance, "external.started", "{}", Some(name))
            .unwrap();
        f.frame.trigger_event = Some(event.event_id.clone());
        f.context.trigger_event_id = Some(event.event_id);
        let start = project(&f, &plan);
        let timer = start.lowering.effects[0].effect_id.clone();
        assert!(start.lowering.facts.is_empty());
        commit(&mut f, &start);
        settle(&mut f, &timer);
        let next = project(&f, &plan);
        assert_eq!(next.lowering.facts[0].fact_id, output);
        commit(&mut f, &next);
        assert_eq!(
            f.kernel
                .store()
                .list_facts(&f.instance)
                .unwrap()
                .iter()
                .filter(|fact| fact.fact_id == output)
                .count(),
            1
        );
    }
    drop(f);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn managed_record_native_replacement_commits_payload_and_consumption_together() {
    use crate::source_action::journal::root::admitted_rule_inputs;
    use timer_fixture::{commit, project, project_with_inputs, settle};
    let plan=record_plan("workflow Captures\nclass Result { ok bool }\naction build() -> Result { timer 1s as wait\nreturn {ok false} }\naction replace(ticket Result) -> null { build() as value\ndone ticket -> record Result from value { }\nreturn null }\nrule finish when Result as ticket => { replace(ticket) }",&["ticket"]);
    let mut f = Fixture::new(SqliteStore::open_in_memory().unwrap());
    f.kernel
        .derive_fact(
            &f.instance,
            "Result",
            "original",
            r#"{"ok":true}"#,
            None,
            Some("original"),
        )
        .unwrap();
    let original = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Result")
        .unwrap();
    f.context.bindings.push(("ticket".into(), original.clone()));
    f.context.trigger_event_id = Some(original.source_event_id.clone());
    f.frame.trigger_event = Some(original.source_event_id.clone());
    let frontier = f.events().last().unwrap().sequence;
    let inputs = admitted_rule_inputs(&plan, &f.context, frontier).unwrap();
    let first = project_with_inputs(&f, &plan, &inputs);
    assert!(first.lowering.consumed_fact_ids.is_empty());
    assert!(first.lowering.facts.is_empty());
    let timer = first.lowering.effects[0].effect_id.clone();
    commit(&mut f, &first);
    assert!(f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .contains(&original));
    settle(&mut f, &timer);
    let ready = project(&f, &plan);
    assert!(ready.lowering.action_captures.is_empty());
    assert_eq!(
        ready.lowering.consumed_fact_ids,
        vec![original.fact_id.clone()]
    );
    assert_eq!(ready.lowering.facts.len(), 1);
    let output = ready.lowering.facts[0].fact_id.clone();
    assert_eq!(ready.lowering.facts[0].value_json, r#"{"ok":false}"#);
    let event = commit(&mut f, &ready);
    let payload: Value = serde_json::from_str(
        &f.events()
            .into_iter()
            .find(|item| item.event_id == event.event_id)
            .unwrap()
            .payload_json,
    )
    .unwrap();
    assert_eq!(payload["facts"][0]["fact_id"], output);
    assert_eq!(payload["consumed_facts"][0]["fact_id"], original.fact_id);
    assert!(!f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .contains(&original));
    consume_record(&mut f, &output);
    f.kernel
        .derive_fact(
            &f.instance,
            "Result",
            "original",
            r#"{"ok":true}"#,
            None,
            Some("revived"),
        )
        .unwrap();
    let revived = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Result")
        .unwrap();
    assert_eq!(revived.fact_id, original.fact_id);
    assert_ne!(revived.source_event_id, original.source_event_id);
    assert!(!project(&f, &plan).lowering.has_commit_work());
}

#[test]
fn managed_coerce_native_inline_and_nested_composition_reopens_without_bridge_facts() {
    use crate::coerce::{CoerceRequest, FakeCoerceClient};
    use crate::source_action::Boundary;
    use crate::CoerceExecution;
    const DECLARATIONS: &str = r#"
workflow Captures
output result Result
class Result { ok bool }
class Answer { text string }
coerce classify(first string, second string?) -> Answer {
  prompt "{{ first }} {{ second }} {{ ctx.output_format }}"
}
rule finish when started => { complete result { ok true } }
"#;
    for nested in [false, true] {
        let source = if nested {
            r#"
workflow Captures
action one(text string) -> Answer {
  coerce classify(text, null) as answer
  return answer
}
action pair() -> Answer {
  one("first") as a
  one("second") as b
  coerce classify(a.text, b.text) as joined
  return joined
}
rule finish when started => { pair() as result
record Answer { text result.text } }
"#
        } else {
            r#"
workflow Captures
rule finish when started => {
  coerce classify("first", null) as a
  coerce classify("second", null) as b
  coerce classify(a.text, b.text) as joined
  record Answer { text joined.text }
}
"#
        };
        let plan = record_plan(source, &[]);
        let path = std::env::temp_dir().join(format!(
            "managed-coerce-{}-{nested}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Component artifact alongside the fixture database. Production storage
        // still belongs to the eventual complete executable-program boundary.
        let plan_path = path.with_extension("plan.json");
        std::fs::write(
            &plan_path,
            crate::source_action::plan_artifact::encode(&plan).unwrap(),
        )
        .unwrap();
        let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), DECLARATIONS);
        let first = timer_fixture::project(&f, &plan);
        assert_eq!(
            first.lowering.effects.len(),
            2,
            "both independent coercions are eligible"
        );
        assert!(first.lowering.facts.is_empty());
        let arguments: BTreeSet<_> = first
            .lowering
            .effects
            .iter()
            .map(|effect| {
                serde_json::from_str::<Value>(&effect.input_json).unwrap()["arguments"]["arg0"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(arguments, BTreeSet::from(["first".into(), "second".into()]));
        timer_fixture::commit(&mut f, &first);
        let settle = |f: &mut Fixture, effect: &OwnedEffect, value: &str| {
            let input: Value = serde_json::from_str(&effect.input_json).unwrap();
            let request = CoerceRequest::with_evidence_hashes(
                input["function_name"].as_str().unwrap().into(),
                input["arguments"].to_string(),
                input["output_type"].as_str().unwrap().into(),
            );
            f.kernel
                .run_coerce(
                    CoerceExecution {
                        instance_id: &f.instance,
                        effect_id: &effect.effect_id,
                        run_id: &format!("run-{}", effect.effect_id),
                        provider: "fake-coerce",
                        worker_id: "fixture",
                        lease_id: &format!("lease-{}", effect.effect_id),
                        lease_expires_at: "2030-01-01T00:00:00Z",
                        request: &request,
                        model: None,
                    },
                    &FakeCoerceClient::succeeds(json!({"text":value}).to_string()),
                )
                .unwrap();
        };
        settle(&mut f, &first.lowering.effects[0], "left");
        let one_done = timer_fixture::project(&f, &plan);
        assert!(
            one_done.lowering.effects.is_empty(),
            "the join still owes the other value"
        );
        assert!(one_done.lowering.facts.is_empty());
        // Remove the ordinary result fact before reopen. The immutable result
        // event is sufficient for managed replay; no replacement bridge fact.
        let fact = f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .into_iter()
            .find(|fact| fact.name == "schema.coerce.succeeded")
            .unwrap();
        consume_record(&mut f, &fact.fact_id);
        let Fixture {
            kernel,
            ir,
            instance,
            frame,
            context,
        } = f;
        drop(kernel);
        drop(plan);
        let plan = crate::source_action::plan_artifact::decode(
            &std::fs::read_to_string(&plan_path).unwrap(),
        )
        .unwrap();
        std::fs::remove_file(plan_path).unwrap();
        let mut f = Fixture {
            kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
            ir,
            instance,
            frame,
            context,
        };
        let reopened = timer_fixture::project(&f, &plan);
        assert!(reopened.lowering.effects.is_empty());
        assert!(matches!(reopened.root.boundary, Boundary::Waiting(_)));
        settle(&mut f, &first.lowering.effects[1], "right");
        let joined = timer_fixture::project(&f, &plan);
        assert_eq!(joined.lowering.effects.len(), 1);
        let input: Value = serde_json::from_str(&joined.lowering.effects[0].input_json).unwrap();
        let joined_args: BTreeSet<_> = input["arguments"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(joined_args, BTreeSet::from(["left", "right"]));
        assert!(input["action_arguments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|arg| !arg["sources"].as_array().unwrap().is_empty()));
        timer_fixture::commit(&mut f, &joined);
        settle(&mut f, &joined.lowering.effects[0], "joined output");
        let done = timer_fixture::project(&f, &plan);
        assert_eq!(done.lowering.facts.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&done.lowering.facts[0].value_json).unwrap(),
            json!({"text":"joined output"})
        );
        timer_fixture::commit(&mut f, &done);
        let replay = timer_fixture::project(&f, &plan);
        assert!(matches!(replay.root.boundary, Boundary::Succeeded(())));
        assert!(!replay.lowering.has_commit_work());
        assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 3);
        let facts = f.kernel.store().list_facts(&f.instance).unwrap();
        assert!(facts
            .iter()
            .all(|fact| matches!(fact.name.as_str(), "Answer" | "schema.coerce.succeeded")));
        assert_eq!(facts.iter().filter(|fact| fact.name == "Answer").count(), 1);
        drop(f);
        std::fs::remove_file(path).unwrap();
    }
}

#[path = "native_recovery_tests.rs"]
mod native_recovery_tests;

#[path = "native_tell_tests.rs"]
mod native_tell_tests;

#[path = "native_terminal_tests.rs"]
mod native_terminal_tests;

#[path = "native_region_tests.rs"]
mod native_region_tests;

#[path = "native_prefix_tests.rs"]
mod native_prefix_tests;

#[path = "native_ownership_tests.rs"]
mod native_ownership_tests;

#[path = "native_region_projection_tests.rs"]
mod native_region_projection_tests;
