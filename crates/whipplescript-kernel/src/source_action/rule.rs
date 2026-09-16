//! One pure managed rule projection, shared by hosts. Compiler support and the
//! recorded executable version select this path; this is not another scheduler.
use super::arguments::QueryContext;
use super::{
    arguments::{Argument, Bindings},
    journal::{Frame, Journal},
    progression::{Leaf, Progression, ProgressionError, RetainedRegion, Statement},
    Boundary, ChosenResult, FailureKind, OwnedWork,
};
use crate::lowering::OwnedUnhandledFailure;
use crate::rule_lowering::RuleContext;
use std::{collections::BTreeMap, fmt, path::Path};
use whipplescript_parser::{
    action_plan::{resolved::TypedActionPlan, NodeId, NodeKind, ScopeId},
    body::{BodyEffectKind, BodyStmt},
    IrProgram,
};
use whipplescript_store::{
    projection_prefix::{ProjectionEffect, ProjectionFact, ProjectionPrefix},
    EventView, RuntimeStore, StoreError,
};

#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub typed: &'a TypedActionPlan,
    pub instance: &'a str,
    pub frame: &'a Frame,
    pub admission: &'a RuleContext,
    pub frontier: i64,
    pub journal: &'a Journal,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub facts: &'a [ProjectionFact],
    pub coercion_fingerprint: &'a str,
    pub source_path: Option<&'a Path>,
}

/// The stable inputs to a captured projection. The store supplies the event,
/// fact and effect views together at the requested frontier.
#[derive(Clone, Copy)]
pub struct StoredContext<'a> {
    pub ir: &'a IrProgram,
    pub typed: &'a TypedActionPlan,
    pub instance: &'a str,
    pub frame: &'a Frame,
    pub admission: &'a RuleContext,
    pub journal: &'a Journal,
    pub coercion_fingerprint: &'a str,
    pub source_path: Option<&'a Path>,
}

#[derive(Debug)]
pub enum StoredProjectionError {
    Store(StoreError),
    Projection(ProgressionError),
}

impl fmt::Display for StoredProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "store error: {error:?}"),
            Self::Projection(error) => write!(formatter, "projection error: {error:?}"),
        }
    }
}

impl std::error::Error for StoredProjectionError {}

impl From<StoreError> for StoredProjectionError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ProgressionError> for StoredProjectionError {
    fn from(error: ProgressionError) -> Self {
        Self::Projection(error)
    }
}

fn stored_context<'a>(context: StoredContext<'a>, prefix: &'a ProjectionPrefix) -> Context<'a> {
    Context {
        ir: context.ir,
        typed: context.typed,
        instance: context.instance,
        frame: context.frame,
        admission: context.admission,
        frontier: prefix.frontier,
        journal: context.journal,
        effects: &prefix.effects,
        events: &prefix.events,
        facts: &prefix.facts,
        coercion_fingerprint: context.coercion_fingerprint,
        source_path: context.source_path,
    }
}

/// One region's actual held selection at its last recorded holding/exit
/// frontier. The progression supplies bindings and located waits for views;
/// these maps make the owned boundary and retained result candidates explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldProjection {
    pub region: NodeId,
    pub frontier: i64,
    pub children: BTreeMap<NodeId, OwnedWork>,
    pub effects: BTreeMap<NodeId, OwnedWork>,
    pub results: BTreeMap<ScopeId, (NodeId, ChosenResult<Argument>)>,
    pub progression: Progression,
}

/// Project a previously admitted firing at a historical frontier. The caller supplies the
/// retained facts/effects at this same frontier, not today's materialized rows.
/// Journal publication can be later than evaluation, so select by the captures'
/// own coordinates. A recorded region cut, not an arbitrary historical query,
/// identifies the frontier used to admit held work. This pure result does not
/// authorize a new commit.
pub fn project_captured(c: Context<'_>) -> Result<Progression, ProgressionError> {
    project_captured_with_regions(c, false)
}

/// Read and project one exact historical prefix through the shared store
/// contract. This path is pure: it neither commits the draft nor mutates the
/// current materialized views.
pub fn project_captured_from_store<S: RuntimeStore>(
    store: &S,
    context: StoredContext<'_>,
    frontier: i64,
) -> Result<Progression, StoredProjectionError> {
    let prefix = store.projection_prefix(context.instance, frontier)?;
    Ok(project_captured(stored_context(context, &prefix))?)
}

/// Reconstruct one region's admitted held graph at the frontier named by its
/// durable cut. The caller supplies historical events, facts and effects for
/// that exact frontier. A lapse-at-entry has no held graph and returns `None`.
pub fn project_region_held(
    c: Context<'_>,
    region: NodeId,
) -> Result<Option<HeldProjection>, ProgressionError> {
    let frontier = match held_frontier(c.typed, c.journal, c.frame, region)? {
        Some(frontier) => frontier,
        None => return Ok(None),
    };
    let fail = |message: String| region_error(c.typed, region, message);
    let layout = super::regions::Layout::build(&c.typed.plan)
        .map_err(|issue| fail(format!("invalid region layout: {issue}")))?;
    let source_region = layout
        .region(region)
        .expect("held frontier validated the source region");
    if c.frontier != frontier {
        return Err(fail(format!(
            "held projection requires historical prefix {frontier}, got {}",
            c.frontier
        )));
    }
    let progression = project_captured_with_regions(c, true)?;
    let selected = source_region
        .held
        .selected_held(region, &progression)
        .map_err(|message| fail(message.into()))?;
    Ok(Some(HeldProjection {
        region,
        frontier,
        children: selected.children,
        effects: selected.effects,
        results: selected.results,
        progression,
    }))
}

/// Reconstruct a held region using the frontier recorded by its durable cut.
/// Callers cannot substitute a current or otherwise mismatched frontier.
pub fn project_region_held_from_store<S: RuntimeStore>(
    store: &S,
    context: StoredContext<'_>,
    region: NodeId,
) -> Result<Option<HeldProjection>, StoredProjectionError> {
    let Some(frontier) = held_frontier(context.typed, context.journal, context.frame, region)?
    else {
        return Ok(None);
    };
    let fail = |message: String| region_error(context.typed, region, message);
    let layout = super::regions::Layout::build(&context.typed.plan)
        .map_err(|issue| fail(format!("invalid region layout: {issue}")))?;
    let source_region = layout
        .region(region)
        .expect("held frontier validated the source region");
    let journal = context.journal.at_evaluation(frontier);
    let progression = project_captured_regions_from_store(
        store,
        StoredContext {
            journal: &journal,
            ..context
        },
        frontier,
    )?;
    let selected = source_region
        .held
        .selected_held(region, &progression)
        .map_err(|message| fail(message.into()))?;
    Ok(Some(HeldProjection {
        region,
        frontier,
        children: selected.children,
        effects: selected.effects,
        results: selected.results,
        progression,
    }))
}

fn region_error(typed: &TypedActionPlan, region: NodeId, message: String) -> ProgressionError {
    ProgressionError {
        node: region,
        span: typed.plan.nodes.get(region.0).map_or(
            whipplescript_parser::SourceSpan { start: 0, end: 0 },
            |node| node.span,
        ),
        message,
        evaluation: None,
    }
}

fn held_frontier(
    typed: &TypedActionPlan,
    journal: &Journal,
    frame: &Frame,
    region: NodeId,
) -> Result<Option<i64>, ProgressionError> {
    let fail = |message: String| region_error(typed, region, message);
    let layout = super::regions::Layout::build(&typed.plan)
        .map_err(|issue| fail(format!("invalid region layout: {issue}")))?;
    if layout.region(region).is_none() {
        return Err(fail("held projection target is not a source region".into()));
    }
    let Some(history) = journal.region(frame, region.0 as u64) else {
        return Err(fail(
            "held projection has no recorded region history".into(),
        ));
    };
    Ok(history.held_frontier())
}

fn project_captured_with_regions(
    c: Context<'_>,
    captured_regions: bool,
) -> Result<Progression, ProgressionError> {
    let fail = |message: &str| ProgressionError {
        node: NodeId(0),
        span: c.typed.plan.root_rule.as_ref().map_or(
            whipplescript_parser::SourceSpan { start: 0, end: 0 },
            |rule| rule.span,
        ),
        message: message.into(),
        evaluation: None,
    };
    if c.events.last().map_or(0, |event| event.sequence) != c.frontier
        || c.events
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        || c.events.iter().any(|event| event.sequence <= 0)
    {
        return Err(fail(
            "captured projection requires the ordered events at its frontier",
        ));
    }
    let journal = c.journal.at_evaluation(c.frontier);
    if journal.root(c.frame).is_none() {
        return Err(fail(
            "captured projection has no admitted root at its frontier",
        ));
    }
    project_with_regions(
        Context {
            journal: &journal,
            ..c
        },
        captured_regions,
    )
}

pub fn project(c: Context<'_>) -> Result<Progression, ProgressionError> {
    project_with_regions(c, false)
}

/// Project one live managed region step. A prospective phase cut is validated
/// in an isolated journal and the selected arm is reprojected at the same
/// frontier, so its drafts and the cut can pass through one guarded commit.
/// Context-only projection handles entry and holding transitions; callers that
/// may observe a later lapse use [`project_regions_from_store`] so the held
/// selection can be reconstructed from its recorded frontier.
pub fn project_regions(c: Context<'_>) -> Result<Progression, ProgressionError> {
    let current = project_with_regions(c, true)?;
    let cuts = super::regions::phase_cuts(&c.typed.plan, c.journal, c.frame, &current);
    if cuts.is_empty() {
        return Ok(current);
    }
    stage_region_cuts(c, current, cuts, &BTreeMap::new())
}

/// Store-backed live projection. A later lapse reconstructs membership and
/// result candidates at the last held cut, refreshes only that admitted work
/// from the current prefix, and then stages the lapse arm at today's frontier.
pub fn project_regions_from_store<S: RuntimeStore>(
    store: &S,
    context: StoredContext<'_>,
    frontier: i64,
) -> Result<Progression, StoredProjectionError> {
    let prefix = store.projection_prefix(context.instance, frontier)?;
    let c = stored_context(context, &prefix);
    let layout = super::regions::Layout::build(&c.typed.plan).map_err(|issue| {
        StoredProjectionError::Projection(region_error(
            c.typed,
            NodeId(0),
            format!("invalid region layout: {issue}"),
        ))
    })?;
    let mut retained = BTreeMap::new();
    let mut cancels = std::collections::BTreeSet::new();
    for (index, node) in c.typed.plan.nodes.iter().enumerate() {
        if !matches!(node.kind, NodeKind::Region { .. }) {
            continue;
        }
        let region = NodeId(index);
        let Some(history) = c.journal.region(c.frame, region.0 as u64) else {
            continue;
        };
        let Some(cut) = history
            .latest()
            .filter(|cut| cut.phase == super::journal::regions::Phase::Lapsed)
        else {
            continue;
        };
        if history.held_frontier().is_none() {
            continue;
        }
        let held = project_region_held_from_store(store, context, region)?
            .expect("later lapse has a held frontier");
        let progress = project_holding_at(store, context, region, cut.frontier)?;
        let refreshed = project_holding_at(store, context, region, frontier)?;
        for (node, historical) in &held.effects {
            let work = refreshed.owned.get(node).unwrap_or(historical);
            if work.state == super::WorkState::Pending {
                cancels.insert(super::progression::operation_identity(
                    c.instance, c.frame, *node,
                ));
            }
        }
        retained.insert(
            region,
            retain_region(&layout, &c.typed.plan, &held, &refreshed, &progress),
        );
    }
    let mut current = project_with_retained_regions(c, true, &retained)?;
    let cuts = super::regions::phase_cuts(&c.typed.plan, c.journal, c.frame, &current);
    if cuts.is_empty() {
        current.lowering.cancels.extend(cancels);
        return Ok(current);
    }
    for cut in &cuts {
        let region = NodeId(cut.region as usize);
        if cut.phase != super::journal::regions::Phase::Lapsed
            || c.journal
                .region(c.frame, cut.region)
                .and_then(|history| history.held_frontier())
                .is_none()
        {
            continue;
        }
        let held = project_region_held_from_store(store, context, region)?
            .expect("later lapse has a held frontier");
        for (node, historical) in &held.effects {
            let work = current.owned.get(node).unwrap_or(historical);
            if work.state == super::WorkState::Pending {
                cancels.insert(super::progression::operation_identity(
                    c.instance, c.frame, *node,
                ));
            }
        }
        retained.insert(
            region,
            retain_region(&layout, &c.typed.plan, &held, &current, &current),
        );
    }
    let mut advanced = stage_region_cuts(c, current, cuts, &retained)?;
    advanced.lowering.cancels.extend(cancels);
    Ok(advanced)
}

fn project_holding_at<S: RuntimeStore>(
    store: &S,
    context: StoredContext<'_>,
    region: NodeId,
    frontier: i64,
) -> Result<Progression, StoredProjectionError> {
    let held_frontier = context
        .journal
        .region(context.frame, region.0 as u64)
        .and_then(|history| history.held_frontier())
        .expect("holding projection requires a held frontier");
    let journal = context.journal.at_evaluation(held_frontier);
    project_captured_regions_from_store(
        store,
        StoredContext {
            journal: &journal,
            ..context
        },
        frontier,
    )
}

/// Project a captured journal selection while recursively reconstructing every
/// lapsed nested region visible in that selection. Each recursive step moves
/// to the region's earlier held cut, so an outer lapse can retain an inner
/// region that had already lapsed without reopening either region.
fn project_captured_regions_from_store<S: RuntimeStore>(
    store: &S,
    context: StoredContext<'_>,
    frontier: i64,
) -> Result<Progression, StoredProjectionError> {
    let prefix = store.projection_prefix(context.instance, frontier)?;
    let c = stored_context(context, &prefix);
    let journal = c.journal.at_evaluation(c.frontier);
    let captured = Context {
        journal: &journal,
        ..c
    };
    let layout = super::regions::Layout::build(&captured.typed.plan).map_err(|issue| {
        StoredProjectionError::Projection(region_error(
            captured.typed,
            NodeId(0),
            format!("invalid region layout: {issue}"),
        ))
    })?;
    let mut retained = BTreeMap::new();
    for (index, node) in captured.typed.plan.nodes.iter().enumerate() {
        if !matches!(node.kind, NodeKind::Region { .. }) {
            continue;
        }
        let region = NodeId(index);
        let Some(history) = captured.journal.region(captured.frame, region.0 as u64) else {
            continue;
        };
        let Some(cut) = history
            .latest()
            .filter(|cut| cut.phase == super::journal::regions::Phase::Lapsed)
        else {
            continue;
        };
        if history.held_frontier().is_none() {
            continue;
        }
        let stored = StoredContext {
            journal: captured.journal,
            ..context
        };
        let held = project_region_held_from_store(store, stored, region)?
            .expect("later lapse has a held frontier");
        let progress = project_holding_at(store, stored, region, cut.frontier)?;
        let refreshed = project_holding_at(store, stored, region, frontier)?;
        retained.insert(
            region,
            retain_region(&layout, &captured.typed.plan, &held, &refreshed, &progress),
        );
    }
    Ok(project_with_retained_regions(captured, true, &retained)?)
}

fn retain_region(
    layout: &super::regions::Layout,
    plan: &whipplescript_parser::action_plan::ActionPlan,
    held: &HeldProjection,
    refreshed: &Progression,
    progress: &Progression,
) -> RetainedRegion {
    let settled_after_lapse = |work: &OwnedWork| {
        let mut work = work.clone();
        if matches!(
            work.state,
            super::WorkState::Failed(super::Disposition::Propagate)
        ) && !work.causes.is_empty()
            && work
                .causes
                .values()
                .all(|cause| cause.cause.kind == FailureKind::Cancelled)
        {
            work.state = super::WorkState::Failed(super::Disposition::Recovered);
        }
        work
    };
    let progress_owned = held
        .children
        .iter()
        .map(|(node, historical)| {
            (
                *node,
                progress.owned.get(node).unwrap_or(historical).clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let owned = held
        .children
        .iter()
        .map(|(node, historical)| {
            (
                *node,
                settled_after_lapse(refreshed.owned.get(node).unwrap_or(historical)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    RetainedRegion {
        progress: layout
            .region(held.region)
            .expect("held projection names a source region")
            .held
            .progress(plan, &progress_owned, progress),
        owned,
        results: held.results.clone(),
    }
}

fn stage_region_cuts(
    c: Context<'_>,
    current: Progression,
    cuts: Vec<super::journal::regions::Cut>,
    retained: &BTreeMap<NodeId, RetainedRegion>,
) -> Result<Progression, ProgressionError> {
    let preview = c
        .journal
        .preview_regions(
            c.frame,
            &cuts,
            current.lowering.action_root.as_ref(),
            c.frontier,
        )
        .map_err(|issue| region_error(c.typed, NodeId(cuts[0].region as usize), issue.0))?;
    let mut advanced = project_with_retained_regions(
        Context {
            journal: &preview,
            ..c
        },
        true,
        retained,
    )?;
    let layout = super::regions::Layout::build(&c.typed.plan)
        .expect("region cuts were derived from this validated plan");
    for cut in cuts
        .iter()
        .filter(|cut| cut.phase == super::journal::regions::Phase::Lapsed)
    {
        let region = NodeId(cut.region as usize);
        let NodeKind::Region {
            until,
            condition,
            lapse_binding,
            ..
        } = &c.typed.plan.nodes[region.0].kind
        else {
            unreachable!("region cut names a validated region node")
        };
        let progress = lapse_binding
            .and_then(|binding| advanced.bindings.get(&binding))
            .and_then(|slot| match slot {
                super::arguments::Slot::Ready(value) => Some(value.clone()),
                _ => None,
            })
            .or_else(|| retained.get(&region).map(|held| held.progress.clone()))
            .unwrap_or_else(|| {
                layout
                    .region(region)
                    .expect("region cut names a source region")
                    .held
                    .empty_progress(&c.typed.plan)
            });
        let mut got = progress
            .value
            .as_object()
            .expect("compiler-owned region progress is an object")
            .clone();
        let steps = got
            .remove("steps")
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let fact_id = crate::idempotency_key(&[
            c.instance,
            "source-region-lapse-v1",
            &serde_json::to_string(c.frame).expect("frame serializes"),
            &region.0.to_string(),
        ]);
        advanced.lowering.facts.push(crate::lowering::OwnedFact {
            fact_id,
            name: "progression.region.lapsed".into(),
            key: format!(
                "{}:{}:{}",
                c.frame.rule,
                c.frame.identity.as_deref().unwrap_or("started"),
                region.0
            ),
            value_json: serde_json::json!({
                "rule": c.frame.rule,
                "region": region.0,
                "condition": condition,
                "until": until,
                "got": got,
                "steps": steps,
            })
            .to_string(),
            schema_id: None,
            provenance_class: "kernel".into(),
            correlation_id: c.frame.identity.clone(),
            source_span_json: None,
            validity_json: None,
        });
    }
    advanced.lowering.action_regions = cuts;
    Ok(advanced)
}

fn project_with_regions(
    c: Context<'_>,
    captured_regions: bool,
) -> Result<Progression, ProgressionError> {
    project_with_retained_regions(c, captured_regions, &BTreeMap::new())
}

fn project_with_retained_regions(
    c: Context<'_>,
    captured_regions: bool,
    retained_regions: &BTreeMap<NodeId, RetainedRegion>,
) -> Result<Progression, ProgressionError> {
    let plan = &c.typed.plan;
    let error = |node: usize, message: String| ProgressionError {
        node: NodeId(node),
        span: plan.nodes.get(node).map_or(
            whipplescript_parser::SourceSpan { start: 0, end: 0 },
            |node| node.span,
        ),
        message,
        evaluation: None,
    };
    c.typed
        .validate_structure()
        .map_err(|message| error(0, message))?;
    if plan.root_rule.as_ref().map(|rule| rule.name.as_str()) != Some(c.frame.rule.as_str())
        || c.admission.identity != c.frame.identity
        || c.admission.trigger_event_id != c.frame.trigger_event
        || !c.ir.rules.iter().any(|rule| rule.name == c.frame.rule)
    {
        return Err(error(
            0,
            "managed rule requires its pinned admission and declaration".into(),
        ));
    }
    for (index, node) in plan.nodes.iter().enumerate() {
        if let NodeKind::Statement(body) = &node.kind {
            let supported = match body.as_ref() {
                BodyStmt::Record(_)
                | BodyStmt::Done { .. }
                | BodyStmt::Terminal(_)
                | BodyStmt::Cancel { .. }
                | BodyStmt::Milestone { .. }
                | BodyStmt::Redact { .. }
                | BodyStmt::Declassify { .. } => true,
                BodyStmt::Effect(effect) => effect.kind.managed_execution_v1_supported(),
                _ => false,
            };
            if !supported {
                let source_name = match body.as_ref() {
                    BodyStmt::Effect(effect) => effect.kind.source_name(),
                    BodyStmt::After(_) => "after",
                    BodyStmt::Case(_) => "case",
                    BodyStmt::Region(_) => "during/until",
                    BodyStmt::Composition(_) => "composition",
                    _ => "statement",
                };
                return Err(error(
                    index,
                    format!(
                        "managed execution does not yet support `{source_name}` in typed composition"
                    ),
                ));
            }
        }
    }
    let inputs = if c.journal.root(c.frame).is_some() {
        Bindings::new()
    } else {
        super::journal::root::admitted_rule_inputs(plan, c.admission, c.frontier)
            .map_err(|issue| error(0, issue.0))?
    };
    let mut progression = super::progression::advance_typed_with_retained_regions(
        c.typed,
        c.ir,
        c.instance,
        c.frame,
        c.frontier,
        &inputs,
        c.journal,
        Some(QueryContext {
            frontier: c.frontier,
            facts: c.facts,
            effects: c.effects,
            views: &c.typed.views,
        }),
        captured_regions,
        retained_regions,
        |statement: Statement<'_>| match statement.body {
            BodyStmt::Record(_)
            | BodyStmt::Done {
                replacement: Some(_),
                ..
            } => super::records::project(
                statement,
                super::records::Context {
                    ir: c.ir,
                    instance: c.instance,
                    frame: c.frame,
                    events: c.events,
                    active: c.facts,
                    source_path: c.source_path,
                },
            ),
            BodyStmt::Done { .. } => super::facts::project(statement, c.frame, c.facts),
            BodyStmt::Terminal(_) => super::terminal::project(statement, c.ir, c.frame),
            BodyStmt::Milestone { .. } => super::milestone::project(
                statement,
                super::milestone::Context {
                    ir: c.ir,
                    instance: c.instance,
                    frame: c.frame,
                    events: c.events,
                    source_path: c.source_path,
                },
            ),
            BodyStmt::Redact { .. } | BodyStmt::Declassify { .. } => {
                super::transforms::project(statement, c.ir)
            }
            BodyStmt::Effect(effect) => {
                let checked = &c.typed.effects[&statement.node];
                if let Some(existing) = c
                    .effects
                    .iter()
                    .find(|effect| effect.effect_id == statement.identity)
                {
                    checked_target(checked, existing.target.as_deref())?;
                }
                let projected = match effect.kind {
                    BodyEffectKind::Tell { .. } => super::tell::project(
                        statement,
                        super::tell::Context {
                            ir: c.ir,
                            frame: c.frame,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::Coerce { .. } => super::coerce::project(
                        statement,
                        super::coerce::Context {
                            ir: c.ir,
                            frame: c.frame,
                            effects: c.effects,
                            events: c.events,
                            coercion_config_fingerprint: c.coercion_fingerprint,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::Prompt { .. } => super::inline_coerce::project_prompt(
                        statement,
                        super::inline_coerce::Context {
                            ir: c.ir,
                            frame: c.frame,
                            effects: c.effects,
                            events: c.events,
                            coercion_config_fingerprint: c.coercion_fingerprint,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::Decide { .. } => super::inline_coerce::project_decide(
                        statement,
                        super::inline_coerce::Context {
                            ir: c.ir,
                            frame: c.frame,
                            effects: c.effects,
                            events: c.events,
                            coercion_config_fingerprint: c.coercion_fingerprint,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::Exec { .. } => super::exec::project(
                        statement,
                        super::exec::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::FileRead { .. } => super::file::project_read(
                        statement,
                        super::file::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            facts: c.facts,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::FileWrite { .. } => super::file::project_write(
                        statement,
                        super::file::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            facts: c.facts,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::FileImport { .. } => super::file::project_import(
                        statement,
                        super::file::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            facts: c.facts,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::FileExport { .. } => super::file::project_export(
                        statement,
                        super::file::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            facts: c.facts,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::Notify { .. } => super::notify::project(
                        statement,
                        super::notify::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::CounterConsume { .. } => super::counter::project(
                        statement,
                        super::counter::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::LedgerAppend { .. } => super::ledger::project(
                        statement,
                        super::ledger::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::TrackerFile { .. } => super::tracker::project(
                        statement,
                        super::tracker::Context {
                            ir: c.ir,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    BodyEffectKind::TrackerClaim { .. }
                    | BodyEffectKind::TrackerRelease { .. }
                    | BodyEffectKind::TrackerFinish { .. } => super::tracker::lifecycle::project(
                        statement,
                        super::tracker::lifecycle::Context {
                            ir: c.ir,
                            typed: c.typed,
                            frame: c.frame,
                            frontier: c.frontier,
                            effects: c.effects,
                            events: c.events,
                            source_path: c.source_path,
                        },
                    ),
                    _ => super::timer::project(
                        statement,
                        c.frame,
                        c.effects,
                        c.events,
                        c.source_path,
                    ),
                }?;
                if let Leaf::Ready { lowering, .. } = &projected {
                    for effect in &lowering.effects {
                        checked_target(checked, effect.target.as_deref())?;
                    }
                }
                Ok(projected)
            }
            _ => unreachable!("managed statement preflight"),
        },
    )?;
    project_outer_failure(c.typed, c.ir, c.frame, &mut progression);
    Ok(progression)
}

fn project_outer_failure(
    typed: &TypedActionPlan,
    ir: &IrProgram,
    frame: &Frame,
    progression: &mut Progression,
) {
    if progression.lowering.terminal.is_some()
        || !matches!(progression.root.boundary, Boundary::Failed)
    {
        return;
    }
    let failures: Vec<_> = progression
        .root
        .causes
        .iter()
        .filter(|(_, cause)| !cause.recovered)
        .filter_map(|(origin, observed)| {
            let owner = progression
                .owned
                .iter()
                .find_map(|(node, work)| work.causes.contains_key(origin).then_some(*node));
            let direct_cancel = observed.cause.kind == FailureKind::Cancelled
                && owner.is_some_and(|node| {
                    matches!(
                        &typed.plan.nodes[node.0].kind,
                        NodeKind::Statement(statement)
                            if matches!(statement.as_ref(), BodyStmt::Effect(_))
                    )
                });
            (!direct_cancel).then_some((origin, observed, owner))
        })
        .collect();
    if failures.is_empty() {
        return;
    }
    if crate::rule_lowering::workflow_is_service(ir) {
        progression
            .lowering
            .unhandled_failures
            .extend(failures.into_iter().map(|(origin, observed, owner)| {
                let binding = owner
                    .and_then(|node| typed.plan.nodes[node.0].result)
                    .and_then(|binding| typed.plan.bindings[binding.0].name.clone())
                    .or_else(|| owner.map(|node| format!("operation-{}", node.0)))
                    .unwrap_or_else(|| "operation".into());
                OwnedUnhandledFailure {
                    rule: frame.rule.clone(),
                    binding,
                    effect_id: origin.0.clone(),
                    status: if observed.cause.kind == FailureKind::TimedOut {
                        "timed_out".into()
                    } else {
                        "failed".into()
                    },
                }
            }));
    } else {
        let origins = failures
            .iter()
            .map(|(origin, _, _)| origin.0.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        progression.lowering.internal_fail = Some(format!(
            "unhandled failure in rule `{}` from {origins}",
            frame.rule
        ));
    }
}

/// The authenticated compiler domain constrains both a new draft and a saved
/// operation. A currently declared agent is not necessarily a member of it.
fn checked_target(
    checked: &whipplescript_parser::action_plan::effects::Effect,
    target: Option<&str>,
) -> Result<(), String> {
    if checked.contract.agent.is_some()
        && !target.is_some_and(|target| {
            checked
                .agent_targets
                .as_ref()
                .is_some_and(|agents| agents.iter().any(|agent| agent == target))
        })
    {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("managed tell target is outside its checked agent domain".into());
    }
    Ok(())
}

#[cfg(test)]
mod outer_failure_tests {
    use super::*;
    use crate::source_action::{
        progression::advance, Cause, CauseId, Disposition, ObservedCause, WorkState,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use whipplescript_parser::compile_program;

    fn source(service: bool) -> String {
        format!(
            "{}workflow W\noutput result Result\nclass Result {{ ok bool }}\naction typed() -> null {{ return null }}\nrule run\nwhen started\n=> {{ timer 1s as primary\nafter primary succeeds {{ complete result {{ ok true }} }} }}",
            if service { "@service\n" } else { "" }
        )
    }

    fn failed(kind: FailureKind) -> Leaf {
        Leaf::Ready {
            lowering: Box::default(),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Failed(Disposition::Propagate),
                causes: BTreeMap::from([(
                    CauseId("effect-primary".into()),
                    ObservedCause {
                        cause: Cause {
                            kind,
                            payload: json!({"reason":"broken"}),
                            evidence: BTreeSet::from(["terminal-event".into()]),
                        },
                        recovered: false,
                    },
                )]),
            }),
        }
    }

    fn project_failure(service: bool, kind: FailureKind) -> Progression {
        let compiled = compile_program(&source(service));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.unwrap();
        let typed = compiled.typed_actions.unwrap().remove("run").unwrap();
        let frame = Frame {
            version: "v".into(),
            revision: "0".into(),
            rule: "run".into(),
            identity: None,
            trigger_event: None,
        };
        let mut progression = advance(
            &typed.plan,
            "instance",
            &frame,
            1,
            &Bindings::new(),
            &Journal::default(),
            |_| Ok(failed(kind.clone())),
        )
        .unwrap();
        project_outer_failure(&typed, &ir, &frame, &mut progression);
        progression
    }

    #[test]
    fn terminating_and_service_roots_keep_their_existing_outer_contract() {
        let terminating = project_failure(false, FailureKind::Failed);
        assert_eq!(
            terminating.lowering.internal_fail.as_deref(),
            Some("unhandled failure in rule `run` from effect-primary")
        );
        assert!(terminating.lowering.unhandled_failures.is_empty());

        let service = project_failure(true, FailureKind::TimedOut);
        assert!(service.lowering.internal_fail.is_none());
        assert_eq!(service.lowering.unhandled_failures.len(), 1);
        let diagnostic = &service.lowering.unhandled_failures[0];
        assert_eq!(diagnostic.rule, "run");
        assert_eq!(diagnostic.binding, "primary");
        assert_eq!(diagnostic.effect_id, "effect-primary");
        assert_eq!(diagnostic.status, "timed_out");
    }

    #[test]
    fn direct_deliberate_cancellation_does_not_enter_the_outer_failure_net() {
        for service in [false, true] {
            let cancelled = project_failure(service, FailureKind::Cancelled);
            assert!(cancelled.lowering.internal_fail.is_none());
            assert!(cancelled.lowering.unhandled_failures.is_empty());
        }
    }
}
