//! The rule-pass orchestration, lifted host-agnostic (DR-0033 chunk 4 groundwork).
//!
//! `step_instance_generic` drives the native `dev`-loop rule fixpoint
//! (project_tracker_issues + match/lower/commit) over ONE held `RuntimeKernel<S>`,
//! where `S` unifies the runtime / coordination / work-items surfaces (native
//! `NativeStores`; the DO's `DoSqliteStore`). This is the piece the instance step
//! machine drives; it lives in the wasm-clean kernel so the DO host can call it.
//! The native CLI keeps the thin `step_instance` wrapper that builds the handle.

#![allow(clippy::too_many_arguments)]

use std::path::Path;

use serde_json::{json, Value};
use whipplescript_core::Severity;
use whipplescript_parser::IrProgram;
use whipplescript_store::coordination::Coordination;
use whipplescript_store::items::WorkItems;
use whipplescript_store::{
    DiagnosticRecord, EffectCancellation, EffectCancellationRequest, EventView, RuleCommit,
    RuleCommitRevisionGuard, RuntimeStore, StoreError,
};

use crate::idempotency_key;
use crate::lowering::{
    BranchReport, OwnedDependency, OwnedEffect, OwnedFact, OwnedLowering, OwnedWorkflowTerminal,
};
use crate::rule_correspondence::{carries_from_json, translate_forward, RuleCarry};
use crate::rule_lowering::{
    context_from_record, context_record_json, json_from_str, lower_rule, ready_contexts_for,
    stable_hash_hex, GuardReport, RuleContext,
};
use crate::RuntimeKernel;

/// One operator-cancelled firing: the rule's name, the firing identity, and the
/// revision epoch the cancellation was recorded at. The epoch is what bounds a
/// carry translation, so that a carry given at a later revision cannot reach
/// backwards to a name recorded before it (DR-0077 Decision 5).
type CancelledFiring = (String, Option<String>, i64);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StepReport {
    pub instance_id: String,
    pub committed_rules: usize,
    pub facts_created: usize,
    pub facts_consumed: usize,
    pub effects_created: usize,
    pub guard_reports: Vec<GuardReport>,
    pub branch_reports: Vec<BranchReport>,
}

/// The host-agnostic rule pass (DR-0033 instance-scheduler lift): the fixpoint of
/// `project_tracker_issues` + rule matching/lowering/commit, run over ONE held store
/// handle instead of re-opening per operation. `S` unifies the runtime,
/// coordination, and work-items surfaces — natively `NativeStores`, on the DO the
/// one `DoSqliteStore`.
pub fn step_instance_generic<S: RuntimeStore + Coordination + WorkItems>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
    source_path: Option<&Path>,
    active_version_guard: Option<&str>,
) -> Result<StepReport, StoreError> {
    let mut report = StepReport {
        instance_id: instance_id.to_owned(),
        ..StepReport::default()
    };
    // Each round of the fixpoint below commits at most one rule and then
    // re-reads the whole event log, so the per-event payload derivations were
    // re-parsed once per commit. Event payloads are immutable — the store only
    // appends, or truncates a whole suffix, and neither can change what an
    // event id derives to — so each event is parsed once per pass and the
    // rounds reuse the derivation. The retention fold, the cancelled set and
    // the `seen` dedup still run per round: they depend on ordering and on the
    // restore markers, not only on the payload bytes.
    let mut restored_targets: std::collections::HashMap<String, Option<i64>> =
        std::collections::HashMap::new();
    let mut cancelled_keys: std::collections::HashMap<String, Option<(String, Option<String>)>> =
        std::collections::HashMap::new();
    let mut committed_firings: std::collections::HashMap<String, Option<RecordedFiring>> =
        std::collections::HashMap::new();
    let mut made_progress = true;
    while made_progress {
        made_progress = false;
        let status = kernel
            .store()
            .status(instance_id)?
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        if status.instance.status != "running" {
            break;
        }
        if let Some(active_version_guard) = active_version_guard {
            if status.instance.version_id != active_version_guard {
                return Err(StoreError::Conflict(format!(
                    "active version changed during step from {active_version_guard} to {}; rerun `whip step` with the active program",
                    status.instance.version_id
                )));
            }
        }
        let active_version_id = status.instance.version_id;
        let active_revision_epoch = status.instance.revision_epoch;
        project_tracker_issues(kernel, instance_id, ir)?;
        let events = kernel.store().list_events(instance_id)?;
        // Branch-distinct effect keys (versioned-workspace note §9.1, modeled
        // in branch-effect-key.maude): the branch/cut ref joins
        // program_version + revision_epoch in every derived idempotency key.
        // The ref has two axes read from the instance log itself (so the
        // derivation is host-agnostic): the branch the instance was born on
        // (the `branch.bound` event, absent = mainline) and the restore
        // lineage — each `context.restored` marker starts a new timeline
        // head, and a re-executed suffix must never dedupe against the
        // orphaned segment's effects. Unbound generation 0 keeps the
        // pre-branch key bytes, so every existing store derives unchanged
        // keys.
        let restore_generation = events
            .iter()
            .filter(|event| event.event_type == "context.restored")
            .count();
        let bound_branch = events
            .iter()
            .rev()
            .find(|event| event.event_type == "branch.bound")
            .and_then(|event| {
                serde_json::from_str::<Value>(&event.payload_json)
                    .ok()?
                    .get("branch_id")?
                    .as_str()
                    .map(str::to_owned)
            });
        let active_revision_epoch_key = revision_branch_key(
            active_revision_epoch,
            bound_branch.as_deref(),
            restore_generation,
        );
        let facts = kernel.store().list_facts(instance_id)?;
        let active_fact_ids: std::collections::BTreeSet<&str> =
            facts.iter().map(|fact| fact.fact_id.as_str()).collect();
        let all_facts = kernel.store().list_facts_including_consumed(instance_id)?;
        let effects = kernel.store().list_effects(instance_id)?;
        let started_event_id = events
            .iter()
            .find(|event| event.event_type == "external.started")
            .map(|event| event.event_id.clone());

        // DR-0043 slice 2 (pinned re-lowering): committed firings re-lower
        // from their RECORDED contexts -- bindings are values; matching gates
        // admission only, so a firing whose trigger was consumed or whose
        // projection retracted still completes its continuations. Restore
        // markers fold exactly as the store's replay fold does (an orphaned
        // timeline's firings are never re-applied); firings dedupe by
        // (rule, identity) against the live-match set below, so a
        // still-matching trigger contributes one context, not two.
        // DR-0077 Decisions 4 and 5. The chain of operator carries this
        // instance has been revised with, ascending by the epoch each one
        // activated to. Only carries are read -- never the derived
        // correspondence recorded beside them, which is evidence for an
        // operator and suppresses nothing on its own.
        let carry_chain: Vec<(i64, Vec<RuleCarry>)> = {
            let mut chain: Vec<(i64, Vec<RuleCarry>)> = kernel
                .store()
                .list_instance_revisions(instance_id)?
                .iter()
                .map(|revision| {
                    let carries = serde_json::from_str::<Value>(&revision.rule_carries_json)
                        .map(|value| carries_from_json(&value))
                        .unwrap_or_default();
                    (revision.epoch, carries)
                })
                .filter(|(_, carries)| !carries.is_empty())
                .collect();
            chain.sort_by_key(|(epoch, _)| *epoch);
            chain
        };
        let pass_head_sequence = events.last().map(|event| event.sequence).unwrap_or(0);
        let (recorded_firings, cancelled_firings): (Vec<RecordedFiring>, Vec<CancelledFiring>) = {
            let mut live: Vec<&EventView> = Vec::new();
            for event in &events {
                if event.event_type == "context.restored" {
                    if !restored_targets.contains_key(&event.event_id) {
                        restored_targets.insert(
                            event.event_id.clone(),
                            restored_target_from_payload(&event.payload_json),
                        );
                    }
                    if let Some(target) = restored_targets[&event.event_id] {
                        live.retain(|kept| kept.sequence <= target);
                    }
                } else {
                    live.push(event);
                }
            }
            let mut seen: std::collections::BTreeSet<(String, Option<String>)> =
                std::collections::BTreeSet::new();
            // Operator-cancelled firings (DR-0043 Decision 8): a
            // `progression.cancelled` closure removes the firing from the
            // derived open set — pinned re-lowering never advances it again,
            // and the lapse arm deliberately does not run.
            //
            // Each cancellation carries the epoch it was recorded at, because
            // translating it forward through the carry chain (below) must not
            // drag it through a carry that was given BEFORE it existed. The
            // epoch is folded from the activation events in the same order the
            // instance saw them.
            let mut cancelled: std::collections::BTreeSet<(String, Option<String>)> =
                std::collections::BTreeSet::new();
            let mut cancelled_at: Vec<CancelledFiring> = Vec::new();
            let mut epoch_here: i64 = 0;
            for event in &live {
                if event.event_type == "workflow.revision_activated" {
                    if let Some(to_epoch) = serde_json::from_str::<Value>(&event.payload_json)
                        .ok()
                        .and_then(|payload| payload.get("to_epoch").and_then(Value::as_i64))
                    {
                        epoch_here = to_epoch;
                    }
                    continue;
                }
                if event.event_type != "progression.cancelled" {
                    continue;
                }
                if !cancelled_keys.contains_key(&event.event_id) {
                    cancelled_keys.insert(
                        event.event_id.clone(),
                        cancelled_key_from_payload(&event.payload_json),
                    );
                }
                if let Some((rule, identity)) = cancelled_keys[&event.event_id].clone() {
                    cancelled.insert((rule.clone(), identity.clone()));
                    cancelled_at.push((rule, identity, epoch_here));
                }
            }
            let mut recorded = Vec::new();
            for event in live {
                if event.event_type != "rule.committed" {
                    continue;
                }
                if !committed_firings.contains_key(&event.event_id) {
                    committed_firings.insert(
                        event.event_id.clone(),
                        recorded_firing_from_payload(&event.payload_json),
                    );
                }
                let Some(firing) = committed_firings[&event.event_id].as_ref() else {
                    continue;
                };
                let key = (firing.rule.clone(), firing.context.identity.clone());
                if cancelled.contains(&key) {
                    continue;
                }
                if seen.insert(key) {
                    recorded.push(firing.clone());
                }
            }
            (recorded, cancelled_at)
        };
        // The `seen` dedup above admits at most one recorded firing per
        // (rule, identity), so keying by the (rule, identity, admission)
        // triple resolves exactly what a scan of `recorded_firings` would --
        // including the miss when the admitting event differs.
        let recorded_by_context: std::collections::HashMap<
            (&str, Option<&str>, Option<&str>),
            &RecordedFiring,
        > = recorded_firings
            .iter()
            .map(|firing| {
                (
                    (
                        firing.rule.as_str(),
                        firing.context.identity.as_deref(),
                        firing.context.trigger_event_id.as_deref(),
                    ),
                    firing,
                )
            })
            .collect();
        // DR-0077 Decision 4: BOTH name-keyed consumers translate. Leaving this
        // one alone would mean a carried rename silently UN-CANCELS an
        // operator-cancelled progression -- the same defect class in the
        // opposite direction, and the reason this record could not claim to
        // reconcile two notions of "the same rule" while a second consumer
        // still disagreed.
        let cancelled_identities: std::collections::BTreeSet<(String, Option<&str>)> =
            cancelled_firings
                .iter()
                .map(|(rule, identity, epoch)| {
                    (
                        translate_forward(rule, *epoch, &carry_chain),
                        identity.as_deref(),
                    )
                })
                .collect();

        // DR-0043 slice 3 (old-body completion): a firing admitted under an
        // earlier program version completes under THAT version's rule body,
        // with its admission-time epoch in every derived key -- the firing
        // owns its bindings AND its code. Sources are content-addressed
        // (`put_content` at version-creation/drive time; blob id ==
        // source_hash), so the old body is a store read + compile, cached per
        // pass. A missing blob (a version never driven since the pinning
        // surface landed) records one loud diagnostic and skips -- never a
        // silent stall, never a wrong-body lowering.
        let (active_recorded, old_recorded): (Vec<&RecordedFiring>, Vec<&RecordedFiring>) =
            recorded_firings.iter().partition(|firing| {
                firing.version_id.as_deref() == Some(active_version_id.as_str())
                    && firing.epoch == active_revision_epoch
                    || firing.version_id.is_none()
            });
        // A firing recorded under a name the operator has since carried is
        // matched against what the ACTIVE program calls that rule. With no
        // carry nothing moves and the renamed rule fires -- today's behaviour,
        // and the safe direction (DR-0077 I1s).
        let old_identity_set: std::collections::BTreeSet<(String, Option<&str>)> = old_recorded
            .iter()
            .map(|firing| {
                (
                    translate_forward(&firing.rule, firing.epoch, &carry_chain),
                    firing.context.identity.as_deref(),
                )
            })
            .collect();
        let mut old_irs: std::collections::BTreeMap<String, Option<IrProgram>> =
            std::collections::BTreeMap::new();
        for firing in &old_recorded {
            let Some(version_id) = firing.version_id.as_deref() else {
                continue;
            };
            if old_irs.contains_key(version_id) {
                continue;
            }
            let loaded = load_version_ir(kernel, instance_id, version_id)?;
            old_irs.insert(version_id.to_owned(), loaded);
        }

        struct LoweringGroup<'g> {
            ir: &'g IrProgram,
            rule_name: String,
            version_id: String,
            epoch_key: String,
            contexts: Vec<RuleContext>,
        }
        let mut groups: Vec<LoweringGroup> = Vec::new();
        for rule in &ir.rules {
            let own_actor = format!("instance:{instance_id}");
            let ready = ready_contexts_for(
                ir,
                rule,
                &facts,
                &effects,
                started_event_id.as_deref(),
                Some(&own_actor),
            );
            report.guard_reports.extend(ready.guard_reports);
            let mut contexts: Vec<RuleContext> = ready
                .contexts
                .into_iter()
                // A live match whose (rule, identity) belongs to an OLD
                // firing is the SAME firing (fact identity is admission
                // identity, DR-0043 Decision 4) -- it completes under its
                // old body below, never re-admits under the new one.
                .filter(|context| {
                    !old_identity_set.contains(&(rule.name.clone(), context.identity.as_deref()))
                })
                // A cancelled firing never re-admits: fact identity is
                // admission identity (Decision 4), so the same (rule,
                // identity) IS the cancelled firing, live match or not.
                .filter(|context| {
                    !cancelled_identities
                        .contains(&(rule.name.clone(), context.identity.as_deref()))
                })
                .collect();
            // Pinned firings (DR-0043 Decision 1): recorded contexts not
            // already present via live matching re-enter lowering here. The
            // recorded identity reproduces the admission identity, so every
            // derived effect key is byte-identical to the original firing's.
            for firing in &active_recorded {
                if firing.rule != rule.name {
                    continue;
                }
                // Dedup by (identity, admission): a live context with the
                // same identity but a FRESH admitting event is a new firing
                // (DR-0044 re-admission), not this recorded one.
                if contexts.iter().any(|context| {
                    context.identity == firing.context.identity
                        && context.trigger_event_id == firing.context.trigger_event_id
                }) {
                    continue;
                }
                contexts.push(firing.context.clone());
            }
            groups.push(LoweringGroup {
                ir,
                rule_name: rule.name.clone(),
                version_id: active_version_id.clone(),
                epoch_key: active_revision_epoch_key.clone(),
                contexts,
            });
        }
        for firing in &old_recorded {
            let Some(version_id) = firing.version_id.as_deref() else {
                continue;
            };
            let Some(Some(old_ir)) = old_irs.get(version_id) else {
                continue;
            };
            let epoch_key =
                revision_branch_key(firing.epoch, bound_branch.as_deref(), restore_generation);
            if let Some(group) = groups.iter_mut().find(|group| {
                group.rule_name == firing.rule
                    && group.version_id == version_id
                    && group.epoch_key == epoch_key
            }) {
                if !group.contexts.iter().any(|context| {
                    context.identity == firing.context.identity
                        && context.trigger_event_id == firing.context.trigger_event_id
                }) {
                    group.contexts.push(firing.context.clone());
                }
            } else {
                groups.push(LoweringGroup {
                    ir: old_ir,
                    rule_name: firing.rule.clone(),
                    version_id: version_id.to_owned(),
                    epoch_key,
                    contexts: vec![firing.context.clone()],
                });
            }
        }

        'rules: for group in groups {
            let ir = group.ir;
            let Some(rule) = ir
                .rules
                .iter()
                .find(|candidate| candidate.name == group.rule_name)
            else {
                continue;
            };
            for context in group.contexts {
                let mut lowering = lower_rule_with_region(
                    instance_id,
                    &group.version_id,
                    &group.epoch_key,
                    kernel.coercion_config_fingerprint(),
                    ir,
                    rule,
                    &context,
                    &facts,
                    &all_facts,
                    &effects,
                    source_path,
                    &active_fact_ids,
                );
                // Consumption is idempotent under pinned re-lowering
                // (DR-0043): a recorded firing re-lowers its own already-
                // committed `done` (or races a sibling's); a fact no longer
                // active is already consumed -- drop it BEFORE the emptiness
                // check, so an otherwise-empty re-lowering commits nothing.
                //
                // And consumption is ADMISSION-scoped (DR-0044): a fact
                // consumed and later re-recorded is live again under a fresh
                // admitting event. The re-admission belongs to a NEW firing —
                // a recorded firing re-lowering here must not consume it, so
                // a bound fact whose CURRENT admission is not among this
                // context's pinned admitting events is dropped too.
                let bound_ids: std::collections::BTreeSet<&str> = context
                    .bindings
                    .iter()
                    .map(|(_, fact)| fact.fact_id.as_str())
                    .collect();
                let admissions = context.trigger_event_id.as_deref();
                lowering.consumed_fact_ids.retain(|fact_id| {
                    if !active_fact_ids.contains(fact_id.as_str()) {
                        return false;
                    }
                    if !bound_ids.contains(fact_id.as_str()) {
                        return true;
                    }
                    let Some(current) = facts
                        .iter()
                        .find(|fact| &fact.fact_id == fact_id)
                        .map(|fact| fact.source_event_id.as_str())
                        .filter(|event| !event.is_empty())
                    else {
                        return true;
                    };
                    match admissions {
                        Some(trigger) => trigger.split('|').any(|event| event == current),
                        None => true,
                    }
                });
                // The fact-emission dual: a recorded firing's re-lowering
                // re-derives the facts its commit already recorded
                // (content-keyed, byte-identical ids). Suppress them so an
                // untouched replay lowers to EMPTY and commits nothing — a
                // since-consumed fact's revival belongs to a new firing.
                if let Some(recorded) = recorded_by_context.get(&(
                    rule.name.as_str(),
                    context.identity.as_deref(),
                    context.trigger_event_id.as_deref(),
                )) {
                    lowering
                        .facts
                        .retain(|fact| !recorded.fact_ids.contains(&fact.fact_id));
                }
                report
                    .branch_reports
                    .extend(lowering.branch_reports.iter().cloned());
                if !lowering.errors.is_empty() {
                    let message = format!(
                        "rule `{}` lowering failed: {}",
                        rule.name,
                        lowering.errors.join("; ")
                    );
                    kernel.store().record_diagnostic(DiagnosticRecord {
                        instance_id: Some(instance_id),
                        program_id: None,
                        program_version_id: Some(&group.version_id),
                        severity: Severity::Error,
                        code: Some("rule.lowering.unresolved"),
                        message: &message,
                        source_span_json: None,
                        subject_type: Some("rule"),
                        subject_id: Some(&rule.name),
                        event_id: None,
                        effect_id: None,
                        run_id: None,
                        assertion_id: None,
                        evidence_ids_json: "[]",
                        artifact_ids_json: "[]",
                        causation_id: context.trigger_event_id.as_deref(),
                        correlation_id: context.identity.as_deref(),
                        idempotency_key: Some(&idempotency_key(&[
                            instance_id,
                            &group.version_id,
                            &group.epoch_key,
                            &rule.name,
                            "lowering-error",
                            &lowering.errors.join("|"),
                        ])),
                    })?;
                    return Err(StoreError::Conflict(message));
                }
                // Auto-fail (R1) in a `@service` workflow: the service can never
                // auto-fail, so each unhandled effect failure the net observed is
                // recorded as a durable diagnostic — idempotent per effect (the
                // failure fact persists, so every later pass re-observes it) —
                // and the service keeps running. Recording is not progress.
                for unhandled in &lowering.unhandled_failures {
                    // A `then`-chained effect carries a synthetic `__then_<name>`
                    // handle; the diagnostic names the author's binding.
                    let named = unhandled
                        .binding
                        .strip_prefix("__then_")
                        .unwrap_or(&unhandled.binding);
                    let message = format!(
                        "unhandled failure of `{named}` in rule `{}` (effect {}): the \
                         `@service` workflow keeps running; handle it with `after {named} \
                         fails {{ … }}` or retry the effect",
                        unhandled.rule, unhandled.status
                    );
                    kernel.store().record_diagnostic(DiagnosticRecord {
                        instance_id: Some(instance_id),
                        program_id: None,
                        program_version_id: Some(&group.version_id),
                        severity: Severity::Warning,
                        code: Some("workflow.unhandled_failure"),
                        message: &message,
                        source_span_json: None,
                        subject_type: Some("rule"),
                        subject_id: Some(&unhandled.rule),
                        event_id: None,
                        effect_id: Some(&unhandled.effect_id),
                        run_id: None,
                        assertion_id: None,
                        evidence_ids_json: "[]",
                        artifact_ids_json: "[]",
                        causation_id: context.trigger_event_id.as_deref(),
                        correlation_id: context.identity.as_deref(),
                        idempotency_key: Some(&idempotency_key(&[
                            instance_id,
                            "workflow.unhandled_failure",
                            &unhandled.effect_id,
                        ])),
                    })?;
                }
                if lowering.facts.is_empty()
                    && lowering.consumed_fact_ids.is_empty()
                    && lowering.effects.is_empty()
                    && lowering.dependencies.is_empty()
                    && lowering.cancels.is_empty()
                    && lowering.terminal.is_none()
                    && lowering.internal_fail.is_none()
                {
                    continue;
                }
                // Auto-fail (R1): an unhandled effect failure in a self-terminating
                // workflow routes to the generic kernel failed terminal (no typed
                // `failure` payload), distinct from the typed terminal commit path.
                // Set by the rule-level net in lower_rule, so handle it before
                // the normal commit. fail_instance_internal transitions
                // running -> failed; the loop then exits (status != running).
                if let Some(reason) = lowering.internal_fail.clone() {
                    let fail_key = idempotency_key(&[
                        instance_id,
                        &group.version_id,
                        &group.epoch_key,
                        &rule.name,
                        context.identity.as_deref().unwrap_or("started"),
                        "rule-autofail",
                        &reason,
                    ]);
                    let event =
                        kernel.fail_instance_internal(instance_id, &reason, Some(&fail_key));
                    match event {
                        Ok(_) => {
                            report.committed_rules += 1;
                            // The release used to be here. It now lives inside
                            // `fail_instance_internal` (DR-0076 P2) so that
                            // reaching a terminal discharges, whoever gets there.
                            made_progress = true;
                            break 'rules;
                        }
                        Err(StoreError::Conflict(_)) => {
                            // Already failed (idempotent re-fire) — nothing to do.
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                let consumed_fact_ids = lowering
                    .consumed_fact_ids
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let new_facts = lowering
                    .facts
                    .iter()
                    .map(OwnedFact::as_new_fact)
                    .collect::<Vec<_>>();
                let new_effects = lowering
                    .effects
                    .iter()
                    .map(OwnedEffect::as_new_effect)
                    .collect::<Vec<_>>();
                let new_dependencies = lowering
                    .dependencies
                    .iter()
                    .map(OwnedDependency::as_new_dependency)
                    .collect::<Vec<_>>();
                let terminal = lowering
                    .terminal
                    .as_ref()
                    .map(OwnedWorkflowTerminal::as_workflow_terminal);
                let lowering_key = lowering_idempotency_key(&lowering);
                let commit_key = idempotency_key(&[
                    instance_id,
                    &group.version_id,
                    &group.epoch_key,
                    &rule.name,
                    context.identity.as_deref().unwrap_or("started"),
                    // The ADMITTING event disambiguates re-admissions: a fact
                    // consumed and later re-recorded with identical content
                    // has the same content-keyed identity but a fresh
                    // admission, and the rule must fire again rather than
                    // collide with the first firing's commit. Replay-safe:
                    // the pinned context records trigger_event_id, so
                    // re-lowering a committed firing reproduces the same key.
                    context.trigger_event_id.as_deref().unwrap_or("-"),
                    &lowering_key,
                ]);
                // Named cut points (experimentation surface): every
                // declared `mark "<name>" after <site>` riding this rule is
                // stamped IN the commit transaction — a durable commit can
                // never exist without its cut coordinate. One event per
                // firing, so a looping site marks each pass.
                // DR-0043 slice 1: embed the firing's pinned context (identity
                // + bound trigger values) in the commit record, making every
                // firing self-contained for pinned re-lowering and the
                // `whip progressions` view.
                let context_record = context_record_json(&context);
                let mark_names: Vec<&str> = ir
                    .marks
                    .iter()
                    .filter(|mark| mark.site == rule.name)
                    .map(|mark| mark.name.as_str())
                    .collect();
                let event = kernel.commit_rule_with_revision_guard(
                    RuleCommit {
                        instance_id,
                        rule: &rule.name,
                        trigger_event_id: context.trigger_event_id.as_deref(),
                        facts: &new_facts,
                        consumed_fact_ids: &consumed_fact_ids,
                        effects: &new_effects,
                        dependencies: &new_dependencies,
                        terminal,
                        idempotency_key: Some(&commit_key),
                        marks: &mark_names,
                        context_json: Some(&context_record),
                    },
                    RuleCommitRevisionGuard {
                        program_version_id: &active_version_id,
                        revision_epoch: active_revision_epoch,
                    },
                );
                let committed = event?;
                // Cancels run on replays too: they are status-guarded no-ops
                // once applied, and a crash between the original commit and
                // its cancel application would otherwise lose the cancels
                // forever (the replay used to `continue` before reaching
                // them).
                apply_rule_cancels(
                    kernel,
                    instance_id,
                    &rule.name,
                    &lowering.cancels,
                    &committed.event_id,
                )?;
                let replayed = committed.sequence <= pass_head_sequence;
                if replayed {
                    // A byte-identical replay of an existing commit: durable
                    // state unchanged, so it is not progress — counting it
                    // would spin the step's fixpoint loop forever.
                    continue;
                }
                report.committed_rules += 1;
                report.facts_created += new_facts.len();
                report.facts_consumed += consumed_fact_ids.len();
                report.effects_created += new_effects.len();
                // Holder-lifetime bound (spec/coordination.md): an
                // instance reaching a workflow terminal auto-releases
                // every lease it held.
                if lowering.terminal.is_some() {
                    release_holder_resources_on_terminal(kernel.store_mut(), instance_id);
                }
                made_progress = true;
                break 'rules;
            }
        }
    }
    Ok(report)
}

/// DR-0043 Decision 5: region-aware lowering. Chooses which pre-rendered body
/// variant this firing lowers against — HOLDS (the canonical `rule.body`),
/// REMOVED (post-lapse suppression is structural: region continuations
/// simply do not exist), or LAPSED (region replaced by its arm) — and, on the
/// first advancing evaluation under a broken condition, produces the LAPSE
/// lowering: the arm's actions plus the durable `progression.region.lapsed`
/// fact (carrying the pinned progress view) in ONE commit, plus cancellation
/// of the region's unsettled effects. The condition is evaluated here, inside
/// the same pass that commits — no check-then-act window.
/// The lapse arm's progress view: the per-step SUCCESS values with the reserved
/// `steps` status map merged in (DR-0043 Decision 6).
///
/// The durable fact stores the two halves separately (`got` and `steps`), so
/// audit and `whip progressions` can read the statuses without unpacking a
/// view. This rebuilds the author-facing shape from them, and it is the ONLY
/// place that shape is defined — the pinned-replay path and the lapse
/// transaction both go through here, so a re-lowered arm sees byte-identical
/// bindings to the one that committed.
fn progress_view_value(got: Option<Value>, steps: Option<Value>) -> Value {
    let mut view = match got {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    view.insert(
        "steps".to_owned(),
        steps.unwrap_or_else(|| Value::Object(serde_json::Map::new())),
    );
    Value::Object(view)
}

#[allow(clippy::too_many_arguments)]
fn lower_rule_with_region(
    instance_id: &str,
    version_id: &str,
    epoch_key: &str,
    coercion_fingerprint: &str,
    ir: &IrProgram,
    rule: &whipplescript_parser::IrRule,
    context: &RuleContext,
    active_facts: &[whipplescript_store::FactView],
    all_facts: &[whipplescript_store::FactView],
    effects: &[whipplescript_store::EffectView],
    source_path: Option<&std::path::Path>,
    active_fact_ids: &std::collections::BTreeSet<&str>,
) -> crate::lowering::OwnedLowering {
    use crate::rule_lowering::{
        effect_binding_value, eval_expr_value, guard_result, push_effect_binding, EvalScope,
        GuardStatus,
    };

    let lower = |body_rule: &whipplescript_parser::IrRule, with: &RuleContext| {
        lower_rule(
            instance_id,
            version_id,
            epoch_key,
            coercion_fingerprint,
            ir,
            body_rule,
            with,
            all_facts,
            effects,
            source_path,
        )
    };
    let Some(region) = rule.metadata.region.as_ref() else {
        return lower(rule, context);
    };
    let identity_key = context.identity.as_deref().unwrap_or("started");
    let lapse_fact_id = idempotency_key(&[instance_id, &rule.name, identity_key, "region-lapse"]);

    // Post-lapse: the region's continuations are structurally gone (REMOVED
    // splice would drop the arm too, so the arm variant is the live body —
    // its actions committed at lapse and re-lower idempotently, and any arm
    // effect's own continuations keep progressing). The progress view is
    // PINNED from the lapse fact, never rebuilt, so later effect settlements
    // cannot drift it.
    if let Some(lapse_fact) = all_facts.iter().find(|fact| fact.fact_id == lapse_fact_id) {
        let mut swapped = rule.clone();
        swapped.body = region.body_lapsed.clone();
        let mut arm_context = context.clone();
        if let Some(view) = &region.lapse_binding {
            let payload = json_from_str(&lapse_fact.value_json);
            let pinned =
                progress_view_value(payload.get("got").cloned(), payload.get("steps").cloned());
            push_effect_binding(&mut arm_context, view, &lapse_fact_id, pinned);
        }
        return lower(&swapped, &arm_context);
    }

    // Evaluate the condition against the CURRENT facts, in this pass.
    let raw_holds = match whipplescript_parser::parse_expression(&region.condition) {
        Ok(expr) => {
            let (status, _, _) = guard_result(eval_expr_value(
                &expr,
                &EvalScope::rule(context, active_facts, effects, ir),
            ));
            status == GuardStatus::Matched
        }
        // The check layer validates the grammar; an unparseable condition at
        // runtime is a kernel bug — fail toward reactivity (treat as broken)
        // so it is loud, never a silent free pass.
        Err(_) => region.until,
    };
    let holds = if region.until { !raw_holds } else { raw_holds };
    if holds {
        return lower(rule, context);
    }

    // Broken. Does the region still owe anything? Compare the HOLDS lowering
    // with the REMOVED lowering: identical output means every region action
    // already committed — the region is complete and the break is moot.
    let normalize = |mut lowering: crate::lowering::OwnedLowering| {
        lowering
            .consumed_fact_ids
            .retain(|fact_id| active_fact_ids.contains(fact_id.as_str()));
        (
            {
                let mut ids: Vec<String> = lowering
                    .facts
                    .iter()
                    .map(|fact| fact.fact_id.clone())
                    .collect();
                ids.sort();
                ids
            },
            {
                let mut ids: Vec<String> = lowering
                    .effects
                    .iter()
                    .map(|effect| effect.effect_id.clone())
                    .collect();
                ids.sort();
                ids
            },
            {
                let mut ids = lowering.consumed_fact_ids.clone();
                ids.sort();
                ids
            },
            lowering.terminal.is_some(),
            lowering.internal_fail.clone(),
        )
    };
    let lowering_holds = lower(rule, context);
    let mut removed_rule = rule.clone();
    removed_rule.body = region.body_removed.clone();
    let lowering_removed = lower(&removed_rule, context);
    // In-flight region effects count as open even when the residue diff is
    // empty (a requested-but-unsettled step produces no NEW lowering, but the
    // region still owes its settlement): the model's [lapse] is enabled the
    // moment the condition breaks with the region open.
    let region_in_flight = region.effects.iter().any(|region_effect| {
        region_effect_id(
            instance_id,
            version_id,
            epoch_key,
            rule,
            region_effect,
            identity_key,
        )
        .and_then(|effect_id| effects.iter().find(|view| view.effect_id == effect_id))
        .is_some_and(|view| {
            !matches!(
                view.status.as_str(),
                "completed" | "failed" | "timed_out" | "cancelled"
            )
        })
    });
    if !region_in_flight && normalize(lowering_holds) == normalize(lowering_removed) {
        // Region complete: proceed as if it never gated anything.
        return lower(rule, context);
    }

    // LAPSE: pin the progress view now, commit the arm + the lapse fact
    // atomically, and cancel the region's unsettled effects.
    let mut got = serde_json::Map::new();
    // DR-0043: the view reserves `steps` — `<view>.steps.<step>` is that
    // step's outcome as a STRING, so an arm can branch on progress with no new
    // machinery. A step's value field is present only when it SUCCEEDED (the
    // field type has no inhabitant for a failure), which is exactly why the
    // status map is needed: without it the arm cannot tell "failed" from
    // "never ran".
    let mut steps = serde_json::Map::new();
    for region_effect in &region.effects {
        // `then`-chained steps carry synthetic `__then_<name>` handles; the
        // progress view exposes the AUTHOR's name.
        let named = region_effect
            .binding
            .strip_prefix("__then_")
            .unwrap_or(&region_effect.binding)
            .to_owned();
        let Some(effect_id) = region_effect_id(
            instance_id,
            version_id,
            epoch_key,
            rule,
            region_effect,
            identity_key,
        ) else {
            steps.insert(named, Value::String("not_requested".to_owned()));
            continue;
        };
        if let Some(value) = effect_binding_value(all_facts, &effect_id, "succeeds") {
            got.insert(named.clone(), value);
        }
        let status = match effects.iter().find(|view| view.effect_id == effect_id) {
            None => "not_requested",
            Some(view) => match view.status.as_str() {
                "completed" | "failed" | "timed_out" | "cancelled" => view.status.as_str(),
                // Unsettled at the moment of lapse: this transaction cancels it
                // just below, so name that outcome rather than leaking a
                // transient queued/running status into a pinned view.
                _ => "cancelled_by_lapse",
            },
        };
        steps.insert(named, Value::String(status.to_owned()));
    }
    let got = Value::Object(got);
    let steps = Value::Object(steps);
    let pinned = progress_view_value(Some(got.clone()), Some(steps.clone()));
    let mut lapsed_rule = rule.clone();
    lapsed_rule.body = region.body_lapsed.clone();
    let mut arm_context = context.clone();
    if let Some(view) = &region.lapse_binding {
        push_effect_binding(&mut arm_context, view, &lapse_fact_id, pinned);
    }
    let mut lowering = lower(&lapsed_rule, &arm_context);
    lowering.facts.push(crate::lowering::OwnedFact {
        fact_id: lapse_fact_id,
        name: "progression.region.lapsed".to_owned(),
        key: format!("{}:{identity_key}", rule.name),
        value_json: json!({
            "rule": rule.name,
            "condition": region.condition,
            "until": region.until,
            "got": got,
            "steps": steps,
        })
        .to_string(),
        schema_id: None,
        provenance_class: "kernel".to_owned(),
        correlation_id: context.identity.clone(),
        source_span_json: None,
    });
    for region_effect in &region.effects {
        let Some(effect_id) = region_effect_id(
            instance_id,
            version_id,
            epoch_key,
            rule,
            region_effect,
            identity_key,
        ) else {
            continue;
        };
        if let Some(view) = effects.iter().find(|view| view.effect_id == effect_id) {
            if !matches!(
                view.status.as_str(),
                "completed" | "failed" | "timed_out" | "cancelled"
            ) {
                lowering.cancels.push(effect_id);
            }
        }
    }
    lowering
}

/// Recomputes a region effect's id exactly as the kernel's emission derives
/// it: level-0 effects key on the node id; effects inside a level-1 `after`
/// block key on that block's (binding, predicate) as well.
fn region_effect_id(
    instance_id: &str,
    version_id: &str,
    epoch_key: &str,
    rule: &whipplescript_parser::IrRule,
    region_effect: &whipplescript_parser::IrRegionEffect,
    identity_key: &str,
) -> Option<String> {
    let node = rule
        .metadata
        .effects
        .iter()
        .find(|node| node.binding.as_deref() == Some(region_effect.binding.as_str()))?;
    Some(match &region_effect.scope {
        None => idempotency_key(&[
            instance_id,
            version_id,
            epoch_key,
            &rule.name,
            &node.id,
            identity_key,
        ]),
        Some((binding, predicate)) => idempotency_key(&[
            instance_id,
            version_id,
            epoch_key,
            &rule.name,
            binding,
            predicate,
            &node.id,
            identity_key,
        ]),
    })
}

/// A committed firing reconstructed from its `rule.committed` record
/// (DR-0043): the rule it fired, its pinned context, and the program
/// version + revision epoch it was ADMITTED under.
#[derive(Clone)]
struct RecordedFiring {
    rule: String,
    context: RuleContext,
    version_id: Option<String>,
    epoch: i64,
    /// The fact ids this firing's commit already recorded: its re-lowering
    /// re-emits them byte-for-byte (content-keyed), and they must be
    /// suppressed — re-recording a since-consumed fact is a NEW firing's
    /// act (DR-0044 re-admission), never a replay's.
    fact_ids: Vec<String>,
}

/// The three per-event payload derivations `step_instance_generic` memoizes
/// across its fixpoint rounds. Each takes only the immutable payload bytes, so
/// an event id derives the same value for the whole pass.
fn restored_target_from_payload(payload_json: &str) -> Option<i64> {
    serde_json::from_str::<Value>(payload_json)
        .ok()?
        .get("restored_to_sequence")
        .and_then(Value::as_i64)
}

fn cancelled_key_from_payload(payload_json: &str) -> Option<(String, Option<String>)> {
    let payload = serde_json::from_str::<Value>(payload_json).ok()?;
    let rule = payload.get("rule").and_then(Value::as_str)?.to_owned();
    let identity = payload
        .get("identity")
        .and_then(Value::as_str)
        .filter(|identity| *identity != "started")
        .map(str::to_owned);
    Some((rule, identity))
}

fn recorded_firing_from_payload(payload_json: &str) -> Option<RecordedFiring> {
    let payload = serde_json::from_str::<Value>(payload_json).ok()?;
    let rule = payload.get("rule").and_then(Value::as_str)?.to_owned();
    let context = payload.get("context").and_then(context_from_record)?;
    let version_id = payload
        .get("program_version_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let epoch = payload
        .get("revision_epoch")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let fact_ids = payload
        .get("facts")
        .and_then(Value::as_array)
        .map(|facts| {
            facts
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(RecordedFiring {
        rule,
        context,
        version_id,
        epoch,
        fact_ids,
    })
}

/// Loads and compiles the rule bodies of an OLD program version for old-body
/// completion (DR-0043 Decision 3). The source is content-addressed: version
/// creation and every verified drive `put_content` it, so the blob id is the
/// version's `source_hash`. A missing blob or a failed compile records ONE
/// loud diagnostic (idempotent per version) and returns `None` -- the firing
/// is skipped visibly, never lowered under the wrong body.
fn load_version_ir<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    version_id: &str,
) -> Result<Option<IrProgram>, StoreError> {
    let unavailable = |kernel: &RuntimeKernel<S>, detail: &str| -> Result<(), StoreError> {
        let message = format!(
            "cannot complete progressions admitted under program version `{version_id}`: {detail}"
        );
        kernel.store().record_diagnostic(DiagnosticRecord {
            instance_id: Some(instance_id),
            program_id: None,
            program_version_id: Some(version_id),
            severity: Severity::Warning,
            code: Some("progression.version_unavailable"),
            message: &message,
            source_span_json: None,
            subject_type: Some("program_version"),
            subject_id: Some(version_id),
            event_id: None,
            effect_id: None,
            run_id: None,
            assertion_id: None,
            evidence_ids_json: "[]",
            artifact_ids_json: "[]",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some(&idempotency_key(&[
                instance_id,
                "progression.version_unavailable",
                version_id,
            ])),
        })?;
        Ok(())
    };
    let Some(view) = kernel.store().get_program_version(version_id)? else {
        unavailable(kernel, "the version record is missing")?;
        return Ok(None);
    };
    let Some(source) = kernel.store().get_content(&view.source_hash)? else {
        unavailable(
            kernel,
            "its source is not in the content store (the version was never driven \
             since source pinning landed)",
        )?;
        return Ok(None);
    };
    let compiled =
        whipplescript_parser::compile_program_with_root(&source, Some(&view.program_name));
    match compiled.ir {
        Some(ir) => Ok(Some(ir)),
        None => {
            unavailable(kernel, "its stored source no longer compiles")?;
            Ok(None)
        }
    }
}

/// Holder-lifetime release on terminal (spec/coordination.md principle 3 +
/// spec/work-queues.md): an instance that reaches ANY terminal — a rule-driven
/// `complete`/`fail` OR an operator `cancel` — drops every workspace-scoped
/// resource it held: coordination leases AND builtin-queue claims. Coordination
/// leases also have a TTL crash net, but queue claims do NOT, so this terminal
/// release is the only automatic recovery for a claim held by a dead instance.
/// Releasing both from one place keeps the terminal paths from forgetting a
/// resource type. Best-effort: a cleanup failure degrades to leaving the
/// resource (lease TTL backstops it) rather than failing an already-committed
/// terminal.
pub fn release_holder_resources_on_terminal<S: Coordination + WorkItems>(
    store: &mut S,
    instance_id: &str,
) {
    let _ = Coordination::release_all_for_holder(store, instance_id);
    let _ = WorkItems::release_claims_for_holder(store, instance_id);
}

/// Projects ready work items from declared builtin queues into
/// instance-local `tracker.issue.ready` facts, and retires projections whose
/// items are no longer ready. The tracker is the source of truth; the run
/// store holds a cache keyed (queue, id).
pub fn project_tracker_issues<S: RuntimeStore + WorkItems>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
) -> Result<(), StoreError> {
    if ir.trackers.is_empty() {
        return Ok(());
    }
    for queue in &ir.trackers {
        if queue.provider != "builtin" {
            continue;
        }
        // Keep a projection alive while this instance holds the claim: the
        // dispatching rule's multi-stage chain needs its trigger fact until
        // the item is finished or released. Re-fires are idempotent (effect
        // ids are identity-derived), matching the engine's existing idiom.
        let ready = WorkItems::list_items(kernel.store(), Some(&queue.name), None)?
            .into_iter()
            .filter(|item| {
                (item.status == "open" && item.claimed_by.is_none())
                    || (item.status == "in_progress"
                        && item.claimed_by.as_deref() == Some(instance_id))
            })
            .collect::<Vec<_>>();
        let existing = kernel
            .store()
            .list_facts(instance_id)?
            .into_iter()
            .filter(|fact| fact.name == "tracker.issue.ready")
            .filter(|fact| {
                json_from_str(&fact.value_json)
                    .get("queue")
                    .and_then(Value::as_str)
                    == Some(queue.name.as_str())
            })
            .collect::<Vec<_>>();
        let ready_prefixes = ready
            .iter()
            .map(|item| format!("{}:{}:", queue.name, item.id))
            .collect::<Vec<_>>();
        // Retired generations (consumed rows) — needed below to revive a
        // projection whose backing item is ready again with an UNCHANGED
        // update generation (claim/release does not bump updated_at): the
        // re-derive would collide with the retired predecessor's event key,
        // which used to poison every subsequent step with a UNIQUE conflict.
        let live_ids: std::collections::BTreeSet<&str> =
            existing.iter().map(|fact| fact.fact_id.as_str()).collect();
        let retired = kernel
            .store()
            .list_facts_including_consumed(instance_id)?
            .into_iter()
            .filter(|fact| fact.name == "tracker.issue.ready")
            .filter(|fact| !live_ids.contains(fact.fact_id.as_str()))
            .collect::<Vec<_>>();
        for item in &ready {
            let prefix = format!("{}:{}:", queue.name, item.id);
            if existing.iter().any(|fact| fact.key.starts_with(&prefix)) {
                continue;
            }
            // Salt the key with the item's update generation: a released
            // item re-projects as a fresh fact instead of colliding with
            // its retired predecessor.
            let key = format!("{prefix}{}", stable_hash_hex(&item.updated_at));
            // Same generation, previously retired: revive the overlay row in
            // place (no event — the exact mirror of retire_fact) instead of
            // re-deriving under the identical event key.
            if let Some(prior) = retired.iter().find(|fact| fact.key == key) {
                kernel
                    .store_mut()
                    .revive_fact(instance_id, &prior.fact_id)?;
                continue;
            }
            let value_json = json!({
                "queue": queue.name,
                "id": item.id,
                "title": item.title,
                "body": item.body,
                "status": item.status,
                "labels": item.labels,
                "metadata": item.metadata,
            })
            .to_string();
            // Salt with updated_at: a released item re-projects as a fresh
            // fact generation instead of colliding with its retired one.
            kernel.derive_fact(
                instance_id,
                "tracker.issue.ready",
                &key,
                &value_json,
                None,
                Some(&idempotency_key(&[
                    instance_id,
                    "tracker.issue.ready",
                    &key,
                    &item.updated_at,
                ])),
            )?;
        }
        for fact in existing {
            if !ready_prefixes
                .iter()
                .any(|prefix| fact.key.starts_with(prefix))
            {
                kernel.store_mut().retire_fact(instance_id, &fact.fact_id)?;
            }
        }
    }
    Ok(())
}

pub fn lowering_idempotency_key(lowering: &OwnedLowering) -> String {
    let mut ids = Vec::new();
    ids.extend(lowering.facts.iter().map(|fact| fact.fact_id.as_str()));
    ids.extend(
        lowering
            .consumed_fact_ids
            .iter()
            .map(|fact_id| fact_id.as_str()),
    );
    ids.extend(
        lowering
            .effects
            .iter()
            .map(|effect| effect.effect_id.as_str()),
    );
    ids.extend(
        lowering
            .dependencies
            .iter()
            .map(|dependency| dependency.dependency_id.as_str()),
    );
    if let Some(terminal) = &lowering.terminal {
        ids.push(terminal.idempotency_key.as_str());
    }
    idempotency_key(&ids)
}

/// Applies `cancel <binding>` operations committed by a rule: pending
/// effects terminal-cancel; running effects get a cancellation request (a
/// request, not a result); already-terminal effects are a recorded no-op.
pub fn apply_rule_cancels<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    rule_name: &str,
    effect_ids: &[String],
    causation_event_id: &str,
) -> Result<(), StoreError> {
    for effect_id in effect_ids {
        let status = kernel
            .store()
            .list_effects(instance_id)?
            .into_iter()
            .find(|effect| &effect.effect_id == effect_id)
            .map(|effect| effect.status);
        match status.as_deref() {
            Some("running") => {
                let _ = kernel
                    .store_mut()
                    .request_effect_cancellation(EffectCancellationRequest {
                        instance_id,
                        effect_id,
                        revision_id: None,
                        reason: Some("cancelled by rule"),
                        requested_by: rule_name,
                        causation_event_id: Some(causation_event_id),
                        idempotency_key: Some(&idempotency_key(&[
                            instance_id,
                            effect_id,
                            rule_name,
                            "rule-cancel-request",
                        ])),
                    });
            }
            Some("completed") | Some("failed") | Some("timed_out") | Some("cancelled") => {
                // Crash-window heal for the cancelled case: the cancel's
                // terminal committed but the effect.cancelled settling-fact
                // derivation may have crashed before running (they are
                // separate transactions). derive_fact is replay-tolerant, so
                // this is a no-op when the fact already exists.
                if status.as_deref() == Some("cancelled") {
                    let value_json = serde_json::json!({
                        "effect_id": effect_id,
                        "status": "cancelled",
                        "reason": "cancelled by rule",
                    })
                    .to_string();
                    kernel.derive_fact(
                        instance_id,
                        "effect.cancelled",
                        effect_id,
                        &value_json,
                        Some(causation_event_id),
                        Some(&idempotency_key(&[
                            instance_id,
                            effect_id,
                            "cancelled-fact",
                        ])),
                    )?;
                }
                // No-op with evidence: cancelling settled work is legal.
                kernel.store().record_diagnostic(DiagnosticRecord {
                    instance_id: Some(instance_id),
                    program_id: None,
                    program_version_id: None,
                    severity: Severity::Info,
                    code: Some("cancel.noop"),
                    message: &format!(
                        "rule `{rule_name}` cancelled effect `{effect_id}` after it reached a terminal status"
                    ),
                    source_span_json: None,
                    subject_type: Some("effect"),
                    subject_id: Some(effect_id),
                    event_id: Some(causation_event_id),
                    effect_id: Some(effect_id),
                    run_id: None,
                    assertion_id: None,
                    evidence_ids_json: "[]",
                    artifact_ids_json: "[]",
                    causation_id: Some(causation_event_id),
                    correlation_id: None,
                    idempotency_key: Some(&idempotency_key(&[
                        instance_id,
                        effect_id,
                        rule_name,
                        "rule-cancel-noop",
                    ])),
                })?;
            }
            Some(_) => {
                kernel.cancel_effect(EffectCancellation {
                    instance_id,
                    effect_id,
                    reason: Some("cancelled by rule"),
                    idempotency_key: Some(&idempotency_key(&[
                        instance_id,
                        effect_id,
                        rule_name,
                        "rule-cancel",
                    ])),
                })?;
            }
            None => {}
        }
    }
    Ok(())
}

/// The revision-axis key component every derived idempotency key carries:
/// the revision epoch, joined by the branch/cut ref once the instance's
/// timeline has forked (versioned-workspace note §9.1 — two branches firing
/// the same version-node are distinct executions; branch-effect-key.maude
/// holds the bite). The ref composes two axes: the branch the instance was
/// born on (`branch.bound`, `None` = mainline) and the restore lineage
/// (`.r<generation>` per `context.restored` marker). Unbound generation 0
/// returns the bare epoch so every pre-branching key derivation stays
/// byte-identical.
pub fn revision_branch_key(
    revision_epoch: i64,
    bound_branch: Option<&str>,
    restore_generation: usize,
) -> String {
    match (bound_branch, restore_generation) {
        (None, 0) => revision_epoch.to_string(),
        (None, generation) => format!(
            "{revision_epoch}@{}.r{generation}",
            whipplescript_store::branches::MAINLINE_BRANCH_ID
        ),
        (Some(branch), generation) => {
            format!("{revision_epoch}@{branch}.r{generation}")
        }
    }
}

#[cfg(test)]
mod branch_key_tests {
    use super::revision_branch_key;
    use crate::idempotency_key;

    /// Unbound generation 0 is the bare epoch: never-restored mainline
    /// instances (every existing store) derive byte-identical keys.
    #[test]
    fn generation_zero_preserves_existing_key_bytes() {
        assert_eq!(revision_branch_key(0, None, 0), "0");
        assert_eq!(revision_branch_key(3, None, 0), "3");
    }

    /// Each restore generation is a distinct timeline head: the same
    /// version-node derives a DISTINCT effect key on every side of a
    /// restore, so a re-executed suffix never dedupes against the orphaned
    /// segment (the branch-effect-key.maude corruption, rejected).
    #[test]
    fn generations_never_collide_on_the_same_version_node() {
        let key_for = |epoch_key: &str| {
            idempotency_key(&["ins_1", "ver_1", epoch_key, "rule_a", "node_1", "started"])
        };
        let gen0 = key_for(&revision_branch_key(3, None, 0));
        let gen1 = key_for(&revision_branch_key(3, None, 1));
        let gen2 = key_for(&revision_branch_key(3, None, 2));
        assert_ne!(gen0, gen1);
        assert_ne!(gen1, gen2);
        assert_ne!(gen0, gen2);
        // Within one generation the key is stable — idempotency retained.
        assert_eq!(gen1, key_for(&revision_branch_key(3, None, 1)));
    }

    /// Instances born on different branches never share a key for the
    /// same version-node (the branch-effect-key.maude working-branch
    /// flavor), and a bound branch is distinct from unbound mainline.
    #[test]
    fn bound_branches_never_collide() {
        let key_for = |epoch_key: &str| {
            idempotency_key(&["ins_1", "ver_1", epoch_key, "rule_a", "node_1", "started"])
        };
        let mainline = key_for(&revision_branch_key(3, None, 0));
        let draft_a = key_for(&revision_branch_key(3, Some("draft_a"), 0));
        let draft_b = key_for(&revision_branch_key(3, Some("draft_b"), 0));
        assert_ne!(mainline, draft_a);
        assert_ne!(draft_a, draft_b);
        // Stable within a branch; restore generations fork within it too.
        assert_eq!(
            draft_a,
            key_for(&revision_branch_key(3, Some("draft_a"), 0))
        );
        assert_ne!(
            key_for(&revision_branch_key(3, Some("draft_a"), 1)),
            draft_a
        );
        assert_eq!(revision_branch_key(3, Some("draft_a"), 0), "3@draft_a.r0");
    }

    /// The epoch and the branch ref are one composed component, so a bumped
    /// epoch inside a generation and a bumped generation at one epoch are
    /// also distinct.
    #[test]
    fn epoch_and_generation_axes_stay_distinct() {
        assert_ne!(
            revision_branch_key(4, None, 1),
            revision_branch_key(3, None, 1)
        );
        assert_ne!(
            revision_branch_key(3, None, 2),
            revision_branch_key(3, None, 1)
        );
        assert_eq!(revision_branch_key(3, None, 1), "3@main.r1");
    }
}
