//! `expect.stats` — the acceptance fixture's token and call budget (DR-0114 S4).
//!
//! The point of the whole stats fold, stated in DR-0114: a change that doubles a
//! rule's spend goes red before it ships. That needs the numbers to be
//! deterministic, and they are, because the fold is a pure function of the
//! durable log and the fixture provider makes the log deterministic.

use super::super::*;
use serde_json::json;
use whipplescript_kernel::stats::{CallInput, EffectInput, FoldInputs, InstanceInput, RunInput};

fn inputs(usage: Option<serde_json::Value>, calls: Vec<CallInput>) -> FoldInputs {
    FoldInputs {
        instances: vec![InstanceInput {
            instance_id: "i1".to_owned(),
            program_id: "p".to_owned(),
            program_version_id: "v".to_owned(),
        }],
        effects: vec![EffectInput {
            effect_id: "e1".to_owned(),
            instance_id: "i1".to_owned(),
            kind: "agent.tell".to_owned(),
            status: "completed".to_owned(),
            created_by_rule: "review".to_owned(),
            program_version_id: Some("v".to_owned()),
            revision_epoch: 0,
            profile: None,
            policy_block_category: None,
        }],
        runs: vec![RunInput {
            run_id: "r1".to_owned(),
            effect_id: "e1".to_owned(),
            provider: "owned-harness".to_owned(),
            status: "completed".to_owned(),
            started_at: "2026-09-14T10:00:00Z".to_owned(),
            completed_at: None,
            metadata_json: usage
                .map(|usage| json!({ "usage": usage }).to_string())
                .unwrap_or_else(|| "{}".to_owned()),
        }],
        calls,
    }
}

/// The store failure the refusal test feeds in.
fn unreadable_store() -> whipplescript_store::StoreError {
    whipplescript_store::StoreError::fault("stats rows", "the store is unreadable")
}

fn failures(expect: serde_json::Value, inputs: &FoldInputs) -> Vec<String> {
    let mut failures = Vec::new();
    acceptance_expect_stats(&expect, inputs, &mut failures);
    failures
}

#[test]
fn a_budget_within_its_ceiling_passes() {
    let world = inputs(
        Some(json!({"input_tokens": 10, "output_tokens": 4})),
        Vec::new(),
    );
    let found = failures(
        json!({"stats": [{"where": {"rule": "review"}, "max": {"output": 6}, "min": {"runs": 1}}]}),
        &world,
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_rule_that_doubles_its_spend_goes_red() {
    // The behaviour DR-0114 named as the reason to build any of this.
    let world = inputs(
        Some(json!({"input_tokens": 10, "output_tokens": 8})),
        Vec::new(),
    );
    let found = failures(
        json!({"stats": [{"where": {"rule": "review"}, "max": {"output": 6}}]}),
        &world,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("output 8 exceeds max 6"), "{found:?}");
}

#[test]
fn a_budget_on_an_unrecorded_measure_fails_rather_than_passing() {
    // The decision this evaluator turns on. A ceiling against a measure the log
    // does not carry cannot be answered, and passing would make the assertion
    // vacuous exactly when the data went missing — a change that stopped
    // recording usage would sail through its own budget.
    let world = inputs(None, Vec::new());
    let found = failures(
        json!({"stats": [{"where": {"rule": "review"}, "max": {"output": 1000}}]}),
        &world,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("does not record output"),
        "the failure must say the measure is UNRECORDED, not that it was over: {found:?}"
    );
    assert!(found[0].contains("unrecorded is not zero"), "{found:?}");
}

#[test]
fn a_call_count_is_budgetable_once_per_call_rows_exist() {
    // Turn grain cannot answer `calls`; call grain can. Same clause, two logs.
    let call = |step: i64| CallInput {
        run_id: "r1".to_owned(),
        step,
        model: Some("m".to_owned()),
        usage: Some(json!({"input_tokens": 5, "output_tokens": 1})),
        compaction: false,
    };
    let world = inputs(Some(json!({"input_tokens": 10})), vec![call(0), call(1)]);
    let clause = json!({"stats": [{"where": {"rule": "review"}, "max": {"calls": 2}}]});
    assert!(failures(clause.clone(), &world).is_empty());

    let over = inputs(
        Some(json!({"input_tokens": 10})),
        vec![call(0), call(1), call(2)],
    );
    let found = failures(clause, &over);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("calls 3 exceeds max 2"), "{found:?}");
}

#[test]
fn a_clause_may_not_budget_by_something_outside_the_closed_vocabulary() {
    // DR-0117 reaches the fixture too: a budget cannot group by a fact value
    // any more than a report can.
    let world = inputs(Some(json!({"output_tokens": 1})), Vec::new());
    let found = failures(
        json!({"stats": [{"where": {"fact_key": "customer"}, "max": {"output": 1}}]}),
        &world,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("unknown stats dimension `fact_key`"),
        "{found:?}"
    );
}

#[test]
fn a_misspelled_measure_fails_loudly_rather_than_matching_nothing() {
    // A clause naming a measure that does not exist would otherwise bound
    // nothing and pass, which is a budget that silently stops budgeting.
    let world = inputs(Some(json!({"output_tokens": 1})), Vec::new());
    let found = failures(json!({"stats": [{"max": {"tokens": 1}}]}), &world);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("is not a stats measure"), "{found:?}");
}

#[test]
fn a_fixture_declaring_stats_passes_the_expect_shape_check() {
    acceptance_validate_expect_shape(&json!({
        "stats": [{"where": {"rule": "review"}, "max": {"output": 6}}]
    }))
    .expect("an array of clauses is a legal expect.stats");
    acceptance_validate_expect_shape(&json!({"stats": {"max": {"output": 6}}}))
        .expect_err("expect.stats must be an array");
}

#[test]
fn a_stats_read_failure_is_refused_with_the_reason() {
    // The refusal the mutation sweep flagged as unexercised. The acceptance flow
    // cannot easily be driven with a store whose read fails, so the message
    // lives in a function the test reaches directly.
    //
    // Why refusing matters rather than being box-ticking: folding an unreadable
    // store as an EMPTY report would leave every clause above evaluating against
    // zero rows and passing, so a fixture would report success while measuring
    // nothing — the same defect as a budget passing on an unrecorded measure,
    // arriving through a different door.
    let refused = acceptance_stats_read_failure(unreadable_store());
    assert!(
        refused.starts_with("failed to read stats rows: "),
        "the refusal must name what could not be read: {refused}"
    );
    assert!(
        refused.contains("the store is unreadable"),
        "the refusal must carry the store's own reason: {refused}"
    );
}
