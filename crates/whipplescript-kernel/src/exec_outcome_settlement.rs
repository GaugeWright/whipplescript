//! Projection of retained broker evidence; no executor I/O or new admission.
use crate::{
    exec_http::{self, ExecDispatchPlan, ExecSettleContext, ExecSettlementProjection},
    exec_invocation::Invocation,
    exec_lifetime,
    sansio::HttpResponse,
    RuntimeKernel,
};
use serde_json::json;
use whipplescript_store::{
    exec_lifetime::FenceReason,
    exec_outcome::{self, Outcome},
    EffectCompletion, RuntimeStore, StoreError, StoreResult, StoredEvent,
};

/// Local settlement remains work after the external cleanup query is closed.
pub fn pending<S: RuntimeStore>(store: &S) -> StoreResult<bool> {
    for instance in store.list_instances()? {
        let runs = store.list_runs(&instance.instance_id)?;
        for run in exec_lifetime::outcomes(store, &instance.instance_id)?.keys() {
            let run = runs
                .iter()
                .find(|r| &r.run_id == run)
                .ok_or_else(|| StoreError::Conflict("observed executor run is missing".into()))?;
            if run.status == "running" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn settle_instance<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
) -> StoreResult<Vec<StoredEvent>> {
    let mut settled = exec_http::recover_pending_exec_settlements(kernel, instance)?;
    let observations = exec_lifetime::outcomes(kernel.store(), instance)?;
    let originals = exec_lifetime::tracked(kernel.store(), instance)?;
    let fences = exec_lifetime::fences(kernel.store(), instance)?;
    for (run, record) in observations {
        let runs = kernel.store().list_runs(instance)?;
        let active = runs
            .iter()
            .find(|r| r.run_id == run)
            .ok_or_else(|| StoreError::Conflict("observed executor run is missing".into()))?;
        if active.status != "running" {
            continue;
        }
        let original = originals
            .get(&run)
            .ok_or_else(|| StoreError::Conflict("observed executor tracking is missing".into()))?;
        let selected: Invocation =
            serde_json::from_value(original.invocation["invocation"].clone())?;
        let effect = kernel
            .store()
            .list_effects(instance)?
            .into_iter()
            .find(|e| e.effect_id == original.effect_id)
            .ok_or_else(|| StoreError::Conflict("observed executor effect is missing".into()))?;
        if effect.status != "running"
            || effect.kind != "exec.command"
            || selected.run_id() != run
            || kernel
                .store()
                .effect_attempt_admission(instance, &effect.effect_id)?
                != selected.attempt_admission_event_id
        {
            return Err(StoreError::Conflict(
                "observed executor settlement differs from current attempt".into(),
            ));
        }
        let plan = ExecDispatchPlan::load(
            kernel.store(),
            instance,
            &effect.effect_id,
            &run,
            &original.input,
        )?;
        let event = kernel
            .store()
            .event_by_idempotency_key(
                instance,
                &json!([exec_outcome::EVENT_TYPE, run]).to_string(),
            )?
            .ok_or_else(|| {
                StoreError::Conflict("observed executor outcome slot is missing".into())
            })?;
        let input = original.input.to_string();
        let terminal = match &record.outcome {
            Outcome::Completed { status, body } => {
                let response = HttpResponse {
                    status: *status,
                    body: body.clone(),
                };
                let schema = plan
                    .parse_contract
                    .as_ref()
                    .and_then(|c| c["schema"].as_str())
                    .unwrap_or("json");
                let ctx = ExecSettleContext {
                    input_json: &input,
                    instance_id: instance,
                    effect_id: &effect.effect_id,
                    run_id: &run,
                    capability: &plan.capability,
                    script_sha256: &plan.script_sha256,
                    cache: plan.content_key.as_deref().map(|key| (key, false)),
                    ingest_schema: schema,
                    executor_response: Some(&response),
                    executor_transport: if original.executor_url == "whip-executor://native/exec" {
                        "native-managed"
                    } else {
                        "http"
                    },
                    dispatch_plan: Some(&plan),
                    resolution_event_id: Some(&event.event_id),
                };
                let outcome =
                    exec_http::decode_exec_http_outcome(&plan, &response, &effect.effect_id);
                exec_http::settle_exec_http_result(kernel, &ctx, outcome)?
            }
            other => {
                let reason = fences
                    .get(&run)
                    .ok_or_else(|| {
                        StoreError::Conflict("observed executor intent is missing".into())
                    })?
                    .reason;
                let (status, summary) = match other {
                    Outcome::Uncertain => (
                        "failed",
                        "executor outcome is unknown after confirmed termination",
                    ),
                    Outcome::NotExecuted => match reason {
                        FenceReason::Cancellation => {
                            ("cancelled", "executor was not admitted before cancellation")
                        }
                        FenceReason::Deadline => {
                            ("timed_out", "executor was not admitted before its deadline")
                        }
                        _ => ("failed", "executor was not admitted"),
                    },
                    Outcome::Completed { .. } => unreachable!(),
                };
                let mut metadata = json!({"mode":"capability","capability":plan.capability,"sha256":plan.script_sha256,"executor_dispatch":plan,"executor_outcome_event_id":event.event_id,"executor_outcome":other});
                if status == "failed" {
                    metadata["failure"] = json!({"error_kind":if matches!(other,Outcome::Uncertain){"exec_uncertain"}else{"exec_not_executed"},"message":summary});
                }
                let value = if status == "failed" {
                    let mut failure = crate::effect_failure_base(
                        "exec",
                        summary,
                        summary,
                        &effect.effect_id,
                        &run,
                    );
                    failure["outcome"] = serde_json::to_value(other)?;
                    failure
                } else {
                    json!({"reason":summary})
                };
                let fact = json!({"effect_id":effect.effect_id,"run_id":run,"status":status,"summary":summary,"reason":summary,"value":value});
                let projection = ExecSettlementProjection {
                    name: if status == "failed" {
                        "exec.command.failed".into()
                    } else {
                        format!("effect.{status}")
                    },
                    key: effect.effect_id.clone(),
                    value: fact.to_string(),
                    ingest: false,
                    event_key: crate::execution_run_key(
                        instance,
                        &effect.effect_id,
                        &run,
                        &["exec-fact"],
                    ),
                };
                exec_http::commit_exec_settlement(
                    kernel,
                    &input,
                    EffectCompletion {
                        instance_id: instance,
                        effect_id: &effect.effect_id,
                        run_id: &run,
                        provider: "exec",
                        worker_id: "whip-exec",
                        status,
                        exit_code: None,
                        summary: Some(summary),
                        metadata_json: &metadata.to_string(),
                        idempotency_key: Some(&crate::execution_run_key(
                            instance,
                            &effect.effect_id,
                            &run,
                            &["terminal"],
                        )),
                    },
                    &[projection],
                    None,
                )?
            }
        };
        settled.push(terminal);
    }
    Ok(settled)
}
