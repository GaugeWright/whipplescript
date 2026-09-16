//! Durable native norm selection before external controller authority.
use super::*;
use serde_json::{json, Value};
use whipplescript_kernel::{
    exec_handoff::{self, Handoff},
    exec_http::{build_executor_exec_request, sha256_hex, ExecDispatchPlan},
    exec_invocation::{Envelope, Invocation},
    exec_lifetime,
    norm_execution::validate_norm_dispatch,
    norm_runner::PythonCallMethod,
    RuntimeKernel,
};
use whipplescript_store::{ClaimableEffect, RunStart};

pub struct NativeNormAdmission {
    pub handoff: Handoff,
    pub binding: NativeRuntimeImage,
    /// None means retained fence intent already forbids a new candidate.
    pub candidate: Option<Owner>,
}

impl NativeNormAdmission {
    /// Repair a run-start/tracking interruption without physical allocation.
    /// The original start event must authorize managed execution; a current
    /// projection's transport label alone cannot upgrade a legacy run.
    pub fn restore_tracking(
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        run: &str,
    ) -> StoreResult<ClaimableEffect> {
        let row = kernel
            .store()
            .list_runs(instance)?
            .into_iter()
            .find(|r| r.run_id == run)
            .ok_or_else(|| StoreError::Conflict("native norm recovery run is missing".into()))?;
        let row_effect = kernel
            .store()
            .list_effects(instance)?
            .into_iter()
            .find(|e| e.effect_id == row.effect_id)
            .ok_or_else(|| StoreError::Conflict("native norm recovery effect is missing".into()))?;
        let effect = ClaimableEffect {
            attempt_admission_event_id: kernel
                .store()
                .effect_attempt_admission(instance, &row.effect_id)?,
            effect_id: row_effect.effect_id,
            kind: row_effect.kind,
            target: row_effect.target,
            profile: row_effect.profile,
            input_json: row_effect.input_json,
            required_capabilities_json: row_effect.required_capabilities_json,
            declared_profiles_json: row_effect.declared_profiles_json,
        };
        let slot = kernel
            .store()
            .event_by_idempotency_key(instance, run)?
            .ok_or_else(|| {
                StoreError::Conflict("native norm recovery admission is missing".into())
            })?;
        let events = kernel.store().list_events(instance)?;
        let event = events
            .iter()
            .find(|e| e.event_id == slot.event_id)
            .ok_or_else(|| {
                StoreError::Conflict("native norm recovery admission event is missing".into())
            })?;
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        let metadata: Value = serde_json::from_str(&row.metadata_json)?;
        if event.source != "kernel"
            || event.event_type != "effect.run_started"
            || payload["run_id"] != run
            || payload["effect_id"] != effect.effect_id
            || payload["metadata"]["executor_transport"] != "native-managed"
            || payload["metadata"] != metadata
        {
            return Err(StoreError::Conflict(
                "native norm cannot restore tracking from a changed or legacy admission".into(),
            ));
        }
        let input: Value = serde_json::from_str(&effect.input_json)?;
        if input["mode"] != "capability" || input.get("norm_intent").is_none() {
            return Err(StoreError::Conflict(
                "native norm recovery requires a prepared norm effect".into(),
            ));
        }
        let method: PythonCallMethod = serde_json::from_str(
            input["stdin"]["method_definition_json"]
                .as_str()
                .unwrap_or_default(),
        )?;
        let binding: NativeRuntimeImage =
            serde_json::from_value(metadata["native_runtime"].clone())?;
        binding.validate_for(&method.runtime)?;
        let handoff = exec_handoff::retained(kernel.store(), instance, &effect, vec![])?;
        let plan =
            ExecDispatchPlan::load(kernel.store(), instance, &effect.effect_id, run, &input)?;
        validate_norm_dispatch(&input, &plan).map_err(StoreError::Conflict)?;
        if handoff.run_id() != run
            || handoff.request().url != "whip-executor://native/exec"
            || plan.environment_epoch != binding.runtime.environment
        {
            return Err(StoreError::Conflict(
                "native norm recovery differs from its original invocation".into(),
            ));
        }
        exec_handoff::select_tracked(
            kernel.store_mut(),
            instance,
            &effect,
            handoff.request().clone(),
        )?;
        Ok(effect)
    }

    /// `installed` is trusted host configuration. Reattachment uses the original
    /// retained binding even when that current configuration has changed.
    pub fn admit(
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        effect: &ClaimableEffect,
        installed: &NativeRuntimeImage,
    ) -> StoreResult<Self> {
        let now = chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Self::admit_at(kernel, instance, effect, installed, &now)
    }

    /// Injected host clock for fresh admission. Recovery never renews the lease.
    pub fn admit_at(
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        effect: &ClaimableEffect,
        installed: &NativeRuntimeImage,
        now: &str,
    ) -> StoreResult<Self> {
        let input: Value = serde_json::from_str(&effect.input_json)?;
        let current = kernel
            .store()
            .list_effects(instance)?
            .into_iter()
            .find(|row| row.effect_id == effect.effect_id)
            .ok_or_else(|| StoreError::Conflict("managed norm effect is missing".into()))?;
        if effect.kind != "exec.command"
            || current.kind != "exec.command"
            || serde_json::from_str::<Value>(&current.input_json)? != input
            || kernel
                .store()
                .effect_attempt_admission(instance, &effect.effect_id)?
                != effect.attempt_admission_event_id
        {
            return Err(StoreError::Conflict(
                "managed norm differs from the current host selection".into(),
            ));
        }

        if input["mode"] != "capability" || input.get("norm_intent").is_none() {
            return Err(StoreError::Conflict(
                "managed norm admission requires a prepared norm effect".into(),
            ));
        }
        let method: PythonCallMethod = serde_json::from_str(
            input["stdin"]["method_definition_json"]
                .as_str()
                .unwrap_or_default(),
        )?;
        let selected = Invocation {
            instance_id: instance.into(),
            effect_id: effect.effect_id.clone(),
            attempt_admission_event_id: effect.attempt_admission_event_id.clone(),
        };
        let run = selected.run_id();
        let original = kernel
            .store()
            .list_runs(instance)?
            .into_iter()
            .find(|row| row.run_id == run);
        let (binding, request) = if let Some(original) = original {
            let metadata: Value = serde_json::from_str(&original.metadata_json)?;
            if metadata["executor_transport"] != "native-managed" {
                return Err(StoreError::Conflict(
                    "managed norm cannot adopt an untracked or foreign run".into(),
                ));
            }
            let binding: NativeRuntimeImage =
                serde_json::from_value(metadata["native_runtime"].clone())?;
            binding.validate_for(&method.runtime)?;
            let handoff = exec_handoff::retained(kernel.store(), instance, effect, vec![])?;
            if handoff.request().url != "whip-executor://native/exec" {
                return Err(StoreError::Conflict(
                    "managed norm cannot reattach another executor".into(),
                ));
            }
            (binding, handoff.request().clone())
        } else {
            let proofs = exec_lifetime::proofs(kernel.store(), instance)?;
            if kernel.store().list_runs(instance)?.iter().any(|prior| {
                prior.effect_id == effect.effect_id && !proofs.contains_key(&prior.run_id)
            }) {
                return Err(StoreError::Conflict(
                    "managed norm cannot redispatch an unclosed or legacy execution".into(),
                ));
            }
            let lease_expires_at = lease_expiry(now)?;
            installed.validate_for(&method.runtime)?;
            let capability = input["capability"].as_str().unwrap_or_default();
            let script = kernel
                .store()
                .get_script_capability(capability)?
                .ok_or_else(|| {
                    StoreError::Conflict("managed norm observer is not registered".into())
                })?;
            let argv: Vec<String> = serde_json::from_str(&script.argv_json)?;
            let declared_env: std::collections::BTreeMap<String, String> =
                serde_json::from_str(&script.env_json)?;
            if script.body != method.adapter()
                || script.sha256 != sha256_hex(script.body.as_bytes())
                || argv
                    != [
                        method.runtime.executable.clone(),
                        "executor".into(),
                        "observe-norm".into(),
                        "{script}".into(),
                    ]
                || !declared_env.is_empty()
            {
                return Err(StoreError::Conflict(
                    "managed norm registration differs from its declared observer".into(),
                ));
            }
            let request = build_executor_exec_request(
                "whip-executor://native",
                &effect.effect_id,
                &script.sha256,
                &script.body,
                &argv,
                &[],
                &input["stdin"],
                Some(30_000),
            )
            .map_err(StoreError::Conflict)?;
            let plan = ExecDispatchPlan::prepare(
                capability,
                &script.sha256,
                &input,
                &request,
                &installed.runtime.environment,
                script.hermetic.then(|| "norm-cache-forbidden".into()),
                input.get("parse").cloned(),
            );
            validate_norm_dispatch(&input, &plan).map_err(StoreError::Conflict)?;
            let envelope =
                Envelope::new(selected, request.body.clone()).map_err(StoreError::Conflict)?;
            let metadata = json!({"mode":"capability", "capability":capability, "executor_dispatch":plan, "executor_invocation":envelope, "executor_url":request.url, "executor_transport":"native-managed", "native_runtime":installed}).to_string();
            let lease = whipplescript_kernel::execution_attempt_key(
                instance,
                &effect.effect_id,
                effect.attempt_admission_event_id.as_deref(),
                "exec-lease",
            );
            kernel.start_run_for_admission(
                RunStart {
                    instance_id: instance,
                    effect_id: &effect.effect_id,
                    run_id: &run,
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: &lease,
                    lease_expires_at: &lease_expires_at,
                    metadata_json: &metadata,
                },
                effect.attempt_admission_event_id.as_deref(),
            )?;
            (installed.clone(), request)
        };
        let plan =
            ExecDispatchPlan::load(kernel.store(), instance, &effect.effect_id, &run, &input)?;
        validate_norm_dispatch(&input, &plan).map_err(StoreError::Conflict)?;
        if plan.environment_epoch != binding.runtime.environment {
            return Err(StoreError::Conflict(
                "native norm retained runtime differs from its dispatch environment".into(),
            ));
        }
        let handoff = exec_handoff::select_tracked(kernel.store_mut(), instance, effect, request)?;
        let candidate = if exec_lifetime::fences(kernel.store(), instance)?.contains_key(&run) {
            None
        } else {
            Some(
                kernel
                    .store_mut()
                    .allocate_native_executor(Allocation {
                        instance_id: instance,
                        run_id: &run,
                        daemon_id: &binding.daemon_id,
                        image_id: &binding.image_id,
                    })?
                    .owner,
            )
        };
        Ok(Self {
            handoff,
            binding,
            candidate,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;

pub(super) use whipplescript_kernel::norm_execution::lease_expiry;
