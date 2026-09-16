//! Bind accepted support data to captured source before durable execution.
//! Host script registration and history verification are trusted inputs. This
//! module grants neither execution authority nor permission to publish evidence.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_core::norm_evidence::{
    AssertionObservation, EvidenceSubject, EvidenceVersion, ReportContract, ReportVerifier,
    RequiredCase, TestReport,
};
use whipplescript_store::norm::NormVerifier;
use whipplescript_store::norm_artifact::{ArtifactBasis, CapturedArtifact};
use whipplescript_store::norm_history::{CapturedNormHistory, NormReadAnchor};
use whipplescript_store::{
    NewEffect, RuleCommit, RuleCommitRevisionGuard, RuntimeStore, ScriptCapabilityRecord,
    StoreError, StoreResult, StoredEvent,
};

use crate::exec_http::{sha256_hex, ExecDispatchPlan};
use crate::norm_runner::{
    candidate_identity, ObserverIntegrity, PreparedNormRun, PythonCallMethod, RunnerObservation,
};
use crate::sansio::{HttpRequest, HttpResponse};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", deny_unknown_fields)]
pub enum PythonCallSupport {
    #[serde(rename = "whipplescript.norm.python-calls-support/v1")]
    V1 {
        method: PythonCallMethod,
        cases: Vec<RequiredCase>,
    },
}

pub struct NormRunSelection<'a> {
    pub ledger: &'a str,
    pub frontier: Option<&'a [String]>,
    pub requirement: &'a str,
    pub effect_id: &'a str,
    pub publisher: &'a str,
    pub executor_url: &'a str,
    pub environment_epoch: &'a str,
}

/// Host-owned inputs for enqueue preparation. None of these references is a
/// request-supplied verification credential; hosts capture their own sources.
pub struct NormEnqueuePreparation<'a> {
    pub history: &'a CapturedNormHistory,
    pub verifier: &'a dyn NormVerifier,
    pub artifact: &'a CapturedArtifact,
    pub installed: Option<&'a ScriptCapabilityRecord>,
    pub capability: &'a str,
    pub selection: NormRunSelection<'a>,
}

/// Serializable recovery coordinates, never proof of verification or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormRunIntent {
    pub anchor: NormReadAnchor,
    pub requirement: EvidenceVersion,
    pub artifact: ArtifactBasis,
    pub effect_id: String,
    pub publisher: String,
}

/// Serializable consistency constraint, never preparation or execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormDispatchBinding {
    protocol: String,
    request_body_sha256: String,
    environment_epoch: String,
}
impl NormDispatchBinding {
    pub fn for_request(request: &HttpRequest, environment_epoch: &str) -> Self {
        Self {
            protocol: "whipplescript.norm.dispatch-binding/v1".into(),
            request_body_sha256: sha256_hex(request.body.to_string().as_bytes()),
            environment_epoch: environment_epoch.into(),
        }
    }
}

/// Check the host's actual plan before run admission, cache lookup or dispatch.
/// Ordinary exec inputs pass through; a norm marker requires a recognized pin.
/// The caller must still apply ordinary runtime execution policy.
pub fn validate_norm_dispatch(input: &Value, plan: &ExecDispatchPlan) -> Result<(), String> {
    if input.get("norm_intent").is_none() && input.get("norm_dispatch").is_none() {
        return Ok(());
    }
    if input.get("norm_intent").is_none() {
        return Err("norm dispatch binding requires invocation intent".into());
    }
    let binding = input.get("norm_dispatch");
    if binding.is_none() {
        return Err("norm dispatch requires a prepared-request binding".into());
    }
    let binding: NormDispatchBinding =
        serde_json::from_value(binding.expect("binding presence was checked").clone())
            .map_err(|error| format!("invalid norm dispatch binding: {error}"))?;
    if binding.protocol != "whipplescript.norm.dispatch-binding/v1" {
        return Err("norm dispatch binding protocol is unsupported".into());
    }
    if binding.request_body_sha256 != plan.request_body_sha256 {
        return Err("norm dispatch request differs from its prepared body".into());
    }
    if binding.environment_epoch != plan.environment_epoch {
        return Err("norm dispatch environment differs from its prepared epoch".into());
    }
    if plan.content_key.is_some() {
        return Err("norm dispatch cannot reuse a content-cache result".into());
    }
    if plan.parse_contract.is_some() {
        return Err("norm dispatch cannot substitute a parse contract".into());
    }
    Ok(())
}

/// Only constructed from verified history and independently captured bytes.
/// Its request still needs normal runtime capability authorization and durable
/// dispatch; receiving this value does not attest that anything has executed.
#[derive(Clone, Debug)]
pub struct PreparedNormExecution {
    intent: NormRunIntent,
    runner: PreparedNormRun,
    request: HttpRequest,
    input: Value,
    environment_epoch: String,
    capability: String,
}
impl PreparedNormExecution {
    /// Recover the selection of an existing invocation before atomic enqueue.
    /// This returns no acknowledgment and grants no execution authority. The
    /// enqueue transaction still compares input, deadline and original revision.
    pub fn prepare_enqueue<S: RuntimeStore>(
        store: &S,
        instance_id: &str,
        request: NormEnqueuePreparation<'_>,
    ) -> Result<Self, String> {
        let NormEnqueuePreparation {
            history,
            verifier,
            artifact,
            installed,
            capability,
            mut selection,
        } = request;
        let existing = store
            .list_effects(instance_id)
            .map_err(|e| format!("{e:?}"))?
            .into_iter()
            .find(|effect| effect.effect_id == selection.effect_id);
        let Some(existing) = existing else {
            let installed = installed.ok_or("norm enqueue observer is not registered")?;
            if installed.name != capability {
                return Err("norm enqueue registration names another capability".into());
            }
            return Self::prepare(history, verifier, artifact, installed, selection);
        };
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|e| format!("invalid retained norm input: {e}"))?;
        let intent: NormRunIntent = serde_json::from_value(input["norm_intent"].clone())
            .map_err(|e| format!("invalid retained norm intent: {e}"))?;
        let dispatch: NormDispatchBinding = serde_json::from_value(input["norm_dispatch"].clone())
            .map_err(|e| format!("invalid retained norm dispatch: {e}"))?;
        let retained_frontier: Vec<_> = intent.anchor.frontier.iter().cloned().collect();
        if selection.frontier.is_none() {
            selection.frontier = Some(&retained_frontier);
        }
        // The epoch is a historical reconstruction coordinate, never a request
        // to change the actual host environment used by future dispatch.
        selection.environment_epoch = &dispatch.environment_epoch;
        let prepared = Self::bind(history, verifier, artifact, capability, selection)?;
        if existing.kind != "exec.command" || prepared.input != input {
            return Err("norm enqueue retry differs from its retained invocation".into());
        }
        Ok(prepared)
    }

    pub fn prepare(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifact: &CapturedArtifact,
        installed: &ScriptCapabilityRecord,
        selection: NormRunSelection<'_>,
    ) -> Result<Self, String> {
        let prepared = Self::bind(history, verifier, artifact, &installed.name, selection)?;
        prepared.runner.validate_installation(installed)?;
        Ok(prepared)
    }

    // Constructs only an internal candidate. Public preparation verifies current
    // installation; recovery instead verifies the historical journal/receipt
    // before exposing any value, and never returns this dispatchable candidate.
    fn bind(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifact: &CapturedArtifact,
        capability: &str,
        selection: NormRunSelection<'_>,
    ) -> Result<Self, String> {
        let view = history
            .project(selection.frontier, verifier)
            .map_err(|e| format!("{e:?}"))?;
        if view.ledger != selection.ledger {
            return Err("norm preparation selected a different ledger".into());
        }
        if selection.publisher.trim().is_empty() || capability.trim().is_empty() {
            return Err(
                "norm preparation requires publisher and installed capability identities".into(),
            );
        }
        let inventory = view.requirement_inventory().map_err(|e| format!("{e:?}"))?;
        let selected = inventory
            .requirements
            .get(selection.requirement)
            .ok_or("norm preparation requires an active requirement")?;
        let (contract, method) = Self::requirement_support(selected, artifact)?;
        let requirement = contract.subject.requirement.clone();
        if method.runtime.environment != selection.environment_epoch {
            return Err("norm method environment differs from the selected executor epoch".into());
        }
        let runner = PreparedNormRun::prepare_from_artifact(
            contract,
            method,
            artifact,
            selection.effect_id.into(),
        )?;
        let request = runner.executor_request(selection.executor_url)?;
        let intent = NormRunIntent {
            anchor: NormReadAnchor {
                checkpoint: view.checkpoint(),
                frontier: view.frontier,
            },
            requirement,
            artifact: artifact.basis().clone(),
            effect_id: selection.effect_id.into(),
            publisher: selection.publisher.into(),
        };
        let input = json!({"mode":"capability", "capability":capability, "stdin":request.body["stdin"], "norm_intent":intent, "norm_dispatch":NormDispatchBinding::for_request(&request, selection.environment_epoch)});
        Ok(Self {
            intent,
            runner,
            request,
            input,
            environment_epoch: selection.environment_epoch.into(),
            capability: capability.into(),
        })
    }
    pub(crate) fn requirement_support(
        selected: &whipplescript_store::norm_inventory::InventoryRequirement,
        artifact: &CapturedArtifact,
    ) -> Result<(ReportContract, PythonCallMethod), String> {
        let requirement = selected
            .requirement
            .clone()
            .ok_or("norm requirement has no usable identity")?;
        let template = selected
            .declaration
            .as_ref()
            .and_then(|d| d.support_contract.as_ref())
            .ok_or("norm requirement has no support template")?;
        let PythonCallSupport::V1 { method, cases } = serde_json::from_str(template)
            .map_err(|e| format!("invalid norm support template: {e}"))?;
        let contract = ReportContract {
            subject: EvidenceSubject {
                requirement: requirement.clone(),
                method: method.reference(),
                artifact: candidate_identity(artifact.files()),
            },
            cases,
        };
        Ok((contract, method))
    }

    pub fn intent(&self) -> &NormRunIntent {
        &self.intent
    }
    pub fn runner(&self) -> &PreparedNormRun {
        &self.runner
    }
    pub fn request(&self) -> &HttpRequest {
        &self.request
    }
    pub fn effect_input(&self) -> &Value {
        &self.input
    }

    /// Persist a prepared invocation through ordinary runtime admission. The
    /// optional deadline includes queue time; it is not the executor timeout.
    /// An existing effect supplies only its original revision coordinates: the
    /// atomic rule commit still checks every immutable payload field on replay.
    pub fn enqueue<S: RuntimeStore>(
        &self,
        kernel: &mut crate::RuntimeKernel<S>,
        instance_id: &str,
        deadline_seconds: Option<u32>,
    ) -> StoreResult<StoredEvent> {
        let instance = kernel.store().get_instance(instance_id)?;
        if instance.is_none() {
            return Err(StoreError::Conflict(
                "norm enqueue requires an existing runtime instance".into(),
            ));
        }
        let instance = instance.expect("instance presence was checked");
        let existing = kernel
            .store()
            .list_effects(instance_id)?
            .into_iter()
            .find(|effect| effect.effect_id == self.intent.effect_id);
        let (version, epoch) = match existing {
            Some(effect) => {
                if effect.program_version_id.is_none() {
                    return Err(StoreError::Conflict(
                        "norm enqueue has no original program revision".into(),
                    ));
                }
                (
                    effect
                        .program_version_id
                        .expect("original revision presence was checked"),
                    effect.revision_epoch,
                )
            }
            None => (instance.version_id, instance.revision_epoch),
        };
        let input = self.input.to_string();
        let required = json!([format!("script.{}", self.capability)]).to_string();
        let key = crate::idempotency_key(&["norm.enqueue", instance_id, &self.intent.effect_id]);
        let effect_key =
            crate::idempotency_key(&["norm.execute", instance_id, &self.intent.effect_id]);
        let effects = [NewEffect {
            effect_id: &self.intent.effect_id,
            kind: "exec.command",
            target: None,
            input_json: &input,
            status: "queued",
            idempotency_key: &effect_key,
            required_capabilities_json: &required,
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: deadline_seconds.map(i64::from),
        }];
        kernel.commit_rule_with_revision_guard(
            RuleCommit {
                instance_id,
                rule: "norm.execute",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some(&key),
                marks: &[],
                context_json: None,
            },
            RuleCommitRevisionGuard {
                program_version_id: &version,
                revision_epoch: epoch,
            },
        )
    }
}

/// A bound observation read from durable executor settlement. This is not an
/// observation-publication grant or a claim of requirement conformance.
#[derive(Clone, Debug)]
pub struct VerifiedNormExecution {
    method: PythonCallMethod,
    contract: ReportContract,
    intent: NormRunIntent,
    instance_id: String,
    run_id: String,
    observation: RunnerObservation,
}
impl VerifiedNormExecution {
    /// Full method reconstructed from the captured historical requirement.
    pub fn method(&self) -> &PythonCallMethod {
        &self.method
    }
    /// Reconstructed from the historically accepted requirement and original
    /// captured artifact, never from the published report's case inventory.
    pub fn contract(&self) -> &ReportContract {
        &self.contract
    }
    pub fn intent(&self) -> &NormRunIntent {
        &self.intent
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn observation(&self) -> &RunnerObservation {
        &self.observation
    }
}
// This binding establishes the recovered adapter's exercise evidence only.
// Consumers must separately admit its observer integrity under their policy,
// and authenticate its publication in the selected causal ledger history.
impl ReportVerifier for VerifiedNormExecution {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        report == &self.observation.report
    }

    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        self.verify_report_binding(report)
            && self.observation.report.observations.contains(observation)
    }
}
impl PreparedNormExecution {
    fn recovery_coordinates<S: RuntimeStore>(
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<(whipplescript_store::RunView, Value, NormRunIntent), String> {
        let runs = store.list_runs(instance_id).map_err(|e| format!("{e:?}"))?;
        let run = runs
            .into_iter()
            .find(|r| r.run_id == run_id)
            .ok_or("norm execution run is missing from the journal")?;
        let effects = store
            .list_effects(instance_id)
            .map_err(|e| format!("{e:?}"))?;
        let effect = effects
            .into_iter()
            .find(|e| e.effect_id == run.effect_id)
            .ok_or("norm execution effect is missing from the journal")?;
        let input: Value = serde_json::from_str(&effect.input_json).map_err(|e| e.to_string())?;
        let intent: NormRunIntent = serde_json::from_value(input["norm_intent"].clone())
            .map_err(|e| format!("invalid norm run intent: {e}"))?;
        Ok((run, input, intent))
    }

    /// Capture the journal-selected cut through a host-owned reader, then
    /// independently reconstruct execution. A serialized cut name supplies
    /// coordinates only, never file bytes or verification authority.
    pub fn recover_with_artifacts<S: RuntimeStore>(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifacts: &whipplescript_store::norm_commands::NormArtifactCapture<'_>,
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<VerifiedNormExecution, String> {
        let (_, _, intent) = Self::recovery_coordinates(store, instance_id, run_id)?;
        let artifact = artifacts(&intent.artifact.cut).map_err(|e| format!("{e:?}"))?;
        Self::recover_settled(history, verifier, &artifact, store, instance_id, run_id)
    }

    /// Recover without the original in-memory preparation or current script
    /// registry. Journal coordinates select independently captured evidence;
    /// neither the journal's serialized files nor its method claims are trusted.
    pub fn recover_settled<S: RuntimeStore>(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifact: &CapturedArtifact,
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<VerifiedNormExecution, String> {
        let (run, input, intent) = Self::recovery_coordinates(store, instance_id, run_id)?;
        let metadata: Value =
            serde_json::from_str(&run.metadata_json).map_err(|e| e.to_string())?;
        let plan: ExecDispatchPlan = serde_json::from_value(metadata["executor_dispatch"].clone())
            .map_err(|e| format!("invalid norm dispatch plan: {e}"))?;
        let frontier: Vec<_> = intent.anchor.frontier.iter().cloned().collect();
        let mut prepared = Self::bind(
            history,
            verifier,
            artifact,
            input["capability"]
                .as_str()
                .ok_or("norm execution capability is missing")?,
            NormRunSelection {
                ledger: &intent.anchor.checkpoint.ledger,
                frontier: Some(&frontier),
                requirement: &intent.requirement.name,
                effect_id: &intent.effect_id,
                publisher: &intent.publisher,
                // Only the expected body is used. Recovery never dispatches or
                // follows an endpoint supplied by the journal.
                executor_url: "https://norm-recovery.invalid",
                environment_epoch: &plan.environment_epoch,
            },
        )?;
        // The original v1 input predates dispatch pins. Reconstruct that exact
        // shape only inside terminal recovery; this candidate never escapes as
        // a dispatchable preparation. verify_settled still checks every field.
        if input.get("norm_dispatch").is_none() {
            prepared
                .input
                .as_object_mut()
                .expect("prepared object")
                .remove("norm_dispatch");
        }
        prepared.verify_settled(store, instance_id, run_id)
    }

    /// Reconstruct judgment from the durable receipt, never from stored judgment
    /// labels. The host must supply its authoritative runtime store and original
    /// verified preparation (or independently reconstruct that preparation).
    pub fn verify_settled<S: RuntimeStore>(
        &self,
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<VerifiedNormExecution, String> {
        let effects = store
            .list_effects(instance_id)
            .map_err(|e| format!("{e:?}"))?;
        let effect = effects
            .iter()
            .find(|e| e.effect_id == self.intent.effect_id)
            .ok_or("norm execution effect is missing from the journal")?;
        let input: Value = serde_json::from_str(&effect.input_json).map_err(|e| e.to_string())?;
        if effect.kind != "exec.command" || input != self.input {
            return Err("norm execution requires its exact effect input".into());
        }
        let runs = store.list_runs(instance_id).map_err(|e| format!("{e:?}"))?;
        let run = runs
            .iter()
            .find(|r| r.run_id == run_id)
            .ok_or("norm execution run is missing from the journal")?;
        if run.effect_id != effect.effect_id
            || run.provider != "exec"
            || run.worker_id != "whip-exec"
            || !matches!(run.status.as_str(), "completed" | "failed")
            || run.completed_at.is_none()
        {
            return Err("norm execution requires its terminal executor run".into());
        }
        let metadata: Value =
            serde_json::from_str(&run.metadata_json).map_err(|e| e.to_string())?;
        let plan: ExecDispatchPlan = serde_json::from_value(metadata["executor_dispatch"].clone())
            .map_err(|e| format!("invalid norm dispatch plan: {e}"))?;
        // Endpoint selection remains a host transport premise. The expected
        // execution body is unchanged if that endpoint is subsequently moved.
        let expected = ExecDispatchPlan::prepare(
            self.input["capability"]
                .as_str()
                .expect("prepared capability"),
            self.request.body["script_sha256"]
                .as_str()
                .expect("prepared script digest"),
            &self.input,
            &self.request,
            &self.environment_epoch,
            None,
            None,
        );
        if plan.protocol != expected.protocol
            || plan.capability != expected.capability
            || plan.script_sha256 != expected.script_sha256
            || plan.input_sha256 != expected.input_sha256
            || plan.request_body_sha256 != expected.request_body_sha256
            || plan.environment_epoch != expected.environment_epoch
            || plan.content_key.is_some()
            || plan.parse_contract.is_some()
        {
            return Err("norm execution dispatch differs from its prepared invocation".into());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Receipt {
            status: u16,
            body: Value,
        }
        let receipt: Receipt = serde_json::from_value(metadata["executor_response"].clone())
            .map_err(|e| format!("invalid norm executor receipt: {e}"))?;
        let observation = self.runner.finish(&HttpResponse {
            status: receipt.status,
            body: receipt.body,
        })?;
        let unbound = matches!(
            observation.observation_integrity,
            ObserverIntegrity::Unbound {}
        );
        if unbound {
            return Err("norm executor receipt has no bound observer header".into());
        }
        Ok(VerifiedNormExecution {
            method: self.runner.method().clone(),
            contract: self.runner.contract().clone(),
            intent: self.intent.clone(),
            instance_id: instance_id.into(),
            run_id: run_id.into(),
            observation,
        })
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_execution_tests.rs"]
mod tests;

#[cfg(all(feature = "native", any(test, feature = "test-support")))]
#[path = "norm_execution_fixtures.rs"]
pub mod fixtures;

/// Shared native/hosted norm lease bound. Replay must reuse its original deadline.
pub fn lease_expiry(now: &str) -> Result<String, whipplescript_store::StoreError> {
    use whipplescript_store::StoreError;
    let instant = chrono::DateTime::parse_from_rfc3339(now)
        .map_err(|_| StoreError::Conflict("norm admission clock is invalid".into()))?
        .with_timezone(&chrono::Utc);
    if now.len() != 20 || instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != now {
        return Err(StoreError::Conflict(
            "norm admission requires a UTC clock with second precision".into(),
        ));
    }
    let expiry = instant
        .checked_add_signed(chrono::TimeDelta::seconds(600))
        .ok_or_else(|| StoreError::Conflict("norm execution lease overflow".into()))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    if expiry.len() != 20 {
        return Err(StoreError::Conflict(
            "norm execution lease is outside its timestamp range".into(),
        ));
    }
    Ok(expiry)
}

pub const NORM_EXECUTION_LEASE_PROTOCOL: &str = "whipplescript.norm.execution-lease/v1";
