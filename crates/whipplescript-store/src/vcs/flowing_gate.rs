//! Store-only native-cut gate runner. A trusted planner derives the current
//! policy, coverage and ordered checks from the exact retained candidate.
//! This module recaptures that plan after execution and retains raw output
//! with the certificate. Hosted transport and plan authority remain separate
//! prerequisites.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::NativeWorkspaceVcs;
use crate::branches::flowing_admission::{
    FlowingAdmissions, FlowingGateCertificate, FlowingGateCheck, FlowingGateEvidence,
};
use crate::branches::flowing_fence::FlowingFence;
use crate::branches::{BranchStatus, Branches, MAINLINE_BRANCH_ID};
use crate::materialize::materialize_manifest;
use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeGateCommand {
    pub check_id: String,
    pub program: String,
    pub args: Vec<String>,
}

/// These digests and the complete command list must come from an authoritative
/// planner. The store cannot infer current norm policy or Home-wide graph
/// coverage from a candidate manifest alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeGatePlan {
    pub attempt_op_id: String,
    pub coordinator: String,
    pub policy_digest: String,
    pub rules_digest: String,
    pub graph_coverage_digest: String,
    pub checks: Vec<NativeGateCommand>,
}

/// Derive the required plan from the retained candidate and current policy,
/// rules, graph coverage and world inputs. Return an error if any required
/// scope is unknown. The runner invokes this twice, but the admission door
/// must still recapture mutable premises under its ref exclusion.
pub trait NativeGatePlanAuthority {
    fn required_plan(
        &mut self,
        vcs: &NativeWorkspaceVcs,
        witness_digest: &str,
        attempt_op_id: &str,
    ) -> StoreResult<NativeGatePlan>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeGateRun {
    pub handle: String,
    pub certificate: FlowingGateCertificate,
}

/// Result returned by the trusted check executor. A host implementation must
/// provide process isolation, time/output bounds and its own rule identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeGateExecution {
    pub exit_code: Option<i32>,
    pub started: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub run_error: Option<String>,
}

pub trait NativeGateExecutor {
    fn run(&mut self, check: &NativeGateCommand, cut_root: &Path) -> NativeGateExecution;
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("native candidate gate refuses: {reason}"))
}

impl NativeWorkspaceVcs {
    /// Run every planned check in its own fresh projection of the retained
    /// candidate cut. A failure is recorded as Failed, and a process that
    /// cannot start is Unrun; neither can authorize ref admission. The scratch
    /// path must be absent and is left for the caller to inspect or remove.
    /// This is an internal native proof seam, not an untrusted host endpoint.
    pub fn run_native_candidate_gate(
        &mut self,
        witness_digest: &str,
        attempt_op_id: &str,
        scratch: &Path,
        authority: &mut impl NativeGatePlanAuthority,
        executor: &mut impl NativeGateExecutor,
    ) -> StoreResult<NativeGateRun> {
        if witness_digest.trim().is_empty() || attempt_op_id.trim().is_empty() {
            return Err(invalid("candidate or attempt identity is incomplete"));
        }
        let plan = authority.required_plan(self, witness_digest, attempt_op_id)?;
        if plan.attempt_op_id.trim().is_empty()
            || plan.attempt_op_id != attempt_op_id
            || plan.coordinator.trim().is_empty()
            || plan.policy_digest.trim().is_empty()
            || plan.rules_digest.trim().is_empty()
            || plan.graph_coverage_digest.trim().is_empty()
            || plan.checks.is_empty()
        {
            return Err(invalid("plan is incomplete"));
        }
        let mut seen = BTreeSet::new();
        for check in &plan.checks {
            if check.check_id.trim().is_empty()
                || check.program.trim().is_empty()
                || !seen.insert(check.check_id.as_str())
            {
                return Err(invalid("check identity or command is incomplete"));
            }
        }
        if scratch.exists() {
            return Err(invalid("scratch path must be absent"));
        }
        let Some(witness) = self.branches.candidate_witness(witness_digest)? else {
            return Err(invalid("candidate witness is missing"));
        };
        let Some(pin) = self.branches.flowing_attempt_pin(&plan.attempt_op_id)? else {
            return Err(invalid("candidate attempt is not retained"));
        };
        if pin.released_at.is_some()
            || pin.witness_digest != witness_digest
            || pin.source_cut_id != witness.source_cut_id
            || pin.candidate_cut_id != witness.candidate_cut_id
        {
            return Err(invalid("candidate attempt pin differs from witness"));
        }
        if self
            .branches
            .flowing_cancellation_for_attempt(&plan.attempt_op_id)?
            .is_some()
        {
            return Err(invalid("candidate attempt was cancelled"));
        }
        let Some(fence) = self.branches.flowing_source(&witness.source_branch_id)? else {
            return Err(invalid("source fence is missing"));
        };
        if fence.incarnation_id != witness.source_incarnation_id
            || fence.owner != plan.coordinator
            || !fence.admission_enabled
            || fence.held
            || fence.revision.is_some()
        {
            return Err(invalid("source eligibility or coordinator changed"));
        }
        let Some(trunk) = self.branches.get_branch(MAINLINE_BRANCH_ID)? else {
            return Err(invalid("trunk is missing"));
        };
        if trunk.status != BranchStatus::Active
            || trunk.head_cut_id != witness.expected_trunk_cut_id
        {
            return Err(invalid("trunk base changed"));
        }
        let Some(cut) = self.branches.get_cut(&witness.candidate_cut_id)? else {
            return Err(invalid("candidate cut is missing"));
        };
        if cut.branch_id != MAINLINE_BRANCH_ID
            || cut.manifest_hash != witness.candidate_manifest_hash
            || (witness.expected_trunk_cut_id.as_deref() != Some(witness.candidate_cut_id.as_str())
                && cut.parent_cut_id != witness.expected_trunk_cut_id)
        {
            return Err(invalid("candidate cut differs from retained witness"));
        }
        let manifest = self.load_manifest(Some(&cut.manifest_hash))?;
        std::fs::create_dir(scratch).map_err(|error| {
            invalid(&format!(
                "cannot create scratch {}: {error}",
                scratch.display()
            ))
        })?;

        let mut results = Vec::with_capacity(plan.checks.len());
        let mut evidence = Vec::with_capacity(plan.checks.len());
        for (index, check) in plan.checks.iter().enumerate() {
            let check_scratch = scratch.join(format!("check-{index:04}"));
            materialize_manifest(&manifest, &self.content, &check_scratch, 0)?;
            let input = serde_json::to_vec(&(
                "native-gate-check-input-v1",
                &plan.attempt_op_id,
                witness_digest,
                &witness.candidate_cut_id,
                &witness.candidate_manifest_hash,
                &plan.policy_digest,
                &plan.rules_digest,
                &plan.graph_coverage_digest,
                check,
            ))?;
            let input_digest = format!("sha256:{}", crate::chunking::content_hash_hex(&input));
            let execution = executor.run(check, &check_scratch);
            let result = FlowingGateEvidence {
                attempt_op_id: plan.attempt_op_id.clone(),
                check_id: check.check_id.clone(),
                input_digest,
                program: check.program.clone(),
                args: check.args.clone(),
                exit_code: execution.exit_code,
                started: execution.started,
                stdout: execution.stdout,
                stderr: execution.stderr,
                run_error: execution.run_error,
            };
            results.push(FlowingGateCheck {
                check_id: check.check_id.clone(),
                input_digest: result.input_digest.clone(),
                evidence_digest: result.digest()?,
                verdict: result.verdict(),
            });
            evidence.push(result);
        }
        // A worker can spend minutes in the checks. Do not issue a certificate
        // for a changed base, source fence or required plan. The final ref
        // transaction must check mutable premises again under CAS.
        let current_trunk = self.branches.get_branch(MAINLINE_BRANCH_ID)?;
        let current_fence = self.branches.flowing_source(&witness.source_branch_id)?;
        let current_pin = self.branches.flowing_attempt_pin(&plan.attempt_op_id)?;
        if current_trunk.as_ref().map(|row| &row.head_cut_id)
            != Some(&witness.expected_trunk_cut_id)
            || current_fence.as_ref() != Some(&fence)
            || current_pin.as_ref() != Some(&pin)
            || self
                .branches
                .flowing_cancellation_for_attempt(&plan.attempt_op_id)?
                .is_some()
        {
            return Err(invalid("trunk or source changed during checks"));
        }
        if authority.required_plan(self, witness_digest, attempt_op_id)? != plan {
            return Err(invalid("required plan changed during checks"));
        }
        let certificate = FlowingGateCertificate {
            candidate_witness_digest: witness_digest.to_owned(),
            expected_trunk_cut_id: witness.expected_trunk_cut_id,
            candidate_cut_id: witness.candidate_cut_id,
            candidate_manifest_hash: witness.candidate_manifest_hash,
            source_eligibility_epoch: fence.eligibility_epoch,
            source_owner_epoch: fence.owner_epoch,
            coordinator: plan.coordinator.clone(),
            policy_digest: plan.policy_digest.clone(),
            rules_digest: plan.rules_digest.clone(),
            graph_coverage_digest: plan.graph_coverage_digest.clone(),
            required_checks: plan
                .checks
                .iter()
                .map(|check| check.check_id.clone())
                .collect(),
            checks: results,
        };
        let handle = self
            .branches
            .record_native_gate_certificate(&certificate, &evidence)?;
        Ok(NativeGateRun {
            handle,
            certificate,
        })
    }
}
