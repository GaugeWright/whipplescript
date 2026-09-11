//! An execution grant is scoped to one synchronous handler invocation. It is
//! consumed before dispatch and cleared even if that handler unwinds.
use std::ops::{Deref, DerefMut};

use whipplescript_store::files::FileStore;
use whipplescript_store::{
    ClaimableEffect, RunStart, RuntimeStore, StoreError, StoreResult, StoredEvent,
};

use crate::host_protocol::execution::VerifiedActionExecution;
use crate::RuntimeKernel;

struct ExecutionScope<'a, S: RuntimeStore>(&'a mut RuntimeKernel<S>);
impl<S: RuntimeStore> Deref for ExecutionScope<'_, S> {
    type Target = RuntimeKernel<S>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
impl<S: RuntimeStore> DerefMut for ExecutionScope<'_, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}
impl<S: RuntimeStore> Drop for ExecutionScope<'_, S> {
    fn drop(&mut self) {
        self.0.action_execution = None;
    }
}

fn is_action(instance: &str) -> bool {
    instance.starts_with(whipplescript_store::host_actions::HOST_ACTION_INSTANCE_PREFIX)
}

impl<S: RuntimeStore> RuntimeKernel<S> {
    pub(crate) fn execute_verified_tracker_closure(
        &mut self,
        verified: VerifiedActionExecution,
        closure: &whipplescript_store::tracker_closure::TrackerClosure,
        binding: &crate::tracker_closure::TrackerClosureBinding,
    ) -> StoreResult<StoredEvent>
    where
        S: whipplescript_store::tracker_closure::TrackerClosures
            + whipplescript_store::items::WorkItems
            + whipplescript_store::vcs::FrontierRead,
    {
        let instance = verified.request().admission.instance_ref.clone();
        let effect = verified.observed().clone();
        self.action_execution = Some(verified);
        let mut scope = ExecutionScope(self);
        crate::tracker_closure::run(&mut scope, &instance, &effect, closure, binding)
    }

    pub(crate) fn execute_verified_tracker_wait(
        &mut self,
        verified: VerifiedActionExecution,
    ) -> StoreResult<StoredEvent> {
        let instance = verified.request().admission.instance_ref.clone();
        let effect = verified.observed().clone();
        self.action_execution = Some(verified);
        let mut scope = ExecutionScope(self);
        crate::tracker_wait::run_governed(&mut scope, &instance, &effect)
    }

    pub(crate) fn execute_verified_tracker_filing(
        &mut self,
        verified: VerifiedActionExecution,
        filing: &whipplescript_store::tracker_filing::TrackerFiling,
        binding: &crate::tracker_filing::TrackerBinding,
    ) -> StoreResult<StoredEvent>
    where
        S: whipplescript_store::tracker_filing::TrackerFilings,
    {
        let instance = verified.request().admission.instance_ref.clone();
        let effect = verified.observed().clone();
        self.action_execution = Some(verified);
        let mut scope = ExecutionScope(self);
        crate::tracker_filing::run(&mut scope, &instance, &effect, filing, binding)
    }

    pub(crate) fn refuse_unverified_action_dispatch(&self, run: RunStart<'_>) -> StoreResult<()> {
        if is_action(run.instance_id) {
            return Err(StoreError::Conflict(
                "action dispatch requires fresh verified execution authority".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn action_dispatch_metadata(
        &mut self,
        run: RunStart<'_>,
        expected: &ClaimableEffect,
    ) -> StoreResult<Option<String>> {
        let Some(grant) = self.action_execution.take() else {
            self.refuse_unverified_action_dispatch(run)?;
            return Ok(None);
        };
        if grant.request().admission.instance_ref != run.instance_id
            || grant.request().effect_id != run.effect_id
            || grant.observed() != expected
        {
            return Err(StoreError::Conflict(
                "execution grant does not bind this dispatch observation".into(),
            ));
        }
        let mut metadata: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(run.metadata_json)?;
        // Overwrite any caller-supplied lookalike with the kernel's verified
        // evidence. The recorded value cannot reconstruct this transient grant.
        metadata.insert("action_execution".into(), grant.evidence());
        Ok(Some(serde_json::to_string(&metadata)?))
    }

    pub(crate) fn execute_verified_resolution_recording<
        B: whipplescript_store::branches::Branches,
        C: whipplescript_store::content::ContentBlobs,
    >(
        &mut self,
        verified: VerifiedActionExecution,
        target: &mut whipplescript_store::vcs_resolution_recording::BoundResolutionRecording<B, C>,
    ) -> StoreResult<StoredEvent> {
        let instance = verified.request().admission.instance_ref.clone();
        let effect = verified.observed().clone();
        self.action_execution = Some(verified);
        let mut scope = ExecutionScope(self);
        crate::resolution_recording::run(&mut scope, &instance, &effect, target)
    }

    pub(crate) fn execute_verified_file_effect(
        &mut self,
        verified: VerifiedActionExecution,
        files: &dyn FileStore,
    ) -> StoreResult<StoredEvent> {
        use crate::effect_handlers::*;
        let instance = verified.request().admission.instance_ref.clone();
        let effect = verified.observed().clone();
        self.action_execution = Some(verified);
        let mut scope = ExecutionScope(self);
        match effect.kind.as_str() {
            "file.read" => run_file_effect_generic(&mut scope, files, &instance, &effect),
            "file.write" => run_file_write_effect_generic(&mut scope, files, &instance, &effect),
            "file.import" => run_file_import_effect_generic(&mut scope, files, &instance, &effect),
            "file.export" => run_file_export_effect_generic(&mut scope, files, &instance, &effect),
            _ => Err(StoreError::Conflict(
                "execution requires a supported governed file effect".into(),
            )),
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::host_protocol::execution::tests::verified;
    use whipplescript_store::native_stores::NativeStores;

    #[test]
    fn execution_grant_is_exact_single_use_and_cannot_be_rehydrated_from_evidence() {
        let mut kernel = RuntimeKernel::new(NativeStores::open_in_memory().expect("store"));
        let grant = verified("file.write");
        let instance = grant.request().admission.instance_ref.clone();
        let effect = grant.observed().clone();
        let evidence = grant.evidence();
        let run = RunStart {
            instance_id: &instance,
            effect_id: &effect.effect_id,
            run_id: "run",
            provider: "files",
            worker_id: "fixture",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: r#"{"action_execution":"forged"}"#,
        };
        kernel.action_execution = Some(grant);
        let recorded = kernel
            .action_dispatch_metadata(run, &effect)
            .expect("consume matching grant")
            .expect("verified metadata");
        let metadata: serde_json::Value = serde_json::from_str(&recorded).expect("metadata");
        assert_eq!(metadata["action_execution"], evidence);
        assert!(
            kernel
                .action_dispatch_metadata(
                    RunStart {
                        metadata_json: &recorded,
                        ..run
                    },
                    &effect
                )
                .is_err(),
            "recorded authority is not a grant"
        );
        for field in ["instance", "effect", "observation"] {
            kernel.action_execution = Some(verified("file.write"));
            let mut observed = effect.clone();
            let mut changed = run;
            match field {
                "instance" => changed.instance_id = "other-instance",
                "effect" => changed.effect_id = "other-effect",
                "observation" => observed.input_json = "{\"other\":true}".into(),
                _ => unreachable!(),
            }
            assert!(
                kernel.action_dispatch_metadata(changed, &observed).is_err(),
                "{field}"
            );
            assert!(
                kernel.action_execution.is_none(),
                "a refused use consumes the transient grant"
            );
        }
    }

    #[test]
    fn execution_scope_clears_unconsumed_authority_on_error_and_unwind() {
        let mut kernel = RuntimeKernel::new(NativeStores::open_in_memory().expect("store"));
        let error = kernel
            .execute_verified_file_effect(
                verified("unsupported"),
                &whipplescript_store::files::NativeFileStore,
            )
            .expect_err("unsupported effect must refuse");
        assert!(
            format!("{error:?}").contains("execution requires a supported governed file effect"),
            "unsupported execution must retain its actionable diagnostic: {error:?}"
        );
        assert!(kernel.action_execution.is_none());
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kernel.action_execution = Some(verified("file.write"));
            let _scope = ExecutionScope(&mut kernel);
            panic!("interrupt before dispatch consumes its grant");
        }));
        assert!(interrupted.is_err());
        assert!(
            kernel.action_execution.is_none(),
            "unwinding cannot leave reusable authority"
        );
    }
}
