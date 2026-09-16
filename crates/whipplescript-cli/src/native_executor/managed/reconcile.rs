use super::*;
use whipplescript_kernel::exec_lifetime;

/// Workflow closure and inert-resource cleanup are independent obligations.
#[derive(Debug, PartialEq, Eq)]
pub struct ManagedReconciliation {
    pub closed: bool,
    pub cleanup_pending: bool,
}
impl Docker {
    /// The caller supplies a retained host binding, not a freshly observed
    /// daemon. Identity and fence intent come only from the original journal.
    pub fn reconcile_managed<S: RuntimeStore>(
        &mut self,
        store: &mut S,
        daemon: &str,
        helper_image: &str,
        instance: &str,
        run: &str,
    ) -> StoreResult<ManagedReconciliation> {
        let originals = exec_lifetime::tracked(store, instance)?;
        let original = originals.get(run).ok_or_else(|| {
            StoreError::Conflict("native reconciliation requires original tracking".into())
        })?;
        if original.executor_url != "whip-executor://native/exec" {
            return Err(StoreError::Conflict(
                "native reconciliation cannot target another executor provider".into(),
            ));
        }
        let intents = exec_lifetime::fences(store, instance)?;
        let intent = intents.get(run).ok_or_else(|| {
            StoreError::Conflict("native reconciliation requires retained fence intent".into())
        })?;
        let identity = Identity {
            selected: serde_json::from_value(original.invocation["invocation"].clone())?,
            envelope: serde_json::from_value(original.invocation.clone())?,
        };
        let reply = self.fence_managed(daemon, helper_image, &identity, &intent.fence_id)?;
        let cleanup_pending = reply.state.owner.is_some() && reply.state.container_id.is_none();
        let view = reply.state.resolution_view()?;
        let closed = exec_lifetime::observe(store, instance, run, &view.to_string())?;
        Ok(ManagedReconciliation {
            closed,
            cleanup_pending,
        })
    }
}
