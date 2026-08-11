//! Unified native store facade (DR-0033 instance-scheduler full lift, chunk 2).
//!
//! Natively the runtime store, the coordination store, and the work-items store
//! are three separate SQLite files (`SqliteStore`/`CoordinationStore`/
//! `WorkItemStore`). The durable-object host, by contrast, backs all three trait
//! surfaces with its *one* `DoSqliteStore`. To let the lifted rule pass / effect
//! executor / instance step machine hold a single generic store handle
//! (`S: RuntimeStore + Coordination + WorkItems`) on both hosts, this facade makes
//! the three native connections present as one object implementing all three
//! traits by delegation. It is the native counterpart to the DO's
//! all-three-traits-on-one-store `DoSqliteStore`.

#![allow(clippy::too_many_arguments)]

use std::path::Path;

use crate::coordination::*;
use crate::items::*;
use crate::*;

/// The three native stores, presented as one handle implementing all three store
/// traits (delegating each method to the connection that owns it).
pub struct NativeStores {
    pub runtime: SqliteStore,
    pub coord: CoordinationStore,
    pub items: WorkItemStore,
}

impl NativeStores {
    /// Open all three native connections: the per-run runtime store, the
    /// workspace coordination store, and the workspace work-items store.
    pub fn open(
        runtime: impl AsRef<Path>,
        coord: impl AsRef<Path>,
        items: impl AsRef<Path>,
    ) -> StoreResult<Self> {
        Ok(Self {
            runtime: SqliteStore::open(runtime)?,
            coord: CoordinationStore::open(coord)?,
            items: WorkItemStore::open(items)?,
        })
    }

    /// Consume the facade, returning the three underlying stores.
    pub fn into_parts(self) -> (SqliteStore, CoordinationStore, WorkItemStore) {
        (self.runtime, self.coord, self.items)
    }
}

impl RuntimeStore for NativeStores {
    fn schema_version(&self) -> StoreResult<i64> {
        self.runtime.schema_version()
    }

    fn append_event(&self, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
        self.runtime.append_event(event)
    }

    fn create_program_version(
        &mut self,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        self.runtime.create_program_version(version)
    }

    fn get_program_version(&self, version_id: &str) -> StoreResult<Option<ProgramVersionView>> {
        self.runtime.get_program_version(version_id)
    }

    fn create_instance(&self, instance: NewInstance<'_>) -> StoreResult<InstanceRecord> {
        self.runtime.create_instance(instance)
    }

    fn create_instance_with_authority(
        &self,
        instance: NewInstance<'_>,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<InstanceRecord> {
        self.runtime
            .create_instance_with_authority(instance, authority)
    }

    fn list_instance_revisions(&self, instance_id: &str) -> StoreResult<Vec<WorkflowRevisionView>> {
        self.runtime.list_instance_revisions(instance_id)
    }

    fn revision_cancellation_impact(
        &self,
        instance_id: &str,
        cancellation_policy: &str,
    ) -> StoreResult<RevisionCancellationImpact> {
        self.runtime
            .revision_cancellation_impact(instance_id, cancellation_policy)
    }

    fn analyze_revision_compatibility(
        &self,
        instance_id: &str,
        candidate_version_id: &str,
    ) -> StoreResult<RevisionCompatibilityReport> {
        self.runtime
            .analyze_revision_compatibility(instance_id, candidate_version_id)
    }

    fn analyze_revision_candidate(
        &self,
        instance_id: &str,
        candidate: RevisionCandidate<'_>,
    ) -> StoreResult<RevisionCompatibilityReport> {
        self.runtime
            .analyze_revision_candidate(instance_id, candidate)
    }

    fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView> {
        self.runtime.activate_revision(activation)
    }

    fn request_effect_cancellation(
        &mut self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView> {
        self.runtime.request_effect_cancellation(request)
    }

    fn effect_has_open_cancellation_request(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<bool> {
        self.runtime
            .effect_has_open_cancellation_request(instance_id, effect_id)
    }

    fn list_effect_cancellation_requests(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<EffectCancellationRequestView>> {
        self.runtime.list_effect_cancellation_requests(instance_id)
    }

    fn record_workflow_invocation(&self, invocation: NewWorkflowInvocation<'_>) -> StoreResult<()> {
        self.runtime.record_workflow_invocation(invocation)
    }

    fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.runtime
            .get_workflow_invocation(parent_instance_id, parent_effect_id)
    }

    fn list_child_workflow_invocations(
        &self,
        parent_instance_id: &str,
    ) -> StoreResult<Vec<WorkflowInvocationView>> {
        self.runtime
            .list_child_workflow_invocations(parent_instance_id)
    }

    fn get_parent_workflow_invocation(
        &self,
        child_instance_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.runtime
            .get_parent_workflow_invocation(child_instance_id)
    }

    fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent> {
        self.runtime.commit_rule(commit)
    }

    fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent> {
        self.runtime.commit_rule_with_revision_guard(commit, guard)
    }

    fn derive_fact(&mut self, derived: DerivedFact<'_>) -> StoreResult<StoredEvent> {
        self.runtime.derive_fact(derived)
    }

    fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome> {
        self.runtime.admit_fact_batch(batch)
    }

    fn complete_effect(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        self.runtime.complete_effect(completion)
    }

    fn complete_effect_with_terminal_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .complete_effect_with_terminal_diagnostic(completion, diagnostic)
    }

    fn resolve_effect_uncertain(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .resolve_effect_uncertain(completion, diagnostic)
    }

    fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>> {
        self.runtime.claimable_effects(instance_id)
    }

    fn fact_exists(&self, instance_id: &str, fact_name: &str) -> StoreResult<bool> {
        self.runtime.fact_exists(instance_id, fact_name)
    }

    fn register_package(&self, package: PackageRegistration<'_>) -> StoreResult<()> {
        self.runtime.register_package(package)
    }

    fn register_package_manifest(&self, manifest_json: &str) -> StoreResult<String> {
        self.runtime.register_package_manifest(manifest_json)
    }

    fn register_capability_schema(
        &self,
        capability: CapabilitySchemaRegistration<'_>,
    ) -> StoreResult<()> {
        self.runtime.register_capability_schema(capability)
    }

    fn register_effect_provider(
        &self,
        provider: EffectProviderRegistration<'_>,
    ) -> StoreResult<()> {
        self.runtime.register_effect_provider(provider)
    }

    fn pin_provider_endpoint(
        &self,
        effect_kind: &str,
        provider: &str,
        digest: &str,
    ) -> StoreResult<()> {
        self.runtime
            .pin_provider_endpoint(effect_kind, provider, digest)
    }

    fn file_provider_custody_claim(&self, claim: ProviderCustodyClaim<'_>) -> StoreResult<()> {
        self.runtime.file_provider_custody_claim(claim)
    }

    fn set_provider_operator_run(
        &self,
        effect_kind: &str,
        provider: &str,
        operator_run: bool,
    ) -> StoreResult<()> {
        self.runtime
            .set_provider_operator_run(effect_kind, provider, operator_run)
    }

    fn provider_trust_evidence(
        &self,
        effect_kind: &str,
        provider: &str,
    ) -> StoreResult<Option<ProviderTrustRow>> {
        self.runtime.provider_trust_evidence(effect_kind, provider)
    }

    fn register_profile(&self, profile: ProfileRegistration<'_>) -> StoreResult<()> {
        self.runtime.register_profile(profile)
    }

    fn registered_profile_policy(
        &self,
        profile: &str,
    ) -> StoreResult<Option<RegisteredProfilePolicy>> {
        self.runtime.registered_profile_policy(profile)
    }

    fn bind_capability(&self, binding: CapabilityBinding<'_>) -> StoreResult<()> {
        self.runtime.bind_capability(binding)
    }

    fn register_skill(&self, skill: SkillRegistration<'_>) -> StoreResult<()> {
        self.runtime.register_skill(skill)
    }

    fn register_project_context_doc(
        &self,
        position: i64,
        path: &str,
        body: &str,
    ) -> StoreResult<()> {
        self.runtime
            .register_project_context_doc(position, path, body)
    }

    fn list_project_context_docs(&self) -> StoreResult<Vec<ProjectContextDoc>> {
        self.runtime.list_project_context_docs()
    }

    fn record_compute_result(
        &self,
        registration: ComputeResultRegistration<'_>,
    ) -> StoreResult<bool> {
        self.runtime.record_compute_result(registration)
    }

    fn lookup_compute_result(&self, content_key: &str) -> StoreResult<Option<ComputeCachedResult>> {
        self.runtime.lookup_compute_result(content_key)
    }

    fn put_content(&self, body: &str) -> StoreResult<String> {
        self.runtime.put_content(body)
    }

    fn get_content(&self, id: &str) -> StoreResult<Option<String>> {
        self.runtime.get_content(id)
    }

    fn capture_checkpoint(
        &mut self,
        capture: CheckpointCapture<'_>,
    ) -> StoreResult<CapturedCheckpoint> {
        self.runtime.capture_checkpoint(capture)
    }

    fn plan_restore(&self, instance_id: &str, cut_id: &str) -> StoreResult<RestoreDecision> {
        self.runtime.plan_restore(instance_id, cut_id)
    }

    fn commit_restore(
        &mut self,
        instance_id: &str,
        restored_to_sequence: i64,
        cut_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .commit_restore(instance_id, restored_to_sequence, cut_id, idempotency_key)
    }

    fn register_script_capability(
        &self,
        registration: ScriptCapabilityRegistration<'_>,
    ) -> StoreResult<()> {
        self.runtime.register_script_capability(registration)
    }

    fn get_script_capability(&self, name: &str) -> StoreResult<Option<ScriptCapabilityRecord>> {
        self.runtime.get_script_capability(name)
    }

    fn attach_skill(&self, attachment: SkillAttachment<'_>) -> StoreResult<()> {
        self.runtime.attach_skill(attachment)
    }

    fn list_skills(&self) -> StoreResult<Vec<SkillView>> {
        self.runtime.list_skills()
    }

    fn list_skill_attachments(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> StoreResult<Vec<SkillAttachmentView>> {
        self.runtime.list_skill_attachments(scope_type, scope_id)
    }

    fn record_evidence(&self, evidence: EvidenceRecord<'_>) -> StoreResult<String> {
        self.runtime.record_evidence(evidence)
    }

    fn record_provider_validation_evidence(
        &self,
        evidence: ProviderValidationEvidence<'_>,
    ) -> StoreResult<String> {
        self.runtime.record_provider_validation_evidence(evidence)
    }

    fn record_codex_app_server_evidence(
        &self,
        evidence: CodexAppServerEvidence<'_>,
    ) -> StoreResult<String> {
        self.runtime.record_codex_app_server_evidence(evidence)
    }

    fn record_claude_agent_sdk_evidence(
        &self,
        evidence: ClaudeAgentSdkEvidence<'_>,
    ) -> StoreResult<String> {
        self.runtime.record_claude_agent_sdk_evidence(evidence)
    }

    fn link_evidence(&self, link: EvidenceLink<'_>) -> StoreResult<()> {
        self.runtime.link_evidence(link)
    }

    fn record_artifact(&self, artifact: ArtifactRecord<'_>) -> StoreResult<String> {
        self.runtime.record_artifact(artifact)
    }

    fn list_artifacts_for_run(&self, run_id: &str) -> StoreResult<Vec<ArtifactView>> {
        self.runtime.list_artifacts_for_run(run_id)
    }

    fn record_workspace(&self, workspace: WorkspaceRecord<'_>) -> StoreResult<String> {
        self.runtime.record_workspace(workspace)
    }

    fn get_workspace(&self, workspace_id: &str) -> StoreResult<Option<WorkspaceView>> {
        self.runtime.get_workspace(workspace_id)
    }

    fn list_workspaces_for_instance(&self, instance_id: &str) -> StoreResult<Vec<WorkspaceView>> {
        self.runtime.list_workspaces_for_instance(instance_id)
    }

    fn record_diagnostic(&self, diagnostic: DiagnosticRecord<'_>) -> StoreResult<String> {
        self.runtime.record_diagnostic(diagnostic)
    }

    fn list_diagnostics(&self, instance_id: Option<&str>) -> StoreResult<Vec<DiagnosticView>> {
        self.runtime.list_diagnostics(instance_id)
    }

    fn list_diagnostics_from_events(&self, instance_id: &str) -> StoreResult<Vec<DiagnosticView>> {
        self.runtime.list_diagnostics_from_events(instance_id)
    }

    fn effect_source_span_json(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<Option<String>> {
        self.runtime.effect_source_span_json(instance_id, effect_id)
    }

    fn record_skill_evidence(&self, evidence: SkillEvidence<'_>) -> StoreResult<String> {
        self.runtime.record_skill_evidence(evidence)
    }

    fn list_evidence(&self, instance_id: &str) -> StoreResult<Vec<EvidenceView>> {
        self.runtime.list_evidence(instance_id)
    }

    fn list_evidence_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<EvidenceView>> {
        self.runtime
            .list_evidence_for_subject(subject_type, subject_id)
    }

    fn list_evidence_links(&self, instance_id: &str) -> StoreResult<Vec<EvidenceLinkView>> {
        self.runtime.list_evidence_links(instance_id)
    }

    fn list_instances(&self) -> StoreResult<Vec<InstanceView>> {
        self.runtime.list_instances()
    }

    fn get_instance(&self, instance_id: &str) -> StoreResult<Option<InstanceView>> {
        self.runtime.get_instance(instance_id)
    }

    fn list_events(&self, instance_id: &str) -> StoreResult<Vec<EventView>> {
        self.runtime.list_events(instance_id)
    }

    fn event_by_idempotency_key(
        &self,
        instance_id: &str,
        idempotency_key: &str,
    ) -> StoreResult<Option<StoredEvent>> {
        self.runtime
            .event_by_idempotency_key(instance_id, idempotency_key)
    }

    fn list_facts(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        self.runtime.list_facts(instance_id)
    }

    fn list_facts_including_consumed(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        self.runtime.list_facts_including_consumed(instance_id)
    }

    fn list_effects(&self, instance_id: &str) -> StoreResult<Vec<EffectView>> {
        self.runtime.list_effects(instance_id)
    }

    fn list_runs(&self, instance_id: &str) -> StoreResult<Vec<RunView>> {
        self.runtime.list_runs(instance_id)
    }

    fn status(&self, instance_id: &str) -> StoreResult<Option<StatusView>> {
        self.runtime.status(instance_id)
    }

    fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize> {
        self.runtime.satisfy_dependencies(instance_id)
    }

    fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent> {
        self.runtime.start_run(run)
    }

    fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .block_effect_binding(instance_id, effect_id, category, detail)
    }

    fn transition_instance(
        &mut self,
        transition: InstanceTransition<'_>,
    ) -> StoreResult<StoredEvent> {
        self.runtime.transition_instance(transition)
    }

    fn due_time_effects(&self, instance_id: &str, now: &str) -> StoreResult<Vec<DueTimeEffect>> {
        self.runtime.due_time_effects(instance_id, now)
    }

    fn due_interval_occurrences(
        &self,
        after_scheduled: &str,
        interval_seconds: i64,
        now: &str,
    ) -> StoreResult<Vec<String>> {
        self.runtime
            .due_interval_occurrences(after_scheduled, interval_seconds, now)
    }

    fn resolve_clock(&self, now: &str) -> StoreResult<String> {
        self.runtime.resolve_clock(now)
    }

    fn last_clock_occurrence(
        &self,
        instance_id: &str,
        signal: &str,
    ) -> StoreResult<Option<String>> {
        self.runtime.last_clock_occurrence(instance_id, signal)
    }

    fn pending_time_effects(&self, instance_id: &str) -> StoreResult<Vec<DueTimeEffect>> {
        self.runtime.pending_time_effects(instance_id)
    }

    fn expire_effect(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .expire_effect(instance_id, effect_id, idempotency_key)
    }

    fn retire_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.runtime.retire_fact(instance_id, fact_id)
    }

    fn revive_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.runtime.revive_fact(instance_id, fact_id)
    }

    fn cancel_effect(&mut self, cancellation: EffectCancellation<'_>) -> StoreResult<StoredEvent> {
        self.runtime.cancel_effect(cancellation)
    }

    fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent> {
        self.runtime.renew_lease(renewal)
    }

    fn expire_leases(&mut self, instance_id: &str, now: &str) -> StoreResult<Vec<ExpiredLease>> {
        self.runtime.expire_leases(instance_id, now)
    }

    fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent> {
        self.runtime.retry_effect(retry)
    }

    fn rebuild_projections(&mut self, instance_id: &str) -> StoreResult<()> {
        self.runtime.rebuild_projections(instance_id)
    }

    fn table_exists(&self, table: &str) -> StoreResult<bool> {
        self.runtime.table_exists(table)
    }
}

impl Coordination for NativeStores {
    fn ledger_positions(&self) -> StoreResult<Vec<(String, String, i64)>> {
        self.coord.ledger_positions_impl()
    }

    fn try_acquire_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome> {
        self.coord
            .try_acquire_for_owner(owner, resource, key, slots, ttl_seconds, holder)
    }

    fn release_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        holder: &str,
    ) -> StoreResult<bool> {
        self.coord.release_for_owner(owner, resource, key, holder)
    }

    fn renew_lease_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<Option<String>> {
        self.coord
            .renew_lease_for_owner(owner, resource, key, ttl_seconds, holder)
    }

    fn release_all_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        self.coord.release_all_for_holder(holder)
    }

    fn append_for_owner(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64> {
        self.coord.append_for_owner(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
        )
    }

    fn consume_for_owner(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.coord
            .consume_for_owner(owner, counter, key, amount, cap, period)
    }

    fn append_for_owner_idempotent(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
        effect_id: &str,
    ) -> StoreResult<i64> {
        self.coord.append_for_owner_idempotent(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
            effect_id,
        )
    }

    fn consume_for_owner_idempotent(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
        effect_id: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.coord
            .consume_for_owner_idempotent(owner, counter, key, amount, cap, period, effect_id)
    }

    fn list_leases_for_owner(
        &self,
        owner: Option<&str>,
        resource: Option<&str>,
    ) -> StoreResult<Vec<LeaseRow>> {
        self.coord.list_leases_for_owner(owner, resource)
    }

    fn list_entries_for_owner(
        &self,
        owner: Option<&str>,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        self.coord.list_entries_for_owner(owner, ledger, partition)
    }

    fn list_counters_for_owner(
        &self,
        owner: Option<&str>,
        counter: Option<&str>,
    ) -> StoreResult<Vec<CounterRow>> {
        self.coord.list_counters_for_owner(owner, counter)
    }
}

impl WorkItems for NativeStores {
    fn event_position(&self) -> StoreResult<i64> {
        WorkItems::event_position(&self.items)
    }

    fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &Value,
        filed_by: Option<&str>,
    ) -> StoreResult<WorkItem> {
        self.items
            .file_item(queue, title, body, labels, metadata, filed_by)
    }

    fn get_item(&self, item_id: &str) -> StoreResult<Option<WorkItem>> {
        self.items.get_item(item_id)
    }

    fn list_items(&self, queue: Option<&str>, status: Option<&str>) -> StoreResult<Vec<WorkItem>> {
        self.items.list_items(queue, status)
    }

    fn ready_items(&self, queue: &str) -> StoreResult<Vec<WorkItem>> {
        self.items.ready_items(queue)
    }

    fn claim_item(
        &mut self,
        item_id: &str,
        claimed_by: &str,
        expires: Option<&str>,
    ) -> StoreResult<ClaimOutcome> {
        self.items.claim_item(item_id, claimed_by, expires)
    }

    fn renew_claim(
        &mut self,
        item_id: &str,
        actor: &str,
        expires: Option<&str>,
    ) -> StoreResult<RenewOutcome> {
        self.items.renew_claim(item_id, actor, expires)
    }

    fn release_item(&mut self, item_id: &str) -> StoreResult<bool> {
        self.items.release_item(item_id)
    }

    fn release_claims_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        self.items.release_claims_for_holder(holder)
    }

    fn finish_item(&mut self, item_id: &str, summary: Option<&str>) -> StoreResult<bool> {
        self.items.finish_item(item_id, summary)
    }

    fn add_blocks(&mut self, from: &str, to: &str) -> StoreResult<()> {
        self.items.add_blocks(from, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whipplescript-native-stores-{}-{}-{}.sqlite",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ))
    }

    // The facade presents all three store surfaces on one handle; each trait
    // method must reach the connection that owns it. Drive one method per trait
    // through a `&mut NativeStores`, proving the delegation is wired end to end.
    #[test]
    fn native_stores_facade_delegates_all_three_trait_surfaces() {
        let mut stores =
            NativeStores::open(temp("rt"), temp("coord"), temp("items")).expect("open facade");

        // RuntimeStore surface: a fresh runtime store reports its migrated schema.
        assert!(
            RuntimeStore::schema_version(&stores).expect("schema_version") >= 1,
            "RuntimeStore surface reaches the runtime connection"
        );

        // WorkItems surface: no items filed yet -> empty listing (reaches the
        // items connection, not the runtime one).
        assert!(
            WorkItems::list_items(&stores, None, None)
                .expect("list_items")
                .is_empty(),
            "WorkItems surface reaches the items connection"
        );

        // Coordination surface, via a `&mut self` method (proving the mutable
        // delegation path): releasing a holder that holds nothing is a no-op that
        // reaches the coordination connection and reports zero released.
        assert_eq!(
            Coordination::release_all_for_holder(&mut stores, "nobody").expect("release"),
            0,
            "Coordination &mut surface reaches the coordination connection"
        );
    }
}
