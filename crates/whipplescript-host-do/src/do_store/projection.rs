//! Row projections whose SELECT list and decoder are one declaration (WS-330).
//!
//! The Durable Object store reads every row as a positional `Vec<SqlValue>`:
//! the Worker's `cursor.raw()` keeps column order and discards names, so a
//! decoder that reads `row[7]` is coupled to whichever SELECT list produced the
//! row. Those lists were written by hand at each call site, apart from the
//! decoder, and nothing checked that the two agreed. A short row indexed out of
//! bounds, which in wasm aborts the whole Durable Object isolate rather than
//! failing one request; a reordered one of the same types decoded silently
//! into the wrong fields.
//!
//! [`row_projection!`] closes both for a view it declares. Each field names its
//! column expression beside its converter, so the SELECT list
//! ([`RowProjection::columns`]) and the decoder are generated from the same
//! list and cannot disagree in width or order. The decoder refuses a row of
//! any other width with [`StoreError::Fault`] before reading a cell.
//!
//! What it does not do: it covers the shared view decoders declared here, not
//! every positional read in the store, and it does not tighten the tolerant
//! cell converters (`as_text` reads a non-text cell as `""`), whose legacy
//! semantics each column's native parity owns.

use super::{as_i64, as_opt_i64, as_opt_text, as_text, SqlValue};
use whipplescript_store::{
    ArtifactView, DiagnosticView, DueTimeEffect, EffectCancellationRequestView, EffectView,
    EventView, EvidenceLinkView, EvidenceView, FactView, InstanceView, ProgramVersionView, RunView,
    SkillView, StoreError, StoreResult, WorkflowInvocationView, WorkflowRevisionView,
    WorkspaceView,
};

/// A SELECT list and the decoder of exactly the rows it produces.
pub(crate) struct RowProjection<V> {
    subject: &'static str,
    columns: &'static str,
    width: usize,
    decode: fn(&[SqlValue]) -> V,
}

impl<V> RowProjection<V> {
    /// The comma-separated column expressions, for `SELECT {columns} FROM ...`.
    pub(crate) const fn columns(&self) -> &'static str {
        self.columns
    }

    /// How many cells a row of this projection has.
    pub(crate) const fn width(&self) -> usize {
        self.width
    }

    /// Decodes a row that is exactly this projection.
    pub(crate) fn decode(&self, row: &[SqlValue]) -> StoreResult<V> {
        self.decode_framed(row, 0, 0)
    }

    /// Decodes this projection out of a row that carries `before` cells ahead
    /// of it and `after` cells behind it, as a query that selects a prefix or
    /// a tail beside a shared view does. The row's width must be exactly the
    /// sum, so a tail that is shorter or longer than its caller declared is a
    /// fault rather than a shifted decode.
    pub(crate) fn decode_framed(
        &self,
        row: &[SqlValue],
        before: usize,
        after: usize,
    ) -> StoreResult<V> {
        let expected = before + self.width + after;
        if row.len() != expected {
            return Err(StoreError::fault(
                self.subject,
                format!(
                    "SQL row has {} cells where its projection selects {expected}",
                    row.len()
                ),
            ));
        }
        Ok((self.decode)(&row[before..before + self.width]))
    }
}

/// Declares a [`RowProjection`] constant from one ordered list of
/// `field: converter = "column expression"` entries.
macro_rules! row_projection {
    (
        $(#[$meta:meta])*
        $name:ident: $view:ident = $subject:literal {
            $first_field:ident: $first_conv:expr => $first_col:literal
            $(, $field:ident: $conv:expr => $col:literal)* $(,)?
        }
    ) => {
        $(#[$meta])*
        pub(crate) const $name: RowProjection<$view> = RowProjection {
            subject: $subject,
            columns: concat!($first_col $(, ", ", $col)*),
            width: [$first_col $(, $col)*].len(),
            decode: |row| {
                // Only ever called on a slice exactly `width` long, so every
                // `next()` yields a cell; the fallback is unreachable and
                // exists so that no path here can panic.
                let mut cells = row.iter();
                let mut next = || cells.next().unwrap_or(&SqlValue::Null);
                $view {
                    $first_field: ($first_conv)(next()),
                    $($field: ($conv)(next()),)*
                }
            },
        };
    };
}

fn as_flag(value: &SqlValue) -> bool {
    as_i64(value) != 0
}

row_projection! {
    SKILL_VIEW: SkillView = "skill row" {
        skill_id: as_text => "skill_id",
        name: as_text => "name",
        version: as_text => "version",
        source: as_text => "source",
        source_path: as_text => "source_path",
        content_hash: as_text => "content_hash",
        description: as_text => "description",
        required_capabilities_json: as_text => "required_capabilities",
    }
}

row_projection! {
    /// The same skill columns read through the `skill` alias of a join.
    ATTACHED_SKILL_VIEW: SkillView = "attached skill row" {
        skill_id: as_text => "skill.skill_id",
        name: as_text => "skill.name",
        version: as_text => "skill.version",
        source: as_text => "skill.source",
        source_path: as_text => "skill.source_path",
        content_hash: as_text => "skill.content_hash",
        description: as_text => "skill.description",
        required_capabilities_json: as_text => "skill.required_capabilities",
    }
}

row_projection! {
    INSTANCE_VIEW: InstanceView = "instance row" {
        instance_id: as_text => "instance_id",
        program_id: as_text => "program_id",
        version_id: as_text => "version_id",
        revision_epoch: as_i64 => "revision_epoch",
        workflow_principal: as_text => "workflow_principal",
        effective_authority_json: as_text => "effective_authority",
        status: as_text => "status",
        input_json: as_text => "input_json",
        created_at: as_text => "created_at",
        updated_at: as_text => "updated_at",
    }
}

row_projection! {
    EVENT_VIEW: EventView = "event row" {
        event_id: as_text => "event_id",
        sequence: as_i64 => "sequence",
        event_type: as_text => "event_type",
        payload_json: as_text => "payload_json",
        source: as_text => "source",
        occurred_at: as_text => "occurred_at",
    }
}

row_projection! {
    FACT_VIEW: FactView = "fact row" {
        fact_id: as_text => "fact_id",
        program_version_id: as_opt_text => "program_version_id",
        revision_epoch: as_i64 => "revision_epoch",
        name: as_text => "name",
        key: as_text => "key",
        value_json: as_text => "value_json",
        provenance_class: as_text => "provenance_class",
        source_span_json: as_opt_text => "source_span_json",
        source_event_id: as_text => "source_event_id",
        validity_json: as_opt_text => "validity_json",
    }
}

row_projection! {
    /// Read from `effects` joined to its instance and to the active and the
    /// effect's own program versions, as `active_versions` and
    /// `effect_versions`.
    EFFECT_VIEW: EffectView = "effect row" {
        effect_id: as_text => "effects.effect_id",
        kind: as_text => "effects.kind",
        target: as_opt_text => "effects.target",
        input_json: as_text => "effects.input_json",
        status: as_text => "effects.status",
        created_by_rule: as_text => "effects.created_by_rule",
        program_version_id: as_opt_text => "effects.program_version_id",
        revision_epoch: as_i64 => "effects.revision_epoch",
        profile: as_opt_text => "effects.profile",
        required_capabilities_json: as_text => "effects.required_capabilities",
        policy_block_reason: as_opt_text => "effects.policy_block_reason",
        policy_block_category: as_opt_text => "effects.policy_block_category",
        declared_profiles_json: as_text =>
            "COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]')",
        cancel_requested: as_flag =>
            "EXISTS (SELECT 1 FROM effect_cancellation_requests AS request \
             WHERE request.instance_id = effects.instance_id \
             AND request.effect_id = effects.effect_id AND request.status = 'requested')",
    }
}

row_projection! {
    RUN_VIEW: RunView = "run row" {
        run_id: as_text => "run_id",
        effect_id: as_text => "effect_id",
        provider: as_text => "provider",
        worker_id: as_text => "worker_id",
        status: as_text => "status",
        started_at: as_text => "started_at",
        completed_at: as_opt_text => "completed_at",
        metadata_json: as_text => "metadata_json",
        cancel_requested: as_flag =>
            "EXISTS (SELECT 1 FROM effect_cancellation_requests AS request \
             WHERE request.instance_id = runs.instance_id \
             AND request.effect_id = runs.effect_id AND request.status = 'requested')",
        summary: as_opt_text => "summary",
    }
}

row_projection! {
    WORKFLOW_REVISION_VIEW: WorkflowRevisionView = "instance revision row" {
        revision_id: as_text => "revision_id",
        instance_id: as_text => "instance_id",
        epoch: as_i64 => "epoch",
        from_version_id: as_text => "from_version_id",
        to_version_id: as_text => "to_version_id",
        activated_by_event_id: as_text => "activated_by_event_id",
        activation_policy_json: as_text => "activation_policy_json",
        cancellation_policy: as_text => "cancellation_policy",
        rule_carries_json: as_text => "rule_carries_json",
        status: as_text => "status",
        idempotency_key: as_opt_text => "idempotency_key",
        created_at: as_text => "created_at",
        activated_at: as_text => "activated_at",
    }
}

row_projection! {
    EFFECT_CANCELLATION_REQUEST_VIEW: EffectCancellationRequestView =
        "effect cancellation request row" {
        request_id: as_text => "request_id",
        instance_id: as_text => "instance_id",
        effect_id: as_text => "effect_id",
        revision_id: as_opt_text => "revision_id",
        reason: as_opt_text => "reason",
        requested_by: as_text => "requested_by",
        causation_event_id: as_opt_text => "causation_event_id",
        status: as_text => "status",
        idempotency_key: as_opt_text => "idempotency_key",
        created_at: as_text => "created_at",
        updated_at: as_text => "updated_at",
        resolved_by_event_id: as_opt_text => "resolved_by_event_id",
    }
}

row_projection! {
    /// Read from `workflow_invocations` joined to the parent and child
    /// instances (`parent_instance`, `child_instance`) and the parent effect
    /// (`parent_effect`); see `WORKFLOW_INVOCATION_FROM`.
    WORKFLOW_INVOCATION_VIEW: WorkflowInvocationView = "workflow invocation row" {
        invocation_id: as_text => "invocation_id",
        parent_instance_id: as_text => "parent_instance_id",
        parent_effect_id: as_text => "parent_effect_id",
        parent_program_version_id: as_opt_text => "parent_program_version_id",
        parent_revision_epoch: as_i64 => "parent_revision_epoch",
        parent_active_program_version_id: as_opt_text => "parent_instance.version_id",
        parent_active_revision_epoch: as_opt_i64 => "parent_instance.revision_epoch",
        child_instance_id: as_text => "child_instance_id",
        child_program_version_id: as_opt_text => "child_program_version_id",
        child_revision_epoch: as_opt_i64 => "child_revision_epoch",
        child_active_program_version_id: as_opt_text => "child_instance.version_id",
        child_active_revision_epoch: as_opt_i64 => "child_instance.revision_epoch",
        target_workflow: as_text => "workflow_invocations.target_workflow",
        input_json: as_text => "workflow_invocations.input_json",
        status: as_text =>
            "CASE WHEN parent_effect.status IN ('completed', 'failed', 'timed_out', 'cancelled') \
             THEN parent_effect.status ELSE workflow_invocations.status END",
        terminal_event_id: as_opt_text => "workflow_invocations.terminal_event_id",
        source_span_json: as_opt_text => "workflow_invocations.source_span_json",
        created_at: as_text => "workflow_invocations.created_at",
        updated_at: as_text =>
            "COALESCE(workflow_invocations.updated_at, workflow_invocations.created_at)",
    }
}

row_projection! {
    /// Read from `program_versions` joined to `programs` for the name.
    PROGRAM_VERSION_VIEW: ProgramVersionView = "program version row" {
        program_id: as_text => "program_versions.program_id",
        program_name: as_text => "programs.name",
        version_id: as_text => "program_versions.version_id",
        source_hash: as_text => "program_versions.source_hash",
        ir_hash: as_text => "program_versions.ir_hash",
        compiler_version: as_text => "program_versions.compiler_version",
        analysis_summary_json: as_text => "program_versions.analysis_summary",
    }
}

row_projection! {
    ARTIFACT_VIEW: ArtifactView = "artifact row" {
        artifact_id: as_text => "artifact_id",
        run_id: as_text => "run_id",
        kind: as_text => "kind",
        path: as_text => "path",
        content_hash: as_opt_text => "content_hash",
        mime_type: as_opt_text => "mime_type",
        created_at: as_text => "created_at",
    }
}

row_projection! {
    WORKSPACE_VIEW: WorkspaceView = "workspace row" {
        workspace_id: as_text => "workspace_id",
        instance_id: as_opt_text => "instance_id",
        effect_id: as_opt_text => "effect_id",
        run_id: as_opt_text => "run_id",
        provider: as_opt_text => "provider",
        policy: as_text => "policy",
        uri: as_text => "uri",
        status: as_text => "status",
        metadata_json: as_text => "metadata_json",
        created_at: as_text => "created_at",
        updated_at: as_text => "updated_at",
    }
}

row_projection! {
    DIAGNOSTIC_VIEW: DiagnosticView = "diagnostic row" {
        diagnostic_id: as_text => "diagnostic_id",
        instance_id: as_opt_text => "instance_id",
        program_id: as_opt_text => "program_id",
        program_version_id: as_opt_text => "program_version_id",
        severity: as_text => "severity",
        code: as_opt_text => "code",
        message: as_text => "message",
        source_span_json: as_opt_text => "source_span_json",
        subject_type: as_opt_text => "subject_type",
        subject_id: as_opt_text => "subject_id",
        event_id: as_opt_text => "event_id",
        effect_id: as_opt_text => "effect_id",
        run_id: as_opt_text => "run_id",
        assertion_id: as_opt_text => "assertion_id",
        evidence_ids_json: as_text => "evidence_ids_json",
        artifact_ids_json: as_text => "artifact_ids_json",
        causation_id: as_opt_text => "causation_id",
        correlation_id: as_opt_text => "correlation_id",
        idempotency_key: as_opt_text => "idempotency_key",
        created_at: as_text => "created_at",
    }
}

row_projection! {
    EVIDENCE_VIEW: EvidenceView = "evidence row" {
        evidence_id: as_text => "evidence_id",
        instance_id: as_text => "instance_id",
        kind: as_text => "kind",
        subject_type: as_text => "subject_type",
        subject_id: as_text => "subject_id",
        causation_id: as_opt_text => "causation_id",
        correlation_id: as_opt_text => "correlation_id",
        summary: as_opt_text => "summary",
        metadata_json: as_text => "metadata_json",
        created_at: as_text => "created_at",
    }
}

row_projection! {
    EVIDENCE_LINK_VIEW: EvidenceLinkView = "evidence link row" {
        evidence_id: as_text => "evidence_id",
        target_type: as_text => "target_type",
        target_id: as_text => "target_id",
        relation: as_text => "relation",
        created_at: as_text => "created_at",
    }
}

row_projection! {
    /// Unqualified, so it reads from `effects` under any alias that is the
    /// only `effects` in its FROM clause. `timeout_seconds` is coalesced so a
    /// deadline-only effect reads as `0`, as the due-effect scan always did.
    DUE_TIME_EFFECT: DueTimeEffect = "time effect row" {
        effect_id: as_text => "effect_id",
        kind: as_text => "kind",
        status: as_text => "status",
        timeout_seconds: as_i64 => "COALESCE(timeout_seconds, 0)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(n: usize) -> Vec<SqlValue> {
        (0..n).map(|i| SqlValue::Text(format!("c{i}"))).collect()
    }

    #[test]
    fn width_and_select_list_come_from_one_declaration() {
        assert_eq!(EVENT_VIEW.width(), 6);
        assert_eq!(
            EVENT_VIEW.columns(),
            "event_id, sequence, event_type, payload_json, source, occurred_at"
        );
        // The width is the number of declared columns, so a list whose
        // expressions contain commas still counts one cell per field.
        assert_eq!(EFFECT_VIEW.width(), 14);
        assert_eq!(WORKFLOW_INVOCATION_VIEW.width(), 19);
        assert_eq!(WORKFLOW_REVISION_VIEW.width(), 13);
        assert_eq!(DIAGNOSTIC_VIEW.width(), 20);
    }

    /// The recovery fold's SELECT is owned by the store crate, which the
    /// native host shares, so it cannot be built from this projection; it must
    /// at least select exactly this projection's columns.
    #[test]
    fn recovery_events_select_is_the_event_projection() {
        let sql = whipplescript_store::effect_recovery::RECOVERY_EVENTS_SQL;
        assert!(
            sql.starts_with(&format!("SELECT {} FROM events ", EVENT_VIEW.columns())),
            "{sql}"
        );
    }

    #[test]
    fn decodes_in_declared_order() {
        let mut row = cells(6);
        row[1] = SqlValue::Int(7);
        let event = EVENT_VIEW.decode(&row).expect("exact width decodes");
        assert_eq!(event.event_id, "c0");
        assert_eq!(event.sequence, 7);
        assert_eq!(event.event_type, "c2");
        assert_eq!(event.occurred_at, "c5");
    }

    #[test]
    fn a_short_or_long_row_is_a_fault_not_a_panic() {
        for width in [0, 5, 7] {
            let error = EVENT_VIEW
                .decode(&cells(width))
                .expect_err("a row of the wrong width is refused");
            assert!(
                matches!(&error, StoreError::Fault { subject, detail }
                if subject == "event row"
                    && detail == &format!(
                        "SQL row has {width} cells where its projection selects 6"
                    )),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_framed_row_must_carry_exactly_its_declared_prefix_and_tail() {
        let mut row = cells(3 + SKILL_VIEW.width());
        row[3] = SqlValue::Text("skill".into());
        let skill = ATTACHED_SKILL_VIEW
            .decode_framed(&row, 3, 0)
            .expect("prefix and view decode");
        assert_eq!(skill.skill_id, "skill");
        assert_eq!(skill.required_capabilities_json, "c10");
        assert!(ATTACHED_SKILL_VIEW.decode_framed(&row, 3, 1).is_err());
        assert!(ATTACHED_SKILL_VIEW.decode_framed(&row[..10], 3, 0).is_err());
    }
}
