//! The native payload-plane inventory (TAC-7). Every column of every protected
//! native store is classified here, so a new table or column cannot reach a
//! protected store without someone deciding whether it carries customer content.
//!
//! Sealed columns pass through the host codec at their own coordinate. Digest
//! columns hold a domain-separated equality index whose original is sealed
//! beside it. Every other column is operational metadata: identities, status,
//! timestamps, content hashes and lengths, actor and holder references, program
//! and capability names declared by the program author, and receipts built only
//! from those. The canary tests beside each store establish that sealed columns
//! leave no plaintext in the database or its WAL; this establishes that the
//! list of sealed columns is the complete list of payload-bearing ones.
use super::*;
use crate::payload_protection::PayloadCodec;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Plane {
    Runtime,
    Tracker,
    Coordination,
    Content,
}
use Plane::*;

/// (store, table, every column, sealed columns, digest-index columns).
const INVENTORY: &[(Plane, &str, &str, &str, &str)] = &[
    (Runtime, "artifacts", "artifact_id run_id kind path content_hash mime_type created_at", "path", ""),
    (Runtime, "capability_bindings", "binding_id program_id capability provider config_json created_at", "config_json", ""),
    (Runtime, "capability_schemas", "capability description schema_json registered_by_package_id created_at", "description schema_json", ""),
    (Runtime, "compute_result_cache", "content_key effect_kind result_json source_instance_id source_effect_id created_at", "result_json", ""),
    (Runtime, "content_blobs", "id body byte_len created_at", "body", ""),
    (Runtime, "diagnostics", "diagnostic_id instance_id program_id program_version_id severity code message source_span_json subject_type subject_id event_id effect_id run_id assertion_id evidence_ids_json artifact_ids_json causation_id correlation_id idempotency_key created_at", "message source_span_json", ""),
    (Runtime, "effect_cancellation_requests", "request_id instance_id effect_id revision_id reason requested_by causation_event_id status idempotency_key created_at updated_at resolved_by_event_id", "reason", ""),
    (Runtime, "effect_dependencies", "dependency_id instance_id upstream_effect_id downstream_effect_id predicate created_by_rule created_at", "", ""),
    (Runtime, "effect_providers", "provider_id effect_kind provider capability config_json registered_by_package_id created_at", "config_json", ""),
    (Runtime, "effects", "effect_id instance_id kind target input_json status created_by_rule created_by_event_id program_version_id revision_epoch correlation_id idempotency_key required_capabilities profile policy_block_reason policy_block_category created_at updated_at timeout_seconds", "input_json policy_block_reason", ""),
    (Runtime, "events", "event_id instance_id sequence event_type payload_json occurred_at source causation_id correlation_id idempotency_key format_version prev_digest entry_digest", "payload_json", ""),
    (Runtime, "evidence", "evidence_id instance_id kind subject_type subject_id causation_id correlation_id summary metadata_json created_at", "summary metadata_json", ""),
    (Runtime, "evidence_links", "link_id evidence_id instance_id target_type target_id relation created_at", "", ""),
    (Runtime, "facts", "fact_id instance_id program_version_id revision_epoch name key value_json source_event_id source_rule source_effect_id source_run_id schema_id provenance_class external_system external_id correlation_id source_span_json consumed_at created_at updated_at key_payload validity_json", "value_json source_span_json key_payload", "key"),
    (Runtime, "instance_revisions", "revision_id instance_id epoch from_version_id to_version_id activated_by_event_id activation_policy_json cancellation_policy rule_carries_json status idempotency_key created_at activated_at", "activation_policy_json rule_carries_json", ""),
    (Runtime, "instances", "instance_id program_id version_id revision_epoch workflow_principal effective_authority status input_json last_event_id last_error created_at started_at updated_at completed_at owner_epoch", "input_json last_error", ""),
    (Runtime, "leases", "lease_id run_id effect_id instance_id worker_id status acquired_at expires_at released_at", "", ""),
    (Runtime, "package_registrations", "package_id name version manifest_json registered_at", "manifest_json", ""),
    (Runtime, "profiles", "profile_id name description enforcement_mode allowed_capabilities config_json created_at", "description config_json", ""),
    (Runtime, "program_import_admissions", "version_id witness_digest witness_json", "", ""),
    (Runtime, "program_import_operations", "sequence operation_id version_id witness_digest kind", "", ""),
    (Runtime, "program_versions", "version_id program_id source_hash ir_hash compiler_version declared_capabilities declared_profiles declared_skills declared_schemas analysis_summary generated_artifacts artifact_root created_at", "declared_profiles declared_skills declared_schemas analysis_summary generated_artifacts artifact_root", ""),
    (Runtime, "programs", "program_id name created_at", "", ""),
    (Runtime, "project_context_docs", "position path content_hash body", "path body", ""),
    (Runtime, "provider_trust_evidence", "effect_kind provider pinned_digest claim_class claim_signer claim_filed_at claim_expires_at operator_run updated_at", "", ""),
    (Runtime, "repair_scopes", "instance_id branch_id slice_expr source_ref granted_at", "slice_expr source_ref", ""),
    (Runtime, "runs", "run_id effect_id instance_id provider worker_id status started_at completed_at exit_code summary metadata_json", "summary metadata_json", ""),
    (Runtime, "runtime_payload_protection", "singleton domain", "", ""),
    (Runtime, "runtime_store_incarnation", "id incarnation_id", "", ""),
    (Runtime, "schema_migrations", "version name applied_at", "", ""),
    (Runtime, "script_capabilities", "name argv_json sha256 env_json hermetic body created_at", "argv_json env_json body", ""),
    (Runtime, "skill_attachments", "attachment_id scope_type scope_id skill_id created_at", "", ""),
    (Runtime, "skills", "skill_id name version source source_path content_hash description required_capabilities metadata_json created_at body", "source source_path description metadata_json body", ""),
    (Runtime, "store_meta", "key value updated_at", "", ""),
    (Runtime, "workflow_invocations", "invocation_id parent_instance_id parent_effect_id parent_program_version_id parent_revision_epoch child_instance_id child_program_version_id child_revision_epoch target_workflow input_json status terminal_event_id source_span_json idempotency_key created_at updated_at", "input_json source_span_json", ""),
    (Runtime, "workspaces", "workspace_id instance_id effect_id run_id provider policy uri status metadata_json created_at updated_at", "uri metadata_json", ""),
    (Tracker, "schema_migrations", "version name", "", ""),
    (Tracker, "tracker_aliases", "content_id alias", "", ""),
    (Tracker, "tracker_anchors", "anchor_id subject region role added_by created_at", "region", ""),
    (Tracker, "tracker_assertion_counter", "singleton next_id", "", ""),
    (Tracker, "tracker_assertions", "assertion_id title body status created_by created_at updated_at", "title body", ""),
    (Tracker, "tracker_closure_receipts", "operation_id receipt_json", "", ""),
    (Tracker, "tracker_comments", "comment_id issue_id author body created_at", "body", ""),
    (Tracker, "tracker_control_receipts", "operation_id receipt_json", "receipt_json", ""),
    (Tracker, "tracker_counter", "singleton next_id", "", ""),
    (Tracker, "tracker_discovery_roots", "root", "", ""),
    (Tracker, "tracker_events", "event_seq event_id parents_json issue_id kind payload_json actor effect_id created_at", "payload_json", ""),
    (Tracker, "tracker_evidence", "evidence_id issue_id kind reference note added_by created_at at_cut basis basis_fingerprint_json", "kind reference note basis basis_fingerprint_json", ""),
    (Tracker, "tracker_filing_receipts", "operation_id fingerprint item_id event_id", "", ""),
    (Tracker, "tracker_issues", "issue_id queue title body status labels_json releases metadata_json claim_summary assigned_to filed_by created_at updated_at", "title body labels_json metadata_json claim_summary", ""),
    (Tracker, "tracker_leases", "lease_id issue_id actor acquired_at expires_at released_at", "", ""),
    (Tracker, "tracker_norm_aliases", "ordinal record_id", "", ""),
    (Tracker, "tracker_norm_checkpoint", "singleton genesis_id authority_head", "", ""),
    (Tracker, "tracker_norm_identity", "singleton genesis_id", "", ""),
    (Tracker, "tracker_payload_protection", "singleton domain", "", ""),
    (Tracker, "tracker_relations", "from_issue to_issue kind dep_kind", "", ""),
    (Tracker, "tracker_subscriptions", "subscriber queue position created_at", "", ""),
    (Coordination, "coord_applied", "owner effect_id outcome_json applied_at", "", ""),
    (Coordination, "coordination_payload_protection", "singleton domain", "", ""),
    (Coordination, "counters", "owner counter key consumed period key_payload", "key_payload", "key"),
    (Coordination, "leases", "owner resource key holder acquired_at expires_at key_payload", "key_payload", "key"),
    (Coordination, "ledger_entries", "owner ledger partition seq payload_json appended_by appended_at partition_payload", "payload_json partition_payload", "partition"),
    (Coordination, "ledger_seq", "owner ledger next_seq", "", ""),
    (Coordination, "schema_migrations", "version name", "", ""),
    (Content, "content_blobs", "id body byte_len created_at", "body", ""),
    (Content, "content_chunk_refs", "root_id seq chunk_id", "", ""),
    (Content, "content_chunk_roots", "root_id byte_len erased_at", "", ""),
    (Content, "content_erasure_ledger", "sequence id kind byte_len erased_at prev_digest entry_digest", "", ""),
    (Content, "content_erasures", "id byte_len erased_at", "", ""),
    (Content, "content_pack_entries", "chunk_id pack_id offset len", "", ""),
    (Content, "content_payload_protection", "singleton domain", "", ""),
    (Content, "schema_migrations", "version name", "", ""),
];

struct Opaque;
impl PayloadCodec for Opaque {
    fn seal(&self, _: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        Ok(body.iter().map(|byte| byte ^ 93).collect())
    }
    fn open(&self, _: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        Ok(body.iter().map(|byte| byte ^ 93).collect())
    }
    fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        publish()
    }
}

fn columns(path: &Path) -> BTreeSet<(String, String)> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT m.name, p.name FROM sqlite_schema AS m, pragma_table_info(m.name) AS p \
             WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    rows
}

#[test]
fn every_protected_native_column_is_classified_as_sealed_digest_or_operational() {
    let root = std::env::temp_dir().join(format!(
        "whip-payload-inventory-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let protection = || PayloadProtection::new("inventory", Arc::new(Opaque)).unwrap();
    drop(SqliteStore::create_protected(root.join("runtime.sqlite"), protection()).unwrap());
    drop(
        crate::items::WorkItemStore::create_protected(root.join("items.sqlite"), protection())
            .unwrap(),
    );
    drop(
        crate::coordination::CoordinationStore::create_protected(
            root.join("coord.sqlite"),
            protection(),
        )
        .unwrap(),
    );
    drop(
        crate::content::ContentStore::create_protected(root.join("content.sqlite"), protection())
            .unwrap(),
    );
    for (plane, file) in [
        (Runtime, "runtime.sqlite"),
        (Tracker, "items.sqlite"),
        (Coordination, "coord.sqlite"),
        (Content, "content.sqlite"),
    ] {
        let actual = columns(&root.join(file));
        let mut declared = BTreeSet::new();
        for (_, table, all, sealed, digest) in INVENTORY.iter().filter(|entry| entry.0 == plane) {
            let all: BTreeSet<_> = all.split_whitespace().collect();
            for column in sealed.split_whitespace().chain(digest.split_whitespace()) {
                assert!(
                    all.contains(column),
                    "{plane:?} {table}.{column} is classified but not a column"
                );
            }
            declared.extend(all.into_iter().map(|c| (table.to_string(), c.to_string())));
        }
        let unclassified: Vec<_> = actual.difference(&declared).collect();
        assert!(
            unclassified.is_empty(),
            "{plane:?} columns {unclassified:?} are unclassified: decide whether each can \
             carry customer content, seal it if so, and record it in this inventory"
        );
        let removed: Vec<_> = declared.difference(&actual).collect();
        assert!(
            removed.is_empty(),
            "{plane:?} columns {removed:?} are inventoried but no longer exist"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
