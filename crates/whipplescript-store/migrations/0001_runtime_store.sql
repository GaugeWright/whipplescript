CREATE TABLE programs (
    program_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE program_versions (
    version_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(program_id),
    source_hash TEXT NOT NULL,
    ir_hash TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    declared_capabilities TEXT NOT NULL DEFAULT '[]',
    declared_profiles TEXT NOT NULL DEFAULT '[]',
    declared_skills TEXT NOT NULL DEFAULT '[]',
    declared_schemas TEXT NOT NULL DEFAULT '[]',
    analysis_summary TEXT NOT NULL DEFAULT '{}',
    generated_artifacts TEXT NOT NULL DEFAULT '[]',
    artifact_root TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, source_hash, ir_hash)
);

CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(program_id),
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    workflow_principal TEXT NOT NULL DEFAULT '',
    effective_authority TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    last_event_id TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
);

CREATE TABLE instance_revisions (
    revision_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    epoch INTEGER NOT NULL,
    from_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    to_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    activated_by_event_id TEXT NOT NULL REFERENCES events(event_id),
    activation_policy_json TEXT NOT NULL DEFAULT '{}',
    cancellation_policy TEXT NOT NULL,
    rule_carries_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, epoch)
);

CREATE UNIQUE INDEX instance_revisions_instance_idempotency_key_idx
    ON instance_revisions(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    causation_id TEXT,
    correlation_id TEXT,
    idempotency_key TEXT,
    UNIQUE(instance_id, sequence)
);

CREATE UNIQUE INDEX events_instance_idempotency_key_idx
    ON events(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    program_version_id TEXT REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    source_event_id TEXT,
    source_rule TEXT,
    source_effect_id TEXT,
    source_run_id TEXT,
    schema_id TEXT,
    provenance_class TEXT NOT NULL,
    external_system TEXT,
    external_id TEXT,
    correlation_id TEXT,
    source_span_json TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, name, key)
);

CREATE TABLE effects (
    effect_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    input_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    created_by_rule TEXT NOT NULL,
    created_by_event_id TEXT,
    program_version_id TEXT REFERENCES program_versions(version_id),
    revision_epoch INTEGER NOT NULL DEFAULT 0,
    correlation_id TEXT,
    idempotency_key TEXT NOT NULL,
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    profile TEXT,
    policy_block_reason TEXT,
    policy_block_category TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, idempotency_key)
);

CREATE TABLE effect_cancellation_requests (
    request_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    revision_id TEXT REFERENCES instance_revisions(revision_id),
    reason TEXT,
    requested_by TEXT NOT NULL,
    causation_event_id TEXT REFERENCES events(event_id),
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_by_event_id TEXT,
    UNIQUE(instance_id, effect_id, revision_id)
);

CREATE UNIQUE INDEX effect_cancellation_requests_instance_idempotency_key_idx
    ON effect_cancellation_requests(instance_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE effect_dependencies (
    dependency_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    upstream_effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    downstream_effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    predicate TEXT NOT NULL,
    created_by_rule TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, upstream_effect_id, downstream_effect_id, predicate)
);

CREATE TABLE workflow_invocations (
    invocation_id TEXT PRIMARY KEY,
    parent_instance_id TEXT NOT NULL,
    parent_effect_id TEXT NOT NULL,
    parent_program_version_id TEXT REFERENCES program_versions(version_id),
    parent_revision_epoch INTEGER NOT NULL DEFAULT 0,
    child_instance_id TEXT NOT NULL,
    child_program_version_id TEXT REFERENCES program_versions(version_id),
    child_revision_epoch INTEGER,
    target_workflow TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'running',
    terminal_event_id TEXT,
    source_span_json TEXT,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    instance_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    exit_code INTEGER,
    summary TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    effect_id TEXT NOT NULL REFERENCES effects(effect_id),
    instance_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    released_at TEXT
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT,
    mime_type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES instances(instance_id),
    effect_id TEXT REFERENCES effects(effect_id),
    run_id TEXT REFERENCES runs(run_id),
    provider TEXT,
    policy TEXT NOT NULL,
    uri TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(instance_id, effect_id, run_id, policy)
);

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    causation_id TEXT,
    correlation_id TEXT,
    summary TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE evidence_links (
    link_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    instance_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(evidence_id, target_type, target_id, relation)
);

CREATE TABLE diagnostics (
    diagnostic_id TEXT PRIMARY KEY,
    instance_id TEXT,
    program_id TEXT,
    program_version_id TEXT,
    severity TEXT NOT NULL,
    code TEXT,
    message TEXT NOT NULL,
    source_span_json TEXT,
    subject_type TEXT,
    subject_id TEXT,
    event_id TEXT,
    effect_id TEXT,
    run_id TEXT,
    assertion_id TEXT,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    causation_id TEXT,
    correlation_id TEXT,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX diagnostics_instance_idempotency_key_idx
    ON diagnostics(instance_id, idempotency_key)
    WHERE instance_id IS NOT NULL AND idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX diagnostics_program_idempotency_key_idx
    ON diagnostics(program_id, idempotency_key)
    WHERE instance_id IS NULL
      AND program_id IS NOT NULL
      AND program_version_id IS NULL
      AND idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX diagnostics_version_idempotency_key_idx
    ON diagnostics(program_version_id, idempotency_key)
    WHERE instance_id IS NULL AND program_version_id IS NOT NULL AND idempotency_key IS NOT NULL;

CREATE TABLE package_registrations (
    package_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE capability_schemas (
    capability TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    schema_json TEXT NOT NULL DEFAULT '{}',
    registered_by_package_id TEXT REFERENCES package_registrations(package_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE effect_providers (
    provider_id TEXT PRIMARY KEY,
    effect_kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    capability TEXT NOT NULL REFERENCES capability_schemas(capability),
    config_json TEXT NOT NULL DEFAULT '{}',
    registered_by_package_id TEXT REFERENCES package_registrations(package_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(effect_kind, provider)
);

CREATE TABLE profiles (
    profile_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
    allowed_capabilities TEXT NOT NULL DEFAULT '[]',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Project-instruction documents (AGENTS.md / CLAUDE.md) for store-backed
-- context resolution on hosts without a filesystem (context-assembly Phase 3).
CREATE TABLE project_context_docs (
    position INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    body TEXT NOT NULL
);

-- Delta-kernel result cache (compute plane P8-1): content-keyed memoization
-- of hermetic exec results, workspace-wide (not instance-scoped). Content key
-- = script hash + environment hash + input hashes. First writer wins; a key
-- is immutable once recorded (same key = same canonical result by
-- construction). Eviction joins the versioned-workspace retention policy.
CREATE TABLE compute_result_cache (
    content_key TEXT PRIMARY KEY,
    effect_kind TEXT NOT NULL,
    result_json TEXT NOT NULL,
    source_instance_id TEXT NOT NULL,
    source_effect_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Content-addressed file-history blobs (restorable-context RC-1). Every file
-- body durably written through the runtime file effect is ALSO captured here,
-- keyed by the SAME stable content hash the `file.write.completed` fact records,
-- so a superseded version's bytes survive an overwrite (the live path->bytes
-- store keeps only the current body). Identical bytes dedupe to one row
-- (content-addressed). This is the byte-preservation floor a later restore slice
-- reads through; it shares its shape with the recall content store on purpose.
-- Captured BEFORE the write's fact commits, so no manifest hash is ever
-- referenced without its bytes present (restorable-context INV-4 coherence).
CREATE TABLE content_blobs (
    id         TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    byte_len   INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Operator-pinned script capabilities (compute plane P8): store-backed mirror
-- of the filesystem script manifest for hosts without a filesystem. body =
-- full script text; sha256 = the operator pin verified at registration and
-- re-verified by the executor before running.
CREATE TABLE script_capabilities (
    name TEXT PRIMARY KEY,
    argv_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    env_json TEXT NOT NULL DEFAULT '{}',
    hermetic INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE skills (
    skill_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    source_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE skill_attachments (
    attachment_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    skill_id TEXT NOT NULL REFERENCES skills(skill_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scope_type, scope_id, skill_id)
);

CREATE TABLE capability_bindings (
    binding_id TEXT PRIMARY KEY,
    program_id TEXT REFERENCES programs(program_id),
    capability TEXT NOT NULL,
    provider TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, capability, provider)
);

INSERT INTO capability_schemas (capability, description, schema_json)
VALUES
    ('agent.tell', 'Run an agent turn through a provider harness.', '{}'),
    ('schema.coerce', 'Coerce unstructured data into a typed value.', '{}'),
    ('event.emit', 'Emit an external event.', '{}'),
    ('workflow.invoke', 'Start and observe a child workflow.', '{}'),
    ('capability.call', 'Call a registered package capability.', '{}'),
    ('messaging.send', 'Send an outbound message through a std.messaging channel.', '{}'),
    ('repo.read', 'Read repository files and metadata.', '{}'),
    ('repo.write', 'Modify repository files and metadata.', '{}'),
    ('command.run', 'Run local commands under an operator-selected provider policy.', '{}'),
    ('internet.research', 'Use networked research providers.', '{}');

INSERT INTO effect_providers (provider_id, effect_kind, provider, capability)
VALUES
    ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell'),
    ('provider_coerce_builtin', 'schema.coerce', 'builtin-coerce', 'schema.coerce'),
    ('provider_event_emit_builtin', 'event.emit', 'builtin-event', 'event.emit'),
    ('provider_workflow_invoke_builtin', 'workflow.invoke', 'builtin-workflow-runtime', 'workflow.invoke'),
    ('provider_capability_call_builtin', 'capability.call', 'builtin-package-call', 'capability.call');

INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities)
VALUES
    ('profile_permissive', 'permissive', 'Allow all registered capabilities.', 'audit', '["*"]'),
    ('profile_repo_reader', 'repo-reader', 'Allow repository reads and agent turns without writes.', 'enforce', '["agent.tell","repo.read","schema.coerce","event.emit","workflow.invoke"]'),
    ('profile_repo_writer', 'repo-writer', 'Allow repository-writing agent workflows.', 'enforce', '["agent.tell","repo.read","repo.write","command.run","schema.coerce","event.emit","workflow.invoke","capability.call"]'),
    ('profile_internet_research', 'internet-research', 'Allow networked research workflows.', 'enforce', '["agent.tell","internet.research","schema.coerce","event.emit","workflow.invoke"]');

INSERT INTO capability_bindings (binding_id, program_id, capability, provider)
VALUES
    ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness'),
    ('binding_coerce_builtin', NULL, 'schema.coerce', 'builtin-coerce'),
    ('binding_event_emit_builtin', NULL, 'event.emit', 'builtin-event'),
    ('binding_workflow_invoke_builtin', NULL, 'workflow.invoke', 'builtin-workflow-runtime'),
    ('binding_capability_call_builtin', NULL, 'capability.call', 'builtin-package-call'),
    ('binding_repo_read_builtin', NULL, 'repo.read', 'builtin-agent-harness'),
    ('binding_repo_write_builtin', NULL, 'repo.write', 'builtin-agent-harness'),
    ('binding_command_run_builtin', NULL, 'command.run', 'builtin-agent-harness');
