            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT);
            INSERT INTO schema_migrations (version, name) VALUES (1, 'init');
            INSERT INTO schema_migrations (version, name) VALUES (2, 'provider-trust-evidence');
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL, payload_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                source TEXT NOT NULL, causation_id TEXT, correlation_id TEXT, idempotency_key TEXT,
                format_version INTEGER,
                -- DR-0066: the hash chain. `entry_digest` = H(prev_digest || canonical(entry)),
                -- so the instance's high-water mark is (sequence, entry_digest) and a gap or a
                -- substitution cannot hide. Digests are computed in Rust
                -- (whipplescript-store::event_chain) so both hosts agree byte for byte.
                prev_digest TEXT, entry_digest TEXT
            );
            CREATE UNIQUE INDEX events_instance_idempotency_key_idx
                ON events(instance_id, idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            -- Native has carried UNIQUE(instance_id, sequence) since migration 0001; this side
            -- did not, so two rows could share a position. DR-0066 needs one entry per sequence
            -- for the chain to mean anything.
            CREATE UNIQUE INDEX events_instance_sequence_idx ON events(instance_id, sequence);
            CREATE TABLE facts (
                fact_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, program_version_id TEXT,
                revision_epoch INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL,
                key TEXT NOT NULL DEFAULT '', value_json TEXT NOT NULL DEFAULT '{}',
                source_event_id TEXT, source_rule TEXT, schema_id TEXT,
                provenance_class TEXT NOT NULL DEFAULT 'derived', correlation_id TEXT,
                source_span_json TEXT, consumed_at TEXT, updated_at TEXT,
                UNIQUE(instance_id, name, key)
            );
            CREATE TABLE instances (
                instance_id TEXT PRIMARY KEY, program_id TEXT NOT NULL, version_id TEXT NOT NULL,
                revision_epoch INTEGER NOT NULL DEFAULT 0, workflow_principal TEXT NOT NULL,
                effective_authority TEXT NOT NULL, status TEXT NOT NULL, input_json TEXT NOT NULL,
                started_at TEXT, last_event_id TEXT, last_error TEXT, completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                -- DR-0066 §3: the writer fence. Counts ownership transfers of this
                -- instance's log, and is NOT `revision_epoch` above, which is program
                -- lineage — two clocks, two names.
                owner_epoch INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE programs (
                program_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE program_versions (
                version_id TEXT PRIMARY KEY, program_id TEXT NOT NULL DEFAULT '',
                source_hash TEXT NOT NULL DEFAULT '', ir_hash TEXT NOT NULL DEFAULT '',
                compiler_version TEXT NOT NULL DEFAULT '',
                declared_capabilities TEXT NOT NULL DEFAULT '[]',
                declared_profiles TEXT NOT NULL DEFAULT '[]',
                declared_skills TEXT NOT NULL DEFAULT '[]',
                declared_schemas TEXT NOT NULL DEFAULT '[]',
                analysis_summary TEXT NOT NULL DEFAULT '{}',
                generated_artifacts TEXT NOT NULL DEFAULT '[]', artifact_root TEXT,
                UNIQUE(program_id, source_hash, ir_hash)
            );
            CREATE TABLE artifacts (
                artifact_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, kind TEXT NOT NULL,
                path TEXT NOT NULL, content_hash TEXT, mime_type TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE workspaces (
                workspace_id TEXT PRIMARY KEY, instance_id TEXT, effect_id TEXT, run_id TEXT,
                provider TEXT, policy TEXT NOT NULL, uri TEXT NOT NULL, status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(instance_id, effect_id, run_id, policy)
            );
            CREATE TABLE diagnostics (
                diagnostic_id TEXT PRIMARY KEY, instance_id TEXT, program_id TEXT,
                program_version_id TEXT, severity TEXT NOT NULL, code TEXT, message TEXT NOT NULL,
                source_span_json TEXT, subject_type TEXT, subject_id TEXT, event_id TEXT,
                effect_id TEXT, run_id TEXT, assertion_id TEXT,
                evidence_ids_json TEXT NOT NULL DEFAULT '[]',
                artifact_ids_json TEXT NOT NULL DEFAULT '[]', causation_id TEXT, correlation_id TEXT,
                idempotency_key TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, kind TEXT NOT NULL,
                subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, causation_id TEXT,
                correlation_id TEXT, summary TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE evidence_links (
                link_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, instance_id TEXT NOT NULL,
                target_type TEXT NOT NULL, target_id TEXT NOT NULL, relation TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(evidence_id, target_type, target_id, relation)
            );
            CREATE TABLE effects (
                effect_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, kind TEXT NOT NULL,
                target TEXT, input_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL,
                created_by_rule TEXT NOT NULL DEFAULT '', program_version_id TEXT,
                revision_epoch INTEGER NOT NULL DEFAULT 0, profile TEXT,
                required_capabilities TEXT NOT NULL DEFAULT '[]', policy_block_reason TEXT,
                policy_block_category TEXT, created_by_event_id TEXT, correlation_id TEXT,
                idempotency_key TEXT, timeout_seconds INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE effect_dependencies (
                instance_id TEXT NOT NULL, downstream_effect_id TEXT NOT NULL,
                upstream_effect_id TEXT NOT NULL, predicate TEXT NOT NULL
            );
            CREATE TABLE leases (
                lease_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, run_id TEXT NOT NULL,
                effect_id TEXT NOT NULL, worker_id TEXT, status TEXT NOT NULL,
                expires_at TEXT NOT NULL, released_at TEXT
            );
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                provider TEXT NOT NULL, worker_id TEXT NOT NULL, status TEXT NOT NULL,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT,
                exit_code INTEGER, summary TEXT, metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE effect_cancellation_requests (
                request_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                revision_id TEXT, reason TEXT, requested_by TEXT NOT NULL DEFAULT 'kernel',
                causation_event_id TEXT, status TEXT NOT NULL, idempotency_key TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_by_event_id TEXT
            );
            CREATE TABLE instance_revisions (
                revision_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                from_version_id TEXT NOT NULL, to_version_id TEXT NOT NULL,
                activated_by_event_id TEXT NOT NULL, activation_policy_json TEXT NOT NULL DEFAULT '{}',
                cancellation_policy TEXT NOT NULL, rule_carries_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL, idempotency_key TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE workflow_invocations (
                invocation_id TEXT PRIMARY KEY, parent_instance_id TEXT NOT NULL,
                parent_effect_id TEXT NOT NULL, parent_program_version_id TEXT,
                parent_revision_epoch INTEGER NOT NULL, child_instance_id TEXT NOT NULL,
                child_program_version_id TEXT, child_revision_epoch INTEGER,
                target_workflow TEXT NOT NULL, input_json TEXT NOT NULL DEFAULT '{}',
                source_span_json TEXT, idempotency_key TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'running',
                terminal_event_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT
            );
            CREATE TABLE project_context_docs (
                position INTEGER PRIMARY KEY, path TEXT NOT NULL,
                content_hash TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE compute_result_cache (
                content_key TEXT PRIMARY KEY, effect_kind TEXT NOT NULL,
                result_json TEXT NOT NULL, source_instance_id TEXT NOT NULL,
                source_effect_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE content_blobs (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, byte_len INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE files (
                key TEXT PRIMARY KEY, content TEXT NOT NULL
            );
            CREATE TABLE script_capabilities (
                name TEXT PRIMARY KEY, argv_json TEXT NOT NULL, sha256 TEXT NOT NULL,
                env_json TEXT NOT NULL DEFAULT '{}', hermetic INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE skills (
                skill_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, version TEXT NOT NULL,
                source TEXT NOT NULL, source_path TEXT NOT NULL, content_hash TEXT NOT NULL,
                -- `register_skill` has always written this column; this side never
                -- declared it, so the insert could only ever fail on a real object.
                body TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '', required_capabilities TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE skill_attachments (
                attachment_id TEXT PRIMARY KEY, scope_type TEXT NOT NULL, scope_id TEXT NOT NULL,
                skill_id TEXT NOT NULL, UNIQUE(scope_type, scope_id, skill_id)
            );
            CREATE TABLE package_registrations (
                package_id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            );
            CREATE TABLE capability_schemas (
                capability TEXT PRIMARY KEY, description TEXT NOT NULL, schema_json TEXT NOT NULL,
                registered_by_package_id TEXT
            );
            CREATE TABLE effect_providers (
                provider_id TEXT NOT NULL, effect_kind TEXT NOT NULL, provider TEXT NOT NULL,
                capability TEXT NOT NULL, config_json TEXT NOT NULL, registered_by_package_id TEXT,
                UNIQUE(effect_kind, provider)
            );
            CREATE TABLE provider_trust_evidence (
                effect_kind TEXT NOT NULL, provider TEXT NOT NULL,
                pinned_digest TEXT,
                claim_class TEXT, claim_signer TEXT, claim_filed_at TEXT, claim_expires_at TEXT,
                operator_run INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (effect_kind, provider),
                CHECK (claim_class IS NULL OR (claim_signer IS NOT NULL AND claim_expires_at IS NOT NULL))
            );
            CREATE TABLE profiles (
                profile_id TEXT NOT NULL, name TEXT PRIMARY KEY, description TEXT NOT NULL,
                enforcement_mode TEXT NOT NULL, allowed_capabilities TEXT NOT NULL,
                config_json TEXT NOT NULL
            );
            CREATE TABLE capability_bindings (
                binding_id TEXT PRIMARY KEY, program_id TEXT, capability TEXT NOT NULL,
                provider TEXT NOT NULL, config_json TEXT NOT NULL
            );
            CREATE TABLE agent_turn_snapshots (
                effect_id TEXT PRIMARY KEY, snapshot_json TEXT NOT NULL
            );
            CREATE TABLE public_turn_commands (
                command_id TEXT PRIMARY KEY,
                turn_command_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('steer', 'follow_up')),
                text TEXT NOT NULL,
                images_json TEXT NOT NULL DEFAULT '[]',
                position INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'applied', 'removed')),
                announced INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                applied_at TEXT
            );
            CREATE INDEX idx_public_turn_commands_pending
                ON public_turn_commands(turn_command_id, kind, status, position);
            CREATE TABLE public_turn_binding (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                request_id TEXT NOT NULL,
                command_id TEXT NOT NULL
            );
            CREATE TABLE inbox_items (
                inbox_item_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                tool_call_id TEXT NOT NULL,
                prompt TEXT NOT NULL,
                choices_json TEXT NOT NULL DEFAULT '[]',
                freeform_allowed INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'pending',
                answer_hash TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                answered_at TEXT
            );
            CREATE UNIQUE INDEX idx_inbox_pending_effect
                ON inbox_items(instance_id, effect_id)
                WHERE status = 'pending';
            CREATE TABLE tracker_events (
                event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT, parents_json TEXT NOT NULL DEFAULT '[]',
                issue_id TEXT, kind TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}', actor TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_subscriptions (
                subscriber TEXT NOT NULL, queue TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (subscriber, queue)
            );
            CREATE TABLE tracker_issues (
                issue_id TEXT PRIMARY KEY, queue TEXT NOT NULL, title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
                labels_json TEXT NOT NULL DEFAULT '[]', metadata_json TEXT NOT NULL DEFAULT '{}',
                claim_summary TEXT, assigned_to TEXT, filed_by TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_relations (
                from_issue TEXT NOT NULL, to_issue TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'blocks', dep_kind TEXT,
                PRIMARY KEY (from_issue, to_issue, kind)
            );
            CREATE TABLE tracker_leases (
                lease_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, actor TEXT NOT NULL,
                acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT, released_at TEXT
            );
            CREATE TABLE tracker_counter (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1), next_id INTEGER NOT NULL
            );
            INSERT INTO tracker_counter (singleton, next_id) VALUES (1, 1);
            CREATE TABLE tracker_aliases (
                content_id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE
            );
            CREATE TABLE tracker_comments (
                comment_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, author TEXT,
                body TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_evidence (
                evidence_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, kind TEXT, reference TEXT,
                note TEXT, added_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_tracker_issues_queue ON tracker_issues(queue, status);
            CREATE INDEX idx_tracker_leases_issue ON tracker_leases(issue_id, released_at);
            CREATE INDEX idx_tracker_events_issue ON tracker_events(issue_id, kind);
            CREATE UNIQUE INDEX idx_tracker_events_id ON tracker_events(event_id);
            CREATE TABLE coord_leases (
                owner TEXT NOT NULL, resource TEXT NOT NULL, key TEXT NOT NULL, holder TEXT NOT NULL,
                acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
                PRIMARY KEY (owner, resource, key, holder)
            );
            CREATE TABLE coord_ledger_seq (
                owner TEXT NOT NULL, ledger TEXT NOT NULL, next_seq INTEGER NOT NULL,
                PRIMARY KEY (owner, ledger)
            );
            CREATE TABLE coord_ledger_entries (
                owner TEXT NOT NULL, ledger TEXT NOT NULL, partition TEXT NOT NULL, seq INTEGER NOT NULL,
                payload_json TEXT NOT NULL, appended_by TEXT NOT NULL,
                appended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (owner, ledger, seq)
            );
            CREATE TABLE coord_counters (
                owner TEXT NOT NULL, counter TEXT NOT NULL, key TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0, period TEXT NOT NULL, PRIMARY KEY (owner, counter, key)
            );
