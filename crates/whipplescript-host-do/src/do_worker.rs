//! The durable-object instance handle (DR-0033 chunk 5c) — the `create` / `step` /
//! `snapshot` orchestration the TS worker shell drives.
//!
//! On a live Durable Object the isolate can only `await fetch`, so the runtime is
//! driven as a resumable step machine: JS calls [`DurableInstance::step`], and
//! either gets back a [`DurableStepOutcome::NeedsHttp`] (perform the `fetch`, call
//! `step` again with the response) or a terminal. This is exactly the
//! [`InstanceStepMachine`](whipplescript_kernel::instance_machine) fixpoint, inlined
//! here so the machine's `in_flight` effect persists in the handle across separate
//! JS calls (and thus across isolate evictions once the handle is rehydrated from
//! DO storage).
//!
//! This handle is plain Rust over any [`DoSql`] + the effect seams (files, coerce
//! creds, agent model/tools). The `#[wasm_bindgen]` surface that the live worker
//! imports is a thin wrapper over these three methods, adding only the JS glue
//! (a `DoSql` backed by `state.storage.sql`, a `fetch`-backed model client, and
//! JSON marshalling) — it carries no orchestration logic of its own.

use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::harness_loop::{HttpModelClient, ToolExecutor};
use whipplescript_kernel::host_protocol::ResourceRef;
use whipplescript_kernel::instance_machine::{EffectStep, InstanceDriver};
use whipplescript_kernel::sansio::{HttpRequest, HttpResponse, TransportError};
use whipplescript_kernel::{idempotency_key, ProgramVersionInput, RuntimeKernel};
use whipplescript_parser::IrProgram;
use whipplescript_store::branches::Branches;
use whipplescript_store::files::FileStore;
use whipplescript_store::{
    CheckpointCapture, ClaimableEffect, NewInstanceAuthority, RestoreDecision, RuntimeStore,
    StoreError,
};

use crate::do_instance::{
    do_coercion_config_fingerprint, DoInstanceDriver, ExecutorSidecarConfig,
    ResolvedCoercionConfig, TurnContainerConfig,
};
use crate::do_store::{DoSql, DoSqlStorage, DoSqliteStore};
use crate::DoFileStore;
use std::rc::Rc;

/// What one [`DurableInstance::step`] yields back to the worker shell.
#[derive(Debug)]
pub enum DurableStepOutcome {
    /// Perform this HTTP request via `fetch` and call `step` again with the
    /// response. The in-flight effect is held in the handle until then.
    NeedsHttp(HttpRequest),
    /// The instance reached a workflow terminal (absorbing).
    Terminal,
    /// Quiescent but not terminal — parked awaiting external input / an alarm.
    /// When the instance holds pending timed effects, `next_due_unix_ms` is
    /// the earliest wake-up it needs; the shell sets the DO alarm from it
    /// (DR-0033 Phase 6).
    Parked { next_due_unix_ms: Option<i64> },
    /// A store error aborted the pass (surfaced, not swallowed).
    Failed(String),
}

/// Unix milliseconds → ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`), dependency-free
/// so it builds for wasm (Howard Hinnant's days-from-civil, inverted). The DO
/// shell passes `Date.now()`; the store's `strftime`-based clock queries all
/// consume this shape.
pub fn unix_ms_to_iso8601(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // civil-from-days (era-based, valid for the whole i64 day range).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The effect seams a live worker injects from its bindings/secrets. All optional
/// so an instance running only store-only + effect-free workflows needs none.
#[derive(Default)]
pub struct DurableEffectPorts {
    pub files: Option<Box<dyn FileStore>>,
    pub coerce: Option<ResolvedCoercionConfig>,
    pub agent_model: Option<Box<dyn HttpModelClient>>,
    pub agent_tools: Option<Box<dyn ToolExecutor>>,
    /// Exact file-store references admitted for this host turn. When present,
    /// the default in-isolate executor serves only these selectors and honors
    /// their write attenuation.
    pub agent_workspace_resources: Option<Vec<ResourceRef>>,
    pub agent_tool_specs: Option<Vec<whipplescript_kernel::harness_loop::ToolSpec>>,
    /// Executor-sidecar wiring for Class-A exec effects (compute plane P8).
    pub exec: Option<ExecutorSidecarConfig>,
    /// Class-B turn-container wiring (agent turns run whole in a container).
    pub turn: Option<TurnContainerConfig>,
}

/// One operator-pinned script capability shipped with the deploy (compute
/// plane P8): the DO-store mirror of a native script-manifest entry. `argv`
/// must carry the `{script}` placeholder element; `body` must hash to
/// `sha256` (verified at registration — fail-closed).
pub struct ScriptCapabilityInput {
    pub name: String,
    pub argv: Vec<String>,
    pub sha256: String,
    pub env: std::collections::BTreeMap<String, String>,
    pub hermetic: bool,
    pub body: String,
}

/// A workflow instance running on the durable object as a resumable step machine.
/// Owns the kernel over the DO's SQLite, the compiled program, and the currently
/// in-flight effect (persisted across `step` calls / evictions).
pub struct DurableInstance<Sql: DoSql> {
    kernel: Option<RuntimeKernel<DoSqliteStore<Rc<Sql>>>>,
    ir: IrProgram,
    instance_id: String,
    system_prompt: String,
    max_steps: usize,
    in_flight: Option<ClaimableEffect>,
    files: Box<dyn FileStore>,
    coerce: Option<ResolvedCoercionConfig>,
    agent_model: Option<Box<dyn HttpModelClient>>,
    agent_tools: Box<dyn ToolExecutor>,
    agent_workspace_resources: Option<Vec<ResourceRef>>,
    agent_tool_specs: Option<Vec<whipplescript_kernel::harness_loop::ToolSpec>>,
    exec: Option<ExecutorSidecarConfig>,
    turn: Option<TurnContainerConfig>,
}

// `'static` so the default `DoFileStore` over the shared `Rc<Sql>` can be boxed
// as `Box<dyn FileStore>` (both real handles — `JsDoSql`, `RusqliteDoSql` — own
// their storage and are `'static`).
impl<Sql: DoSql + 'static> DurableInstance<Sql> {
    /// Attach the step machine to an instance and program already admitted and
    /// registered by the governed host facade. This is the hosted-placement
    /// counterpart to `create`: it never creates a second instance or ingests
    /// an ungoverned start event.
    pub fn attach(
        sql: Sql,
        ir: IrProgram,
        instance_id: &str,
        system_prompt: String,
        max_steps: usize,
        ports: DurableEffectPorts,
    ) -> Result<Self, String> {
        let sql = Rc::new(sql);
        let kernel = RuntimeKernel::new(DoSqliteStore {
            sql: Rc::clone(&sql),
        })
        .with_coercion_config_fingerprint(do_coercion_config_fingerprint(ports.coerce.as_ref()));
        let exists = kernel
            .store()
            .list_instances()
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .any(|instance| instance.instance_id == instance_id);
        if !exists {
            return Err(format!("no governed host instance `{instance_id}`"));
        }
        // DR-0067 §3 / DR-0073 §3: claim the instance's log.
        //
        // This is the ONE place in the tree where a claim is a real transfer
        // rather than self-election. The platform gives one live object per id,
        // so an attach is either the first one or a resumption after eviction or
        // hibernation — and in the second case the epoch bump is exactly the
        // statement that wants making: whatever isolate held this log before is
        // superseded, now, and its writes must stop rather than interleave.
        //
        // Natively the same call would prove nothing, because any process may
        // claim any instance at any time and a "claim" there is a writer
        // electing itself. That is why DR-0073 §3 scopes the fence to this host
        // and leaves the native path to its per-write guards.
        //
        // The epoch is deliberately not stored: no append on this host presents
        // one yet. Claiming still does the load-bearing half — it EVICTS — so a
        // previous isolate's fenced append is refused from this moment. Wiring
        // the presenting half is tracked in `spec/substrate-wiring-tracker.md`.
        let _epoch = kernel
            .store()
            .claim_instance_ownership(instance_id)
            .map_err(|error| format!("claim instance log ownership: {error:?}"))?;

        // DO-plane package bootstrap (see `create`): the governed host facade
        // opens the instance without seeding std packages, so seed them here
        // too. Idempotent (`ON CONFLICT DO UPDATE`), so a re-attach after an
        // isolate eviction is a no-op.
        crate::do_packages::register_embedded_std_packages(kernel.store())
            .map_err(|error| format!("{error:?}"))?;
        let default_files: Box<dyn FileStore> = Box::new(DoFileStore::new(
            DoSqlStorage::for_instance(Rc::clone(&sql), instance_id),
        ));
        let agent_tools = match ports.agent_tools {
            Some(tools) => tools,
            None => {
                let executor =
                    crate::do_tools::DoToolExecutor::for_instance(Rc::clone(&sql), instance_id);
                match ports.agent_workspace_resources.as_deref() {
                    Some(resources) => {
                        Box::new(executor.with_resources(resources)?) as Box<dyn ToolExecutor>
                    }
                    None => Box::new(executor) as Box<dyn ToolExecutor>,
                }
            }
        };
        Ok(Self {
            kernel: Some(kernel),
            ir,
            instance_id: instance_id.to_owned(),
            system_prompt,
            max_steps,
            in_flight: None,
            files: ports.files.unwrap_or(default_files),
            coerce: ports.coerce,
            agent_model: ports.agent_model,
            agent_tools,
            agent_workspace_resources: ports.agent_workspace_resources,
            agent_tool_specs: ports.agent_tool_specs,
            exec: ports.exec,
            turn: ports.turn,
        })
    }

    /// Compile `program_source`, then get-or-create THE instance in the DO
    /// store (a Durable Object holds exactly one workflow instance). The first
    /// call creates + starts it; any later call — an alarm wake-up, a poke, an
    /// isolate-eviction rehydration — reattaches to the existing durable state
    /// instead of minting a second instance.
    pub fn create(
        sql: Sql,
        program_source: &str,
        input_json: &str,
        workflow_principal: &str,
        ports: DurableEffectPorts,
        project_context: &[(String, String)],
        scripts: &[ScriptCapabilityInput],
    ) -> Result<Self, String> {
        let ir = whipplescript_parser::compile_program(program_source)
            .ir
            .ok_or_else(|| "program did not compile".to_owned())?;
        // P1: share ONE DoSql handle between the runtime store and the file
        // plane (both hit the same DO SQLite). `Rc` shares without requiring the
        // handle to be `Clone` (the test `RusqliteDoSql` wraps a non-`Clone`
        // `Connection`).
        let sql = Rc::new(sql);
        let mut kernel = RuntimeKernel::new(DoSqliteStore {
            sql: Rc::clone(&sql),
        })
        .with_coercion_config_fingerprint(do_coercion_config_fingerprint(ports.coerce.as_ref()));
        // DR-0054 Phase B: real revision identity. The literal "do" stamps
        // meant every deployed wasm — whatever its lowering — reattached to old
        // instance state under one indistinguishable version, so a redeploy
        // that changed semantics was invisible. Stamp the actual bootstrap
        // source hash and this build's crate version. The IR is compiled
        // in-process from `program_source` by THIS build, so
        // (source_hash, compiler_version) identifies the lowering; ir_hash
        // records that derived identity (no canonical IR serialization exists
        // to hash directly).
        let source_hash = whipplescript_kernel::exec_http::sha256_hex(program_source.as_bytes());
        let compiler_version = concat!("whipplescript-host-do ", env!("CARGO_PKG_VERSION"));
        let ir_hash = format!("{source_hash}+{compiler_version}");
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &source_hash,
                    ir_hash: &ir_hash,
                    compiler_version,
                },
                &ir,
            )
            .map_err(|error| format!("{error:?}"))?;
        // DO-plane package bootstrap (spec/durable-object-runtime-tracker.md):
        // seed the embedded std manifests so the admission gate is REAL for
        // coordination / file / tracker / ingress / coercion kinds — the DO
        // counterpart to native `register_locked_packages`. Must precede the
        // first worker pass; the `do_policy_block_on` exemptions those kinds
        // relied on are gone.
        crate::do_packages::register_embedded_std_packages(kernel.store())
            .map_err(|error| format!("{error:?}"))?;
        // Register deploy-shipped project instructions (context-assembly
        // Phase 3 item 4) — content-addressed, idempotent by position, read by
        // the agent turn's store-backed context resolution.
        for (position, (path, body)) in project_context.iter().enumerate() {
            if !whipplescript_kernel::context_assembly::is_managed_agents_path(path) {
                continue;
            }
            kernel
                .store()
                .register_project_context_doc(position as i64, path, body)
                .map_err(|error| format!("{error:?}"))?;
        }
        // Register deploy-shipped script capabilities (compute plane P8),
        // verifying each body against its operator pin — fail-closed, the
        // same TOCTOU discipline the native manifest loader applies.
        //
        // Script hard-off Layer 2, seeding key (a) (spec/std-script.md "Two
        // layers, both required"): capability rows are seeded only when the
        // program imports std.script. The DO compiles the program it
        // registers (above), so the compiled IR IS the registered IR — its
        // `uses` list is the import key. Deploy-shipped scripts (key b, the
        // operator authority) stay dormant for a program that never consented
        // to script execution, and every exec.command effect then blocks at
        // the store admission gate (blocked_by_capability /
        // security.script_disabled) before any executor round.
        let imports_std_script = ir.uses.iter().any(|use_decl| use_decl.name == "std.script");
        let seedable_scripts = if imports_std_script { scripts } else { &[] };
        for script in seedable_scripts {
            let actual = whipplescript_kernel::exec_http::sha256_hex(script.body.as_bytes());
            if actual != script.sha256 {
                return Err(format!(
                    "script capability `{}` hash mismatch: expected {}, got {actual}",
                    script.name, script.sha256
                ));
            }
            let argv_json = serde_json::to_string(&script.argv)
                .map_err(|error| format!("script `{}` argv: {error}", script.name))?;
            let env_json = serde_json::to_string(&script.env)
                .map_err(|error| format!("script `{}` env: {error}", script.name))?;
            kernel
                .store()
                .register_script_capability(whipplescript_store::ScriptCapabilityRegistration {
                    name: &script.name,
                    argv_json: &argv_json,
                    sha256: &script.sha256,
                    env_json: &env_json,
                    hermetic: script.hermetic,
                    body: &script.body,
                })
                .map_err(|error| format!("{error:?}"))?;
            // The policy gate reuses the standard capability machinery
            // (spec/script-capabilities.md): each entry registers as
            // `script.<name>` with a binding, so an exec naming an
            // unregistered script blocks as blocked_by_capability.
            let capability = format!("script.{}", script.name);
            kernel
                .store()
                .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
                    capability: &capability,
                    description: "Run an operator-pinned script capability.",
                    schema_json: "{}",
                    registered_by_package_id: None,
                })
                .map_err(|error| format!("{error:?}"))?;
            kernel
                .store()
                .bind_capability(whipplescript_store::CapabilityBinding {
                    binding_id: &format!("binding_script_{}", script.name),
                    program_id: None,
                    capability: &capability,
                    provider: "builtin-script",
                    config_json: "{}",
                })
                .map_err(|error| format!("{error:?}"))?;
        }
        let existing = kernel
            .store()
            .list_instances()
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .next();
        let instance_id = match existing {
            Some(instance) => {
                // DR-0054 Phase B: a reattach under a DIFFERENT build/source
                // than the one the instance's pinned version row records is
                // observable version drift, not business as usual. Record a
                // diagnosable row (idempotent per drift pair) and continue —
                // whether the drift is compatible is a revision-compatibility
                // analysis that lives native-side (`whip revise` machinery),
                // so the DO observes rather than refuses.
                let stored = kernel
                    .store()
                    .get_program_version(&instance.version_id)
                    .map_err(|error| format!("{error:?}"))?;
                if let Some(stored) = stored {
                    if stored.source_hash != source_hash
                        || stored.compiler_version != compiler_version
                    {
                        let message = format!(
                            "durable instance `{}` reattached under a different build: \
                             stored source_hash `{}` / compiler `{}` vs current \
                             source_hash `{source_hash}` / compiler `{compiler_version}`",
                            instance.instance_id, stored.source_hash, stored.compiler_version
                        );
                        let drift_key = format!(
                            "do.revision_drift:{}:{}:{ir_hash}",
                            stored.version_id, instance.instance_id
                        );
                        kernel
                            .store()
                            .record_diagnostic(whipplescript_store::DiagnosticRecord {
                                instance_id: Some(&instance.instance_id),
                                program_id: Some(&instance.program_id),
                                program_version_id: Some(&stored.version_id),
                                severity: whipplescript_store::Severity::Warning,
                                code: Some("do.revision_drift"),
                                message: &message,
                                source_span_json: None,
                                subject_type: Some("program_version"),
                                subject_id: Some(&version.version_id),
                                event_id: None,
                                effect_id: None,
                                run_id: None,
                                assertion_id: None,
                                evidence_ids_json: "[]",
                                artifact_ids_json: "[]",
                                causation_id: None,
                                correlation_id: None,
                                idempotency_key: Some(&drift_key),
                            })
                            .map_err(|error| format!("{error:?}"))?;
                    }
                }
                instance.instance_id
            }
            None => {
                let instance_id = kernel
                    .create_instance_with_authority(
                        &version,
                        input_json,
                        NewInstanceAuthority {
                            workflow_principal,
                            effective_authority_json: "{}",
                        },
                    )
                    .map_err(|error| format!("{error:?}"))?;
                kernel
                    .ingest_external_event(
                        &instance_id,
                        "external.started",
                        input_json,
                        Some("started"),
                    )
                    .map_err(|error| format!("{error:?}"))?;
                instance_id
            }
        };
        // Per-instance branch dispatch, DO parity (untie-substrate P1): an
        // instance born on a branch gets the branch working set as its file
        // surface — the same WorkspaceVcs/BranchFileStore logic as native,
        // over the DO's own Branches/ContentBlobs seams. The cut seed
        // derives from (instance, current head): minting a cut moves the
        // head, so a rehydrated isolate can never reuse a seed that already
        // produced cuts. An explicit port override still wins; unbound
        // instances keep the plain DO file plane.
        let default_files: Box<dyn FileStore> = {
            let branches = crate::do_branches::DoBranches::new(Rc::clone(&sql))
                .map_err(|error| format!("branch store unavailable: {error:?}"))?;
            match branches.instance_branch(&instance_id) {
                Ok(Some(branch_id)) => {
                    let head = branches
                        .get_branch(&branch_id)
                        .ok()
                        .flatten()
                        .and_then(|row| row.head_cut_id)
                        .unwrap_or_default();
                    let seed = crate::do_store::stable_hash_hex(&format!("{instance_id}|{head}"));
                    let content = crate::do_branches::DoContentBlobs::new(Rc::clone(&sql))
                        .map_err(|error| format!("content blobs unavailable: {error:?}"))?;
                    let mut vcs =
                        whipplescript_store::vcs::WorkspaceVcs::from_parts(branches, content);
                    // The run's writes carry the deepest observed tier
                    // (DR-0052; session carriage upgrades this later).
                    vcs.set_actor(Some(format!("instance:{instance_id}")));
                    Box::new(whipplescript_store::vcs::BranchFileStore::new(
                        vcs,
                        &branch_id,
                        &format!("cut-{seed}"),
                        &format!("after:{head}"),
                    ))
                }
                _ => Box::new(DoFileStore::new(DoSqlStorage::new(Rc::clone(&sql)))),
            }
        };
        // DR-0067 §3 / DR-0073 §3, the same claim `attach` takes. `create` is
        // also a resumption path — it matches an existing instance rather than
        // always minting one — so the isolate arriving here may well be
        // superseding a previous holder, and says so.
        // DR-0067 §3 / DR-0073 §3, the same claim `attach` takes. `create` is
        // also a resumption path — it matches an existing instance rather than
        // always minting one — so the isolate arriving here may well be
        // superseding a previous holder, and says so.
        kernel
            .store()
            .claim_instance_ownership(&instance_id)
            .map_err(|error| format!("claim instance log ownership: {error:?}"))?;

        Ok(Self {
            kernel: Some(kernel),
            ir,
            instance_id,
            system_prompt: "You are a WhippleScript agent.".to_owned(),
            max_steps: 8,
            in_flight: None,
            // P1: files work by default on the DO — the file plane is intrinsic
            // to having DO SQLite, so a live instance always gets a real
            // file surface over the shared handle (an explicit port override,
            // e.g. a `TieredFileStore`, still wins).
            files: ports.files.unwrap_or(default_files),
            coerce: ports.coerce,
            agent_model: ports.agent_model,
            // P4: the DO agent turn gets a real in-isolate tool executor over
            // the shared DO SQLite by default (the file plane IS the sandbox),
            // so agent turns can read/write/edit/search files and drive the
            // tracker with no extra deploy config. An explicit port override
            // (e.g. an HTTP sidecar broker) still wins.
            agent_tools: ports
                .agent_tools
                .unwrap_or_else(|| Box::new(crate::do_tools::DoToolExecutor::new(Rc::clone(&sql)))),
            agent_workspace_resources: ports.agent_workspace_resources,
            agent_tool_specs: ports.agent_tool_specs,
            exec: ports.exec,
            turn: ports.turn,
        })
    }

    /// Bind THIS durable instance to the branch it works on (write-once;
    /// the operator's DO-side counterpart of `whip dev --branch` /
    /// `whip branch bind`): records the `branch_instances` row, appends the
    /// `branch.bound` event so the kernel derives branch-distinct effect
    /// keys, and swaps the live file surface onto the branch working set
    /// so effects dispatched after the bind land on the branch.
    pub fn bind_branch(&mut self, branch_id: &str, at: &str) -> Result<(), String> {
        use whipplescript_store::branches::BindOutcome;
        use whipplescript_store::RuntimeStore;
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| "instance kernel already consumed".to_owned())?;
        let sql = Rc::clone(&kernel.store().sql);
        let mut branches = crate::do_branches::DoBranches::new(Rc::clone(&sql))
            .map_err(|error| format!("branch store unavailable: {error:?}"))?;
        match branches
            .bind_instance(&self.instance_id, branch_id, at)
            .map_err(|error| format!("bind failed: {error:?}"))?
        {
            BindOutcome::Bound => {}
            BindOutcome::AlreadyBound { branch_id: other } => {
                return Err(format!("instance is already bound to branch `{other}`"));
            }
            BindOutcome::BranchMissing => {
                return Err(format!("no such branch `{branch_id}`"));
            }
            BindOutcome::BranchNotActive { status } => {
                return Err(format!(
                    "branch `{branch_id}` is {} — instances cannot be born on a closed line",
                    status.as_str()
                ));
            }
        }
        let payload = format!("{{\"branch_id\":\"{branch_id}\"}}");
        kernel
            .store()
            .append_event(whipplescript_store::NewEvent {
                instance_id: &self.instance_id,
                event_type: "branch.bound",
                payload_json: &payload,
                source: "do",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some(&whipplescript_kernel::idempotency_key(&[
                    &self.instance_id,
                    branch_id,
                    "branch-bind",
                ])),
            })
            .map_err(|error| format!("could not record the binding event: {error:?}"))?;
        // Swap the live surface: the head is fresh-read, so the cut seed
        // stays collision-free by the head-moves-on-mint argument.
        let head = branches
            .get_branch(branch_id)
            .ok()
            .flatten()
            .and_then(|row| row.head_cut_id)
            .unwrap_or_default();
        let seed = crate::do_store::stable_hash_hex(&format!("{}|{head}", self.instance_id));
        let content = crate::do_branches::DoContentBlobs::new(Rc::clone(&sql))
            .map_err(|error| format!("content blobs unavailable: {error:?}"))?;
        let vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(branches, content);
        self.files = Box::new(whipplescript_store::vcs::BranchFileStore::new(
            vcs,
            branch_id,
            &format!("cut-{seed}"),
            at,
        ));
        Ok(())
    }

    /// Advance the instance until it next needs an HTTP round or settles. `incoming`
    /// is the response to the request the previous `step` returned (`None` on the
    /// first call); `now_unix_ms` is the host's clock instant (the DO shell passes
    /// `Date.now()`) — injected so the core never reads wall time (DR-0033
    /// Phase 6). This is the `InstanceStepMachine` fixpoint with the in-flight
    /// effect held in `self`.
    pub fn step(
        &mut self,
        incoming: Option<Result<HttpResponse, TransportError>>,
        now_unix_ms: i64,
    ) -> DurableStepOutcome {
        // Borrow disjoint fields: the driver takes the kernel by value and the effect
        // seams + program by reference, while `in_flight` is threaded separately.
        let kernel = match self.kernel.take() {
            Some(kernel) => kernel,
            None => {
                return DurableStepOutcome::Failed("instance kernel already consumed".to_owned())
            }
        };
        let mut driver = DoInstanceDriver {
            kernel,
            files: self.files.as_ref(),
            coerce: self.coerce.as_ref(),
            agent_model: self.agent_model.as_deref(),
            agent_tools: self.agent_tools.as_ref(),
            agent_workspace_resources: self.agent_workspace_resources.as_deref(),
            agent_tool_specs: self.agent_tool_specs.as_deref(),
            exec: self.exec.as_ref(),
            turn: self.turn.as_ref(),
            ir: &self.ir,
            instance_id: &self.instance_id,
            system_prompt: &self.system_prompt,
            max_steps: self.max_steps,
        };

        let now = unix_ms_to_iso8601(now_unix_ms);
        let outcome = drive_fixpoint(&mut driver, &mut self.in_flight, incoming, &now);
        self.kernel = Some(driver.kernel);
        outcome
    }

    /// The instance's durable status (`"running"` / `"completed"` / `"failed"` / …),
    /// for the worker to expose or to decide whether to keep the object warm.
    pub fn status(&self) -> Result<Option<String>, StoreError> {
        let kernel = self.kernel.as_ref().expect("kernel present between steps");
        Ok(kernel
            .store()
            .get_instance(&self.instance_id)?
            .map(|instance| instance.status))
    }

    #[cfg(test)]
    pub(crate) fn admitted_max_steps(&self) -> usize {
        self.max_steps
    }

    /// Whether coerce is configured (mirrors a live worker's binding check).
    pub fn coerce_provider(&self) -> Option<CoerceProvider> {
        self.coerce.as_ref().map(|config| config.backend)
    }

    /// Capture a restorable consistent-cut checkpoint (DO parity P3 — the
    /// operator-command counterpart to the CLI `whip checkpoint`). Refuses if an
    /// effect is mid-run.
    pub fn checkpoint(&mut self, cut_id: &str) -> Result<DoCheckpointReport, String> {
        let instance_id = self.instance_id.clone();
        let key = idempotency_key(&[&instance_id, cut_id, "checkpoint"]);
        let kernel = self.kernel.as_mut().ok_or("instance kernel consumed")?;
        // Two-plane consistent cut, DO parity: the workspace plane's
        // monotone high-water positions land in the same pass as the
        // substance cut (all three surfaces share the one DO SQLite).
        {
            use whipplescript_store::coordination::Coordination;
            use whipplescript_store::items::WorkItems;
            let ledgers = kernel.store().ledger_positions().unwrap_or_default();
            let tracker_seq = kernel.store().event_position().unwrap_or(0);
            let ledger_entries = ledgers
                .iter()
                .map(|(owner, ledger, seq)| {
                    format!("{{\"owner\":\"{owner}\",\"ledger\":\"{ledger}\",\"seq\":{seq}}}")
                })
                .collect::<Vec<_>>()
                .join(",");
            let payload = format!(
                "{{\"cut_id\":\"{cut_id}\",\"positions\":{{\"coordination_ledgers\":[{ledger_entries}],\"tracker_event_seq\":{tracker_seq}}}}}"
            );
            kernel
                .store()
                .append_event(whipplescript_store::NewEvent {
                    instance_id: &instance_id,
                    event_type: "plane.positions",
                    payload_json: &payload,
                    source: "do",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: Some(&idempotency_key(&[
                        &instance_id,
                        cut_id,
                        "plane-positions",
                    ])),
                })
                .map_err(|error| format!("plane positions: {error:?}"))?;
        }
        let captured = kernel
            .store_mut()
            .capture_checkpoint(CheckpointCapture {
                instance_id: &instance_id,
                cut_id,
                transcript_ref: None,
                idempotency_key: Some(&key),
            })
            .map_err(|error| format!("{error:?}"))?;
        Ok(DoCheckpointReport {
            cut_id: captured.cut_id,
            sequence: captured.sequence,
            manifest_hash: captured.manifest_hash,
            file_count: captured.file_count,
        })
    }

    /// Restore the three planes to a prior checkpoint (DO parity P3 — the
    /// operator-command counterpart to the CLI `whip restore`). Same order:
    /// (1) `plan_restore` — the whole coherence check up front; a refusal mutates
    /// nothing; (2) auto-checkpoint the current head as `auto-before-<cut>` so
    /// the restore is itself undoable; (3) apply the full file reconcile — write
    /// every manifest path back to its cut content, remove post-cut mediated
    /// files — through this instance's `FileStore` (the DO file plane, P1);
    /// (4) `commit_restore` so the instance + transcript planes fold to the cut.
    pub fn restore(&mut self, cut_id: &str) -> Result<DoRestoreReport, String> {
        let instance_id = self.instance_id.clone();
        // 1) Plan (read-only). A refusal is returned as an error with no mutation.
        let plan = {
            let kernel = self.kernel.as_ref().ok_or("instance kernel consumed")?;
            match kernel
                .store()
                .plan_restore(&instance_id, cut_id)
                .map_err(|error| format!("{error:?}"))?
            {
                RestoreDecision::Ready(plan) => plan,
                RestoreDecision::Refused { reason } => {
                    return Err(format!("restore refused: {reason}"))
                }
            }
        };
        // 2) Auto-checkpoint the current head so this restore is itself undoable.
        let auto_cut_id = format!("auto-before-{cut_id}");
        {
            let auto_key = idempotency_key(&[&instance_id, &auto_cut_id, "checkpoint"]);
            let kernel = self.kernel.as_mut().ok_or("instance kernel consumed")?;
            kernel
                .store_mut()
                .capture_checkpoint(CheckpointCapture {
                    instance_id: &instance_id,
                    cut_id: &auto_cut_id,
                    transcript_ref: None,
                    idempotency_key: Some(&auto_key),
                })
                .map_err(|error| format!("auto-checkpoint before restore: {error:?}"))?;
        }
        // DR-0073 §5, captured after the auto-checkpoint for the same reason as
        // native: that checkpoint appends, so a plan-time head would refuse
        // every restore.
        let expected_head = {
            let kernel = self.kernel.as_ref().ok_or("instance kernel consumed")?;
            kernel
                .store()
                .chain_head(&instance_id)
                .map_err(|error| format!("read log head: {error:?}"))?
                .digest
        };

        // 3) Apply the file reconcile through the DO file plane. Every content
        //    hash was verified present in step 1, so writes cannot fail for
        //    missing bytes.
        for (path, body) in &plan.writes {
            let target = std::path::Path::new(path);
            if let Some(parent) = target.parent() {
                self.files
                    .create_dir_all(parent)
                    .map_err(|error| format!("restore: create parent of `{path}`: {error}"))?;
            }
            self.files
                .write(target, body.as_bytes())
                .map_err(|error| format!("restore: write `{path}`: {error}"))?;
        }
        for path in &plan.removes {
            self.files
                .remove(std::path::Path::new(path))
                .map_err(|error| format!("restore: remove `{path}`: {error}"))?;
        }
        // 4) Commit: the marker + marker-aware rebuild fold the instance and
        //    transcript planes to the cut.
        let commit_key = idempotency_key(&[&instance_id, cut_id, "restore"]);
        let marker = {
            let kernel = self.kernel.as_mut().ok_or("instance kernel consumed")?;
            kernel
                .store_mut()
                .commit_restore(
                    &instance_id,
                    plan.restored_to_sequence,
                    cut_id,
                    &expected_head,
                    Some(&commit_key),
                )
                .map_err(|error| format!("commit restore: {error:?}"))?
        };
        Ok(DoRestoreReport {
            cut_id: cut_id.to_owned(),
            restored_to_sequence: plan.restored_to_sequence,
            marker_sequence: marker.sequence,
            files_written: plan.writes.len(),
            files_removed: plan.removes.len(),
            auto_checkpoint: auto_cut_id,
        })
    }
}

/// The outcome of a DO checkpoint (P3), for the worker to marshal to JSON.
pub struct DoCheckpointReport {
    pub cut_id: String,
    pub sequence: i64,
    pub manifest_hash: String,
    pub file_count: usize,
}

/// The outcome of a DO restore (P3), for the worker to marshal to JSON.
pub struct DoRestoreReport {
    pub cut_id: String,
    pub restored_to_sequence: i64,
    pub marker_sequence: i64,
    pub files_written: usize,
    pub files_removed: usize,
    pub auto_checkpoint: String,
}

/// The `InstanceStepMachine` fixpoint, factored out so it can borrow `in_flight`
/// disjointly from the handle's other fields.
fn drive_fixpoint<D: InstanceDriver>(
    driver: &mut D,
    in_flight: &mut Option<ClaimableEffect>,
    incoming: Option<Result<HttpResponse, TransportError>>,
    now: &str,
) -> DurableStepOutcome {
    // Resume an effect suspended on an HTTP round with the host's response.
    if let Some(effect) = in_flight.take() {
        match driver.run_effect(&effect, incoming) {
            Ok(EffectStep::Done(_)) => {}
            Ok(EffectStep::NeedsHttp(request)) => {
                *in_flight = Some(effect);
                return DurableStepOutcome::NeedsHttp(request);
            }
            Ok(EffectStep::Parked) => {
                return DurableStepOutcome::Parked {
                    next_due_unix_ms: None,
                }
            }
            Err(error) => return DurableStepOutcome::Failed(format!("{error:?}")),
        }
    }

    // The due-time pass first (DR-0033 Phase 6): an alarm-driven re-entry
    // completes its due timers / expires deadlines before the rule pass, so
    // the rules see the fired facts this same step.
    if let Err(error) = driver.advance_time(now) {
        return DurableStepOutcome::Failed(format!("{error:?}"));
    }

    loop {
        match driver.advance_rules() {
            Ok(true) => return DurableStepOutcome::Terminal,
            Ok(false) => {}
            Err(error) => return DurableStepOutcome::Failed(format!("{error:?}")),
        }
        let ready = match driver.next_ready_effect() {
            Ok(Some(effect)) => effect,
            Ok(None) => {
                // Parked: surface the earliest pending wake-up so the shell
                // can set the DO's single alarm.
                return match driver.next_due_unix_ms(now) {
                    Ok(next_due_unix_ms) => DurableStepOutcome::Parked { next_due_unix_ms },
                    Err(error) => DurableStepOutcome::Failed(format!("{error:?}")),
                };
            }
            Err(error) => return DurableStepOutcome::Failed(format!("{error:?}")),
        };
        match driver.run_effect(&ready, None) {
            Ok(EffectStep::Done(_)) => continue,
            Ok(EffectStep::NeedsHttp(request)) => {
                *in_flight = Some(ready);
                return DurableStepOutcome::NeedsHttp(request);
            }
            Ok(EffectStep::Parked) => {
                return DurableStepOutcome::Parked {
                    next_due_unix_ms: None,
                }
            }
            Err(error) => return DurableStepOutcome::Failed(format!("{error:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed injected clock for deterministic tests (2026-01-01T00:00:00Z).
    const TEST_NOW_MS: i64 = 1_767_225_600_000;
    use crate::do_store::test_support::store;

    // The worker-shell loop over an effect-free workflow: `create`, then `step`
    // until a terminal — no HTTP round, one settle.

    /// DR-0054 Phase B: `create` registers REAL revision identity (the hash of
    /// the bootstrap source bytes and this build's crate version — never the
    /// old `"do"` literals), and a reattach under a different source records a
    /// diagnosable `do.revision_drift` row instead of silently reattaching
    /// under an indistinguishable identity. The reattach itself proceeds.
    // DR-0067 §3's fence gets its first production caller here (2026-08-25).
    //
    // The mechanism was built, tested, and reached by NOTHING — that is what
    // the review of DR-0066..DR-0071 found, and what
    // `spec/substrate-wiring-tracker.md` exists to close. This test is the
    // evidence that a claim is now actually taken: bringing a second isolate
    // up on the same instance evicts the first, so the first's fenced append
    // stops being accepted.
    //
    // Only this host. Natively the same call would be a writer electing
    // itself, since any process may claim any instance at any time; DR-0073
    // §3 scopes the fence here and leaves native to its per-write guards.
    #[test]
    fn attaching_a_second_isolate_evicts_the_first() {
        use whipplescript_store::{GuardKind, StoreError};

        let sql = store().sql;
        // A minimal program: what matters is that an instance exists for two
        // isolates to contend over, not what it does.
        let source = r#"workflow MinimalNoop

output result StartupSeen

class StartupSeen {
  source string
  state "observed"
}

rule observe_start
  when started
=> {
  record StartupSeen {
    source "evict"
    state "observed"
  }

  complete result {
    source "evict"
    state "observed"
  }
}
"#
        .to_owned();
        let first = DurableInstance::create(
            sql.clone(),
            &source,
            "{}",
            "local/MinimalNoop",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("first isolate creates");
        let instance_id = first.instance_id.clone();
        let epoch_first = first
            .kernel
            .as_ref()
            .expect("kernel")
            .store()
            .instance_owner_epoch(&instance_id)
            .expect("epoch reads");

        // A second isolate comes up on the same instance — an eviction or a
        // hibernation wake, which on this platform is the only way two of
        // them exist for one id.
        let second = DurableInstance::create(
            sql.clone(),
            &source,
            "{}",
            "local/MinimalNoop",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("second isolate creates");
        let store_second = second.kernel.as_ref().expect("kernel").store();
        let epoch_second = store_second
            .instance_owner_epoch(&instance_id)
            .expect("epoch reads");
        assert!(
            epoch_second > epoch_first,
            "bringing up a second isolate must claim, or the fence protects \
             nothing: {epoch_first} -> {epoch_second}"
        );

        // The first isolate, resuming mid-flight, re-reads the head — so the
        // compare-and-set has nothing to object to. Only the fence refuses.
        let head = store_second.chain_head(&instance_id).expect("head");
        let zombie = store_second.append_event_fenced(
            epoch_first,
            &head.digest,
            whipplescript_store::NewEvent {
                instance_id: &instance_id,
                event_type: "rule.fired",
                payload_json: "{}",
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            },
        );
        let Err(StoreError::GuardRefused { guard, .. }) = zombie else {
            panic!("the superseded isolate must not append, got {zombie:?}");
        };
        assert_eq!(guard, GuardKind::OwnershipFence);
    }

    #[test]
    fn create_stamps_real_revision_identity_and_records_drift_on_reattach() {
        fn minimal_source(marker: &str) -> String {
            format!(
                r#"workflow MinimalNoop

output result StartupSeen

class StartupSeen {{
  source string
  state "observed"
}}

rule observe_start
  when started
=> {{
  record StartupSeen {{
    source "{marker}"
    state "observed"
  }}

  complete result {{
    source "{marker}"
    state "observed"
  }}
}}
"#
            )
        }

        let sql = store().sql;
        let source_v1 = minimal_source("external.started");
        let instance = DurableInstance::create(
            sql.clone(),
            &source_v1,
            "{}",
            "local/MinimalNoop",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("create");
        let kernel = instance.kernel.as_ref().expect("kernel");
        let view = {
            let instances = kernel.store().list_instances().expect("instances");
            kernel
                .store()
                .get_program_version(&instances[0].version_id)
                .expect("version loads")
                .expect("version exists")
        };
        let expected_hash = whipplescript_kernel::exec_http::sha256_hex(source_v1.as_bytes());
        assert_eq!(view.source_hash, expected_hash, "real source hash stamped");
        assert!(
            view.compiler_version.contains(env!("CARGO_PKG_VERSION")),
            "real build version stamped: {}",
            view.compiler_version
        );
        assert_ne!(view.ir_hash, "do", "no placeholder identity remains");
        assert!(
            kernel
                .store()
                .list_diagnostics(None)
                .expect("diagnostics")
                .iter()
                .all(|d| d.code.as_deref() != Some("do.revision_drift")),
            "same-build create records no drift"
        );
        drop(instance);

        // Reattach after a "redeploy" whose bootstrap source changed: the
        // instance still attaches, and the drift is now observable.
        let source_v2 = minimal_source("external.redeployed");
        let instance = DurableInstance::create(
            sql.clone(),
            &source_v2,
            "{}",
            "local/MinimalNoop",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("reattach under a different source succeeds");
        let kernel = instance.kernel.as_ref().expect("kernel");
        let drift: Vec<_> = kernel
            .store()
            .list_diagnostics(None)
            .expect("diagnostics")
            .into_iter()
            .filter(|d| d.code.as_deref() == Some("do.revision_drift"))
            .collect();
        assert_eq!(drift.len(), 1, "one drift diagnostic per drift pair");
        assert!(
            drift[0].message.contains(&expected_hash),
            "drift names the stored identity: {}",
            drift[0].message
        );
        assert!(
            drift[0]
                .message
                .contains(&whipplescript_kernel::exec_http::sha256_hex(
                    source_v2.as_bytes()
                )),
            "drift names the current identity: {}",
            drift[0].message
        );
        drop(instance);

        // Re-reattaching under the SAME drifted source is idempotent — the
        // diagnostic does not accumulate.
        let instance = DurableInstance::create(
            sql,
            &source_v2,
            "{}",
            "local/MinimalNoop",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("repeat reattach");
        let kernel = instance.kernel.as_ref().expect("kernel");
        let drift_count = kernel
            .store()
            .list_diagnostics(None)
            .expect("diagnostics")
            .into_iter()
            .filter(|d| d.code.as_deref() == Some("do.revision_drift"))
            .count();
        assert_eq!(drift_count, 1, "drift diagnostic is idempotent");
    }

    #[test]
    fn durable_exec_sidecar_round_survives_complete_handle_loss() {
        use whipplescript_kernel::exec_http;
        use whipplescript_kernel::sansio::HttpResponse;

        let source = r#"use std.script
workflow ExecRecovery

output result Report

class Request {
  text string
}

class Report {
  verdict string
}

table requests as Request [
  {
    text "check"
  }
]

rule go
  when Request as request
=> {
  exec judge with request -> Report as report

  after report succeeds as out {
    complete result {
      verdict out.verdict
    }
  }
}
"#;
        let script_body = "read line\necho '{\"verdict\":\"pass\"}'\n";
        let script_sha = whipplescript_kernel::exec_http::sha256_hex(script_body.as_bytes());
        let scripts = vec![ScriptCapabilityInput {
            name: "judge".to_owned(),
            argv: vec!["sh".to_owned(), "{script}".to_owned()],
            sha256: script_sha,
            env: std::collections::BTreeMap::from([(
                "ALLOWED_VALUE".to_owned(),
                "env:SAFE_VALUE".to_owned(),
            )]),
            hermetic: false,
            body: script_body.to_owned(),
        }];
        let ports = || DurableEffectPorts {
            exec: Some(ExecutorSidecarConfig {
                base_url: "http://executor:8080".to_owned(),
                env_values: std::collections::BTreeMap::from([
                    ("SAFE_VALUE".to_owned(), "visible-safe-value".to_owned()),
                    (
                        "UNRELATED_PROVIDER_CREDENTIAL".to_owned(),
                        "canary-provider-secret-must-not-enter-command".to_owned(),
                    ),
                ]),
                environment_epoch: "test-epoch".to_owned(),
                timeout_ms: Some(10_000),
                auth_token: None,
            }),
            ..DurableEffectPorts::default()
        };
        let sql = store().sql;
        let mut instance = DurableInstance::create(
            sql.clone(),
            source,
            "{}",
            "local/ExecRecovery",
            ports(),
            &[],
            &scripts,
        )
        .expect("create");
        let request = match instance.step(None, TEST_NOW_MS) {
            DurableStepOutcome::NeedsHttp(request) => request,
            other => panic!("expected executor request, got {other:?}"),
        };
        drop(instance);

        let mut instance = DurableInstance::create(
            sql,
            source,
            "{}",
            "local/ExecRecovery",
            ports(),
            &[],
            &scripts,
        )
        .expect("reattach");
        let replay = match instance.step(None, TEST_NOW_MS) {
            DurableStepOutcome::NeedsHttp(request) => request,
            other => panic!("expected replayed executor request, got {other:?}"),
        };
        assert_eq!(replay.url, request.url);
        assert_eq!(replay.headers, request.headers);
        assert_eq!(replay.body, request.body);
        assert_eq!(
            replay.body["env"],
            serde_json::json!({"ALLOWED_VALUE": "visible-safe-value"}),
            "the command receives only script-declared environment references"
        );
        assert!(
            !replay
                .body
                .to_string()
                .contains("canary-provider-secret-must-not-enter-command"),
            "an unrelated host credential must not enter the executor request"
        );

        let effect_id = replay.body["effect_id"]
            .as_str()
            .expect("executor request effect id");
        let response = HttpResponse {
            status: 200,
            body: serde_json::json!({
                "protocol": exec_http::EXECUTOR_PROTOCOL,
                "effect_id": effect_id,
                "exit_code": 0,
                "timed_out": false,
                "stdout": "{\"verdict\":\"pass\"}\n",
                "stderr": "",
            }),
        };
        assert!(matches!(
            instance.step(Some(Ok(response)), TEST_NOW_MS),
            DurableStepOutcome::Terminal
        ));
        let kernel = instance.kernel.as_ref().expect("kernel");
        let runs = kernel
            .store()
            .list_runs(&instance.instance_id)
            .expect("runs");
        assert_eq!(runs.len(), 1, "reattachment must not mint a second run");
        assert_eq!(runs[0].status, "completed");
        let effects = kernel
            .store()
            .list_effects(&instance.instance_id)
            .expect("effects");
        assert_eq!(
            effects
                .iter()
                .filter(|effect| effect.kind == "exec.command" && effect.status == "completed")
                .count(),
            1,
            "the executor round has one terminal effect"
        );
    }

    #[test]
    fn durable_turn_container_round_survives_complete_handle_loss() {
        use whipplescript_kernel::sansio::HttpResponse;

        let source = "workflow AgentContainerRecovery\n\noutput result Done\n\n\
             class Done {\n  ok int\n}\n\n\
             agent helper {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n}\n\n\
             rule go\n  when started\n=> {\n  tell helper as reply \"\"\"\n  Do the thing.\n  \"\"\"\n\n\
             \x20 after reply succeeds {\n    complete result { ok 1 }\n  }\n\n\
             \x20 after reply fails {\n    complete result { ok 0 }\n  }\n}\n";
        let ports = || DurableEffectPorts {
            turn: Some(TurnContainerConfig {
                base_url: "http://turn".to_owned(),
                provider: serde_json::json!({"provider": "fixture"}),
                max_steps: 8,
                auth_token: None,
            }),
            ..DurableEffectPorts::default()
        };
        let base = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('agent.tell', 'Run an agent turn.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) \
             VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
        ] {
            base.sql.execute(stmt, &[]).expect("seed agent provider");
        }
        let sql = base.sql;
        let mut instance = DurableInstance::create(
            sql.clone(),
            source,
            "{}",
            "local/AgentContainerRecovery",
            ports(),
            &[],
            &[],
        )
        .expect("create");
        let request = match instance.step(None, TEST_NOW_MS) {
            DurableStepOutcome::NeedsHttp(request) => request,
            other => panic!("expected turn-container request, got {other:?}"),
        };
        drop(instance);

        let mut instance = DurableInstance::create(
            sql,
            source,
            "{}",
            "local/AgentContainerRecovery",
            ports(),
            &[],
            &[],
        )
        .expect("reattach");
        let replay = match instance.step(None, TEST_NOW_MS) {
            DurableStepOutcome::NeedsHttp(request) => request,
            other => panic!("expected replayed turn-container request, got {other:?}"),
        };
        assert_eq!(replay.url, request.url);
        assert_eq!(replay.headers, request.headers);
        assert_eq!(replay.body, request.body);

        let turn_id = replay.body["turn_id"].as_str().expect("turn id");
        let response = HttpResponse {
            status: 200,
            body: serde_json::json!({
                "protocol": "whip-turn/1",
                "turn_id": turn_id,
                "resumed": true,
                "outcome": {
                    "status": "completed",
                    "summary": "container turn complete",
                    "steps": 2,
                    "usage": {"input_tokens": 5, "output_tokens": 7},
                },
            }),
        };
        assert!(matches!(
            instance.step(Some(Ok(response)), TEST_NOW_MS),
            DurableStepOutcome::Terminal
        ));
        let kernel = instance.kernel.as_ref().expect("kernel");
        let runs = kernel
            .store()
            .list_runs(&instance.instance_id)
            .expect("runs");
        assert_eq!(runs.len(), 1, "reattachment must not mint a second run");
        assert_eq!(runs[0].status, "completed");
        let effects = kernel
            .store()
            .list_effects(&instance.instance_id)
            .expect("effects");
        assert_eq!(
            effects
                .iter()
                .filter(|effect| effect.kind == "agent.tell" && effect.status == "completed")
                .count(),
            1,
            "the container round has one terminal effect"
        );
    }

    /// Script hard-off Layer 2, seeding key (a) on the DO (S6d-6,
    /// spec/std-script.md "Two layers, both required"): deploy-shipped script
    /// capabilities register only when the program imports std.script. Same
    /// operator scripts (key b), two programs — the importing one gets the
    /// `script.<name>` schema/binding rows; the non-importing one (the
    /// forged-IR analog: `exec` compiles fine outside the CLI check gate)
    /// gets none, so its exec.command effects block at the DO admission gate.
    #[test]
    fn script_capabilities_seed_only_when_the_program_imports_std_script() {
        let script_body = "read line\necho '{\"verdict\":\"pass\"}'\n";
        let script_sha = whipplescript_kernel::exec_http::sha256_hex(script_body.as_bytes());
        let scripts = vec![ScriptCapabilityInput {
            name: "judge".to_owned(),
            argv: vec!["sh".to_owned(), "{script}".to_owned()],
            sha256: script_sha,
            env: std::collections::BTreeMap::new(),
            hermetic: false,
            body: script_body.to_owned(),
        }];
        let body = "\n\noutput result Done\n\nclass Done {\n  ok int\n}\n\n\
             rule go\n  when started\n=> {\n  complete result { ok 1 }\n}\n";
        let seeded_rows = |source: String| {
            let instance = DurableInstance::create(
                store().sql,
                &source,
                "{}",
                "local/SeedProbe",
                DurableEffectPorts::default(),
                &[],
                &scripts,
            )
            .expect("create");
            let kernel = instance.kernel.as_ref().expect("kernel present");
            kernel
                .store()
                .sql
                .query(
                    "SELECT 1 FROM capability_bindings WHERE capability = 'script.judge'",
                    &[],
                )
                .expect("bindings query")
                .len()
        };

        assert_eq!(
            seeded_rows(format!("workflow NoConsent{body}")),
            0,
            "no import (key a) => the operator scripts stay dormant"
        );
        assert_eq!(
            seeded_rows(format!("use std.script\nworkflow Consent{body}")),
            1,
            "import + operator scripts => the capability row is seeded"
        );
    }
}

#[cfg(test)]
mod branch_dispatch_tests {
    use super::*;
    use crate::do_branches::{DoBranches, DoContentBlobs};
    use crate::do_store::test_support::store;
    use whipplescript_store::branches::{
        Branches, CreateBranch, CreateBranchOutcome, MAINLINE_BRANCH_ID,
    };
    use whipplescript_store::vcs::WorkspaceVcs;

    const TEST_NOW_MS: i64 = 1_767_225_600_000;

    /// DO parity for per-instance branch dispatch: an instance bound to a
    /// branch runs its `file.write` effect through the branch working set —
    /// the content lands as a cut on the branch (readable through the same
    /// generic `WorkspaceVcs` the native CLI uses), the plain DO file plane
    /// stays untouched, and the workflow still reaches its terminal.
    #[test]
    fn branch_bound_instance_dispatches_file_effects_onto_the_branch() {
        let sql = Rc::new(store().sql);

        // The branch exists before the instance is born on it.
        {
            let mut branches = DoBranches::new(Rc::clone(&sql)).expect("branch store");
            branches.ensure_mainline("t0").expect("mainline");
            assert!(matches!(
                branches
                    .create_branch(CreateBranch {
                        branch_id: "draft_a",
                        name: None,
                        parent_branch_id: MAINLINE_BRANCH_ID,
                        at_cut: None,
                        created_at: "t0",
                        idempotency_key: None,
                    })
                    .expect("create branch"),
                CreateBranchOutcome::Created(_)
            ));
        }

        let source = "workflow BranchDispatch\n\noutput result Result\n\n\
             class Result {\n  status string\n}\n\n\
             file store out_files {\n  root \"/ws\"\n  allow write [\"**\"]\n}\n\n\
             rule pick\n  when started\n=> {\n\
             \x20 write text to out_files at \"note.md\" {\n\
             \x20   body \"branch body\"\n    mode create\n  } as written\n\n\
             \x20 after written succeeds as result {\n\
             \x20   complete result {\n      status \"wrote\"\n    }\n  }\n}\n";
        let mut instance = DurableInstance::create(
            Rc::clone(&sql),
            source,
            "{}",
            "local/BranchDispatch",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("create");
        // Born on the branch: bind before any step runs; the live file
        // surface swaps onto the branch working set.
        instance.bind_branch("draft_a", "t1").expect("bind");
        assert!(
            matches!(
                instance.step(None, TEST_NOW_MS),
                DurableStepOutcome::Terminal
            ),
            "the branch-dispatched write settles and the instance terminates"
        );
        assert_eq!(
            instance.status().expect("status").as_deref(),
            Some("completed")
        );

        // The content is a cut on the branch, keyed by the resolved full
        // path — read back through the same generic VCS the native CLI uses.
        let vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).expect("branch store"),
            DoContentBlobs::new(Rc::clone(&sql)).expect("content blobs"),
        );
        assert_eq!(
            vcs.read("draft_a", "/ws/note.md").expect("read").as_deref(),
            Some("branch body")
        );
        // Mainline is isolated until a merge.
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "/ws/note.md").expect("read"),
            None
        );

        // The plain DO file plane never saw the write. The files table keys on
        // `key`, and the query must not be allowed to fail silently — a broken
        // query would make this isolation assertion pass vacuously.
        let plain_rows = sql
            .query("SELECT COUNT(*) FROM files WHERE key LIKE '%note.md'", &[])
            .expect("plain file plane queries")
            .first()
            .map(|row| crate::do_store::as_i64(&row[0]))
            .unwrap_or(0);
        assert_eq!(
            plain_rows, 0,
            "a branch-bound instance's file effect must not touch the plain DO file plane"
        );

        // A rebind to a different branch is refused (write-once birth).
        assert!(instance.bind_branch("main", "t2").is_err());
    }

    /// DO parity for the relocated export core (std.files slice F4): the
    /// `file.export` handler now lives in kernel::effect_handlers (it was
    /// CLI-crate-bound, so exports could not execute on the DO plane at all),
    /// and a plain instance drives it in-isolate — the serialized collection
    /// lands on the DO file plane and the workflow reaches its terminal.
    #[test]
    fn do_instance_exports_fact_collection_through_the_relocated_core() {
        let sql = Rc::new(store().sql);
        let source = "workflow ExportParity\n\noutput result Result\n\n\
             class Result {\n  status string\n}\n\n\
             class Row {\n  id string\n}\n\n\
             class Seeded {\n  note string\n}\n\n\
             file store out_files {\n  root \"/ws\"\n  allow write [\"**\"]\n}\n\n\
             rule seed\n  when started\n=> {\n\
             \x20 record Row { id \"a\" }\n\
             \x20 record Seeded { note \"go\" }\n}\n\n\
             rule dump\n  when Seeded as s\n=> {\n\
             \x20 export jsonl Row to out_files at \"rows.jsonl\" {\n\
             \x20   mode upsert\n  } as dumped\n\n\
             \x20 after dumped succeeds as receipt {\n\
             \x20   complete result {\n      status \"ok\"\n    }\n  }\n}\n";
        let mut instance = DurableInstance::create(
            Rc::clone(&sql),
            source,
            "{}",
            "local/ExportParity",
            DurableEffectPorts::default(),
            &[],
            &[],
        )
        .expect("create");
        assert!(
            matches!(
                instance.step(None, TEST_NOW_MS),
                DurableStepOutcome::Terminal
            ),
            "the in-isolate export settles and the instance terminates"
        );
        assert_eq!(
            instance.status().expect("status").as_deref(),
            Some("completed")
        );

        // The golden serialized collection is on the DO file plane, keyed by
        // the resolved full path — the same jsonl bytes the native handler
        // writes (one JSON object per line, trailing newline).
        let content = sql
            .query(
                "SELECT content FROM files WHERE key = ?1",
                &[crate::do_store::text("/ws/rows.jsonl")],
            )
            .expect("file plane readable")
            .first()
            .map(|row| crate::do_store::as_text(&row[0]))
            .expect("exported file exists");
        assert_eq!(content, "{\"id\":\"a\"}\n");
    }
}
