# Rust API Reference

The Rust crates are APIs with internal stability for the workspace. These APIs
are useful for an integration test, for a tool on your machine, and for a
contributor. These APIs are not a published semver contract. If you automate
WhippleScript, use the CLI and the JSON contracts in the
[JSON reference](json-reference.md).

There is one exception. That exception is the native surface for a host, which
a revision pins. GaugeDesk and other hosts that embed WhippleScript use that
surface. The surface is deliberately pre-1.0, and you must pin the surface to an
exact commit. But its types are public. Thus a host does not implement the
semantics of governance, of IFC, or of the lifecycle of a turn again.

## `whipplescript` host library

The `host_protocol` module defines the `whipplescript.host.v1` wire types. These
types do not depend on the placement. The `OpenInstanceCommand` type opens one
durable WhippleScript instance for a chat of a host. The `StartTurnCommand`,
`LabeledRuntimeEvent`, terminal `TurnReceipt`, `LabeledHumanAsk`,
`AnswerHumanAskCommand`, and `HumanAnswerReceipt` types carry the same verified
`PolicyEpochRef` value. A command has a reference to a resource and a reference
to a provider. A command has no body of a resource and no credential.

The `ResourceRef::handle` field names the capability that governance and IFC
check. The `ResourceRef::selector` field can name one object that is local to
the resolver, below that capability. An ephemeral image for a turn is an
example. A selector never makes a principal for a policy. A selector never
contains the body of a resource.

The `host_runtime::GovernedHostRuntime` type is the native facade that persists:

| Item | Meaning |
| --- | --- |
| `open(store_path, epoch, signed_envelope)` | Opens SQLite, or opens SQLite again. Binds the runtime to the exact verified epoch of the policy. |
| `open_with_verifier(store_path, epoch, signed_envelope, verifier)` | Opens an embedded runtime under an envelope that an external party signed. The method needs the `GovernanceAttestationVerifier` value that the host pinned. The method never reads the admin state that is global to the process. |
| `open_instance(command, packages)` | Resolves a pinned package and issues a reference to a durable WhippleScript instance. A replay of the same identifier of a request opens that exact instance again. |
| `fork_instance_from(source, command, packages)` | Seeds a different instance from an exact coordinate of the source. The method resolves and validates the packages of the source and of the target independently. Thus an explicit fork across versions keeps a live thread across an upgrade of a package. |
| `run_turn(...)` | Runs the owned brokered loop with the native HTTP driver and the transcript that persists. The method returns a terminal receipt, or a pending question for a person with a label. The method never returns the two items. |
| `run_turn_with_driver(...)` | Drives the same sans-IO machine with a transport that the host supplies. Use this method for a test and for a remote placement. |
| `pending_human_turn(...)` | Recovers the original admitted command and the question with a label after a restart of the host. The method does not examine the runtime store of WhippleScript. |
| `answer_human_ask(...)` / `answer_human_ask_with_driver(...)` | Admits a reference to a respondent that the system authenticated. Appends the correlated result of the tool. Issues a receipt for the answer that you can attribute. Continues the same suspended turn under its unchanged epoch. |
| `cancellation_handle(instance, command)` | Makes a `HostCancellationHandle` value outside the usual path. Its independent connection to the store records a durable request for a cooperative cancel operation while the thread of the runtime is blocked. |
| `TurnExecution::output` / `LabeledTurnOutput` | The projection of the assistant and the tools that WhippleScript folded. The projection carries the join label of the IFC of the turn. A host never examines the runtime store and never builds the fold of the transcript again. |
| `TurnExecution::evidence_pointers()` / `RuntimeEvidencePointer` | References with no body to the labeled events, the questions and answers of a person, and the terminal receipts that WhippleScript owns. Use these references for admission into an external log of the decisions of a product. |
| `PackageResolver` | Resolves the immutable bytes and the IR of a WhippleScript package, and the schemas of the tools that the package declares. |
| `SecretResolver` | Resolves the credentials of a provider ephemerally, after the admission by the policy. |
| `ResolvedProviderBinding::new_codex(...)` | The short-life Codex material that the host resolved. WhippleScript owns the Codex request and the SSE wire. WhippleScript never acquires, refreshes, looks up, or persists a credential. |
| `ResourceResolver` | Resolves the bytes of an image. Realizes a tool that the system already admitted. Projects a question for a person that a package declares against only the references that the system admitted for the turn. Receives, through `observe_text_delta`, each delta of the answer text of the assistant while the native turn streams — an ephemeral projection under "Live Turn Observation" of `spec/agent-harness.md`; the durable output of the settled turn replaces it, and a delta of reasoning never arrives. |
| `NativeWorkspaceResolver` / `native_workspace_tool_specs_with_capabilities` | The native surface for files and commands that WhippleScript owns: confined file operations and governed simple commands through an executor of the host. |

The facade fails closed unless the signed envelope governs each resource, each
binding of a provider, and each handle of a placement. The
`ResolvedPackage::compile` method keeps the pinned IR of the program. The
admission of an instance and of a turn runs the IFC checker of WhippleScript
over that IR, under the verified envelope, before the system resolves a secret.

The facade binds an instance to a fingerprint of the package. The fingerprint
covers the source of the workflow, the selected root and agent, the system
prompt, the exact schemas of the tools, and the limit on the steps. The
fingerprint also covers the identity of the policy. The facade rejects reuse
across bindings and reuse with changed content. The facade persists references
and evidence only. The facade does not persist a resolved secret of a provider.

A turn never stops to wait for a person (DR-0050). A workflow that needs
something from someone sends on a channel or files an issue into a tracker;
both are durable, both name their destination, and the turn settles. The reply
arrives later and fires a rule of its own. There is no suspended turn for a new
policy epoch to continue, so the class of question about which epoch may answer
does not arise.

An authority that embeds WhippleScript makes the exact bytes to sign with the
`gov::external_signing_bytes` function. The authority attaches the result with
the `SignedEnvelope::from_external_signature` method. The authority verifies the
result through the `GovernanceAttestationVerifier` type. The `PolicyEpochRef`
value carries the identifier of the external key. Thus the protection against a
mix-up of a command, an event, and a receipt binds the cryptographic root of the
trust. The protection also binds the hash of the envelope, the epoch, and the
signer. The legacy `whip gov` path uses an attestation with a hash. That path
still needs root or admin privilege. That path cannot verify an external
artifact without its pinned verifier.

## `whipplescript-core`

| Item | Meaning |
| --- | --- |
| `version()` | The string of the version of the package of the workspace. |
| `IMPLEMENTATION_STAGE` | The current label of the implementation stage that the CLI prints. |

## `whipplescript-parser`

These are the primary entry points:

| Item | Meaning |
| --- | --- |
| `parse_program(source)` | Parses the source into an AST and diagnostics. |
| `compile_program(source)` | Parses, type-checks, and lowers the source into an `IrProgram` value. |
| `compile_program_with_root(source, root)` | Compiles a bundle of source with an explicit selection of the root. |
| `format_program(source)` | Formats the source and keeps the bodies of the `rule` blocks and the `coerce` blocks. |
| `parse_expression(expr)` | Parses an expression of a guard or of an assertion. |
| `parse_duration_seconds(value)` | Parses a supported literal of a duration into seconds. |
| `parse_time_epoch_seconds(value)` | Parses a supported literal of a timestamp into seconds from the epoch. |

These are important structs of the AST and the IR. This list is an
illustration. The parser defines approximately thirty `*Decl` types:

```text
Program
WorkflowDecl
WorkflowContractDecl
PatternDecl
ApplyDecl
IncludeDecl
UseDecl
HarnessDecl
FlowDecl
AgentDecl
EnumDecl
EventDecl
LeaseDecl
LedgerDecl
CounterDecl
ClassDecl
TableDecl
CoerceDecl
TrackerDecl
ChannelDecl
ActionDecl
FileStoreDecl
SourceDecl
AssertDecl
RuleDecl
WhenClause
IrProgram
IrWorkflowContract
IrPatternApplication
IrAssertion
IrUse
IrSchema
IrAgent
IrCoerce
IrRule
IrEffectNode
IrEffectDependency
IrTerminalOutput
Expr
```

## `whipplescript-store`

The `SqliteStore` type owns the durable persistence of the runtime.

These are the methods for the lifecycle and for a program:

| Method | Meaning |
| --- | --- |
| `open(path)` / `open_in_memory()` | Opens the store and applies the migrations. |
| `schema_version()` | Reads the version of the schema that the store applied. |
| `create_program_version(...)` | Makes the metadata of a version of a program, or finds the metadata. |
| `create_instance(...)` | Makes an instance that runs. |
| `transition_instance(...)` | Pauses, resumes, or cancels an instance, with guards on the transition. |
| `status(instance_id)` | The aggregate view of the status of an instance. |
| `list_instances()` / `get_instance()` | The inspection of an instance. |

These are the methods for a rule and for an effect:

| Method | Meaning |
| --- | --- |
| `append_event(...)` | Appends a raw event. |
| `commit_rule(...)` | An atomic commit of a rule, with the facts, the effects, the dependencies, and an optional terminal action of the workflow. |
| `derive_fact(...)` | Derives a fact from an event or a projection. |
| `claimable_effects(instance_id)` | Lists the effects that are ready for the execution by a worker. |
| `satisfy_dependencies(instance_id)` | Releases each effect that a dependency blocked and whose predicates are now true. |
| `start_run(...)` | Starts a run of a provider and an active lease. |
| `complete_effect(...)` | Marks a run that operates, and its effect, as terminal. |
| `complete_effect_with_terminal_diagnostic(...)` | A terminal completion that also captures a diagnostic. |
| `cancel_effect(...)` | Cancels an effect. |
| `renew_lease(...)` / `expire_leases(...)` | The maintenance of a lease. |
| `retry_effect(...)` | Retries an effect that failed or that timed out. |

These are the methods for a checkpoint and a restore operation. These methods
support the `whip checkpoint` command and the `whip restore` command:

| Method | Meaning |
| --- | --- |
| `capture_checkpoint(...)` | Captures a cut of the state of the files of an instance, the transcript of the agent, and the position in the event log. The method checks the coherence of the cut. |
| `plan_restore(instance_id, cut_id)` | Plans a restore operation to a captured cut. The method returns a `RestoreDecision` value. |
| `commit_restore(...)` | Commits the planned restore operation. The method appends the append-only `context.restored` marker that each read folds. |

These are the methods for inspection:

```text
list_events
list_facts
list_facts_including_consumed
list_effects
list_runs
list_evidence
list_evidence_links
list_diagnostics
list_diagnostics_from_events
list_artifacts_for_run
```

These are the methods for the registry and for an extension:

```text
register_package
register_package_manifest
load_package_manifests_from_dir
register_capability_schema
register_effect_provider
register_profile
bind_capability
register_skill
attach_skill
list_skills
list_skill_attachments
record_skill_evidence
```

These are the methods for the invocation of a workflow:

```text
record_workflow_invocation
get_workflow_invocation
list_child_workflow_invocations
get_parent_workflow_invocation
```

## `whipplescript-kernel`

The `RuntimeKernel` type contains the operations of the store. The type also
emits the records of the traces.

These are the core methods:

```text
create_program_version
create_program_version_for_program
create_instance
ingest_external_event
derive_fact
evaluate_rules
commit_rule
claimable_effects
satisfy_dependencies
start_run
complete_run
fail_run
timeout_run
cancel_run
cancel_effect
pause_instance
resume_instance
cancel_instance
renew_lease
expire_leases
retry_effect
```

These are the methods for the execution by a provider:

```text
run_agent_turn
record_native_agent_turn_observation
record_artifact_capture_failure
recover_provider_terminal_from_evidence
recover_running_provider_runs
run_coerce
run_human_ask
```

These are the traits and the helpers for a provider:

| Item | Meaning |
| --- | --- |
| `AgentHarness` | The trait for an adapter of an agent provider. |
| `CommandAgentHarness` | A harness that a command supports, for a local adapter. |
| `CodexAgentHarness` | The wrapper of the Codex adapter over the plan to launch a command. |
| `ClaudeCodeAgentHarness` | The wrapper of the Claude Code adapter over the plan to launch a command. |
| `MockAgentHarness` | A deterministic harness for a test. |
| `CoerceClient` / `FakeCoerceClient` | The abstraction of a coercion provider. |

These are the modules for a native provider:

| Module | Meaning |
| --- | --- |
| `provider` | The validation of the capabilities and the configuration of a provider, and the built-in native capabilities. |
| `whipplescript-provider-codex` (crate) | The transport of the Codex app server and the summaries of the evidence. This crate is separate from the kernel. The `codex` feature of the CLI enables the crate. |
| `whipplescript-provider-claude` (crate) | The client of the sidecar of the Claude Agent SDK, the map of the policy, and the summaries of the evidence. This crate is separate from the kernel. The `claude` feature enables the crate. |
| `native_lifecycle` | The normalization of a Codex event and a Claude event into an `agent.turn.*` event. |
| `artifact_manifest` | The helpers for the manifest of an artifact and for the payload of a failure to capture an artifact. |

This is the API for a trace:

| Item | Meaning |
| --- | --- |
| `TraceEvent` | An abstract event of the lifecycle. |
| `TraceRecord` | An abstract event with a sequence number. |
| `check_trace(records)` | Validates the conformance of a trace. |

## `whipplescript-host-do`

The `whipplescript-host-do` crate is the binding of the host of the Cloudflare
Durable Object for the sans-IO core of WhippleScript. The crate runs the same
kernel for the evaluation in a wasm isolate. The crate supplies the synchronous
storage of the DO in place of the native `rusqlite` backend. The crate depends
on `whipplescript-kernel` and `whipplescript-store`. The build of those crates
uses `default-features = false`, which gives the traits of the store and the
types of the data only, and no rusqlite. The crate builds as a `cdylib` and as
an `rlib`.

These are the traits of the seam of the host. The shell of the DO implements
these traits:

| Item | Meaning |
| --- | --- |
| `DoSql` | The synchronous SQL interface that the DO gives to the store after the port. |
| `DoStorage` | The flat storage of the file plane that supports `DoFileStore`. |
| `FetchClient` / `FetchHost` | The one async primitive that is available to an effect that uses HTTP. The primitive is `fetch`. |
| `Alarms` | The schedule of the alarms of the DO, for a timer and for a deadline. |
| `Secrets` | The resolution of a credential of a provider from the secrets of the DO. |
| `ObjectStore` | The optional tier of objects that supports `TieredFileStore`. |

This is the surface of the runtime and the store:

| Item | Meaning |
| --- | --- |
| `DoSqlStorage` / `DoSqliteStore` | The store for the runtime, the coordination, and the work items, ported onto `DoSql`. |
| `DoFileStore` / `TieredFileStore` | The file plane that the DO owns. The types implement the `FileStore` trait. |
| `DurableInstance` | The driver of an instance over the storage of the DO. The methods are `create`, `step`, `status`, `checkpoint`, `restore`, and `bind_branch`. |
| `DoToolExecutor` / `do_tool_specs()` | The set of tools in the isolate, over the flat `files` table. The tools are read, write, edit, ls, find, grep, recall, and the todo items of the work tracker. |
| `WasmDurableInstance` | The wrapper with the `#[wasm_bindgen]` attribute, for wasm32 only. The wrapper gives `create`, `step`, `status`, `checkpoint`, and `restore` to the shell of the Worker. |

The `whip deploy` command packages a workflow onto a Worker and a DO with this
crate. To enable the Class-A compute plane and the Class-B compute plane in
production, do a follow-on step of the configuration. The planes are not on by
default.
