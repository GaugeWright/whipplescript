//! Cloudflare Durable Object host binding for the sans-IO WhippleScript core
//! (DR-0033 Phase 5).
//!
//! The whip evaluation core is host-agnostic: effects are sans-IO step machines
//! ([`whipplescript_kernel::sansio`]) and the durable store is a set of traits
//! ([`whipplescript_store`]). This crate is the *durable-object* binding for
//! those seams — the Rust side of a Cloudflare Worker/DO. It is built for wasm
//! against the core with `--no-default-features` (no rusqlite), so the DO
//! supplies its own SQLite and its own `fetch`.
//!
//! Two boundaries cross into the JavaScript isolate (wired by the TS Worker shell
//! via `wasm-bindgen`/the `worker` crate in a deployment):
//!   - [`FetchClient`] — the DO's `fetch`, which fulfills a `NeedsIo(Http)` from a
//!     step machine. [`FetchHost`] adapts it into the sans-IO [`HostDriver`].
//!   - [`DoStorage`] — the DO's *synchronous* SQLite. [`DoFileStore`] implements
//!     the file seam over it (small files inline; large files spill to an object
//!     store in Phase 7).
//!
//! What is intentionally NOT here yet (the Cloudflare-runtime greenfield): the
//! full [`RuntimeStore`](whipplescript_store::RuntimeStore) implementation over
//! `DoStorage` (the DO runs the same SQL the native `SqliteStore` does, through
//! the DO SQL API), the alarms/secrets wiring (Phase 6), and the object-store
//! tier (Phase 7). Those need a live DO to build and test against; the seams they
//! plug into are the ones proven here.

use std::io;
use std::path::Path;

use whipplescript_kernel::sansio::{
    HostDriver, HttpRequest, HttpResponse, IoRequest, IoResult, TransportError,
};
use whipplescript_store::files::FileStore;

pub mod do_branches;
pub mod do_instance;
pub mod do_memory;
pub mod do_packages;
/// `RuntimeStore` over the DO's synchronous SQLite (`DoSql`).
pub mod do_store;
/// The in-isolate agent-turn tool executor over the DO file plane (P4).
pub mod do_tools;
#[cfg(target_arch = "wasm32")]
pub mod do_wasm;
pub mod do_worker;
pub mod do_workstreams;
/// GaugeDesk-compatible governance verification for hosted placements.
pub mod governance;
/// Placement-neutral projection of one governed hosted turn into the public
/// host protocol's body-free pointers and terminal receipt.
pub mod host_projection;

#[cfg(test)]
mod governed_host_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use serde_json::json;
    use whipplescript_kernel::coerce_native::CoerceProvider;
    use whipplescript_kernel::gov::{external_signing_bytes, SignedEnvelope};
    use whipplescript_kernel::harness_model::MessagesApiClient;
    use whipplescript_kernel::host_facade::{GovernedHostFacade, ProviderRealization};
    use whipplescript_kernel::host_package::{
        AuthoredAgentPackage, PackageResolver, AGENT_PACKAGE_SCHEMA,
    };
    use whipplescript_kernel::host_policy::{
        HostGovernancePolicy, PlacementPolicy, ProviderBindingPolicy, ResourcePolicy,
    };
    use whipplescript_kernel::host_protocol::{
        CredentialRef, OpenInstanceCommand, ProviderBindingRef, StartTurnCommand, TurnInput,
        HOST_PROTOCOL,
    };
    use whipplescript_kernel::sansio::HttpResponse;
    use whipplescript_store::RuntimeStore;

    use crate::do_store::{test_support, DoSql, DoSqliteStore};
    use crate::do_worker::{DurableEffectPorts, DurableInstance, DurableStepOutcome};
    use crate::governance::{GaugeDeskGovernanceRoot, GAUGEDESK_ATTESTATION_ALGORITHM};

    fn package() -> AuthoredAgentPackage {
        AuthoredAgentPackage::from_documents(
            json!({
                "schema": AGENT_PACKAGE_SCHEMA,
                "source": "method.whip",
                "workflow": "Method",
                "agent": "assistant",
                "system_prompt": "persona.md",
                "capabilities": [],
                "agent_abilities": [],
                "max_steps": 4,
            })
            .to_string(),
            r#"
workflow Method {
  agent assistant {
    provider owned
    profile "repo-reader"
    capacity 1
    capabilities []
  }
  rule converse when started => { tell assistant "Answer without tools." }
}
"#,
            "Be helpful.",
        )
        .expect("package")
    }

    fn signed_policy() -> (GaugeDeskGovernanceRoot, String) {
        let principal = ResourcePolicy {
            principal: true,
            ..ResourcePolicy::default()
        };
        let policy = HostGovernancePolicy {
            resources: BTreeMap::from([
                ("provider:openai".to_owned(), principal.clone()),
                ("placement:do".to_owned(), principal),
            ]),
            bindings: BTreeMap::from([
                ("model".to_owned(), "provider:openai".to_owned()),
                ("do".to_owned(), "placement:do".to_owned()),
            ]),
            parties: BTreeMap::from([("operator".to_owned(), "public".to_owned())]),
            provider_bindings: BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-test".to_owned(),
                    base_url: "https://provider.invalid".to_owned(),
                    credential_ref: "credential:model".to_owned(),
                },
            )]),
            placements: BTreeMap::from([(
                "do".to_owned(),
                PlacementPolicy {
                    kind: "durable_object".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            ..HostGovernancePolicy::default()
        };
        let signer = "authority:gaugedesk";
        let key = SigningKey::from_slice(&[7u8; 32]).expect("test key");
        let public_key = hex::encode(
            key.verifying_key()
                .as_affine()
                .to_sec1_point(true)
                .as_bytes(),
        );
        let unsigned = policy.to_json().expect("policy");
        let signing_bytes = external_signing_bytes(
            &unsigned,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
        )
        .expect("bytes");
        let signature: Signature = key.sign(&signing_bytes);
        let signed = SignedEnvelope::from_external_signature(
            &unsigned,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            &hex::encode(signature.to_bytes()),
        )
        .expect("signed")
        .to_json();
        (GaugeDeskGovernanceRoot::new(signer, public_key), signed)
    }

    #[test]
    fn gaugedesk_host_protocol_admits_the_same_package_on_the_do_store() {
        let (root, signed) = signed_policy();
        let verified = root.verify_epoch(7, &signed).expect("verified");
        let sql = Rc::new(test_support::store().sql);
        for statement in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('agent.tell', 'Run an agent turn.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) \
             VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
        ] {
            sql.execute(statement, &[]).expect("seed hosted agent policy");
        }
        let mut host = GovernedHostFacade::from_verified_store(
            DoSqliteStore::new(Rc::clone(&sql)),
            7,
            verified.envelope,
        )
        .expect("host");
        let package = package();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-do-1".to_owned(),
            package_version_ref: package.version_ref().to_owned(),
            policy: host.policy_ref().clone(),
        };
        let opened = host.open_instance(&open, &package).expect("opened");
        let turn = StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: "turn-do-1".to_owned(),
            run_ref: "gaugedesk:run:do:1".to_owned(),
            instance_ref: opened.instance_ref,
            package_version_ref: package.version_ref().to_owned(),
            policy: host.policy_ref().clone(),
            actor_ref: "operator".to_owned(),
            input: TurnInput {
                text: "hello from GaugeDesk".to_owned(),
                images: Vec::new(),
            },
            resources: Vec::new(),
            provider_binding: ProviderBindingRef {
                binding_id: "model".to_owned(),
                credential: CredentialRef {
                    credential_id: "credential:model".to_owned(),
                },
            },
            placement_ceiling_ref: "do".to_owned(),
        };
        assert!(host
            .begin_turn(
                &turn,
                &package,
                ProviderRealization {
                    provider: "openai",
                    model: "gpt-test",
                    base_url: "https://provider.invalid",
                },
            )
            .expect("admitted"));
        let effects = host
            .kernel()
            .store()
            .list_effects(&turn.instance_ref)
            .expect("effects");
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].effect_id, turn.command_id);

        let resolved = package
            .resolve_package(package.version_ref())
            .expect("package IR");
        let ports = DurableEffectPorts {
            agent_model: Some(Box::new(MessagesApiClient::new(
                CoerceProvider::OpenAi,
                "test-key",
                "gpt-test",
                "https://provider.invalid",
                1024,
                None,
            ))),
            ..DurableEffectPorts::default()
        };
        let mut attached = DurableInstance::attach(
            Rc::clone(&sql),
            resolved.program,
            &turn.instance_ref,
            resolved.system_prompt,
            resolved.max_steps,
            ports,
        )
        .expect("attach hosted instance");
        assert_eq!(attached.admitted_max_steps(), 4);
        let first_step = attached.step(None, 1_767_225_600_000);
        let instance_status = attached.status().expect("instance status");
        let after_step = host
            .kernel()
            .store()
            .list_effects(&turn.instance_ref)
            .expect("effects after step");
        assert!(
            matches!(first_step, DurableStepOutcome::NeedsHttp(_)),
            "an admitted hosted turn must be claimed and driven, got {first_step:?}; status: {instance_status:?}; effects: {after_step:?}"
        );
        let resumed = attached.step(
            Some(Ok(HttpResponse {
                status: 200,
                body: json!({
                    "choices": [{
                        "message": { "role": "assistant", "content": "done" },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 3, "completion_tokens": 0 }
                }),
            })),
            1_767_225_600_000,
        );
        assert!(
            matches!(
                resumed,
                DurableStepOutcome::Parked {
                    next_due_unix_ms: None
                }
            ),
            "the hosted turn settles and leaves the reusable instance open, got {resumed:?}"
        );
        let projection = crate::host_projection::project_host_turn(
            host.kernel_mut().store_mut(),
            &turn.instance_ref,
            &turn.command_id,
        )
        .expect("runtime projection");
        let receipt = projection.receipt.expect("terminal receipt");
        assert_eq!(receipt.command_id, turn.command_id);
        assert!(receipt.guarantee_report_ref.starts_with("whip:evidence:"));
        assert_eq!(
            projection.usage_observation,
            Some(crate::host_projection::HostedUsageObservation {
                usage_ref: receipt.usage_ref.clone(),
                input_tokens: 3,
                cached_input_tokens: 0,
                output_tokens: 0,
            })
        );
        assert!(projection.runtime_evidence_pointers.iter().any(|pointer| {
            matches!(
                pointer,
                whipplescript_kernel::host_protocol::RuntimeEvidencePointer::TurnReceipt(_)
            )
        }));
    }
}

// -- HTTP: the fetch host driver ------------------------------------------

/// The DO's HTTP `fetch`, surfaced to the synchronous sans-IO core. A deployment
/// implements this over the Worker runtime's `fetch`; the TS shell awaits the
/// promise and re-enters the step machine on resolve (the suspension point the
/// sans-IO design exists for).
pub trait FetchClient {
    fn fetch(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// Adapts a [`FetchClient`] into the sans-IO [`HostDriver`], so any effect step
/// machine (`coerce`, an agent turn) runs on the DO by having its `NeedsIo(Http)`
/// fulfilled through the isolate's `fetch`.
pub struct FetchHost<F: FetchClient> {
    pub fetch: F,
}

impl<F: FetchClient> HostDriver for FetchHost<F> {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        match request {
            IoRequest::Http(http) => IoResult::Http(self.fetch.fetch(http)),
        }
    }
}

// -- Files: the DO storage file store -------------------------------------

/// The DO's synchronous SQLite, abstracted to the byte operations a file needs.
/// Keys are flat content paths (the DO has no directory tree). Small files live
/// inline here, transactional with the rest of the store; large files spill to a
/// platform object store behind the same handle (Phase 7).
pub trait DoStorage {
    fn read_file(&self, key: &str) -> io::Result<Option<String>>;
    fn write_file(&self, key: &str, content: &str) -> io::Result<()>;
    fn append_file(&self, key: &str, content: &str) -> io::Result<()>;
    fn file_exists(&self, key: &str) -> bool;
    /// Remove the file at `key` (P2, for restore's reconcile). A no-op on an
    /// absent key.
    fn delete_file(&self, key: &str) -> io::Result<()>;
}

/// The file seam ([`FileStore`]) backed by DO storage: the DO binding's answer to
/// the native `NativeFileStore` (`std::fs`). Path resolution and the `file store`
/// policy boundary stay in the effect handler; only the bytes cross here.
pub struct DoFileStore<S: DoStorage> {
    pub storage: S,
}

impl<S: DoStorage> DoFileStore<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

/// A workspace path becomes a flat storage key (the DO has no filesystem tree).
fn storage_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

impl<S: DoStorage> FileStore for DoFileStore<S> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        match self.storage.read_file(&storage_key(path))? {
            Some(content) => Ok(content),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such file: {}", path.display()),
            )),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        self.storage.file_exists(&storage_key(path))
    }

    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        // Flat key space: there are no directories to create.
        Ok(())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.storage
            .write_file(&storage_key(path), &String::from_utf8_lossy(bytes))
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.storage
            .append_file(&storage_key(path), &String::from_utf8_lossy(bytes))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.storage.delete_file(&storage_key(path))
    }
}

// -- Scheduling + config: alarms and secrets (Phase 6) --------------------

/// The DO's single-wake-up alarm scheduler. The clock-source / timer effects set
/// the next due time here instead of an external poller; the Worker's `alarm()`
/// handler steps the instance when it fires. One pending wake-up per instance —
/// the runtime keeps the earliest due time.
pub trait Alarms {
    /// Schedule (or reschedule) the next wake-up at `at_unix_ms`.
    fn set_alarm(&self, at_unix_ms: i64);
    /// The currently-scheduled wake-up, if any.
    fn current_alarm(&self) -> Option<i64>;
    /// Clear the pending wake-up.
    fn clear_alarm(&self);
}

/// Worker secrets — the DO's config/credentials plane (no dotfiles). Provider API
/// keys and endpoint config are read from here.
pub trait Secrets {
    fn get(&self, name: &str) -> Option<String>;
}

// -- Large-object tier (Phase 7) ------------------------------------------

/// A platform object store for large files spilled out of DO SQLite. Keys are
/// content paths; in a deployment the bytes stream out-of-band (the isolate never
/// buffers them in the general path).
pub trait ObjectStore {
    fn put(&self, key: &str, bytes: &[u8]) -> io::Result<()>;
    fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> io::Result<()>;
    fn exists(&self, key: &str) -> bool;
}

/// Default small-file / large-file tier boundary (DR-0033 Decision 4), in bytes.
///
/// A file **below** this size inlines in DO SQLite (synchronous, transactional
/// with fact-derivation); a file **at or above** it spills to the [`ObjectStore`].
/// 128 KiB is chosen to keep the common structured-I/O case (config, transcripts,
/// small JSON payloads) on the fast transactional path while staying comfortably
/// under DO SQLite's practical per-value ceiling (Cloudflare caps a stored value
/// around 2 MiB, and large inline blobs bloat the row cache and the write-amplified
/// transaction), so the object-store round trip is paid only for genuinely large
/// bytes. v1 keeps the boundary a single runtime constant, not a user-facing knob:
/// per DR-0033 the size is known at write time, so the optional size *hint* is not
/// exposed in v1 (revisit only if a workload needs to pre-place a file whose final
/// size the writer can't yet see). Callers may still override [`threshold_bytes`]
/// directly when constructing the store.
///
/// [`threshold_bytes`]: TieredFileStore::threshold_bytes
pub const DEFAULT_TIER_THRESHOLD_BYTES: usize = 128 * 1024;

/// Runtime-owned file tiering (DR-0033 Decision 4): small files inline in DO
/// SQLite ([`DoStorage`]); files at or above `threshold_bytes` spill to the
/// [`ObjectStore`]. One [`FileStore`] surface — the language never sees the
/// split. Each file lives in exactly one tier: a write picks the tier by size and
/// clears any copy in the other tier, so reads are unambiguous.
pub struct TieredFileStore<S: DoStorage, O: ObjectStore> {
    pub storage: S,
    pub objects: O,
    pub threshold_bytes: usize,
}

impl<S: DoStorage, O: ObjectStore> TieredFileStore<S, O> {
    /// Build a tiered store with the v1 default spill threshold
    /// ([`DEFAULT_TIER_THRESHOLD_BYTES`]). Set [`threshold_bytes`] afterwards to
    /// override.
    ///
    /// [`threshold_bytes`]: TieredFileStore::threshold_bytes
    pub fn new(storage: S, objects: O) -> Self {
        Self {
            storage,
            objects,
            threshold_bytes: DEFAULT_TIER_THRESHOLD_BYTES,
        }
    }
}

impl<S: DoStorage, O: ObjectStore> FileStore for TieredFileStore<S, O> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let key = storage_key(path);
        if let Some(bytes) = self.objects.get(&key)? {
            return String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
        match self.storage.read_file(&key)? {
            Some(content) => Ok(content),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such file: {}", path.display()),
            )),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        let key = storage_key(path);
        self.storage.file_exists(&key) || self.objects.exists(&key)
    }

    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let key = storage_key(path);
        if bytes.len() >= self.threshold_bytes {
            // Large tier: spill to the object store, drop any inline copy.
            if self.storage.file_exists(&key) {
                self.storage.write_file(&key, "")?;
            }
            self.objects.put(&key, bytes)
        } else {
            // Small tier: inline in SQLite, drop any spilled copy.
            if self.objects.exists(&key) {
                self.objects.delete(&key)?;
            }
            self.storage
                .write_file(&key, &String::from_utf8_lossy(bytes))
        }
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        // Append targets the inline tier; a large spilled file would need a
        // streamed read-modify-write through the object store (deferred).
        self.storage
            .append_file(&storage_key(path), &String::from_utf8_lossy(bytes))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        // Each file lives in exactly one tier, but a paranoid delete clears
        // both so no stale copy survives in the other.
        let key = storage_key(path);
        self.storage.delete_file(&key)?;
        if self.objects.exists(&key) {
            self.objects.delete(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use whipplescript_kernel::sansio::{run_to_completion, Outcome, StepMachine};

    // -- fetch host --------------------------------------------------------

    struct StaticFetch {
        body: serde_json::Value,
        seen: RefCell<Option<HttpRequest>>,
    }

    impl FetchClient for StaticFetch {
        fn fetch(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
            *self.seen.borrow_mut() = Some(request.clone());
            Ok(HttpResponse {
                status: 200,
                body: self.body.clone(),
            })
        }
    }

    /// A trivial one-round step machine that yields one HTTP request then settles
    /// on the response status — enough to prove FetchHost drives the sans-IO core.
    struct OneShot {
        url: String,
    }

    impl StepMachine for OneShot {
        type Output = u16;
        fn step(&mut self, incoming: Option<IoResult>) -> Outcome<u16> {
            match incoming {
                None => Outcome::NeedsIo(IoRequest::Http(HttpRequest {
                    url: self.url.clone(),
                    headers: vec![],
                    body: serde_json::json!({}),
                })),
                Some(IoResult::Http(Ok(response))) => Outcome::Settle(response.status),
                Some(IoResult::Http(Err(_))) => Outcome::Settle(0),
            }
        }
    }

    #[test]
    fn fetch_host_drives_a_step_machine_over_the_do_fetch() {
        let host = FetchHost {
            fetch: StaticFetch {
                body: serde_json::json!({"ok": true}),
                seen: RefCell::new(None),
            },
        };
        let mut machine = OneShot {
            url: "https://api.anthropic.com/v1/messages".to_string(),
        };
        let status = run_to_completion(&mut machine, &host);
        assert_eq!(status, 200);
        assert!(host.fetch.seen.borrow().is_some(), "fetch was invoked");
    }

    // -- DO file store -----------------------------------------------------

    /// In-memory stand-in for the DO's SQLite (what the `worker` crate wires up).
    #[derive(Default)]
    struct MemStorage {
        files: RefCell<HashMap<String, String>>,
    }

    impl DoStorage for MemStorage {
        fn read_file(&self, key: &str) -> io::Result<Option<String>> {
            Ok(self.files.borrow().get(key).cloned())
        }
        fn write_file(&self, key: &str, content: &str) -> io::Result<()> {
            self.files
                .borrow_mut()
                .insert(key.to_string(), content.to_string());
            Ok(())
        }
        fn append_file(&self, key: &str, content: &str) -> io::Result<()> {
            self.files
                .borrow_mut()
                .entry(key.to_string())
                .or_default()
                .push_str(content);
            Ok(())
        }
        fn file_exists(&self, key: &str) -> bool {
            self.files.borrow().contains_key(key)
        }
        fn delete_file(&self, key: &str) -> io::Result<()> {
            self.files.borrow_mut().remove(key);
            Ok(())
        }
    }

    #[test]
    fn do_file_store_round_trips_through_the_file_seam() {
        let files: &dyn FileStore = &DoFileStore {
            storage: MemStorage::default(),
        };
        let path = Path::new("notes/todo.txt");

        assert!(!files.exists(path));
        files
            .create_dir_all(Path::new("notes"))
            .expect("mkdir noop");
        files.write(path, b"hello").expect("write");
        assert!(files.exists(path));
        assert_eq!(files.read_to_string(path).expect("read"), "hello");
        files.append(path, b" world").expect("append");
        assert_eq!(files.read_to_string(path).expect("read"), "hello world");
        assert!(files.read_to_string(Path::new("missing")).is_err());
    }

    // -- large-object tier -------------------------------------------------

    #[derive(Default)]
    struct MemObjects {
        blobs: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl ObjectStore for MemObjects {
        fn put(&self, key: &str, bytes: &[u8]) -> io::Result<()> {
            self.blobs
                .borrow_mut()
                .insert(key.to_string(), bytes.to_vec());
            Ok(())
        }
        fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
            Ok(self.blobs.borrow().get(key).cloned())
        }
        fn delete(&self, key: &str) -> io::Result<()> {
            self.blobs.borrow_mut().remove(key);
            Ok(())
        }
        fn exists(&self, key: &str) -> bool {
            self.blobs.borrow().contains_key(key)
        }
    }

    #[test]
    fn tiered_file_store_routes_by_size_and_keeps_one_tier() {
        let store = TieredFileStore {
            storage: MemStorage::default(),
            objects: MemObjects::default(),
            threshold_bytes: 8,
        };
        let small = Path::new("s.txt");
        let big = Path::new("b.bin");

        // Small file inlines in DO SQLite; not in the object store.
        store.write(small, b"hi").expect("small write");
        assert!(store.storage.file_exists("s.txt"));
        assert!(!store.objects.exists("s.txt"));
        assert_eq!(store.read_to_string(small).expect("read small"), "hi");

        // Large file spills to the object store; not inline.
        store.write(big, b"0123456789").expect("big write");
        assert!(store.objects.exists("b.bin"));
        assert!(!store.storage.file_exists("b.bin"));
        assert_eq!(store.read_to_string(big).expect("read big"), "0123456789");
        assert!(store.exists(big));

        // Rewriting the big file small moves it back to the inline tier (one tier).
        store.write(big, b"tiny").expect("shrink");
        assert!(store.storage.file_exists("b.bin"));
        assert!(!store.objects.exists("b.bin"));
        assert_eq!(store.read_to_string(big).expect("read shrunk"), "tiny");
    }

    #[test]
    fn tiered_file_store_new_uses_the_default_threshold() {
        let store = TieredFileStore::new(MemStorage::default(), MemObjects::default());
        assert_eq!(store.threshold_bytes, DEFAULT_TIER_THRESHOLD_BYTES);

        // A payload just under the default inlines; the default is a real boundary
        // (not the 8-byte test value), so an ordinary small file stays transactional.
        let small = Path::new("cfg.json");
        store
            .write(small, &vec![b'x'; DEFAULT_TIER_THRESHOLD_BYTES - 1])
            .expect("under-threshold write");
        assert!(store.storage.file_exists("cfg.json"));
        assert!(!store.objects.exists("cfg.json"));
    }

    // -- alarms + secrets --------------------------------------------------

    #[derive(Default)]
    struct MemAlarms {
        at: RefCell<Option<i64>>,
    }

    impl Alarms for MemAlarms {
        fn set_alarm(&self, at_unix_ms: i64) {
            *self.at.borrow_mut() = Some(at_unix_ms);
        }
        fn current_alarm(&self) -> Option<i64> {
            *self.at.borrow()
        }
        fn clear_alarm(&self) {
            *self.at.borrow_mut() = None;
        }
    }

    struct MemSecrets;
    impl Secrets for MemSecrets {
        fn get(&self, name: &str) -> Option<String> {
            match name {
                "ANTHROPIC_API_KEY" => Some("sk-ant-test".to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn alarms_hold_one_wakeup_and_secrets_resolve_config() {
        let alarms = MemAlarms::default();
        assert_eq!(alarms.current_alarm(), None);
        alarms.set_alarm(1_000);
        alarms.set_alarm(2_000);
        assert_eq!(alarms.current_alarm(), Some(2_000));
        alarms.clear_alarm();
        assert_eq!(alarms.current_alarm(), None);

        let secrets = MemSecrets;
        assert_eq!(
            secrets.get("ANTHROPIC_API_KEY").as_deref(),
            Some("sk-ant-test")
        );
        assert_eq!(secrets.get("MISSING"), None);
    }
}
