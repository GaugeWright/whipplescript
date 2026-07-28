//! The typed signal-admission core + external source-driver passes
//! (spec/std-ingress.md slice I3, spec/event-ingress.md). The load-bearing
//! invariant: EVERY ingress driver — `whip signal` (cli), `whip ingress serve
//! --stdio`, the `file` and `http` worker-pass pollers — converges on the ONE
//! shared admission function [`admit_external_signal`], so no driver can
//! become a second door around declaration validation, the H8 internal-channel
//! gate, or idempotent admission. Lifted kernel-side (generic over
//! `RuntimeStore`) alongside `time_pass`; provider I/O (filesystem walks, the
//! HTTP GET with its SSRF screens) stays behind native driver seams the passes
//! call, and the `whip ingress serve` command shell stays CLI-side.
//!
//! Admission identity: every driver derives a DELIVERY KEY (the events unique
//! index `(instance_id, idempotency_key)`, migrations/0001) and a re-delivered
//! key is ABSORBED — observed as [`SignalAdmission::Duplicate`], never a
//! second fact and never a store conflict. Modeled in
//! models/maude/admission.maude (delivery-id and file-occurrence key forms).

use serde_json::{json, Value};
use whipplescript_parser::{IrProgram, IrSource};
use whipplescript_store::{RuntimeStore, StoreResult};

use crate::rule_lowering::validate_json_for_object;
use crate::time_pass::clock_emit_payload;
use crate::{idempotency_key, ifc, RuntimeKernel};

/// One admission attempt's outcome through the shared core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalAdmission {
    /// A new durable signal fact was admitted.
    Admitted {
        event_id: String,
        fact_event_id: String,
        sequence: i64,
    },
    /// The delivery key was already admitted; nothing was appended (the
    /// observable duplicate, spec/event-ingress.md "CLI Admission").
    Duplicate { existing_event_id: String },
    /// The candidate never reached the store: the validation gate refused it
    /// (an invalid candidate admits no fact).
    Refused(SignalRefusal),
}

/// Why the validation gate refused a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalRefusal {
    /// The target instance does not exist.
    InstanceNotFound,
    /// The signal is not declared by the program (`signal <name> { … }`), so
    /// there is no admission contract to validate against.
    UndeclaredSignal { declared: Vec<String> },
    /// The governance envelope marks the signal an INTERNAL channel (DR-0027
    /// H8 stage b): an internal channel carries its emitter's integrity and
    /// must not be sourced from outside (W6 no-laundering).
    InternalChannel,
    /// The payload does not conform to the declared signal schema.
    PayloadInvalid { errors: Vec<String> },
}

/// The `whip signal` / stdio-envelope delivery key: an operator/provider
/// supplied delivery id WINS over the derived payload hash
/// (spec/std-ingress.md slice I5, "CLI Admission" in spec/event-ingress.md).
pub fn signal_delivery_key(
    instance_id: &str,
    signal: &str,
    payload_json: &str,
    delivery_id: Option<&str>,
) -> String {
    match delivery_id {
        Some(delivery_id) => idempotency_key(&[instance_id, "signal-delivery", delivery_id]),
        None => idempotency_key(&[instance_id, "signal", signal, payload_json]),
    }
}

/// THE admission core (spec/std-ingress.md "Providers"): declared-signal
/// check, payload validation against the declaration, H8 internal-channel
/// gate, idempotent event append under `delivery_key`, and the durable
/// `fact.derived` signal fact — the exact sequence the `whip signal` door
/// shipped, extracted so every driver inherits it by construction.
pub fn admit_external_signal<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
    signal: &str,
    payload: &Value,
    delivery_key: &str,
) -> StoreResult<SignalAdmission> {
    // Static refusals first (declaration, governance, payload shape): they
    // hold whether or not the target instance exists, so a driver surfaces
    // the real problem before any store lookup.
    let Some(event) = ir.events.iter().find(|event| event.name == signal) else {
        return Ok(SignalAdmission::Refused(SignalRefusal::UndeclaredSignal {
            declared: ir.events.iter().map(|event| event.name.clone()).collect(),
        }));
    };
    // No laundering (H8 stage b): an internal-governed signal refuses external
    // injection, whatever the driver.
    if ifc::signal_is_internal(signal) {
        return Ok(SignalAdmission::Refused(SignalRefusal::InternalChannel));
    }
    // IR-typed validation (Family B conditional presence included) — the same
    // validator the workflow-input door uses, not the weaker embedded-shape
    // mirror.
    let mut errors = Vec::new();
    validate_json_for_object(ir, payload, &event.fields, "$", &mut errors);
    if !errors.is_empty() {
        return Ok(SignalAdmission::Refused(SignalRefusal::PayloadInvalid {
            errors,
        }));
    }
    if kernel.store().get_instance(instance_id)?.is_none() {
        return Ok(SignalAdmission::Refused(SignalRefusal::InstanceNotFound));
    }
    // Idempotency: the events unique index would refuse a re-delivered key
    // with a store conflict; absorbing it HERE makes re-delivery an observable
    // duplicate for every driver (same id twice admits once, across passes and
    // process runs).
    if let Some(existing) = kernel
        .store()
        .event_by_idempotency_key(instance_id, delivery_key)?
    {
        // Crash-window heal: if the original delivery committed its ingest
        // event but crashed before deriving the signal fact, the signal was
        // silently lost — every re-delivery absorbed as Duplicate with no
        // fact. derive_fact is replay-tolerant (existing derivation = no-op;
        // missing = derives now), so re-running it here is safe.
        kernel.derive_fact(
            instance_id,
            signal,
            &existing.event_id,
            &payload.to_string(),
            Some(&existing.event_id),
            Some(&idempotency_key(&[
                instance_id,
                "signal-fact",
                &existing.event_id,
            ])),
        )?;
        return Ok(SignalAdmission::Duplicate {
            existing_event_id: existing.event_id,
        });
    }
    let payload_json = payload.to_string();
    let received =
        kernel.ingest_external_event(instance_id, signal, &payload_json, Some(delivery_key))?;
    let fact_event = kernel.derive_fact(
        instance_id,
        signal,
        &received.event_id,
        &payload_json,
        Some(&received.event_id),
        Some(&idempotency_key(&[
            instance_id,
            "signal-fact",
            &received.event_id,
        ])),
    )?;
    Ok(SignalAdmission::Admitted {
        event_id: received.event_id,
        fact_event_id: fact_event.event_id,
        sequence: received.sequence,
    })
}

/// What one external-source pass did: admissions plus the per-source refusals
/// it observed (the host decides how to surface them; the kernel never
/// prints).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IngressPassReport {
    pub admitted: u64,
    /// Human-readable per-source skip/refusal notes (network failures, refused
    /// candidates). Duplicates are NOT noted: absorbing them silently is the
    /// pass being idempotent.
    pub notes: Vec<String>,
}

/// Filesystem access for the `file` source driver — the native seam the
/// kernel pass calls (the `FileStore` plane has no directory listing, and the
/// kernel owns no ambient filesystem authority).
pub trait IngressFileIo {
    /// Full contents of `path`; `Ok(None)` when the file does not exist (a
    /// missing file is not an error: the source has nothing to admit yet).
    fn read_file(&mut self, path: &str) -> Result<Option<String>, String>;
    /// The file paths currently matching a `watch` glob.
    fn glob_files(&mut self, pattern: &str) -> Result<Vec<String>, String>;
}

/// The delivery key for one observed source occurrence: the `dedup`
/// observation field when declared (provider delivery id), else the caller's
/// positional/content identity.
fn source_delivery_key(source: &IrSource, observation: &Value, ordinal_key: String) -> String {
    let Some(field) = source.dedup_field.as_deref() else {
        return ordinal_key;
    };
    let value = observation.get(field).cloned().unwrap_or(Value::Null);
    let value_text = match &value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    idempotency_key(&[&source.name, "dedup", &value_text])
}

/// Admits durable signal facts from `file` sources through the admission core.
///
/// LINE MODE (`path`): each non-empty line at ordinal `i` is one delivery,
/// keyed `H(source, i, line)` (or the `dedup` field) — re-reads and unchanged
/// lines are absorbed, a growing file adds only its new tail, and a changed
/// line at an existing index re-admits (its content is part of the key).
/// Observation record: `{ line, line_index, path }`.
///
/// OCCURRENCE MODE (`watch`, spec/std-ingress.md I2a/I3): each glob-matched
/// file is one delivery per (path, content-hash) occurrence — a dropped file
/// admits once, an unchanged file never re-admits, a content change
/// re-admits. Observation record: `{ path, content_hash, watch }`; content
/// READING stays std.files.
pub fn resolve_due_file_sources<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
    io: &mut dyn IngressFileIo,
) -> StoreResult<IngressPassReport> {
    let mut report = IngressPassReport::default();
    // A pass over an absent instance admits nothing (mirrors the clock pass);
    // per-observation refusals would only spam the report.
    if kernel.store().get_instance(instance_id)?.is_none() {
        return Ok(report);
    }
    for source in &ir.sources {
        if !source.is_file {
            continue;
        }
        if let Some(path) = source.path.as_ref() {
            let contents = match io.read_file(path) {
                Ok(Some(contents)) => contents,
                Ok(None) => continue,
                Err(error) => {
                    report
                        .notes
                        .push(format!("file source `{}`: {error}", source.name));
                    continue;
                }
            };
            for (index, line) in contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                let observation = json!({
                    "line": line,
                    "line_index": index,
                    "path": path,
                });
                // Fold the line CONTENT into the delivery key, not just the
                // ordinal: keying on (source, index) alone silently drops a
                // changed line at an existing index (its key already exists ->
                // Duplicate -> absorbed). With content in the key, an unchanged
                // line still absorbs (same key), a growing file still adds only
                // its new tail, but a mutated line at an existing index
                // re-admits. A declared `dedup` field still overrides this in
                // source_delivery_key.
                let ordinal_key = idempotency_key(&[&source.name, &index.to_string(), line]);
                admit_source_observation(
                    kernel,
                    instance_id,
                    ir,
                    source,
                    &observation,
                    ordinal_key,
                    &mut report,
                )?;
            }
        }
        if let Some(watch) = source.watch.as_ref() {
            let paths = match io.glob_files(watch) {
                Ok(paths) => paths,
                Err(error) => {
                    report
                        .notes
                        .push(format!("file source `{}`: {error}", source.name));
                    continue;
                }
            };
            for path in paths {
                let contents = match io.read_file(&path) {
                    Ok(Some(contents)) => contents,
                    Ok(None) => continue,
                    Err(error) => {
                        report
                            .notes
                            .push(format!("file source `{}`: {error}", source.name));
                        continue;
                    }
                };
                let content_hash = idempotency_key(&[&contents]);
                let observation = json!({
                    "path": path,
                    "content_hash": content_hash,
                    "watch": watch,
                });
                let occurrence_key =
                    idempotency_key(&[&source.name, "occurrence", &path, &content_hash]);
                admit_source_observation(
                    kernel,
                    instance_id,
                    ir,
                    source,
                    &observation,
                    occurrence_key,
                    &mut report,
                )?;
            }
        }
    }
    Ok(report)
}

/// Admits durable signal facts from `http` sources through the admission
/// core: `fetch` GETs each source's `url` (the native seam carrying the SSRF
/// screens and the HTTP client), the body parses as a JSON array, and every
/// element at ordinal `i` is one delivery keyed `H(source, i)` (or the
/// `dedup` field) — append-only feed semantics. Observation record:
/// `{ item, item_index, url }` (`item` is the element re-stringified). A
/// network error is NOT a hard failure: a flaky endpoint admits nothing this
/// pass rather than crashing the worker.
pub fn resolve_due_http_sources<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
    fetch: &mut dyn FnMut(&str) -> Result<String, String>,
) -> StoreResult<IngressPassReport> {
    let mut report = IngressPassReport::default();
    // A pass over an absent instance admits nothing (mirrors the clock pass).
    if kernel.store().get_instance(instance_id)?.is_none() {
        return Ok(report);
    }
    for source in &ir.sources {
        if !source.is_http {
            continue;
        }
        let Some(url) = source.url.as_ref() else {
            continue;
        };
        let body = match fetch(url) {
            Ok(body) => body,
            Err(error) => {
                report
                    .notes
                    .push(format!("http source `{}`: {error}", source.name));
                continue;
            }
        };
        let elements = match serde_json::from_str::<Value>(&body) {
            Ok(Value::Array(elements)) => elements,
            Ok(_) => {
                report.notes.push(format!(
                    "http source `{}`: {url} did not return a JSON array; skipping",
                    source.name
                ));
                continue;
            }
            Err(error) => {
                report.notes.push(format!(
                    "http source `{}`: {url} returned invalid JSON: {error}",
                    source.name
                ));
                continue;
            }
        };
        for (index, element) in elements.into_iter().enumerate() {
            // `item` carries the element re-stringified, so a source can emit
            // the whole element as a string field; `item_index`/`url` mirror
            // the file source's `line_index`/`path`.
            let observation = json!({
                "item": element.to_string(),
                "item_index": index,
                "url": url,
            });
            let ordinal_key = idempotency_key(&[&source.name, &index.to_string()]);
            admit_source_observation(
                kernel,
                instance_id,
                ir,
                source,
                &observation,
                ordinal_key,
                &mut report,
            )?;
        }
    }
    Ok(report)
}

/// One source observation through the admission core: map the observation
/// onto the declared payload by the author's `emit` clause, derive the
/// delivery key, admit. Duplicates are absorbed silently (idempotent pass);
/// refusals are noted for the host to surface.
fn admit_source_observation<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    ir: &IrProgram,
    source: &IrSource,
    observation: &Value,
    ordinal_key: String,
    report: &mut IngressPassReport,
) -> StoreResult<()> {
    let observation_map = observation
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    let payload = clock_emit_payload(source, &observation_map);
    let delivery_key = source_delivery_key(source, observation, ordinal_key);
    match admit_external_signal(
        kernel,
        instance_id,
        ir,
        &source.emit_signal,
        &payload,
        &delivery_key,
    )? {
        SignalAdmission::Admitted { .. } => report.admitted += 1,
        SignalAdmission::Duplicate { .. } => {}
        SignalAdmission::Refused(refusal) => report.notes.push(format!(
            "source `{}`: refused `{}` admission: {}",
            source.name,
            source.emit_signal,
            refusal_reason(&refusal)
        )),
    }
    Ok(())
}

/// A one-line human reason for a refusal (drivers surface it; the CLI door
/// keeps its own richer messages).
pub fn refusal_reason(refusal: &SignalRefusal) -> String {
    match refusal {
        SignalRefusal::InstanceNotFound => "instance not found".to_owned(),
        SignalRefusal::UndeclaredSignal { declared } => format!(
            "signal is not declared{}",
            if declared.is_empty() {
                String::new()
            } else {
                format!(" (declared: {})", declared.join(", "))
            }
        ),
        SignalRefusal::InternalChannel => {
            "signal is governed as an INTERNAL channel (DR-0027 H8); external injection is refused"
                .to_owned()
        }
        SignalRefusal::PayloadInvalid { errors } => {
            format!(
                "payload does not conform to the declaration: {}",
                errors.join("; ")
            )
        }
    }
}

// NOTE: the pre-I3 native drivers kept a positional CURSOR (skip
// `i < count(admitted external events)`); the admission core's delivery-key
// lookup makes that cursor redundant — and fixes the head-insert desync the
// count-prefix skip had — so no cursor state survives the lift.
#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_parser::compile_program;
    use whipplescript_store::{NewInstance, NewProgramVersion, SqliteStore};

    const PROGRAM: &str = r#"
@service
workflow IngressCore

signal deploy.finished {
  service string
  status string
}

rule react
  when deploy.finished as f
=> {
  record Done { service f.service }
}

class Done {
  service string
}
"#;

    fn instance_on(store: &mut SqliteStore, name: &str) -> String {
        let version = store
            .create_program_version(NewProgramVersion {
                program_name: name,
                source_hash: "source-1",
                ir_hash: "ir-1",
                compiler_version: "test",
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            })
            .expect("version creates");
        store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates")
            .instance_id
    }

    fn kernel_with_instance() -> (RuntimeKernel<SqliteStore>, String, IrProgram) {
        let ir = compile_program(PROGRAM).ir.expect("program compiles");
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let instance_id = instance_on(&mut store, "IngressCore");
        (RuntimeKernel::new(store), instance_id, ir)
    }

    /// The admission core is a validation gate + idempotent door: a valid
    /// candidate admits exactly once per delivery key (re-delivery is an
    /// observable duplicate, not a second fact and not a store conflict).
    #[test]
    fn admits_once_and_absorbs_redelivered_delivery_key() {
        let (mut kernel, instance_id, ir) = kernel_with_instance();
        let payload = json!({"service": "api", "status": "ok"});
        let key = signal_delivery_key(&instance_id, "deploy.finished", "ignored", Some("dl-1"));
        let first = admit_external_signal(
            &mut kernel,
            &instance_id,
            &ir,
            "deploy.finished",
            &payload,
            &key,
        )
        .expect("admission runs");
        let SignalAdmission::Admitted { event_id, .. } = first else {
            panic!("first delivery admits: {first:?}");
        };
        let second = admit_external_signal(
            &mut kernel,
            &instance_id,
            &ir,
            "deploy.finished",
            &payload,
            &key,
        )
        .expect("admission runs");
        assert_eq!(
            second,
            SignalAdmission::Duplicate {
                existing_event_id: event_id
            }
        );
        let facts = kernel.store().list_facts(&instance_id).expect("facts");
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.name == "deploy.finished")
                .count(),
            1,
            "one identity key never yields two facts: {facts:?}"
        );
    }

    /// An invalid candidate admits no fact: undeclared signal and
    /// non-conforming payload are refused before any store append.
    #[test]
    fn refuses_undeclared_signal_and_invalid_payload_before_any_append() {
        let (mut kernel, instance_id, ir) = kernel_with_instance();
        let undeclared = admit_external_signal(
            &mut kernel,
            &instance_id,
            &ir,
            "deploy.unknown",
            &json!({}),
            "key-1",
        )
        .expect("admission runs");
        assert!(
            matches!(
                &undeclared,
                SignalAdmission::Refused(SignalRefusal::UndeclaredSignal { declared })
                    if declared == &vec!["deploy.finished".to_owned()]
            ),
            "{undeclared:?}"
        );
        let invalid = admit_external_signal(
            &mut kernel,
            &instance_id,
            &ir,
            "deploy.finished",
            &json!({"service": "api", "status": 7}),
            "key-2",
        )
        .expect("admission runs");
        assert!(
            matches!(
                &invalid,
                SignalAdmission::Refused(SignalRefusal::PayloadInvalid { .. })
            ),
            "{invalid:?}"
        );
        let events = kernel.store().list_events(&instance_id).expect("events");
        assert!(
            events.iter().all(|event| event.source != "external"),
            "a refused candidate appends nothing: {events:?}"
        );
    }

    /// The `dedup` observation field replaces the positional ordinal as the
    /// delivery key: two elements with the same dedup value admit once, and a
    /// re-ordered feed does not double-admit.
    #[test]
    fn http_pass_dedups_by_observation_field_across_reordered_feeds() {
        const HTTP_PROGRAM: &str = r#"
@service
workflow IngressHttpDedup

signal feed.item {
  body string
}

source http as feed {
  url "https://example.com/feed.json"
  dedup obs.item
  observe as obs
  emit feed.item {
    body obs.item
  }
}

rule react
  when feed.item as f
=> {
  record Seen { body f.body }
}

class Seen {
  body string
}
"#;
        let ir = compile_program(HTTP_PROGRAM).ir.expect("program compiles");
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let instance_id = instance_on(&mut store, "IngressHttpDedup");
        let mut kernel = RuntimeKernel::new(store);

        let mut fetch = |_: &str| Ok(r#"["a", "b"]"#.to_owned());
        let first = resolve_due_http_sources(&mut kernel, &instance_id, &ir, &mut fetch)
            .expect("pass runs");
        assert_eq!(first.admitted, 2, "{first:?}");

        // Re-ordered + grown feed: only the genuinely new element admits. The
        // positional cursor the pre-I3 driver used would have double-admitted
        // the re-ordered head.
        let mut fetch = |_: &str| Ok(r#"["b", "a", "c"]"#.to_owned());
        let second = resolve_due_http_sources(&mut kernel, &instance_id, &ir, &mut fetch)
            .expect("pass runs");
        assert_eq!(second.admitted, 1, "{second:?}");
    }

    /// Watch-mode file sources admit one occurrence per (path, content-hash):
    /// a dropped file admits once, an unchanged file never re-admits, a
    /// content change re-admits.
    #[test]
    fn file_watch_mode_admits_per_content_occurrence() {
        const WATCH_PROGRAM: &str = r#"
@service
workflow IngressWatch

signal drop.arrived {
  path string
  digest string
}

source file as drops {
  watch "./drops/*.json"
  observe as obs
  emit drop.arrived {
    path obs.path
    digest obs.content_hash
  }
}

rule react
  when drop.arrived as f
=> {
  record Seen { path f.path }
}

class Seen {
  path string
}
"#;
        struct FakeIo(Vec<(String, String)>);
        impl IngressFileIo for FakeIo {
            fn read_file(&mut self, path: &str) -> Result<Option<String>, String> {
                Ok(self
                    .0
                    .iter()
                    .find(|(candidate, _)| candidate == path)
                    .map(|(_, contents)| contents.clone()))
            }
            fn glob_files(&mut self, _pattern: &str) -> Result<Vec<String>, String> {
                Ok(self.0.iter().map(|(path, _)| path.clone()).collect())
            }
        }

        let ir = compile_program(WATCH_PROGRAM).ir.expect("program compiles");
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let instance_id = instance_on(&mut store, "IngressWatch");
        let mut kernel = RuntimeKernel::new(store);

        let mut io = FakeIo(vec![("./drops/a.json".to_owned(), "one".to_owned())]);
        let first =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(first.admitted, 1, "dropped file admits once: {first:?}");

        let second =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(
            second.admitted, 0,
            "unchanged file never re-admits: {second:?}"
        );

        let mut io = FakeIo(vec![("./drops/a.json".to_owned(), "two".to_owned())]);
        let third =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(third.admitted, 1, "content change re-admits: {third:?}");
    }

    /// Line-mode file sources fold the line CONTENT into the delivery key: an
    /// unchanged line at an existing index re-reads as a duplicate (absorbed),
    /// a growing file admits only its new tail, but a CHANGED line at an
    /// existing index re-admits instead of being silently dropped.
    #[test]
    fn file_line_mode_readmits_a_changed_line_at_an_existing_index() {
        const LINE_PROGRAM: &str = r#"
@service
workflow IngressLines

signal status.line {
  value string
}

source file as status {
  path "./status.txt"
  observe as obs
  emit status.line {
    value obs.line
  }
}

rule react
  when status.line as f
=> {
  record Seen { value f.value }
}

class Seen {
  value string
}
"#;
        struct FakeIo(String);
        impl IngressFileIo for FakeIo {
            fn read_file(&mut self, path: &str) -> Result<Option<String>, String> {
                Ok((path == "./status.txt").then(|| self.0.clone()))
            }
            fn glob_files(&mut self, _pattern: &str) -> Result<Vec<String>, String> {
                Ok(Vec::new())
            }
        }

        let ir = compile_program(LINE_PROGRAM).ir.expect("program compiles");
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let instance_id = instance_on(&mut store, "IngressLines");
        let mut kernel = RuntimeKernel::new(store);

        // One line at index 0.
        let mut io = FakeIo("pending".to_owned());
        let first =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(first.admitted, 1, "the first line admits: {first:?}");

        // Same content re-read: absorbed (append-log semantics preserved).
        let second =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(
            second.admitted, 0,
            "an unchanged line re-reads once: {second:?}"
        );

        // The line at index 0 is rewritten in place: it must RE-ADMIT, not be
        // silently dropped as a positional duplicate.
        let mut io = FakeIo("done".to_owned());
        let third =
            resolve_due_file_sources(&mut kernel, &instance_id, &ir, &mut io).expect("pass runs");
        assert_eq!(
            third.admitted, 1,
            "a changed line at an existing index re-admits: {third:?}"
        );
    }
}
