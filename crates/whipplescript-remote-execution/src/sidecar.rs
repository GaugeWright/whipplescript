//! The sidecar tier as a runner (DR-0124 §14.4, compute-plane design note
//! §3–§4): the endpoint hands an action to a Class-A executor over HTTP or
//! HTTPS, and the executor runs it with the same confined run the endpoint's
//! own runner uses. It is another runner, not another endpoint — the endpoint
//! still resolves the action under the caller's view, classifies it, refuses
//! it, stores its outputs and caches its result; the sidecar only runs what it
//! is handed and holds no view, no label and no cache of results.
//!
//! The wire is `whipplescript.build.action/v2`, routes beside the executor's
//! `whip-executor/1` ones. No request and no answer has to hold more than one
//! chunk of any blob, so neither side's size is bounded by a response:
//!
//! - `POST /action/missing` names the input digests the action will need and
//!   is answered with the ones the sidecar does not hold, so only those
//!   travel (the note's "pulls only missing blobs", pushed by the endpoint);
//! - `POST /action/blobs` carries a batch of small blobs, and
//!   `POST /action/upload` one chunk of a large one at a checked offset — the
//!   blob is kept only once it is complete and hashes to its digest;
//! - `POST /action` names the command, its environment, its working
//!   directory, its inputs by digest and the outputs it may produce, and is
//!   answered with the exit status, the two streams and the named outputs —
//!   each inline when small, otherwise by digest, left in the sidecar's cache
//!   — or with the inputs still missing, when the sidecar lost some between
//!   the requests, which the runner sends and asks once more;
//! - `POST /action/fetch` reads one chunk of a blob the sidecar holds, as raw
//!   bytes, which is how an output named by digest comes back.
//!
//! The executor's blobs are a cache keyed by digest and nothing more: bytes
//! that do not hash to their key are refused, never kept, and the cache holds
//! at most its capacity — the least recently used blobs are evicted past it.
//! A blob evicted between two requests is sent again, or read as lost; it is
//! never answered as something else.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use serde_json::{json, Value};

use crate::digest::Digest;
use crate::runner::{run_confined, ActionOutcome, Output, PreparedAction};

/// The protocol every request and response of these routes names.
pub const ACTION_PROTOCOL: &str = "whipplescript.build.action/v2";

/// The largest request body the executor accepts on these routes: one chunk
/// or one batch, base64, and the JSON around it.
pub const MAX_ACTION_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The raw bytes one chunk, or one batch of small blobs, carries at most.
pub const CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// An output or stream at most this large comes back inside the answer;
/// anything larger is fetched by digest.
pub const INLINE_BYTES: usize = 1024 * 1024;

/// The executor's cache capacity unless `WHIP_EXECUTOR_ACTIONS_BYTES` says.
pub const DEFAULT_CAPACITY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The name results the sidecar ran are recorded under.
pub const SIDECAR_EXECUTOR: &str = "whip-executor/sidecar";

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|error| format!("{what} is not base64: {error}"))
}

fn parse_digest(text: &str) -> Result<Digest, String> {
    let (hash, size) = text
        .split_once('/')
        .ok_or_else(|| format!("not a digest: {text}"))?;
    Digest::from_resource(hash, size)
}

fn check_protocol(request: &Value) -> Result<(), String> {
    match request.get("protocol").and_then(Value::as_str) {
        Some(ACTION_PROTOCOL) => Ok(()),
        other => Err(format!(
            "expected protocol {ACTION_PROTOCOL}, not {}",
            other.unwrap_or("none")
        )),
    }
}

fn not_those_bytes(digest: &Digest) -> String {
    format!("the bytes sent as {digest} are not those bytes")
}

fn size_of(digest: &Digest) -> u64 {
    u64::try_from(digest.size_bytes).unwrap_or(0)
}

/// The digest of a file's bytes, read in chunks.
fn digest_of_file(path: &Path) -> std::io::Result<Digest> {
    use sha2::Digest as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut window = vec![0u8; 256 * 1024];
    let mut size: u64 = 0;
    loop {
        let read = file.read(&mut window)?;
        if read == 0 {
            break;
        }
        hasher.update(&window[..read]);
        size += read as u64;
    }
    Ok(Digest {
        hash: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        size_bytes: i64::try_from(size).unwrap_or(i64::MAX),
    })
}

/// An action as the wire names it: its inputs by digest, not by bytes.
pub fn encode_action(action: &PreparedAction) -> Value {
    let inputs: serde_json::Map<String, Value> = action
        .inputs
        .iter()
        .map(|(path, (bytes, executable))| {
            (
                path.clone(),
                json!({"digest": Digest::of(bytes).to_string(), "executable": executable}),
            )
        })
        .collect();
    json!({
        "protocol": ACTION_PROTOCOL,
        "arguments": action.arguments,
        "environment": action.environment,
        "working_directory": action.working_directory,
        "inputs": inputs,
        "output_paths": action.output_paths,
        "timeout_ms": action.timeout.map(|t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX)),
    })
}

/// A blob an answer names: its bytes inline, or only its digest.
fn blob_of(
    value: &Value,
    what: &str,
    fetch: &mut dyn FnMut(&Digest) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let digest = parse_digest(value.get("digest").and_then(Value::as_str).unwrap_or(""))?;
    let bytes = match value.get("bytes").and_then(Value::as_str) {
        Some(text) => decode(text, what)?,
        None => fetch(&digest)?,
    };
    if Digest::of(&bytes) != digest {
        return Err(format!(
            "the sidecar sent other bytes for {what} than {digest}"
        ));
    }
    Ok(bytes)
}

/// The outcome a sidecar answered with, fetching with `fetch` every blob it
/// named only by digest.
pub fn decode_outcome(
    response: &Value,
    mut fetch: impl FnMut(&Digest) -> Result<Vec<u8>, String>,
) -> Result<ActionOutcome, String> {
    check_protocol(response)?;
    let executable = |file: &Value| {
        file.get("executable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let mut outputs = BTreeMap::new();
    if let Some(named) = response.get("outputs").and_then(Value::as_object) {
        for (path, output) in named {
            let decoded = if let Some(file) = output.get("file") {
                Output::File {
                    bytes: blob_of(file, path, &mut fetch)?,
                    executable: executable(file),
                }
            } else if let Some(files) = output.get("directory").and_then(Value::as_object) {
                let mut decoded = BTreeMap::new();
                for (name, file) in files {
                    let what = format!("{path}/{name}");
                    decoded.insert(
                        name.clone(),
                        (blob_of(file, &what, &mut fetch)?, executable(file)),
                    );
                }
                Output::Directory { files: decoded }
            } else {
                return Err(format!("output {path} is neither a file nor a directory"));
            };
            outputs.insert(path.clone(), decoded);
        }
    }
    let stream =
        |name: &str, fetch: &mut dyn FnMut(&Digest) -> Result<Vec<u8>, String>| match response
            .get(name)
        {
            Some(blob) => blob_of(blob, name, fetch),
            None => Ok(Vec::new()),
        };
    Ok(ActionOutcome {
        exit_code: response
            .get("exit_code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .ok_or("the sidecar's answer names no exit code")?,
        timed_out: response
            .get("timed_out")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stdout: stream("stdout", &mut fetch)?,
        stderr: stream("stderr", &mut fetch)?,
        outputs,
    })
}

/// What the executor answers one of these routes with.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Json(Value),
    /// One chunk of a blob, raw.
    Bytes(Vec<u8>),
}

type Refusal = (u16, String);

/// The executor's half: a bounded blob cache keyed by digest and a scratch
/// root for confined runs, answering the routes. Synchronous, because the
/// executor serves each connection on its own thread.
pub struct ActionSidecar {
    root: PathBuf,
    capacity: u64,
    /// Held while a chunk is appended, so two uploads of one blob cannot
    /// interleave.
    uploads: Mutex<()>,
    /// What the cache holds, as last counted plus what has been written
    /// since; counted again whenever it passes the capacity.
    held_bytes: Mutex<Option<u64>>,
}

impl ActionSidecar {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_capacity(root, DEFAULT_CAPACITY_BYTES)
    }

    pub fn with_capacity(root: impl Into<PathBuf>, capacity: u64) -> Self {
        Self {
            root: root.into(),
            capacity,
            uploads: Mutex::new(()),
            held_bytes: Mutex::new(None),
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join(&digest.hash)
    }

    fn partial_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("partial").join(&digest.hash)
    }

    /// Mark a blob used now, so eviction takes others first.
    fn touch(path: &Path) {
        let _ = std::fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(SystemTime::now()));
    }

    /// Whether the cache holds a blob of the digest's size. Cheap: the bytes
    /// are checked against the digest when they are used.
    fn holds(&self, digest: &Digest) -> bool {
        if digest.is_empty() {
            return true;
        }
        let path = self.blob_path(digest);
        let held = std::fs::metadata(&path).is_ok_and(|meta| meta.len() == size_of(digest));
        if held {
            Self::touch(&path);
        }
        held
    }

    /// The bytes of a blob, only when they are the bytes its digest names.
    fn held(&self, digest: &Digest) -> Option<Vec<u8>> {
        if digest.is_empty() {
            return Some(Vec::new());
        }
        let path = self.blob_path(digest);
        let bytes = std::fs::read(&path)
            .ok()
            .filter(|bytes| Digest::of(bytes) == *digest)?;
        Self::touch(&path);
        Some(bytes)
    }

    fn keep_refusal(digest: &Digest, error: impl std::fmt::Display) -> Refusal {
        (500, format!("cannot keep blob {digest}: {error}"))
    }

    fn dir(path: &Path) -> Result<(), Refusal> {
        std::fs::create_dir_all(path)
            .map_err(|error| (500, format!("cannot create {}: {error}", path.display())))
    }

    /// Keep verified bytes under their digest: written aside and renamed, so
    /// a concurrent reader never sees a partial blob under its digest.
    fn store(&self, digest: &Digest, bytes: &[u8]) -> Result<(), Refusal> {
        let dir = self.root.join("blobs");
        Self::dir(&dir)?;
        tempfile::NamedTempFile::new_in(&dir)
            .and_then(|mut file| {
                file.write_all(bytes)?;
                Ok(file)
            })
            .and_then(|file| {
                file.persist(self.blob_path(digest))
                    .map_err(|error| error.error)
            })
            .map_err(|error| Self::keep_refusal(digest, error))?;
        self.note_written(bytes.len() as u64);
        Ok(())
    }

    /// Account for bytes just written, evicting when the cache passes its
    /// capacity.
    fn note_written(&self, bytes: u64) {
        let mut held = Self::lock(&self.held_bytes);
        let total = held.get_or_insert_with(|| self.counted().iter().map(|e| e.1).sum());
        *total += bytes;
        if *total > self.capacity {
            *total = self.evict(self.capacity / 10 * 9);
        }
    }

    /// Every blob and partial upload the cache holds: path, size, last use.
    fn counted(&self) -> Vec<(PathBuf, u64, SystemTime)> {
        let mut entries = Vec::new();
        for dir in [self.root.join("blobs"), self.root.join("partial")] {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        let used = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                        entries.push((entry.path(), meta.len(), used));
                    }
                }
            }
        }
        entries
    }

    /// Remove the least recently used blobs until the cache holds at most
    /// `target` bytes; returns what it then holds.
    fn evict(&self, target: u64) -> u64 {
        let mut entries = self.counted();
        entries.sort_by_key(|entry| entry.2);
        let mut total: u64 = entries.iter().map(|entry| entry.1).sum();
        for (path, size, _) in entries {
            if total <= target {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
        total
    }

    /// Answer one request to a route of this protocol, or `None` when the
    /// path is not one of them.
    pub fn handle(&self, path: &str, body: &[u8]) -> Option<(u16, Answer)> {
        let answer = match path {
            "/action/missing" => self.missing(body),
            "/action/blobs" => self.keep(body),
            "/action/upload" => self.upload(body),
            "/action/fetch" => self.fetch(body),
            "/action" => self.run(body),
            _ => return None,
        };
        Some(
            answer
                .unwrap_or_else(|(status, error)| (status, Answer::Json(json!({"error": error})))),
        )
    }

    fn request(body: &[u8]) -> Result<Value, Refusal> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|error| (400, format!("invalid JSON body: {error}")))?;
        check_protocol(&request).map_err(|error| (400, error))?;
        Ok(request)
    }

    fn named_digest(request: &Value) -> Result<Digest, Refusal> {
        parse_digest(request.get("digest").and_then(Value::as_str).unwrap_or(""))
            .map_err(|error| (400, error))
    }

    fn missing(&self, body: &[u8]) -> Result<(u16, Answer), Refusal> {
        let request = Self::request(body)?;
        let mut missing = Vec::new();
        for named in request
            .get("digests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let digest = parse_digest(named.as_str().unwrap_or("")).map_err(|e| (400, e))?;
            if !self.holds(&digest) {
                missing.push(digest.to_string());
            }
        }
        Ok((
            200,
            Answer::Json(json!({"protocol": ACTION_PROTOCOL, "missing": missing})),
        ))
    }

    fn keep(&self, body: &[u8]) -> Result<(u16, Answer), Refusal> {
        let request = Self::request(body)?;
        let blobs = request
            .get("blobs")
            .and_then(Value::as_object)
            .ok_or((400, "a blob batch names no blobs".to_owned()))?;
        let mut kept = 0;
        for (named, encoded) in blobs {
            let digest = parse_digest(named).map_err(|e| (400, e))?;
            let bytes = decode(encoded.as_str().unwrap_or(""), named).map_err(|e| (400, e))?;
            if Digest::of(&bytes) != digest {
                return Err((400, not_those_bytes(&digest)));
            }
            self.store(&digest, &bytes)?;
            kept += 1;
        }
        Ok((
            200,
            Answer::Json(json!({"protocol": ACTION_PROTOCOL, "kept": kept})),
        ))
    }

    /// One chunk of a large blob, appended at the offset the upload has
    /// reached; the blob is kept once it is complete and hashes to its
    /// digest.
    fn upload(&self, body: &[u8]) -> Result<(u16, Answer), Refusal> {
        let request = Self::request(body)?;
        let digest = Self::named_digest(&request)?;
        let offset = request
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or((400, "an upload names no offset".to_owned()))?;
        let chunk = decode(
            request.get("bytes").and_then(Value::as_str).unwrap_or(""),
            "the chunk",
        )
        .map_err(|e| (400, e))?;
        let size = size_of(&digest);
        let answer = |committed: u64, complete: bool| {
            Answer::Json(
                json!({"protocol": ACTION_PROTOCOL, "committed": committed, "complete": complete}),
            )
        };
        let _uploading = Self::lock(&self.uploads);
        if self.holds(&digest) {
            return Ok((200, answer(size, true)));
        }
        let partial = self.partial_path(&digest);
        Self::dir(&self.root.join("partial"))?;
        let committed = std::fs::metadata(&partial).map_or(0, |meta| meta.len());
        if offset != committed {
            return Ok((
                409,
                Answer::Json(json!({
                    "protocol": ACTION_PROTOCOL,
                    "error": format!("the upload of {digest} is at {committed}, not {offset}"),
                    "committed": committed,
                })),
            ));
        }
        let reached = committed + chunk.len() as u64;
        if reached > size {
            let _ = std::fs::remove_file(&partial);
            return Err((
                400,
                format!("the upload of {digest} is longer than its digest says"),
            ));
        }
        std::fs::File::options()
            .create(true)
            .append(true)
            .open(&partial)
            .and_then(|mut file| file.write_all(&chunk))
            .map_err(|error| Self::keep_refusal(&digest, error))?;
        if reached < size {
            return Ok((200, answer(reached, false)));
        }
        if digest_of_file(&partial).ok().as_ref() != Some(&digest) {
            let _ = std::fs::remove_file(&partial);
            return Err((400, not_those_bytes(&digest)));
        }
        Self::dir(&self.root.join("blobs"))?;
        std::fs::rename(&partial, self.blob_path(&digest))
            .map_err(|error| Self::keep_refusal(&digest, error))?;
        self.note_written(size);
        Ok((200, answer(size, true)))
    }

    /// One chunk of a held blob, raw.
    fn fetch(&self, body: &[u8]) -> Result<(u16, Answer), Refusal> {
        let request = Self::request(body)?;
        let digest = Self::named_digest(&request)?;
        let offset = request.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let limit = request
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(CHUNK_BYTES as u64)
            .min(CHUNK_BYTES as u64);
        if !self.holds(&digest) {
            return Err((404, format!("the sidecar does not hold {digest}")));
        }
        let mut chunk = Vec::new();
        std::fs::File::open(self.blob_path(&digest))
            .and_then(|mut file| {
                file.seek(SeekFrom::Start(offset))?;
                file.take(limit).read_to_end(&mut chunk)
            })
            .map_err(|error| (500, format!("cannot read blob {digest}: {error}")))?;
        Ok((200, Answer::Bytes(chunk)))
    }

    /// A blob an answer names: inline when small, otherwise kept here and
    /// named by digest for the runner to fetch.
    fn answer_blob(&self, bytes: &[u8]) -> Result<Value, Refusal> {
        let digest = Digest::of(bytes);
        if bytes.len() <= INLINE_BYTES {
            return Ok(json!({"digest": digest.to_string(), "bytes": encode(bytes)}));
        }
        if !self.holds(&digest) {
            self.store(&digest, bytes)?;
        }
        Ok(json!({"digest": digest.to_string()}))
    }

    fn run(&self, body: &[u8]) -> Result<(u16, Answer), Refusal> {
        let request = Self::request(body)?;
        let strings = |field: &str| -> Vec<String> {
            request
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        };
        let mut inputs = BTreeMap::new();
        let mut missing = Vec::new();
        for (path, input) in request
            .get("inputs")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let digest = Self::named_digest(input)?;
            let executable = input
                .get("executable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match self.held(&digest) {
                Some(bytes) => {
                    inputs.insert(path.clone(), (bytes, executable));
                }
                None => missing.push(digest.to_string()),
            }
        }
        if !missing.is_empty() {
            missing.sort();
            missing.dedup();
            return Ok((
                409,
                Answer::Json(
                    json!({"protocol": ACTION_PROTOCOL, "error": "inputs are missing from the sidecar", "missing": missing}),
                ),
            ));
        }
        let action = PreparedAction {
            arguments: strings("arguments"),
            environment: request
                .get("environment")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|pair| {
                    Some((
                        pair.get(0)?.as_str()?.to_owned(),
                        pair.get(1)?.as_str()?.to_owned(),
                    ))
                })
                .collect(),
            working_directory: request
                .get("working_directory")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            inputs,
            output_paths: strings("output_paths"),
            timeout: request
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .map(Duration::from_millis),
        };
        let outcome = run_confined(&self.root.join("actions"), &action).map_err(|e| (422, e))?;
        let mut outputs = serde_json::Map::new();
        for (path, output) in &outcome.outputs {
            let encoded = match output {
                Output::File { bytes, executable } => {
                    let mut blob = self.answer_blob(bytes)?;
                    blob["executable"] = json!(executable);
                    json!({"file": blob})
                }
                Output::Directory { files } => {
                    let mut encoded = serde_json::Map::new();
                    for (name, (bytes, executable)) in files {
                        let mut blob = self.answer_blob(bytes)?;
                        blob["executable"] = json!(executable);
                        encoded.insert(name.clone(), blob);
                    }
                    json!({"directory": encoded})
                }
            };
            outputs.insert(path.clone(), encoded);
        }
        Ok((
            200,
            Answer::Json(json!({
                "protocol": ACTION_PROTOCOL,
                "executor": SIDECAR_EXECUTOR,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "stdout": self.answer_blob(&outcome.stdout)?,
                "stderr": self.answer_blob(&outcome.stderr)?,
                "outputs": outputs,
            })),
        ))
    }
}

/// Where an executor keeps its action blobs and scratch: `WHIP_EXECUTOR_ACTIONS`,
/// else a directory under the system's temporary one.
pub fn default_sidecar_root() -> PathBuf {
    std::env::var_os("WHIP_EXECUTOR_ACTIONS")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("whip-executor-actions"))
}

/// The executor's cache capacity: `WHIP_EXECUTOR_ACTIONS_BYTES`, else
/// [`DEFAULT_CAPACITY_BYTES`]. A value that is not a positive count of bytes
/// is the default rather than an unbounded cache.
pub fn default_sidecar_capacity() -> u64 {
    std::env::var("WHIP_EXECUTOR_ACTIONS_BYTES")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_CAPACITY_BYTES)
}

#[cfg(feature = "endpoint")]
pub use client::SidecarRunner;

#[cfg(feature = "endpoint")]
mod client {
    use std::sync::Arc;

    use super::*;
    use crate::runner::ActionRunner;

    /// The largest answer the runner reads in one response: an action's
    /// answer with its small outputs inline, or one chunk.
    const MAX_ANSWER_BYTES: u64 = 256 * 1024 * 1024;

    /// The endpoint's half: a runner that hands each action to a Class-A
    /// executor at an `http://` or `https://` address, authenticated with the
    /// executor's own bearer token when one is configured. HTTPS trusts the
    /// platform's roots (and `SSL_CERT_FILE`), and a pool's own CA when it is
    /// named.
    #[derive(Clone)]
    pub struct SidecarRunner {
        url: String,
        agent: ureq::Agent,
        token: Option<String>,
    }

    impl SidecarRunner {
        pub fn new(url: &str, token: Option<String>) -> Result<Self, String> {
            Self::connect(url, token, None)
        }

        /// A runner whose HTTPS also trusts the certificates in `ca`, a PEM
        /// bundle — a pool behind its own authority.
        pub fn trusting(url: &str, token: Option<String>, ca: &Path) -> Result<Self, String> {
            Self::connect(url, token, Some(ca))
        }

        fn connect(url: &str, token: Option<String>, ca: Option<&Path>) -> Result<Self, String> {
            let base = url.trim_end_matches('/');
            let host = base
                .strip_prefix("http://")
                .or_else(|| base.strip_prefix("https://"))
                .filter(|host| !host.is_empty());
            if host.is_none() {
                return Err(format!(
                    "the sidecar runner speaks HTTP or HTTPS; {url} is neither"
                ));
            }
            let mut agent = ureq::AgentBuilder::new();
            if let Some(ca) = ca {
                agent = agent.tls_config(Arc::new(trusting(ca)?));
            }
            Ok(Self {
                url: base.to_owned(),
                agent: agent.build(),
                token: token.filter(|token| !token.trim().is_empty()),
            })
        }

        /// One request; the status and the body, whatever the status.
        fn call(&self, path: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
            let mut request = self
                .agent
                .post(&format!("{}{path}", self.url))
                .set("content-type", "application/json");
            if let Some(token) = &self.token {
                request = request.set("authorization", &format!("Bearer {token}"));
            }
            // A request that never reached an answer, and an answer that
            // broke off, are the same fact to the caller.
            let answered = match request.send_string(&body.to_string()) {
                Ok(response) | Err(ureq::Error::Status(_, response)) => {
                    let status = response.status();
                    let mut answer = Vec::new();
                    response
                        .into_reader()
                        .take(MAX_ANSWER_BYTES)
                        .read_to_end(&mut answer)
                        .map(|_| (status, answer))
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            };
            answered.map_err(|error| {
                format!("the sidecar at {} did not answer {path}: {error}", self.url)
            })
        }

        fn json(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
            let (status, answer) = self.call(path, body)?;
            let value = serde_json::from_slice(&answer).map_err(|error| {
                format!(
                    "the sidecar at {} answered {path} with no JSON: {error}",
                    self.url
                )
            })?;
            Ok((status, value))
        }

        fn refused(&self, path: &str, status: u16, value: &Value) -> String {
            format!(
                "the sidecar at {} refused {path} ({status}): {}",
                self.url,
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason given")
            )
        }

        fn ok(&self, path: &str, body: &Value) -> Result<Value, String> {
            let (status, value) = self.json(path, body)?;
            if status != 200 {
                return Err(self.refused(path, status, &value));
            }
            Ok(value)
        }

        /// Send the named blobs: small ones in batches, large ones in chunks.
        fn send(&self, action: &PreparedAction, wanted: &[String]) -> Result<(), String> {
            let by_digest: BTreeMap<String, &Vec<u8>> = action
                .inputs
                .values()
                .map(|(bytes, _)| (Digest::of(bytes).to_string(), bytes))
                .collect();
            let mut batch = serde_json::Map::new();
            let mut size = 0;
            for named in wanted {
                let Some(bytes) = by_digest.get(named) else {
                    return Err(format!(
                        "the sidecar at {} asked for {named}, which this action does not name",
                        self.url
                    ));
                };
                if bytes.len() > CHUNK_BYTES {
                    self.upload(&Digest::of(bytes), bytes)?;
                    continue;
                }
                if size + bytes.len() > CHUNK_BYTES {
                    self.ok(
                        "/action/blobs",
                        &json!({"protocol": ACTION_PROTOCOL, "blobs": std::mem::take(&mut batch)}),
                    )?;
                    size = 0;
                }
                size += bytes.len();
                batch.insert(named.clone(), Value::String(encode(bytes)));
            }
            if !batch.is_empty() {
                self.ok(
                    "/action/blobs",
                    &json!({"protocol": ACTION_PROTOCOL, "blobs": batch}),
                )?;
            }
            Ok(())
        }

        /// Upload one large blob chunk by chunk, resuming where the sidecar
        /// says its upload stands.
        fn upload(&self, digest: &Digest, bytes: &[u8]) -> Result<(), String> {
            let mut offset: usize = 0;
            // Every chunk, and one resumption per chunk, before it is a
            // refusal rather than a loop.
            let mut budget = 2 * (bytes.len() / CHUNK_BYTES + 1);
            loop {
                let end = (offset + CHUNK_BYTES).min(bytes.len());
                let request = json!({
                    "protocol": ACTION_PROTOCOL,
                    "digest": digest.to_string(),
                    "offset": offset,
                    "bytes": encode(&bytes[offset..end]),
                });
                let (status, value) = self.json("/action/upload", &request)?;
                let committed = value
                    .get("committed")
                    .and_then(Value::as_u64)
                    .and_then(|committed| usize::try_from(committed).ok());
                match (status, committed) {
                    (200, _) if value.get("complete").and_then(Value::as_bool) == Some(true) => {
                        return Ok(())
                    }
                    (200 | 409, Some(committed)) if committed < bytes.len() && budget > 0 => {
                        offset = committed;
                        budget -= 1;
                    }
                    _ => return Err(self.refused("/action/upload", status, &value)),
                }
            }
        }

        /// Read one blob the sidecar holds, chunk by chunk.
        fn fetch(&self, digest: &Digest) -> Result<Vec<u8>, String> {
            let size = usize::try_from(digest.size_bytes).unwrap_or(0);
            let mut bytes = Vec::with_capacity(size.min(CHUNK_BYTES));
            while bytes.len() < size {
                let request = json!({
                    "protocol": ACTION_PROTOCOL,
                    "digest": digest.to_string(),
                    "offset": bytes.len(),
                    "limit": CHUNK_BYTES,
                });
                match self.call("/action/fetch", &request)? {
                    (200, chunk) if !chunk.is_empty() => bytes.extend_from_slice(&chunk),
                    (200, _) => {
                        return Err(format!(
                            "the sidecar at {} ended {digest} after {} bytes",
                            self.url,
                            bytes.len()
                        ))
                    }
                    (status, answer) => {
                        let value = serde_json::from_slice(&answer).unwrap_or(Value::Null);
                        return Err(self.refused("/action/fetch", status, &value));
                    }
                }
            }
            Ok(bytes)
        }

        fn missing_of(value: &Value) -> Vec<String> {
            value
                .get("missing")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        }

        /// The whole exchange for one action, blocking.
        pub fn run_blocking(&self, action: &PreparedAction) -> Result<ActionOutcome, String> {
            let digests: Vec<String> = action
                .inputs
                .values()
                .map(|(bytes, _)| Digest::of(bytes).to_string())
                .collect();
            let asked = json!({"protocol": ACTION_PROTOCOL, "digests": digests});
            let missing = Self::missing_of(&self.ok("/action/missing", &asked)?);
            self.send(action, &missing)?;
            let encoded = encode_action(action);
            // A sidecar may lose a blob between the requests; what it names
            // as missing is sent once more, and a second loss is a refusal
            // rather than a loop.
            for attempt in 0..2 {
                match self.json("/action", &encoded)? {
                    (200, value) => return decode_outcome(&value, |digest| self.fetch(digest)),
                    (409, value) if attempt == 0 && !Self::missing_of(&value).is_empty() => {
                        self.send(action, &Self::missing_of(&value))?;
                    }
                    (status, value) => return Err(self.refused("/action", status, &value)),
                }
            }
            unreachable!("the second attempt returns")
        }
    }

    /// A TLS configuration trusting the platform's roots and every
    /// certificate in the PEM bundle at `ca`.
    fn trusting(ca: &Path) -> Result<rustls::ClientConfig, String> {
        let unusable = |error: String| {
            format!(
                "{} is not a usable PEM certificate bundle: {error}",
                ca.display()
            )
        };
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
            let _ = roots.add(cert);
        }
        let pem = std::fs::read(ca).map_err(|error| unusable(error.to_string()))?;
        let mut named = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|error| unusable(error.to_string()))?;
            roots
                .add(cert)
                .map_err(|error| unusable(error.to_string()))?;
            named += 1;
        }
        if named == 0 {
            return Err(unusable("it holds no certificate".into()));
        }
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth())
    }

    #[async_trait::async_trait]
    impl ActionRunner for SidecarRunner {
        fn name(&self) -> &str {
            SIDECAR_EXECUTOR
        }

        async fn run(&self, action: PreparedAction) -> Result<ActionOutcome, String> {
            let runner = self.clone();
            tokio::task::spawn_blocking(move || runner.run_blocking(&action))
                .await
                .unwrap_or_else(|failed| std::panic::resume_unwind(failed.into_panic()))
        }
    }
}

#[cfg(test)]
mod tests;
