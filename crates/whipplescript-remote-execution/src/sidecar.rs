//! The sidecar tier as a runner (DR-0124 §14.4, compute-plane design note
//! §3–§4): the endpoint hands an action to a Class-A executor over HTTP, and
//! the executor runs it with the same confined run the endpoint's own runner
//! uses. It is another runner, not another endpoint — the endpoint still
//! resolves the action under the caller's view, classifies it, refuses it,
//! stores its outputs and caches its result; the sidecar only runs what it is
//! handed and holds no view, no label and no cache of results.
//!
//! The wire is `whipplescript.build.action/v1`, three routes beside the
//! executor's `whip-executor/1` ones, each one request and one response:
//!
//! - `POST /action/missing` names the input digests the action will need and
//!   is answered with the ones the sidecar does not hold, so only those
//!   travel (the note's "pulls only missing blobs", pushed by the endpoint);
//! - `POST /action/blobs` carries a batch of those blobs, each checked
//!   against its digest before it is kept;
//! - `POST /action` names the command, its environment, its working
//!   directory, its inputs by digest and the outputs it may produce, and is
//!   answered with the exit status, the two streams and the named outputs —
//!   or with the inputs still missing, when the sidecar lost some between the
//!   two requests, which the runner uploads and asks once more.
//!
//! Bytes travel as base64 inside JSON, as the executor's own protocol
//! carries scripts. The executor's blobs are a cache keyed by digest and
//! nothing more: bytes that do not hash to their key are refused, never
//! stored.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Value};

use crate::digest::Digest;
use crate::runner::{run_confined, ActionOutcome, Output, PreparedAction};

/// The protocol every request and response of these routes names.
pub const ACTION_PROTOCOL: &str = "whipplescript.build.action/v1";

/// The largest request body the executor accepts on these routes. A blob
/// batch is sized below it by the runner; a single input larger than a batch
/// can hold is refused by the runner before anything is sent.
pub const MAX_ACTION_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The raw bytes one blob batch carries at most, leaving room for base64's
/// third and the JSON around it.
pub const BLOB_BATCH_BYTES: usize = 32 * 1024 * 1024;

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

fn encode_files(files: &BTreeMap<String, (Vec<u8>, bool)>) -> Value {
    Value::Object(
        files
            .iter()
            .map(|(path, (bytes, executable))| {
                (
                    path.clone(),
                    json!({"bytes": encode(bytes), "executable": executable}),
                )
            })
            .collect(),
    )
}

fn decode_files(value: &Value, what: &str) -> Result<BTreeMap<String, (Vec<u8>, bool)>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{what} is not a map of files"))?
        .iter()
        .map(|(path, file)| {
            let bytes = decode(
                file.get("bytes").and_then(Value::as_str).unwrap_or(""),
                path,
            )?;
            let executable = file
                .get("executable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Ok((path.clone(), (bytes, executable)))
        })
        .collect()
}

/// An outcome as the wire carries it back.
pub fn encode_outcome(outcome: &ActionOutcome) -> Value {
    let outputs: serde_json::Map<String, Value> = outcome
        .outputs
        .iter()
        .map(|(path, output)| {
            let encoded = match output {
                Output::File { bytes, executable } => {
                    json!({"file": {"bytes": encode(bytes), "executable": executable}})
                }
                Output::Directory { files } => json!({"directory": encode_files(files)}),
            };
            (path.clone(), encoded)
        })
        .collect();
    json!({
        "protocol": ACTION_PROTOCOL,
        "executor": SIDECAR_EXECUTOR,
        "exit_code": outcome.exit_code,
        "timed_out": outcome.timed_out,
        "stdout": encode(&outcome.stdout),
        "stderr": encode(&outcome.stderr),
        "outputs": outputs,
    })
}

/// The outcome a sidecar answered with.
pub fn decode_outcome(response: &Value) -> Result<ActionOutcome, String> {
    check_protocol(response)?;
    let mut outputs = BTreeMap::new();
    if let Some(named) = response.get("outputs").and_then(Value::as_object) {
        for (path, output) in named {
            let decoded = if let Some(file) = output.get("file") {
                Output::File {
                    bytes: decode(
                        file.get("bytes").and_then(Value::as_str).unwrap_or(""),
                        path,
                    )?,
                    executable: file
                        .get("executable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                }
            } else if let Some(files) = output.get("directory") {
                Output::Directory {
                    files: decode_files(files, path)?,
                }
            } else {
                return Err(format!("output {path} is neither a file nor a directory"));
            };
            outputs.insert(path.clone(), decoded);
        }
    }
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
        stdout: decode(
            response.get("stdout").and_then(Value::as_str).unwrap_or(""),
            "stdout",
        )?,
        stderr: decode(
            response.get("stderr").and_then(Value::as_str).unwrap_or(""),
            "stderr",
        )?,
        outputs,
    })
}

/// The executor's half: a blob cache keyed by digest and a scratch root for
/// confined runs, answering the three routes. Synchronous, because the
/// executor serves each connection on its own thread.
pub struct ActionSidecar {
    root: PathBuf,
}

impl ActionSidecar {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join(&digest.hash)
    }

    fn held(&self, digest: &Digest) -> Option<Vec<u8>> {
        if digest.is_empty() {
            return Some(Vec::new());
        }
        std::fs::read(self.blob_path(digest))
            .ok()
            .filter(|bytes| Digest::of(bytes) == *digest)
    }

    /// Answer one request to a route of this protocol, or `None` when the
    /// path is not one of them.
    pub fn handle(&self, path: &str, body: &[u8]) -> Option<(u16, Value)> {
        let answer = match path {
            "/action/missing" => self.missing(body),
            "/action/blobs" => self.keep(body),
            "/action" => self.run(body),
            _ => return None,
        };
        Some(answer.unwrap_or_else(|(status, error)| (status, json!({"error": error}))))
    }

    fn request(body: &[u8]) -> Result<Value, (u16, String)> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|error| (400, format!("invalid JSON body: {error}")))?;
        check_protocol(&request).map_err(|error| (400, error))?;
        Ok(request)
    }

    fn missing(&self, body: &[u8]) -> Result<(u16, Value), (u16, String)> {
        let request = Self::request(body)?;
        let mut missing = Vec::new();
        for named in request
            .get("digests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let digest = parse_digest(named.as_str().unwrap_or("")).map_err(|e| (400, e))?;
            if self.held(&digest).is_none() {
                missing.push(digest.to_string());
            }
        }
        Ok((
            200,
            json!({"protocol": ACTION_PROTOCOL, "missing": missing}),
        ))
    }

    fn keep(&self, body: &[u8]) -> Result<(u16, Value), (u16, String)> {
        let request = Self::request(body)?;
        let blobs = request
            .get("blobs")
            .and_then(Value::as_object)
            .ok_or((400, "a blob batch names no blobs".to_owned()))?;
        let dir = self.root.join("blobs");
        std::fs::create_dir_all(&dir)
            .map_err(|error| (500, format!("cannot create {}: {error}", dir.display())))?;
        let mut kept = 0;
        for (named, encoded) in blobs {
            let digest = parse_digest(named).map_err(|e| (400, e))?;
            let bytes = decode(encoded.as_str().unwrap_or(""), named).map_err(|e| (400, e))?;
            if Digest::of(&bytes) != digest {
                return Err((
                    400,
                    format!("the bytes sent as {digest} are not those bytes"),
                ));
            }
            // Written aside and renamed, so a concurrent reader never sees a
            // partial blob under its digest.
            let target = self.blob_path(&digest);
            let partial = tempfile::NamedTempFile::new_in(&dir)
                .and_then(|mut file| {
                    std::io::Write::write_all(&mut file, &bytes)?;
                    Ok(file)
                })
                .and_then(|file| file.persist(&target).map_err(|error| error.error))
                .map_err(|error| (500, format!("cannot keep blob {digest}: {error}")));
            partial?;
            kept += 1;
        }
        Ok((200, json!({"protocol": ACTION_PROTOCOL, "kept": kept})))
    }

    fn run(&self, body: &[u8]) -> Result<(u16, Value), (u16, String)> {
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
            let digest = parse_digest(input.get("digest").and_then(Value::as_str).unwrap_or(""))
                .map_err(|e| (400, e))?;
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
                json!({"protocol": ACTION_PROTOCOL, "error": "inputs are missing from the sidecar", "missing": missing}),
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
        Ok((200, encode_outcome(&outcome)))
    }
}

/// Where an executor keeps its action blobs and scratch: `WHIP_EXECUTOR_ACTIONS`,
/// else a directory under the system's temporary one.
pub fn default_sidecar_root() -> PathBuf {
    std::env::var_os("WHIP_EXECUTOR_ACTIONS")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("whip-executor-actions"))
}

#[cfg(feature = "endpoint")]
pub use client::SidecarRunner;

#[cfg(feature = "endpoint")]
mod client {
    use super::*;
    use crate::runner::ActionRunner;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The largest answer the runner reads from a sidecar: the outputs of one
    /// action, inline.
    const MAX_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;

    /// The endpoint's half: a runner that hands each action to a Class-A
    /// executor at `http://host:port`, authenticated with the executor's own
    /// bearer token when one is configured.
    pub struct SidecarRunner {
        url: String,
        address: String,
        token: Option<String>,
    }

    impl SidecarRunner {
        pub fn new(url: &str, token: Option<String>) -> Result<Self, String> {
            let address = url
                .strip_prefix("http://")
                .map(|rest| rest.trim_end_matches('/'))
                .filter(|rest| !rest.is_empty() && !rest.contains('/'))
                .ok_or_else(|| {
                    format!("the sidecar runner speaks plain HTTP to host:port; {url} is not an http://host:port address")
                })?;
            Ok(Self {
                url: url.trim_end_matches('/').to_owned(),
                address: address.to_owned(),
                token: token.filter(|token| !token.trim().is_empty()),
            })
        }

        /// One HTTP/1.1 request, `connection: close`, as the executor serves.
        async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
            let unreachable = |error: std::io::Error| {
                format!("the sidecar at {} did not answer {path}: {error}", self.url)
            };
            let payload = body.to_string();
            let mut stream = tokio::net::TcpStream::connect(&self.address)
                .await
                .map_err(unreachable)?;
            let authorization = self
                .token
                .as_ref()
                .map(|token| format!("authorization: Bearer {token}\r\n"))
                .unwrap_or_default();
            let head = format!(
                "POST {path} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{authorization}connection: close\r\n\r\n",
                self.address,
                payload.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .map_err(unreachable)?;
            stream
                .write_all(payload.as_bytes())
                .await
                .map_err(unreachable)?;
            let mut answer = Vec::new();
            (&mut stream)
                .take(MAX_RESPONSE_BYTES)
                .read_to_end(&mut answer)
                .await
                .map_err(unreachable)?;
            let (split, status) = answer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .and_then(|split| {
                    let status = std::str::from_utf8(&answer[..split])
                        .ok()?
                        .split_whitespace()
                        .nth(1)?
                        .parse::<u16>()
                        .ok()?;
                    Some((split, status))
                })
                .ok_or_else(|| {
                    format!(
                        "the sidecar at {} answered {path} with no HTTP response",
                        self.url
                    )
                })?;
            let value = serde_json::from_slice(&answer[split + 4..]).map_err(|error| {
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

        /// Send the named blobs in batches the executor accepts.
        async fn send(&self, action: &PreparedAction, wanted: &[String]) -> Result<(), String> {
            let by_digest: BTreeMap<String, (&String, &Vec<u8>)> = action
                .inputs
                .iter()
                .map(|(path, (bytes, _))| (Digest::of(bytes).to_string(), (path, bytes)))
                .collect();
            let mut batch = serde_json::Map::new();
            let mut size = 0;
            for named in wanted {
                let Some((path, bytes)) = by_digest.get(named) else {
                    return Err(format!(
                        "the sidecar at {} asked for {named}, which this action does not name",
                        self.url
                    ));
                };
                if bytes.len() > BLOB_BATCH_BYTES {
                    return Err(format!(
                        "input {path} ({} bytes) is larger than the sidecar accepts in one request",
                        bytes.len()
                    ));
                }
                if size + bytes.len() > BLOB_BATCH_BYTES {
                    self.keep(std::mem::take(&mut batch)).await?;
                    size = 0;
                }
                size += bytes.len();
                batch.insert(named.clone(), Value::String(encode(bytes)));
            }
            if !batch.is_empty() {
                self.keep(batch).await?;
            }
            Ok(())
        }

        async fn keep(&self, blobs: serde_json::Map<String, Value>) -> Result<(), String> {
            let body = json!({"protocol": ACTION_PROTOCOL, "blobs": blobs});
            match self.post("/action/blobs", &body).await? {
                (200, _) => Ok(()),
                (status, value) => Err(self.refused("/action/blobs", status, &value)),
            }
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
    }

    #[async_trait::async_trait]
    impl ActionRunner for SidecarRunner {
        fn name(&self) -> &str {
            SIDECAR_EXECUTOR
        }

        async fn run(&self, action: PreparedAction) -> Result<ActionOutcome, String> {
            let digests: Vec<String> = action
                .inputs
                .values()
                .map(|(bytes, _)| Digest::of(bytes).to_string())
                .collect();
            let asked = json!({"protocol": ACTION_PROTOCOL, "digests": digests});
            let missing = match self.post("/action/missing", &asked).await? {
                (200, value) => Self::missing_of(&value),
                (status, value) => return Err(self.refused("/action/missing", status, &value)),
            };
            self.send(&action, &missing).await?;
            let encoded = encode_action(&action);
            // A sidecar may lose a blob between the two requests; what it
            // names as missing is sent once more, and a second loss is a
            // refusal rather than a loop.
            for attempt in 0..2 {
                match self.post("/action", &encoded).await? {
                    (200, value) => return decode_outcome(&value),
                    (409, value) if attempt == 0 && !Self::missing_of(&value).is_empty() => {
                        self.send(&action, &Self::missing_of(&value)).await?;
                    }
                    (status, value) => return Err(self.refused("/action", status, &value)),
                }
            }
            unreachable!("the second attempt returns")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(inputs: &[(&str, &[u8])]) -> PreparedAction {
        PreparedAction {
            arguments: vec![
                "sh".into(),
                "-c".into(),
                "tr a-z A-Z < in.txt > out.txt; mkdir -p d; echo x > d/x; echo ran".into(),
            ],
            environment: vec![("LANG".into(), "C".into())],
            working_directory: String::new(),
            inputs: inputs
                .iter()
                .map(|(path, bytes)| ((*path).to_owned(), (bytes.to_vec(), false)))
                .collect(),
            output_paths: vec!["out.txt".into(), "d".into()],
            timeout: Some(Duration::from_secs(30)),
        }
    }

    fn body(value: Value) -> Vec<u8> {
        value.to_string().into_bytes()
    }

    #[test]
    fn the_sidecar_runs_what_it_holds_and_names_what_it_lacks() {
        let root = tempfile::tempdir().expect("scratch");
        let sidecar = ActionSidecar::new(root.path());
        let prepared = action(&[("in.txt", b"shout")]);
        let input = Digest::of(b"shout");
        assert_eq!(sidecar.handle("/exec", b"{}"), None);
        let (status, answer) = sidecar
            .handle(
                "/action/missing",
                &body(json!({"protocol": ACTION_PROTOCOL, "digests": [input.to_string(), Digest::empty().to_string()]})),
            )
            .unwrap();
        assert_eq!(
            (status, answer["missing"].clone()),
            (200, json!([input.to_string()]))
        );
        // Asked to run before it holds the input, it names what is missing.
        let (status, answer) = sidecar
            .handle("/action", &body(encode_action(&prepared)))
            .unwrap();
        assert_eq!(status, 409);
        assert_eq!(answer["missing"], json!([input.to_string()]));
        // Bytes that are not the digest they are sent as are refused.
        let (status, answer) = sidecar
            .handle(
                "/action/blobs",
                &body(json!({"protocol": ACTION_PROTOCOL, "blobs": {input.to_string(): encode(b"other")}})),
            )
            .unwrap();
        assert_eq!(
            (status, answer["error"].clone()),
            (
                400,
                json!(format!("the bytes sent as {input} are not those bytes"))
            )
        );
        let (status, _) = sidecar
            .handle(
                "/action/blobs",
                &body(json!({"protocol": ACTION_PROTOCOL, "blobs": {input.to_string(): encode(b"shout")}})),
            )
            .unwrap();
        assert_eq!(status, 200);
        let (status, answer) = sidecar
            .handle("/action", &body(encode_action(&prepared)))
            .unwrap();
        assert_eq!(status, 200, "{answer}");
        let outcome = decode_outcome(&answer).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, b"ran\n");
        assert!(
            matches!(&outcome.outputs["out.txt"], Output::File { bytes, .. } if bytes == b"SHOUT")
        );
        assert!(
            matches!(&outcome.outputs["d"], Output::Directory { files } if files["x"].0 == b"x\n")
        );
        // What the wire refuses, it refuses by name.
        for (path, request, expected) in [
            (
                "/action",
                json!({"protocol": "other/v1"}),
                "expected protocol whipplescript.build.action/v1, not other/v1",
            ),
            (
                "/action/blobs",
                json!({"protocol": ACTION_PROTOCOL}),
                "a blob batch names no blobs",
            ),
            (
                "/action/missing",
                json!({"protocol": ACTION_PROTOCOL, "digests": ["nohash"]}),
                "not a digest: nohash",
            ),
        ] {
            let (status, answer) = sidecar.handle(path, &body(request)).unwrap();
            assert_eq!((status, answer["error"].as_str().unwrap()), (400, expected));
        }
        assert!(sidecar.handle("/action", b"not json").unwrap().1["error"]
            .as_str()
            .unwrap()
            .starts_with("invalid JSON body: "));
        let (status, answer) = sidecar
            .handle(
                "/action",
                &body(json!({"protocol": ACTION_PROTOCOL, "arguments": []})),
            )
            .unwrap();
        assert_eq!(
            (status, answer["error"].as_str().unwrap()),
            (422, "an action names no command")
        );
        assert_eq!(
            decode_outcome(&json!({"protocol": ACTION_PROTOCOL})).unwrap_err(),
            "the sidecar's answer names no exit code"
        );
        assert_eq!(
            decode_outcome(
                &json!({"protocol": ACTION_PROTOCOL, "exit_code": 0, "outputs": {"o": {}}})
            )
            .unwrap_err(),
            "output o is neither a file nor a directory"
        );
        assert_eq!(
            decode_outcome(&json!({"protocol": ACTION_PROTOCOL, "exit_code": 0, "stdout": "!!"}))
                .unwrap_err(),
            "stdout is not base64: Invalid symbol 33, offset 0."
        );
        assert_eq!(
            decode_outcome(&json!({"protocol": ACTION_PROTOCOL, "exit_code": 0, "outputs": {"o": {"directory": 3}}}))
                .unwrap_err(),
            "o is not a map of files"
        );
        // A root it cannot write under, and a blob it cannot put in place.
        let batch = body(
            json!({"protocol": ACTION_PROTOCOL, "blobs": {input.to_string(): encode(b"shout")}}),
        );
        let unwritable = root.path().join("blobs").join(&input.hash);
        let (status, answer) = ActionSidecar::new(&unwritable)
            .handle("/action/blobs", &batch)
            .unwrap();
        assert_eq!(status, 500);
        assert!(answer["error"].as_str().unwrap().starts_with(&format!(
            "cannot create {}: ",
            unwritable.join("blobs").display()
        )));
        let blocked = tempfile::tempdir().expect("scratch");
        std::fs::create_dir_all(blocked.path().join("blobs").join(&input.hash).join("x"))
            .expect("the fixture's own step");
        let (status, answer) = ActionSidecar::new(blocked.path())
            .handle("/action/blobs", &batch)
            .unwrap();
        assert_eq!(status, 500);
        assert!(answer["error"]
            .as_str()
            .unwrap()
            .starts_with(&format!("cannot keep blob {input}: ")));
    }
}

#[cfg(all(test, feature = "endpoint"))]
mod client_tests {
    use super::*;
    use crate::runner::ActionRunner;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// A one-thread HTTP/1.1 server answering each request with `respond`,
    /// recording each path and its authorization header.
    fn serve(respond: impl Fn(&str, &[u8]) -> Vec<u8> + Send + 'static) -> (String, Seen) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let url = format!("http://{}", listener.local_addr().expect("an address"));
        let seen: Seen = Arc::default();
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("a request line");
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let (mut length, mut authorization) = (0, None);
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).expect("a header");
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').expect("a header");
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().expect("a length");
                    } else if name.eq_ignore_ascii_case("authorization") {
                        authorization = Some(value.trim().to_owned());
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).expect("a body");
                log.lock()
                    .expect("the log")
                    .push((path.clone(), authorization));
                let _ = stream.write_all(&respond(&path, &body));
            }
        });
        (url, seen)
    }

    fn http(status: u16, value: &Value) -> Vec<u8> {
        let body = value.to_string();
        format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn sidecar(root: &std::path::Path) -> impl Fn(&str, &[u8]) -> Vec<u8> + Send + 'static {
        let sidecar = ActionSidecar::new(root);
        move |path, body| {
            let (status, value) = sidecar.handle(path, body).expect("an action route");
            http(status, &value)
        }
    }

    fn action(input: &[u8]) -> PreparedAction {
        PreparedAction {
            arguments: vec![
                "sh".into(),
                "-c".into(),
                "tr a-z A-Z < in.txt > out.txt".into(),
            ],
            environment: vec![],
            working_directory: String::new(),
            inputs: [("in.txt".to_owned(), (input.to_vec(), false))]
                .into_iter()
                .collect(),
            output_paths: vec!["out.txt".into()],
            timeout: Some(Duration::from_secs(30)),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_runner_sends_only_what_the_sidecar_lacks_and_reads_back_the_outputs() {
        let root = tempfile::tempdir().expect("scratch");
        let (url, seen) = serve(sidecar(root.path()));
        let runner = SidecarRunner::new(&url, Some("secret".into())).unwrap();
        assert_eq!(runner.name(), SIDECAR_EXECUTOR);
        for _ in 0..2 {
            let outcome = runner
                .run(action(b"loud"))
                .await
                .expect("ran at the sidecar");
            assert!(
                matches!(&outcome.outputs["out.txt"], Output::File { bytes, .. } if bytes == b"LOUD")
            );
        }
        let seen = seen.lock().unwrap().clone();
        let paths: Vec<&str> = seen.iter().map(|(path, _)| path.as_str()).collect();
        // The second run found the input held and sent no blob.
        assert_eq!(
            paths,
            [
                "/action/missing",
                "/action/blobs",
                "/action",
                "/action/missing",
                "/action"
            ]
        );
        assert!(seen
            .iter()
            .all(|(_, auth)| auth.as_deref() == Some("Bearer secret")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_sidecar_that_loses_an_input_is_sent_it_once_more_and_then_refused() {
        let root = tempfile::tempdir().expect("scratch");
        let real = sidecar(root.path());
        let losses = Arc::new(Mutex::new(1));
        let remaining = losses.clone();
        let blob_dir = root.path().join("blobs");
        let (url, _) = serve(move |path, body| {
            if path == "/action" && *remaining.lock().unwrap() > 0 {
                *remaining.lock().unwrap() -= 1;
                let _ = std::fs::remove_dir_all(&blob_dir);
            }
            real(path, body)
        });
        let runner = SidecarRunner::new(&url, None).unwrap();
        runner
            .run(action(b"once"))
            .await
            .expect("recovered by one resend");
        *losses.lock().unwrap() = 2;
        assert_eq!(
            runner.run(action(b"twice")).await.unwrap_err(),
            format!(
                "the sidecar at {url} refused /action (409): inputs are missing from the sidecar"
            )
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_the_runner_cannot_use_it_refuses_by_name() {
        assert_eq!(
            SidecarRunner::new("https://pool.example:8080", None).err(),
            Some("the sidecar runner speaks plain HTTP to host:port; https://pool.example:8080 is not an http://host:port address".into())
        );
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        assert!(SidecarRunner::new(&closed, None)
            .unwrap()
            .run(action(b"x"))
            .await
            .unwrap_err()
            .starts_with(&format!(
                "the sidecar at {closed} did not answer /action/missing: "
            )));
        let (url, _) = serve(|_, _| b"garbage".to_vec());
        assert_eq!(
            SidecarRunner::new(&url, None)
                .unwrap()
                .run(action(b"x"))
                .await
                .unwrap_err(),
            format!("the sidecar at {url} answered /action/missing with no HTTP response")
        );
        let (url, _) = serve(|_, _| b"HTTP/1.1 200 OK\r\n\r\nnot json".to_vec());
        assert!(SidecarRunner::new(&url, None)
            .unwrap()
            .run(action(b"x"))
            .await
            .unwrap_err()
            .starts_with(&format!(
                "the sidecar at {url} answered /action/missing with no JSON: "
            )));
        let (url, _) = serve(|_, _| http(401, &json!({"error": "unauthorized"})));
        assert_eq!(
            SidecarRunner::new(&url, None)
                .unwrap()
                .run(action(b"x"))
                .await
                .unwrap_err(),
            format!("the sidecar at {url} refused /action/missing (401): unauthorized")
        );
        let stranger = Digest::of(b"not an input").to_string();
        let (url, _) = serve(move |path, _| {
            if path == "/action/missing" {
                http(
                    200,
                    &json!({"protocol": ACTION_PROTOCOL, "missing": [stranger.clone()]}),
                )
            } else {
                http(500, &json!({}))
            }
        });
        assert_eq!(
            SidecarRunner::new(&url, None)
                .unwrap()
                .run(action(b"x"))
                .await
                .unwrap_err(),
            format!(
                "the sidecar at {url} asked for {}, which this action does not name",
                Digest::of(b"not an input")
            )
        );
        let root = tempfile::tempdir().expect("scratch");
        let (url, _) = serve(sidecar(root.path()));
        let (blobs, _) = serve(|path, _| {
            if path == "/action/missing" {
                http(
                    200,
                    &json!({"protocol": ACTION_PROTOCOL, "missing": [Digest::of(b"x").to_string()]}),
                )
            } else {
                http(507, &json!({"error": "full"}))
            }
        });
        assert_eq!(
            SidecarRunner::new(&blobs, None)
                .unwrap()
                .run(action(b"x"))
                .await
                .unwrap_err(),
            format!("the sidecar at {blobs} refused /action/blobs (507): full")
        );
        let huge = vec![b'a'; BLOB_BATCH_BYTES + 1];
        assert_eq!(
            SidecarRunner::new(&url, None)
                .unwrap()
                .run(action(&huge))
                .await
                .unwrap_err(),
            format!(
                "input in.txt ({} bytes) is larger than the sidecar accepts in one request",
                BLOB_BATCH_BYTES + 1
            )
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_endpoint_records_what_the_sidecar_ran_as_the_sidecars() {
        use crate::endpoint::Endpoint;
        use crate::proto::re;
        use crate::store::{Labels, Principal};
        use prost::Message;
        let root = tempfile::tempdir().expect("scratch");
        let (url, seen) = serve(sidecar(root.path()));
        let endpoint = Endpoint::new(Arc::new(SidecarRunner::new(&url, None).unwrap()));
        let (_, view) = endpoint
            .admit(Principal {
                name: "owner".into(),
                labels: Labels::new(),
            })
            .expect("admitted");
        let put = |bytes: Vec<u8>| endpoint.store.put(&view, &bytes, &Labels::new()).unwrap();
        let file = put(b"remote".to_vec());
        let command = put(re::Command {
            arguments: vec![
                "sh".into(),
                "-c".into(),
                "tr a-z A-Z < in.txt > out.txt".into(),
            ],
            output_paths: vec!["out.txt".into()],
            ..Default::default()
        }
        .encode_to_vec());
        let root_directory = put(re::Directory {
            files: vec![re::FileNode {
                name: "in.txt".into(),
                digest: Some(file.to_proto()),
                is_executable: false,
                node_properties: None,
            }],
            ..Default::default()
        }
        .encode_to_vec());
        let action = put(re::Action {
            command_digest: Some(command.to_proto()),
            input_root_digest: Some(root_directory.to_proto()),
            ..Default::default()
        }
        .encode_to_vec());
        let executed = endpoint.execute(&view, &action, false).await.expect("ran");
        assert_eq!(
            executed.result.execution_metadata.as_ref().unwrap().worker,
            SIDECAR_EXECUTOR
        );
        let output =
            Digest::from_proto(executed.result.output_files[0].digest.as_ref().unwrap()).unwrap();
        assert_eq!(
            endpoint.store.get(&view, &output).as_deref(),
            Some(&b"REMOTE"[..])
        );
        assert_eq!(
            endpoint.evidence(&action).map(|entry| entry.origin),
            Some(crate::cache::Origin::Executed {
                executor: SIDECAR_EXECUTOR.into()
            })
        );
        assert!(seen
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == "/action"));
        assert!(
            endpoint
                .execute(&view, &action, false)
                .await
                .expect("served")
                .cached
        );
    }
}
