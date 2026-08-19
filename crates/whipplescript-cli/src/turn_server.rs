//! Class-B turn server (compute plane P8): the container side of the
//! `whip-turn/1` WebSocket protocol. A Class-B container runs the WHOLE
//! owned agent turn natively — harness loop, tools against a per-turn
//! scratch directory, provider HTTP — and streams progress frames up to the
//! workflow DO, which hibernates between frames and settles the final
//! outcome through `settle_provider_run_result`.
//!
//! Wire (text frames, JSON):
//! - client → server, first frame: the turn request
//!   `{protocol: "whip-turn/1", turn_id, provider: {provider|"fixture",
//!   base_url?, api_key?, model?, max_tokens?}, system, user, max_steps?,
//!   tools: "file"|"none"}` — or `{protocol, resume: turn_id}` to re-attach
//!   (DR-0035 B4 re-query: the container outlives any one DO invocation).
//! - server → client: `{"kind":"accepted","turn_id":..}`, then zero or more
//!   `{"kind":"progress","messages":N}`, then exactly one
//!   `{"kind":"final","outcome":{status,summary,steps,usage}}`, then close.
//!
//! The WebSocket layer is a minimal hand-rolled RFC 6455 server (handshake +
//! text/ping/close frames) in keeping with the repo's threads-not-async,
//! no-heavy-deps style.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};
use sha1::{Digest, Sha1};

use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::coerce_native::CoerceTransport;
use whipplescript_kernel::harness_loop::{
    run_brokered_loop, BrokeredTurnInput, BrokeredTurnOutcome, ChatMessage, HarnessModelClient,
    HarnessModelError, HttpModelClient, ModelReply, ToolSpec, TurnStatus,
};
use whipplescript_kernel::harness_model::{MessagesApiClient, RealHarnessModelClient};

use crate::coerce_runtime::UreqCoerceTransport;
use crate::harness_tools::{file_tool_specs_for_profile, FileToolExecutor, FixtureModelClient};
use whipplescript::host_runtime::AuthoredAgentPackage;

/// Wire protocol marker for the Class-B turn channel.
pub const TURN_PROTOCOL: &str = "whip-turn/1";

/// One tracked turn: progress subscribers and, once finished, the final
/// frame — retained so a re-attaching client (B4 re-query) gets the result
/// even after the original channel is gone.
struct TurnState {
    subscribers: Vec<Sender<String>>,
    final_frame: Option<String>,
}

/// The in-process turn registry. Keyed by turn id; survives across WS
/// connections for the container's lifetime.
fn registry() -> &'static Mutex<HashMap<String, TurnState>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, TurnState>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Publish a frame to a turn's subscribers (dropping closed ones); a final
/// frame is retained for later re-queries.
fn publish(turn_id: &str, frame: &str, is_final: bool) {
    let mut registry = registry().lock().expect("turn registry lock");
    if let Some(state) = registry.get_mut(turn_id) {
        state
            .subscribers
            .retain(|subscriber| subscriber.send(frame.to_owned()).is_ok());
        if is_final {
            state.final_frame = Some(frame.to_owned());
            state.subscribers.clear();
        }
    }
}

/// Subscribe to a turn. Returns `(receiver, already_final_frame)`; a turn
/// that already finished yields its retained final frame immediately.
fn subscribe(turn_id: &str) -> Option<(Receiver<String>, Option<String>)> {
    let mut registry = registry().lock().expect("turn registry lock");
    let state = registry.get_mut(turn_id)?;
    if let Some(final_frame) = &state.final_frame {
        return Some((std::sync::mpsc::channel().1, Some(final_frame.clone())));
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    state.subscribers.push(sender);
    Some((receiver, None))
}

/// Handle one upgraded `GET /turn` connection: complete the RFC 6455
/// handshake, read the request frame, and either start a turn or re-attach.
pub fn handle_turn_websocket(mut stream: TcpStream, websocket_key: &str) -> std::io::Result<()> {
    let accept = websocket_accept(websocket_key);
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
    )?;
    stream.flush()?;

    let request = match read_text_frame(&mut stream)? {
        Some(text) => text,
        None => return Ok(()),
    };
    let request: Value = match serde_json::from_str(&request) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_text_frame(
                &mut stream,
                &json!({"kind": "error", "message": format!("invalid request: {error}")})
                    .to_string(),
            );
            return write_close_frame(&mut stream);
        }
    };
    if request.get("protocol").and_then(Value::as_str) != Some(TURN_PROTOCOL) {
        let _ = write_text_frame(
            &mut stream,
            &json!({"kind": "error", "message": format!("expected protocol `{TURN_PROTOCOL}`")})
                .to_string(),
        );
        return write_close_frame(&mut stream);
    }

    // Re-attach (B4 re-query): stream the retained final frame or live tail.
    if let Some(resume_id) = request.get("resume").and_then(Value::as_str) {
        match subscribe(resume_id) {
            Some((receiver, final_frame)) => {
                write_text_frame(
                    &mut stream,
                    &json!({"kind": "accepted", "turn_id": resume_id, "resumed": true}).to_string(),
                )?;
                if let Some(frame) = final_frame {
                    write_text_frame(&mut stream, &frame)?;
                    return write_close_frame(&mut stream);
                }
                return pump_frames(stream, receiver);
            }
            None => {
                let _ = write_text_frame(
                    &mut stream,
                    &json!({"kind": "error", "message": format!("unknown turn `{resume_id}`")})
                        .to_string(),
                );
                return write_close_frame(&mut stream);
            }
        }
    }

    let turn_id = request
        .get("turn_id")
        .and_then(Value::as_str)
        .unwrap_or("turn")
        .to_owned();
    let (receiver, final_frame, resumed) = start_or_attach(&turn_id, &request);
    write_text_frame(
        &mut stream,
        &json!({"kind": "accepted", "turn_id": turn_id, "resumed": resumed}).to_string(),
    )?;
    if let Some(frame) = final_frame {
        write_text_frame(&mut stream, &frame)?;
        return write_close_frame(&mut stream);
    }
    pump_frames(stream, receiver)
}

/// Start the turn (spawning its thread) or attach to an existing one — a
/// duplicate start is an implicit re-attach, which is what makes turn
/// dispatch idempotent under at-least-once delivery (DR-0033 Decision 3):
/// a workflow DO evicted mid-await simply re-sends the start and lands back
/// on the same turn.
fn start_or_attach(turn_id: &str, request: &Value) -> (Receiver<String>, Option<String>, bool) {
    {
        let mut registry = registry().lock().expect("turn registry lock");
        if registry.contains_key(turn_id) {
            drop(registry);
            let (receiver, final_frame) =
                subscribe(turn_id).expect("turn present after contains_key");
            return (receiver, final_frame, true);
        }
        registry.insert(
            turn_id.to_owned(),
            TurnState {
                subscribers: Vec::new(),
                final_frame: None,
            },
        );
    }
    let (receiver, _) = subscribe(turn_id).expect("turn just registered");
    let run_request = request.clone();
    let run_turn_id = turn_id.to_owned();
    std::thread::spawn(move || {
        let outcome = run_turn(&run_turn_id, &run_request);
        let frame = json!({
            "kind": "final",
            "turn_id": run_turn_id,
            "outcome": {
                "status": status_name(&outcome.status),
                "summary": outcome.summary,
                "steps": outcome.steps,
                "usage": outcome.usage,
            },
        })
        .to_string();
        publish(&run_turn_id, &frame, true);
    });
    (receiver, None, false)
}

/// The blocking HTTP form of the turn channel (`POST /turn`): start or
/// attach, wait for the final frame, answer with the outcome. This is the
/// v1 transport the workflow DO's per-turn controller uses — the WebSocket
/// form above carries progress streaming and explicit re-query; hibernating
/// progress consumption by the workflow DO is a recorded follow-on.
pub fn handle_turn_http(request: &Value) -> Result<Value, (u16, String)> {
    if request.get("protocol").and_then(Value::as_str) != Some(TURN_PROTOCOL) {
        return Err((400, format!("expected protocol `{TURN_PROTOCOL}`")));
    }
    let turn_id = request
        .get("turn_id")
        .and_then(Value::as_str)
        .ok_or((400, "turn_id is required".to_owned()))?
        .to_owned();
    let (receiver, final_frame, resumed) = start_or_attach(&turn_id, request);
    let final_frame = match final_frame {
        Some(frame) => frame,
        None => loop {
            match receiver.recv() {
                Ok(frame) if frame.contains("\"kind\":\"final\"") => break frame,
                Ok(_) => continue,
                Err(_) => return Err((500, "turn ended without a final frame".to_owned())),
            }
        },
    };
    let frame: Value = serde_json::from_str(&final_frame)
        .map_err(|error| (500, format!("final frame did not decode: {error}")))?;
    Ok(json!({
        "protocol": TURN_PROTOCOL,
        "turn_id": turn_id,
        "resumed": resumed,
        "outcome": frame.get("outcome").cloned().unwrap_or(Value::Null),
    }))
}

/// Forward published frames to the socket until the final frame (or the
/// client goes away — the turn keeps running; re-attach picks it back up).
fn pump_frames(mut stream: TcpStream, receiver: Receiver<String>) -> std::io::Result<()> {
    for frame in receiver {
        let is_final = frame.contains("\"kind\":\"final\"");
        if write_text_frame(&mut stream, &frame).is_err() {
            // Client gone; the turn continues and the final frame is
            // retained in the registry for re-query.
            return Ok(());
        }
        if is_final {
            break;
        }
    }
    write_close_frame(&mut stream)
}

/// Execute the turn synchronously on this thread (the container's whole
/// reason to exist), publishing progress after each checkpoint.
/// Map a client-supplied `turn_id` (arrives over the wire) to a SAFE,
/// single-segment scratch directory name. Using the raw id verbatim as a
/// path lets a value like `../../etc/cron.d/x` escape `temp_dir` and give a
/// turn arbitrary read/write outside its sandbox. Keep only characters that
/// cannot form a path separator or a `..` traversal; replace everything else
/// with `_`, and append a deterministic digest of the raw id so distinct
/// turns never collide onto one scratch after sanitization.
fn scratch_dir_name(turn_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let safe: String = turn_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // `DefaultHasher::new()` uses fixed keys, so this is stable across runs.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    turn_id.hash(&mut hasher);
    format!("whip-turn-{safe}-{:016x}", hasher.finish())
}

fn run_turn(turn_id: &str, request: &Value) -> BrokeredTurnOutcome {
    let scratch = std::env::temp_dir().join(scratch_dir_name(turn_id));
    run_turn_in_workspace(turn_id, request, &scratch)
}

/// Run the Class-B whole-turn loop against an explicitly materialized
/// workspace. The caller owns confinement and lifecycle; this function owns
/// only the governed agent loop and file tools rooted at `workspace`.
pub fn run_turn_in_workspace(
    turn_id: &str,
    request: &Value,
    workspace: &Path,
) -> BrokeredTurnOutcome {
    let mut system = request
        .get("system")
        .and_then(Value::as_str)
        .unwrap_or("You are a coding agent working in a scratch directory.")
        .to_owned();
    let user = request
        .get("user")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut max_steps = request
        .get("max_steps")
        .and_then(Value::as_u64)
        .unwrap_or(30) as usize;
    let use_file_tools = request.get("tools").and_then(Value::as_str) != Some("none");

    if let Err(error) = std::fs::create_dir_all(workspace) {
        return BrokeredTurnOutcome {
            status: TurnStatus::Failed,
            summary: format!("could not open workspace: {error}"),
            steps: 0,
            observations: Vec::new(),
            usage: json!({"input_tokens": 0, "output_tokens": 0}),
        };
    }
    let protected_write_paths = request
        .get("protected_write_paths")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let executor = FileToolExecutor::new(workspace)
        .with_protected_write_paths(protected_write_paths)
        .with_native_processes(
            request
                .get("native_processes")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
    let mut tools = if use_file_tools {
        file_tool_specs_for_profile(None)
    } else {
        Vec::new()
    };
    if let Some(package) = request.get("package") {
        if let (Some(manifest), Some(source), Some(persona), Some(version_ref)) = (
            package.get("manifest").and_then(Value::as_str),
            package.get("source").and_then(Value::as_str),
            package.get("system_prompt").and_then(Value::as_str),
            package.get("version_ref").and_then(Value::as_str),
        ) {
            let authored = match AuthoredAgentPackage::from_documents(manifest, source, persona) {
                Ok(authored) => authored,
                Err(error) => return failed_outcome(&error),
            };
            let resolved = match authored.resolve(version_ref) {
                Ok(resolved) => resolved,
                Err(error) => return failed_outcome(&error),
            };
            system = resolved.system_prompt;
            max_steps = resolved.max_steps;
            tools = resolved.tools;
        } else {
            let root = package
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let version_ref = package
                .get("version_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let safe_root = Path::new(root);
            if root.is_empty()
                || safe_root.is_absolute()
                || safe_root
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return failed_outcome("turn package root is not workspace-relative");
            }
            let authored = match AuthoredAgentPackage::load(workspace.join(safe_root)) {
                Ok(authored) => authored,
                Err(error) => return failed_outcome(&error),
            };
            let resolved = match authored.resolve(version_ref) {
                Ok(resolved) => resolved,
                Err(error) => return failed_outcome(&error),
            };
            system = resolved.system_prompt;
            max_steps = resolved.max_steps;
            tools = resolved.tools;
        }
    }
    let input = BrokeredTurnInput {
        system,
        user,
        tools,
        max_steps,
        resume_from: Vec::new(),
        user_images: Vec::new(),
        context_bundles: Vec::new(),
        pinned_skills: Vec::new(),
    };
    let progress_turn_id = turn_id.to_owned();
    let mut checkpoint = move |messages: &[whipplescript_kernel::harness_loop::ChatMessage]| {
        publish(
            &progress_turn_id,
            &json!({"kind": "progress", "messages": messages.len()}).to_string(),
            false,
        );
    };

    let provider = request
        .get("provider")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let provider_name = provider
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("fixture");
    if provider_name == "fixture" {
        let client = FixtureModelClient::from_env();
        return run_brokered_loop(&client, &executor, &input, &mut checkpoint);
    }
    let coerce_provider = match provider_name {
        "anthropic" => CoerceProvider::Anthropic,
        "openai" | "openai-codex" => CoerceProvider::OpenAi,
        "openai-generic" => CoerceProvider::OpenAiCompat,
        "xai" => CoerceProvider::Xai,
        other => {
            return BrokeredTurnOutcome {
                status: TurnStatus::Failed,
                summary: format!("unknown provider `{other}`"),
                steps: 0,
                observations: Vec::new(),
                usage: json!({"input_tokens": 0, "output_tokens": 0}),
            }
        }
    };
    let field = |name: &str| {
        provider
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let max_tokens = provider
        .get("max_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(4096) as u32;
    let transport = UreqCoerceTransport::new(std::time::Duration::from_secs(120))
        .with_workspace_egress_token(
            request
                .get("workspace_egress_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
    if provider_name == "openai-codex" {
        let client = MessagesApiClient::new_codex(
            field("api_key"),
            "gaugewright-final-fetch",
            turn_id,
            field("model"),
            field("base_url"),
            u64::from(max_tokens),
            Some(turn_id.to_owned()),
        );
        let client = TransportedModelClient {
            client,
            transport: &transport,
        };
        return run_brokered_loop(&client, &executor, &input, &mut checkpoint);
    }
    let client = RealHarnessModelClient::new(
        &transport,
        coerce_provider,
        field("api_key"),
        field("model"),
        field("base_url"),
        u64::from(max_tokens),
        Some(turn_id.to_owned()),
    );
    run_brokered_loop(&client, &executor, &input, &mut checkpoint)
}

fn failed_outcome(reason: &str) -> BrokeredTurnOutcome {
    BrokeredTurnOutcome {
        status: TurnStatus::Failed,
        summary: reason.to_owned(),
        steps: 0,
        observations: Vec::new(),
        usage: json!({"input_tokens": 0, "output_tokens": 0}),
    }
}

struct TransportedModelClient<'a, C, T> {
    client: C,
    transport: &'a T,
}

impl<C: HttpModelClient, T: CoerceTransport> HarnessModelClient
    for TransportedModelClient<'_, C, T>
{
    fn next(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ModelReply, HarnessModelError> {
        let request = self.client.build_request(messages, tools);
        self.client.parse_response(self.transport.post(&request))
    }
}

fn status_name(status: &TurnStatus) -> &'static str {
    match status {
        TurnStatus::Completed => "completed",
        TurnStatus::Failed => "failed",
        TurnStatus::TimedOut => "timed_out",
        TurnStatus::Cancelled => "cancelled",
    }
}

/// Stable, adapter-neutral terminal wire value for batch execution.
pub fn outcome_json(outcome: &BrokeredTurnOutcome) -> Value {
    json!({
        "status": status_name(&outcome.status),
        "summary": outcome.summary,
        "steps": outcome.steps,
        "observations": outcome.observations,
        "usage": outcome.usage,
    })
}

/// RFC 6455 `Sec-WebSocket-Accept` for a client key.
pub fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.trim().as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64_encode_bytes(&hasher.finalize())
}

fn base64_encode_bytes(bytes: &[u8]) -> String {
    whipplescript_kernel::exec_http::base64_encode(bytes)
}

/// Read frames until one text frame arrives (answering pings, ignoring
/// continuation/binary); `None` on close or EOF.
fn read_text_frame(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    loop {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).is_err() {
            return Ok(None);
        }
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut length = u64::from(header[1] & 0x7f);
        if length == 126 {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended)?;
            length = u64::from(u16::from_be_bytes(extended));
        } else if length == 127 {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended)?;
            length = u64::from_be_bytes(extended);
        }
        if length > 16 * 1024 * 1024 {
            return Ok(None);
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; length as usize];
        stream.read_exact(&mut payload)?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x1 => return Ok(Some(String::from_utf8_lossy(&payload).into_owned())),
            0x8 => return Ok(None),
            0x9 => {
                // ping → pong with the same payload.
                write_frame(stream, 0xA, &payload)?;
            }
            _ => {}
        }
    }
}

/// Write one server→client text frame (unmasked, per RFC 6455).
fn write_text_frame(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    write_frame(stream, 0x1, text.as_bytes())
}

fn write_close_frame(stream: &mut TcpStream) -> std::io::Result<()> {
    write_frame(stream, 0x8, &[])
}

fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = vec![0x80 | opcode];
    let length = payload.len();
    if length < 126 {
        frame.push(length as u8);
    } else if length <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    // A client-supplied turn_id cannot escape temp_dir: the scratch dir name
    // is a single safe segment (no `/`, `\`, or `..`), and distinct ids never
    // collide onto one scratch.
    #[test]
    fn scratch_dir_name_is_a_safe_single_segment() {
        for evil in [
            "../../etc/cron.d/x",
            "..\\..\\windows",
            "a/b/c",
            "/absolute/path",
            "..",
            "",
        ] {
            let name = scratch_dir_name(evil);
            assert!(name.starts_with("whip-turn-"), "prefix kept: {name}");
            assert!(!name.contains('/'), "no path separator: {name}");
            assert!(!name.contains('\\'), "no backslash: {name}");
            assert!(!name.contains(".."), "no traversal: {name}");
            // The joined path stays directly under temp_dir (single segment).
            let joined = std::env::temp_dir().join(&name);
            assert_eq!(
                joined.parent(),
                Some(std::env::temp_dir().as_path()),
                "scratch stays directly under temp_dir: {name}"
            );
        }
        // Distinct ids that sanitize to the same safe chars still differ.
        assert_ne!(scratch_dir_name("a/b"), scratch_dir_name("a_b"));
    }

    /// A minimal masked-frame WS client for the tests.
    fn client_send_text(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
        let payload = text.as_bytes();
        let mut frame = vec![0x80 | 0x1];
        let mask = [7u8, 21, 42, 99];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        stream.write_all(&frame)?;
        stream.flush()
    }

    fn client_read_text(stream: &mut TcpStream) -> Option<String> {
        loop {
            let mut header = [0u8; 2];
            stream.read_exact(&mut header).ok()?;
            let opcode = header[0] & 0x0f;
            let mut length = u64::from(header[1] & 0x7f);
            if length == 126 {
                let mut extended = [0u8; 2];
                stream.read_exact(&mut extended).ok()?;
                length = u64::from(u16::from_be_bytes(extended));
            }
            let mut payload = vec![0u8; length as usize];
            stream.read_exact(&mut payload).ok()?;
            match opcode {
                0x1 => return Some(String::from_utf8_lossy(&payload).into_owned()),
                0x8 => return None,
                _ => {}
            }
        }
    }

    fn open_turn_socket(address: std::net::SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(address).expect("connect");
        write!(
            stream,
            "GET /turn HTTP/1.1\r\nhost: test\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
        )
        .expect("handshake request");
        // Read until the end of the 101 response headers.
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("handshake response");
            response.push(byte[0]);
        }
        let response = String::from_utf8_lossy(&response).into_owned();
        assert!(response.contains("101"), "{response}");
        assert!(
            response.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "RFC 6455 sample key must produce the sample accept: {response}"
        );
        stream
    }

    #[test]
    fn websocket_accept_matches_rfc_sample() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn every_turn_status_has_an_explicit_wire_name() {
        assert_eq!(status_name(&TurnStatus::Completed), "completed");
        assert_eq!(status_name(&TurnStatus::Failed), "failed");
        assert_eq!(status_name(&TurnStatus::TimedOut), "timed_out");
        assert_eq!(status_name(&TurnStatus::Cancelled), "cancelled");
    }

    #[test]
    fn batch_turn_binds_inline_package_bytes_to_the_pinned_version() {
        let manifest = r#"{
          "schema":"whipplescript.agent_package.v0",
          "source":"method.whip",
          "workflow":"Agent",
          "agent":"assistant",
          "system_prompt":"persona.md",
          "capabilities":["workspace.read"],
          "agent_abilities":["workspace.read"],
          "max_steps":4
        }"#;
        let source = r#"
          file store project {
            root "."
            allow read ["**"]
          }
          workflow Agent {
            agent assistant {
              provider owned
              profile "repo-reader"
              capacity 1
              capabilities ["workspace.read"]
            }
            rule converse when started => {
              tell assistant requires ["workspace.read"]
                with access to project { read ["**"] }
                "work"
            }
          }
        "#;
        let authored =
            AuthoredAgentPackage::from_documents(manifest, source, "Read the workspace.")
                .expect("package");
        let workspace = std::env::temp_dir().join(format!(
            "whipple-batch-package-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&workspace).expect("workspace");
        let request = json!({
            "turn_id": "batch-package",
            "user": "inspect it",
            "package": {
                "manifest": manifest,
                "source": source,
                "system_prompt": "Read the workspace.",
                "version_ref": authored.version_ref(),
            },
            "provider": {"provider": "not-a-provider"},
        });
        let outcome = run_turn_in_workspace("batch-package", &request, &workspace);
        assert_eq!(outcome.status, TurnStatus::Failed);
        assert_eq!(outcome.summary, "unknown provider `not-a-provider`");

        let mut tampered = request;
        tampered["package"]["system_prompt"] = json!("Different bytes.");
        let outcome = run_turn_in_workspace("batch-package", &tampered, &workspace);
        assert_eq!(outcome.status, TurnStatus::Failed);
        assert!(outcome.summary.contains("pinned version"));
        std::fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn turn_over_websocket_runs_and_requeries() {
        // The fixture model client answers without a network; tools "none"
        // keeps the turn to a single reply.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let _ = crate::exec_server::serve_on(listener);
        });

        let mut stream = open_turn_socket(address);
        client_send_text(
            &mut stream,
            &json!({
                "protocol": TURN_PROTOCOL,
                "turn_id": "turn-ws-test",
                "provider": {"provider": "fixture"},
                "user": "do the thing",
                "tools": "none",
                "max_steps": 3,
            })
            .to_string(),
        )
        .expect("send request");

        let accepted: Value =
            serde_json::from_str(&client_read_text(&mut stream).expect("accepted frame"))
                .expect("accepted json");
        assert_eq!(accepted["kind"], json!("accepted"));
        assert_eq!(accepted["resumed"], json!(false));

        let final_frame = loop {
            let frame: Value = serde_json::from_str(&client_read_text(&mut stream).expect("frame"))
                .expect("frame json");
            if frame["kind"] == json!("final") {
                break frame;
            }
            assert_eq!(frame["kind"], json!("progress"), "{frame}");
        };
        assert_eq!(final_frame["outcome"]["status"], json!("completed"));

        // Re-query (B4): a fresh connection resuming the finished turn gets
        // the retained final frame immediately.
        let mut requery = open_turn_socket(address);
        client_send_text(
            &mut requery,
            &json!({"protocol": TURN_PROTOCOL, "resume": "turn-ws-test"}).to_string(),
        )
        .expect("send resume");
        let resumed: Value =
            serde_json::from_str(&client_read_text(&mut requery).expect("resume accepted"))
                .expect("resume json");
        assert_eq!(resumed["resumed"], json!(true));
        let replay: Value =
            serde_json::from_str(&client_read_text(&mut requery).expect("replayed final"))
                .expect("replay json");
        assert_eq!(replay["kind"], json!("final"));
        assert_eq!(replay["outcome"]["status"], json!("completed"));

        // Unknown turn → error frame.
        let mut unknown = open_turn_socket(address);
        client_send_text(
            &mut unknown,
            &json!({"protocol": TURN_PROTOCOL, "resume": "no-such-turn"}).to_string(),
        )
        .expect("send unknown resume");
        let error: Value =
            serde_json::from_str(&client_read_text(&mut unknown).expect("error frame"))
                .expect("error json");
        assert_eq!(error["kind"], json!("error"));
    }
}
