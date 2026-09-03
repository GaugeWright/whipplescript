//! Exec-over-HTTP pure halves (compute plane P8): everything about a
//! `whip-executor/1` exec round that is not the process spawn itself, shared
//! by every host. The native CLI uses the content-key builder (its exec runs
//! in-process); the DO host uses all of it — build the sidecar request, raise
//! `NeedsHttp`, parse the response, and settle. Wasm-clean: serde_json +
//! sha2 only.
//!
//! The content key MUST be byte-identical across hosts — the delta-kernel
//! result cache is workspace-wide, and a native-recorded result should serve
//! a DO request for the same content key once the stores converge.

use std::fmt::Write;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use whipplescript_store::{
    ComputeResultRegistration, EffectCompletion, RuntimeStore, StoreResult, StoredEvent,
};

use crate::effect_handlers::{effect_failure_base, validate_ingest_value};
use crate::sansio::{HttpRequest, HttpResponse};
use crate::{idempotency_key, RuntimeKernel};

/// Wire protocol marker for the executor sidecar.
pub const EXECUTOR_PROTOCOL: &str = "whip-executor/1";

/// The argv element that stands for "the staged script path" in store-backed
/// script capabilities (hosts with no filesystem cannot probe argv for a
/// readable file the way the native manifest loader does).
pub const SCRIPT_ARGV_PLACEHOLDER: &str = "{script}";

/// sha256 as lowercase hex — the script-pin digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Delta-kernel content key for a hermetic exec (compute plane P8-1):
/// sha256 over script hash + argv + resolved env + host environment epoch +
/// effect input (stdin + parse contract). `resolved_env` must be sorted by
/// name (BTreeMap iteration order natively; sort before calling otherwise).
pub fn exec_content_key(
    script_sha256: &str,
    argv: &[String],
    resolved_env: &[(String, String)],
    environment_epoch: &str,
    stdin_json: &str,
    parse_contract: &Option<Value>,
) -> String {
    let mut material = String::new();
    material.push_str("exec.command\x00");
    material.push_str(script_sha256);
    material.push('\x00');
    for arg in argv {
        material.push_str(arg);
        material.push('\x1f');
    }
    material.push('\x00');
    for (name, value) in resolved_env {
        material.push_str(name);
        material.push('=');
        material.push_str(value);
        material.push('\x1f');
    }
    material.push('\x00');
    material.push_str(environment_epoch);
    material.push('\x00');
    material.push_str(stdin_json);
    material.push('\x00');
    if let Some(contract) = parse_contract {
        material.push_str(&contract.to_string());
    }
    sha256_hex(material.as_bytes())
}

/// Build the `POST /exec` request for one script run. `argv` must contain
/// the [`SCRIPT_ARGV_PLACEHOLDER`] element naming where the staged script
/// path goes; the executor substitutes it after verifying the pin.
#[allow(clippy::too_many_arguments)]
pub fn build_executor_exec_request(
    executor_base_url: &str,
    effect_id: &str,
    script_sha256: &str,
    script_body: &str,
    argv: &[String],
    resolved_env: &[(String, String)],
    stdin: &Value,
    timeout_ms: Option<u64>,
) -> Result<HttpRequest, String> {
    let script_index = argv
        .iter()
        .position(|arg| arg == SCRIPT_ARGV_PLACEHOLDER)
        .ok_or_else(|| {
            format!("script argv must contain the `{SCRIPT_ARGV_PLACEHOLDER}` placeholder")
        })?;
    let env: serde_json::Map<String, Value> = resolved_env
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    let mut body = json!({
        "protocol": EXECUTOR_PROTOCOL,
        "effect_id": effect_id,
        "script_sha256": script_sha256,
        "script_b64": base64_encode(script_body.as_bytes()),
        "script_ext": "sh",
        "argv": argv,
        "script_index": script_index,
        "env": Value::Object(env),
        "stdin": stdin,
    });
    if let Some(timeout_ms) = timeout_ms {
        body["timeout_ms"] = json!(timeout_ms);
    }
    Ok(HttpRequest {
        url: format!("{}/exec", executor_base_url.trim_end_matches('/')),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body,
    })
}

/// A decoded executor exec response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorExecResult {
    pub exit_code: i64,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Decode + validate the sidecar's `POST /exec` response.
pub fn parse_executor_exec_response(response: &HttpResponse) -> Result<ExecutorExecResult, String> {
    if response.status != 200 {
        let detail = response
            .body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        return Err(format!(
            "executor returned status {}: {detail}",
            response.status
        ));
    }
    let protocol = response
        .body
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol != EXECUTOR_PROTOCOL {
        return Err(format!(
            "executor answered protocol `{protocol}`; expected `{EXECUTOR_PROTOCOL}`"
        ));
    }
    let exit_code = response
        .body
        .get("exit_code")
        .and_then(Value::as_i64)
        .ok_or("executor response is missing exit_code")?;
    Ok(ExecutorExecResult {
        exit_code,
        timed_out: response
            .body
            .get("timed_out")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stdout: response
            .body
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stderr: response
            .body
            .get("stderr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A typed-ingest outcome for `exec ... -> Schema` / `-> each Schema`.
#[derive(Debug)]
pub enum ExecIngest {
    Single(Value),
    Stream(Vec<Value>),
}

/// Parses and validates exec stdout against the effect's embedded parse
/// contract (`{schema, shape, each}`). Pure JSON work — shared by the native
/// in-process exec and the DO's exec-over-HTTP settle.
pub fn ingest_exec_stdout(contract: &Value, stdout: &str) -> Result<ExecIngest, String> {
    let schema = contract
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("json");
    let shape = contract.get("shape").cloned().unwrap_or(Value::Null);
    let each = contract
        .get("each")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = stdout.trim();
    if !each {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| format!("stdout is not valid JSON for `{schema}`: {error}"))?;
        if !value.is_object() {
            return Err(format!(
                "stdout must be a single JSON object conforming to `{schema}`"
            ));
        }
        let mut errors = Vec::new();
        validate_ingest_value(&value, &shape, "$", &mut errors);
        if !errors.is_empty() {
            return Err(format!(
                "stdout does not conform to `{schema}`: {}",
                errors.join("; ")
            ));
        }
        return Ok(ExecIngest::Single(value));
    }
    let mut elements = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(element) => {
                validate_ingest_value(&element, &shape, &format!("[{index}]"), &mut errors);
                elements.push(element);
            }
            Err(error) => {
                errors.push(format!("line {index} is not valid JSON: {error}"));
            }
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "stream does not conform to `{schema}`: {}",
            errors.join("; ")
        ));
    }
    Ok(ExecIngest::Stream(elements))
}

/// Identity of one exec-over-HTTP settle: which effect/run this outcome
/// belongs to, plus the cache posture (`(content_key, served_from_cache)`
/// when the capability is hermetic).
pub struct ExecSettleContext<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub capability: &'a str,
    pub script_sha256: &'a str,
    pub cache: Option<(&'a str, bool)>,
    /// The parse contract's schema name — the fact name streamed elements
    /// ingest under (`-> each Schema`); `"json"` when untyped.
    pub ingest_schema: &'a str,
}

/// The shaped outcome of an exec round, mirroring the native `ExecOutcome`:
/// `Ok((exit_code, stdout, stderr, ingested))` on success, `Err((detail,
/// reason))` where detail carries the streams when the process ran.
pub type ExecSettleOutcome =
    Result<(i64, String, String, Option<ExecIngest>), (Option<(i64, String, String)>, String)>;

/// Settle one exec-over-HTTP outcome through the effect ledger — the store
/// half of the native `run_exec_effect`, generic over the runtime store so
/// the DO host settles with the same terminal, metadata, and fact shapes the
/// native host writes. Also populates the delta-kernel result cache on a
/// fresh hermetic success (first-writer-wins).
pub fn settle_exec_http_result<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    ctx: &ExecSettleContext<'_>,
    outcome: ExecSettleOutcome,
) -> StoreResult<StoredEvent> {
    match outcome {
        Ok((exit_code, stdout, stderr, ingested)) => {
            let mut value = json!({
                "mode": "capability",
                "command": "",
                "capability": ctx.capability,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "sha256": ctx.script_sha256,
            });
            if let Some((content_key, hit)) = ctx.cache {
                if !hit {
                    kernel
                        .store()
                        .record_compute_result(ComputeResultRegistration {
                            content_key,
                            effect_kind: "exec.command",
                            result_json: &encode_cached_exec_result(
                                exit_code,
                                value["stdout"].as_str().unwrap_or_default(),
                                value["stderr"].as_str().unwrap_or_default(),
                                &ingested,
                            ),
                            source_instance_id: ctx.instance_id,
                            source_effect_id: ctx.effect_id,
                        })?;
                }
                value["cache"] = json!({"content_key": content_key, "hit": hit});
            }
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id: ctx.instance_id,
                effect_id: ctx.effect_id,
                run_id: ctx.run_id,
                provider: "exec",
                worker_id: "whip-exec",
                status: "completed",
                exit_code: Some(exit_code),
                summary: Some("exec completed"),
                metadata_json: &value.to_string(),
                idempotency_key: Some(&idempotency_key(&[
                    ctx.instance_id,
                    ctx.effect_id,
                    "terminal",
                ])),
            })?;
            let mut fact = json!({
                "effect_id": ctx.effect_id,
                "run_id": ctx.run_id,
                "status": "completed",
                "mode": "capability",
                "capability": ctx.capability,
                "exit_code": exit_code,
                "stdout": value.get("stdout").cloned().unwrap_or(Value::Null),
            });
            match ingested {
                Some(ExecIngest::Single(parsed)) => {
                    fact["value"] = parsed;
                }
                Some(ExecIngest::Stream(elements)) => {
                    for (index, element) in elements.iter().enumerate() {
                        kernel.ingest_fact(
                            ctx.instance_id,
                            ctx.ingest_schema,
                            &format!("{}:{index}", ctx.effect_id),
                            &element.to_string(),
                            Some(&terminal.event_id),
                            Some(&idempotency_key(&[
                                ctx.instance_id,
                                ctx.effect_id,
                                "ingest",
                                &index.to_string(),
                            ])),
                        )?;
                    }
                    fact["ingested_count"] = json!(elements.len());
                }
                None => {}
            }
            kernel.derive_fact(
                ctx.instance_id,
                "exec.command.completed",
                ctx.effect_id,
                &fact.to_string(),
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    ctx.instance_id,
                    ctx.effect_id,
                    "exec-fact",
                ])),
            )?;
            Ok(terminal)
        }
        Err((detail, reason)) => {
            // Both arms name the same failure: the exec boundary was crossed and
            // the far side did not succeed. The detail arm carries the process's
            // own output as well, which is evidence, not a different kind.
            let failure = json!({"error_kind": "exec_failed", "message": reason});
            let metadata = match &detail {
                Some((exit_code, stdout, stderr)) => json!({
                    "failure": failure,
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                }),
                None => json!({"failure": failure}),
            };
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id: ctx.instance_id,
                effect_id: ctx.effect_id,
                run_id: ctx.run_id,
                provider: "exec",
                worker_id: "whip-exec",
                status: "failed",
                exit_code: detail.as_ref().map(|(code, _, _)| *code),
                summary: Some(&reason),
                metadata_json: &metadata.to_string(),
                idempotency_key: Some(&idempotency_key(&[
                    ctx.instance_id,
                    ctx.effect_id,
                    "terminal",
                ])),
            })?;
            // P3 per-kind extras: the command's exit code (when the process
            // actually ran) rides the bound failure value.
            let mut failure_value =
                effect_failure_base("exec", &reason, &reason, ctx.effect_id, ctx.run_id);
            if let (Some((exit_code, _, _)), Some(object)) =
                (&detail, failure_value.as_object_mut())
            {
                object.insert("exit_code".to_owned(), Value::from(*exit_code));
            }
            let fact = json!({
                "effect_id": ctx.effect_id,
                "run_id": ctx.run_id,
                "status": "failed",
                "mode": "capability",
                "capability": ctx.capability,
                "value": failure_value,
                "error": {"message": reason},
            })
            .to_string();
            kernel.derive_fact(
                ctx.instance_id,
                "exec.command.failed",
                ctx.effect_id,
                &fact,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    ctx.instance_id,
                    ctx.effect_id,
                    "exec-fact",
                ])),
            )?;
            Ok(terminal)
        }
    }
}

/// Encode a successful exec outcome for the delta-kernel result cache.
pub fn encode_cached_exec_result(
    exit_code: i64,
    stdout: &str,
    stderr: &str,
    ingested: &Option<ExecIngest>,
) -> String {
    let ingested_value = match ingested {
        None => Value::Null,
        Some(ExecIngest::Single(value)) => json!({"single": value}),
        Some(ExecIngest::Stream(elements)) => json!({"stream": elements}),
    };
    json!({
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "ingested": ingested_value,
    })
    .to_string()
}

/// Decode a cached exec result back into the success-outcome shape. `None`
/// (treated as a miss) if the recorded JSON does not decode, so a malformed
/// entry degrades to a real run instead of an error.
pub fn decode_cached_exec_result(
    result_json: &str,
) -> Option<(i64, String, String, Option<ExecIngest>)> {
    let value = serde_json::from_str::<Value>(result_json).ok()?;
    let exit_code = value.get("exit_code")?.as_i64()?;
    let stdout = value.get("stdout")?.as_str()?.to_owned();
    let stderr = value.get("stderr")?.as_str()?.to_owned();
    let ingested = match value.get("ingested") {
        None | Some(Value::Null) => None,
        Some(ingested) => {
            if let Some(single) = ingested.get("single") {
                Some(ExecIngest::Single(single.clone()))
            } else {
                let stream = ingested.get("stream").and_then(Value::as_array)?;
                Some(ExecIngest::Stream(stream.clone()))
            }
        }
    };
    Some((exit_code, stdout, stderr, ingested))
}

/// Minimal standard-alphabet base64 encode (no dependency; the executor wire
/// carries script bytes inline).
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for position in 0..4 {
            if position <= chunk.len() {
                let index = ((accumulator >> (18 - 6 * position)) & 0x3f) as usize;
                output.push(ALPHABET[index] as char);
            } else {
                output.push('=');
            }
        }
    }
    output
}

/// Minimal standard-alphabet base64 decode (`=` padding tolerated).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(ch: u8) -> Option<u32> {
        match ch {
            b'A'..=b'Z' => Some(u32::from(ch - b'A')),
            b'a'..=b'z' => Some(u32::from(ch - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(ch - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let chunk = value(byte)?;
        accumulator = (accumulator << 6) | chunk;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_the_known_vector() {
        // This digest feeds persisted script pins, exec content keys, and
        // package identity, so the rendering is pinned against a fixed vector
        // rather than against whatever the helper currently emits.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn content_key_is_stable_and_component_sensitive() {
        let argv = vec!["sh".to_owned(), "{script}".to_owned()];
        let env = vec![("MODEL".to_owned(), "m1".to_owned())];
        let key = exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":1}"#, &None);
        assert_eq!(
            key,
            exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":1}"#, &None)
        );
        for other in [
            exec_content_key("a2", &argv, &env, "native-v0", r#"{"n":1}"#, &None),
            exec_content_key("a1", &argv, &env, "epoch-2", r#"{"n":1}"#, &None),
            exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":2}"#, &None),
            exec_content_key(
                "a1",
                &argv,
                &env,
                "native-v0",
                r#"{"n":1}"#,
                &Some(json!({"schema": "S"})),
            ),
        ] {
            assert_ne!(key, other);
        }
    }

    #[test]
    fn request_builder_places_script_and_env() {
        let request = build_executor_exec_request(
            "http://executor:8080/",
            "effect-1",
            "a".repeat(64).as_str(),
            "echo hi\n",
            &["sh".to_owned(), "{script}".to_owned()],
            &[("MODE".to_owned(), "strict".to_owned())],
            &json!({"n": 1}),
            Some(15_000),
        )
        .expect("builds");
        assert_eq!(request.url, "http://executor:8080/exec");
        assert_eq!(request.body["script_index"], json!(1));
        assert_eq!(request.body["env"]["MODE"], json!("strict"));
        assert_eq!(request.body["timeout_ms"], json!(15_000));
        assert_eq!(
            base64_decode(request.body["script_b64"].as_str().expect("b64")).expect("decodes"),
            b"echo hi\n"
        );

        let error = build_executor_exec_request(
            "http://executor:8080",
            "effect-1",
            "aa",
            "echo hi\n",
            &["sh".to_owned(), "judge.sh".to_owned()],
            &[],
            &Value::Null,
            None,
        )
        .expect_err("missing placeholder rejected");
        assert!(error.contains("{script}"), "{error}");
    }

    #[test]
    fn response_parser_validates_protocol_and_shape() {
        let ok = parse_executor_exec_response(&HttpResponse {
            status: 200,
            body: json!({
                "protocol": EXECUTOR_PROTOCOL,
                "exit_code": 0,
                "timed_out": false,
                "stdout": "out",
                "stderr": "",
            }),
        })
        .expect("parses");
        assert_eq!(ok.exit_code, 0);
        assert_eq!(ok.stdout, "out");

        let error = parse_executor_exec_response(&HttpResponse {
            status: 500,
            body: json!({"error": "boom"}),
        })
        .expect_err("status surfaced");
        assert!(error.contains("500") && error.contains("boom"), "{error}");

        let error = parse_executor_exec_response(&HttpResponse {
            status: 200,
            body: json!({"protocol": "bogus/1", "exit_code": 0}),
        })
        .expect_err("protocol mismatch");
        assert!(error.contains("bogus/1"), "{error}");
    }

    #[test]
    fn ingest_single_and_stream() {
        let single =
            ingest_exec_stdout(&json!({"schema": "S"}), r#"{"ok": true}"#).expect("single ingests");
        assert!(matches!(single, ExecIngest::Single(_)));
        let stream = ingest_exec_stdout(
            &json!({"schema": "S", "each": true}),
            "{\"n\":1}\n{\"n\":2}\n",
        )
        .expect("stream ingests");
        match stream {
            ExecIngest::Stream(elements) => assert_eq!(elements.len(), 2),
            other => panic!("expected stream, got {other:?}"),
        }
        assert!(ingest_exec_stdout(&json!({"schema": "S"}), "not json").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for sample in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"\xff\x00!"[..],
        ] {
            assert_eq!(
                base64_decode(&base64_encode(sample)).expect("decodes"),
                sample
            );
        }
    }
}
