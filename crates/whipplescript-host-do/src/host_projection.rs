//! Runtime-owned projection for the Durable Object host surface.
//!
//! The Worker shell must not reverse-engineer WhippleScript's SQL into a second
//! receipt format. This module folds the admitted command and durable runtime
//! rows through the public `whipplescript.host.v1` pointer schema. It is generic
//! over `RuntimeStore`, so native SQLite-backed tests exercise the same code the
//! wasm boundary calls over DO SQLite.

use serde::Serialize;
use serde_json::{json, Value};
use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::harness_loop::{chat_messages_from_json, ChatMessage};
use whipplescript_kernel::host_protocol::{
    EventPosition, LabeledRuntimeEvent, RuntimeEvidencePointer, StartTurnCommand, TurnReceipt,
    TurnStatus, HOST_PROTOCOL,
};
use whipplescript_kernel::idempotency_key;
use whipplescript_store::{EventView, EvidenceRecord, NewEvent, RuntimeStore, StoreError};

#[derive(Clone, Debug, Serialize)]
pub struct HostedOutputFieldFlow {
    pub field: String,
    pub reads: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HostedTurnProjection {
    pub runtime_evidence_pointers: Vec<RuntimeEvidencePointer>,
    pub receipt: Option<TurnReceipt>,
    /// Typed, host-published token counts for product metering. The opaque
    /// `usage_ref` remains the authoritative runtime evidence pointer; this is
    /// only its deliberately narrow billing projection.
    pub usage_observation: Option<HostedUsageObservation>,
    /// Runtime-owned, label-carrying content projection for browser panels.
    /// The Worker publishes this typed result; it never folds transcript SQL.
    pub output_observation: Option<HostedOutputObservation>,
    pub output_flow_signature: Vec<HostedOutputFieldFlow>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HostedUsageObservation {
    pub usage_ref: String,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    /// The last MAIN reply's prompt size — the settled context-window reading
    /// the harness loop stamps at the terminal. A gauge, not a meter: the token
    /// counts above sum the turn's calls for billing; this reports how full the
    /// window was on the final call. 0 when the turn settled without one.
    pub last_input_tokens: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HostedOutputObservation {
    pub label_ref: String,
    pub assistant_text: String,
    pub tool_calls: Vec<HostedToolCallObservation>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HostedToolCallObservation {
    pub call_id: String,
    pub name: String,
    pub arguments: Value,
    pub result: Option<String>,
    pub ok: Option<bool>,
}

pub fn current_position<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
) -> Result<EventPosition, StoreError> {
    let sequence = store
        .list_events(instance_id)?
        .last()
        .map_or(0, |event| event.sequence);
    Ok(EventPosition {
        instance_ref: instance_id.to_owned(),
        sequence: u64::try_from(sequence).map_err(|_| {
            StoreError::Conflict("runtime event position cannot be negative".to_owned())
        })?,
    })
}

pub fn project_host_turn<S: RuntimeStore>(
    store: &mut S,
    instance_id: &str,
    command_id: &str,
) -> Result<HostedTurnProjection, String> {
    let effect = store
        .list_effects(instance_id)
        .map_err(store_error)?
        .into_iter()
        .find(|effect| effect.effect_id == command_id)
        .ok_or_else(|| "host turn was not found".to_owned())?;
    let command: StartTurnCommand =
        serde_json::from_str(&effect.input_json).map_err(|error| error.to_string())?;
    command.validate().map_err(|error| error.to_string())?;
    if command.instance_ref != instance_id || command.command_id != command_id {
        return Err("host turn command does not match its durable identity".to_owned());
    }

    let label_ref = format!("whip:label:{}", command.policy.envelope_hash);
    let mut events = store.list_events(instance_id).map_err(store_error)?;
    let first_turn_event = events
        .iter()
        .find(|event| event_mentions_command(&event.payload_json, command_id))
        .map_or_else(
            || events.last().map_or(0, |event| event.sequence),
            |event| event.sequence,
        );
    let mut pointers = events
        .iter()
        .filter(|event| {
            event.sequence >= first_turn_event
                && (event_mentions_command(&event.payload_json, command_id)
                    || event.event_type == "host.turn.receipt")
        })
        .map(|event| {
            Ok(RuntimeEvidencePointer::Event(LabeledRuntimeEvent {
                protocol: HOST_PROTOCOL.to_owned(),
                command_id: command_id.to_owned(),
                position: EventPosition {
                    instance_ref: instance_id.to_owned(),
                    sequence: positive_sequence(event.sequence)?,
                },
                policy: command.policy.clone(),
                kind: event.event_type.clone(),
                label_ref: label_ref.clone(),
                evidence_ref: format!("whip:event:{}", event.event_id),
                payload_ref: Some(format!("whip:event:{}:payload", event.event_id)),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let Some(run) = store
        .list_runs(instance_id)
        .map_err(store_error)?
        .into_iter()
        .rev()
        .find(|run| run.effect_id == command_id)
    else {
        return Ok(HostedTurnProjection {
            runtime_evidence_pointers: pointers,
            receipt: None,
            usage_observation: None,
            output_observation: None,
            output_flow_signature: output_flows(&command),
        });
    };
    let Some(status) = turn_status(&run.status) else {
        return Ok(HostedTurnProjection {
            runtime_evidence_pointers: pointers,
            receipt: None,
            usage_observation: None,
            output_observation: None,
            output_flow_signature: output_flows(&command),
        });
    };

    let usage_ref = ensure_evidence(
        store,
        &command,
        &run.run_id,
        "host.turn.usage",
        &run.metadata_json,
    )?;
    let usage_observation = project_usage(&run.metadata_json, &usage_ref)?;
    let output_observation = project_output(&events, &command.command_id, &label_ref)?;
    let guarantee = json!({
        "protocol": HOST_PROTOCOL,
        "policy": command.policy,
        "actor_ref": command.actor_ref,
        "package_version_ref": command.package_version_ref,
        "resources": command.resources,
        "images": command.input.images,
        "provider_binding_ref": command.provider_binding,
        "placement_ceiling_ref": command.placement_ceiling_ref,
        "guarantees": [
            "signed_policy_identity_verified",
            "package_ifc_checked_under_verified_envelope",
            "instance_package_policy_binding_verified",
            "resource_provider_placement_handles_governed",
            "tool_surface_pinned_to_package",
            "resource_and_secret_bodies_resolved_after_admission"
        ],
        "dynamic": [],
        "workspace_cut": "unwitnessed"
    })
    .to_string();
    let guarantee_report_ref = ensure_evidence(
        store,
        &command,
        &run.run_id,
        "host.turn.guarantee",
        &guarantee,
    )?;
    let output_handle =
        matches!(status, TurnStatus::Completed).then(|| format!("whip:run:{}:output", run.run_id));
    let marker_payload = json!({
        "command_id": command.command_id,
        "run_ref": command.run_ref,
        "status": status,
        "output_handle": output_handle,
        "usage_ref": usage_ref,
        "guarantee_report_ref": guarantee_report_ref,
        "workspace_cut_ref": Value::Null,
    })
    .to_string();
    let marker = events
        .iter()
        .find(|event| {
            event.event_type == "host.turn.receipt"
                && json_field_equals(&event.payload_json, "command_id", command_id)
        })
        .map(|event| (event.event_id.clone(), event.sequence))
        .map_or_else(
            || {
                store
                    .append_event(NewEvent {
                        instance_id,
                        event_type: "host.turn.receipt",
                        payload_json: &marker_payload,
                        source: "host-do",
                        causation_id: Some(&run.run_id),
                        correlation_id: Some(command_id),
                        idempotency_key: Some(&idempotency_key(&[
                            instance_id,
                            command_id,
                            "host-turn-receipt",
                        ])),
                    })
                    .map(|event| (event.event_id, event.sequence))
                    .map_err(store_error)
            },
            Ok,
        )?;
    let receipt = TurnReceipt {
        protocol: HOST_PROTOCOL.to_owned(),
        command_id: command_id.to_owned(),
        run_ref: command.run_ref.clone(),
        instance_ref: instance_id.to_owned(),
        policy: command.policy.clone(),
        terminal_position: EventPosition {
            instance_ref: instance_id.to_owned(),
            sequence: positive_sequence(marker.1)?,
        },
        status,
        output_handle,
        usage_ref,
        guarantee_report_ref,
        workspace_cut_ref: None,
    };
    receipt
        .validate_for(&command)
        .map_err(|error| error.to_string())?;
    if !events.iter().any(|event| event.event_id == marker.0) {
        events = store.list_events(instance_id).map_err(store_error)?;
        if let Some(event) = events.iter().find(|event| event.event_id == marker.0) {
            pointers.push(RuntimeEvidencePointer::Event(LabeledRuntimeEvent {
                protocol: HOST_PROTOCOL.to_owned(),
                command_id: command_id.to_owned(),
                position: receipt.terminal_position.clone(),
                policy: command.policy.clone(),
                kind: event.event_type.clone(),
                label_ref,
                evidence_ref: format!("whip:event:{}", event.event_id),
                payload_ref: Some(format!("whip:event:{}:payload", event.event_id)),
            }));
        }
    }
    pointers.push(RuntimeEvidencePointer::TurnReceipt(receipt.clone()));
    Ok(HostedTurnProjection {
        runtime_evidence_pointers: pointers,
        receipt: Some(receipt),
        usage_observation,
        output_observation,
        output_flow_signature: output_flows(&command),
    })
}

fn project_output(
    events: &[EventView],
    command_id: &str,
    label_ref: &str,
) -> Result<Option<HostedOutputObservation>, String> {
    let Some(checkpoint) = events.iter().rev().find(|event| {
        event.event_type == "agent.turn.brokered.transcript"
            && json_field_equals(&event.payload_json, "effect_id", command_id)
    }) else {
        return Ok(None);
    };
    let value: Value =
        serde_json::from_str(&checkpoint.payload_json).map_err(|error| error.to_string())?;
    let messages = chat_messages_from_json(value.get("messages").unwrap_or(&Value::Null));
    let turn_start = messages
        .iter()
        .rposition(|message| matches!(message, ChatMessage::User { .. }))
        .map_or(0, |index| index + 1);
    let mut assistant_text = String::new();
    let mut tool_calls: Vec<HostedToolCallObservation> = Vec::new();
    for message in &messages[turn_start..] {
        match message {
            ChatMessage::Assistant {
                text,
                tool_calls: calls,
            } => {
                // Text and tool calls are not alternatives. Providers routinely
                // narrate a step and call a tool in the same message, and
                // treating `calls` as a discriminator silently dropped that
                // narration: the observation reported no answer for a turn that
                // had produced one. Take whichever the message actually carries.
                if !text.is_empty() {
                    assistant_text.clone_from(text);
                }
                tool_calls.extend(calls.iter().map(|call| HostedToolCallObservation {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: call.arguments.clone(),
                    result: None,
                    ok: None,
                }));
            }
            ChatMessage::ToolResults(results) => {
                for result in results {
                    if let Some(projected) = tool_calls
                        .iter_mut()
                        .rev()
                        .find(|call| call.call_id == result.tool_call_id)
                    {
                        projected.result = Some(result.content.clone());
                        projected.ok = Some(!result.is_error);
                    }
                }
            }
            ChatMessage::System(_) | ChatMessage::User { .. } => {}
        }
    }
    Ok(Some(HostedOutputObservation {
        label_ref: label_ref.to_owned(),
        assistant_text,
        tool_calls,
    }))
}

/// The wire protocol a metered-gateway round speaks, read from its admitted
/// base URL.
///
/// The gateway fronts both an OpenAI-compatible shim (`/compat`) and each
/// provider's native surface (`/anthropic`). The admitted base URL is already
/// the egress grant the runtime proves every managed turn against, so it is the
/// honest place to read the wire from — a separately-set flag could disagree
/// with the URL actually being called, and the URL is what the request goes to.
///
/// The distinction is not cosmetic. The shim **drops `cache_control`**, so an
/// Anthropic model routed through `/compat` can never use the prompt cache the
/// deterministic assembler exists to exploit, and pays full price on every
/// re-sent prefix. Measured 2026-08-11 against `gaugewright-panels`: same
/// prefix, 9.25x cheaper on the native route's cached span.
///
/// Anything that is not the native surface stays `OpenAiCompat`, which is both
/// the historical behaviour and the safe default — an unrecognized surface gets
/// the wire that has always worked rather than one that would send a body the
/// endpoint cannot read.
pub fn metered_gateway_wire(base_url: Option<&str>) -> CoerceProvider {
    if base_url
        .unwrap_or("")
        .trim_end_matches('/')
        .ends_with("/anthropic")
    {
        CoerceProvider::Anthropic
    } else {
        CoerceProvider::OpenAiCompat
    }
}

fn project_usage(
    metadata_json: &str,
    usage_ref: &str,
) -> Result<Option<HostedUsageObservation>, String> {
    let metadata: Value = serde_json::from_str(metadata_json).map_err(|error| error.to_string())?;
    let Some(usage) = metadata.get("usage").filter(|usage| usage.is_object()) else {
        return Ok(None);
    };
    let tokens = |primary: &str, alias: &str| {
        usage
            .get(primary)
            .or_else(|| usage.get(alias))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let cached_in = |details: &str| {
        usage
            .get(details)
            .and_then(|details| details.get("cached_tokens"))
    };
    // Anthropic's native Messages API reports the cached span in its own fields
    // and leaves `input_tokens` as the *uncached remainder* — the inverse of
    // Chat Completions, where `prompt_tokens` is the total and `cached_tokens`
    // is a subset of it. Presence of the field is what identifies the wire; a
    // native round that cached nothing reports an explicit zero, and the
    // arithmetic below is an identity in that case.
    //
    // Reported raw, a cached native round would show `cached > input`, and the
    // edge rejects exactly that as inexact usage ("exact provider usage is
    // required"). So the wire that finally *can* cache would fail every turn it
    // cached on. Normalizing to the Chat Completions convention keeps one meter
    // honest across both surfaces.
    let cache_read = usage.get("cache_read_input_tokens").and_then(Value::as_u64);
    let raw_input = tokens("input_tokens", "prompt_tokens");
    let (input_tokens, cached_input_tokens) = match cache_read {
        Some(read) => {
            // Cache *writes* are billed at 1.25x rather than the card's flat
            // input rate, so folding them in under-states their cost slightly.
            // That is deliberate: they are genuinely fresh (uncached) input, and
            // the card is only the fallback basis — a settled turn bills the
            // gateway's measured cost, which prices the premium exactly.
            let created = usage
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            (raw_input.saturating_add(read).saturating_add(created), read)
        }
        // Chat Completions and the OpenAI Responses wire. The other two fields
        // have carried their alias since this was written; the cached one did
        // not, and the omission was not visible as a failure — it read as an
        // honest zero while every cached token priced as a fresh one.
        None => (
            raw_input,
            usage
                .get("cached_input_tokens")
                .or_else(|| cached_in("input_tokens_details"))
                .or_else(|| cached_in("prompt_tokens_details"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
        ),
    };
    Ok(Some(HostedUsageObservation {
        usage_ref: usage_ref.to_owned(),
        input_tokens,
        cached_input_tokens,
        output_tokens: tokens("output_tokens", "completion_tokens"),
        last_input_tokens: usage
            .get("last_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }))
}

fn output_flows(command: &StartTurnCommand) -> Vec<HostedOutputFieldFlow> {
    let reads = command
        .resources
        .iter()
        .chain(command.input.images.iter())
        .map(|resource| resource.handle.clone())
        .collect::<Vec<_>>();
    ["assistant_text", "tool_calls"]
        .into_iter()
        .map(|field| HostedOutputFieldFlow {
            field: field.to_owned(),
            reads: reads.clone(),
        })
        .collect()
}

fn ensure_evidence<S: RuntimeStore>(
    store: &S,
    command: &StartTurnCommand,
    run_id: &str,
    kind: &str,
    metadata_json: &str,
) -> Result<String, String> {
    if let Some(existing) = store
        .list_evidence_for_subject("run", run_id)
        .map_err(store_error)?
        .into_iter()
        .find(|item| {
            item.kind == kind && item.correlation_id.as_deref() == Some(&command.command_id)
        })
    {
        return Ok(format!("whip:evidence:{}", existing.evidence_id));
    }
    let evidence_id = store
        .record_evidence(EvidenceRecord {
            instance_id: &command.instance_ref,
            kind,
            subject_type: "run",
            subject_id: run_id,
            causation_id: Some(&command.command_id),
            correlation_id: Some(&command.command_id),
            summary: None,
            metadata_json,
        })
        .map_err(store_error)?;
    Ok(format!("whip:evidence:{evidence_id}"))
}

fn turn_status(status: &str) -> Option<TurnStatus> {
    match status {
        "completed" | "succeeded" => Some(TurnStatus::Completed),
        "failed" => Some(TurnStatus::Failed),
        "timed_out" => Some(TurnStatus::TimedOut),
        "cancelled" => Some(TurnStatus::Cancelled),
        _ => None,
    }
}

fn event_mentions_command(payload: &str, command_id: &str) -> bool {
    serde_json::from_str::<Value>(payload)
        .ok()
        .is_some_and(|value| value_mentions(&value, command_id))
}

fn value_mentions(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value == needle,
        Value::Array(values) => values.iter().any(|value| value_mentions(value, needle)),
        Value::Object(values) => values.values().any(|value| value_mentions(value, needle)),
        _ => false,
    }
}

fn json_field_equals(payload: &str, field: &str, expected: &str) -> bool {
    serde_json::from_str::<Value>(payload)
        .ok()
        .and_then(|value| value.get(field).and_then(Value::as_str).map(str::to_owned))
        .as_deref()
        == Some(expected)
}

fn positive_sequence(sequence: i64) -> Result<u64, String> {
    u64::try_from(sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| "runtime event position must be positive".to_owned())
}

fn store_error(error: StoreError) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_projection_preserves_cached_input_for_exact_settlement() {
        let projected = project_usage(
            r#"{"usage":{"input_tokens":9,"input_tokens_details":{"cached_tokens":7},"output_tokens":2}}"#,
            "usage:test",
        )
        .expect("usage projection")
        .expect("usage");
        assert_eq!(
            projected,
            HostedUsageObservation {
                usage_ref: "usage:test".to_owned(),
                input_tokens: 9,
                cached_input_tokens: 7,
                output_tokens: 2,
                // Absent in legacy metadata: an honest zero, never an error.
                last_input_tokens: 0,
            }
        );
    }

    /// The context gauge rides the projection when the loop stamped one, and
    /// stays a distinct reading from the summed billing counters.
    #[test]
    fn usage_projection_carries_the_stamped_context_reading() {
        let projected = project_usage(
            r#"{"usage":{"input_tokens":90,"output_tokens":12,"last_input_tokens":34}}"#,
            "usage:test",
        )
        .expect("usage projection")
        .expect("usage");
        assert_eq!(projected.input_tokens, 90);
        assert_eq!(projected.last_input_tokens, 34);
    }

    /// The surface in the admitted base URL is what picks the wire. Getting this
    /// wrong is not a crash: `/anthropic` read as compat sends a chat-completions
    /// body to the Messages API, and `/compat` read as native sends an
    /// Anthropic body to the shim.
    #[test]
    fn metered_gateway_wire_follows_the_admitted_surface() {
        let base = "https://gateway.ai.cloudflare.com/v1/abc/gw";
        assert_eq!(
            metered_gateway_wire(Some(&format!("{base}/anthropic"))),
            CoerceProvider::Anthropic
        );
        // A trailing slash is the same admitted endpoint.
        assert_eq!(
            metered_gateway_wire(Some(&format!("{base}/anthropic/"))),
            CoerceProvider::Anthropic
        );
        assert_eq!(
            metered_gateway_wire(Some(&format!("{base}/compat"))),
            CoerceProvider::OpenAiCompat
        );
        // Unknown and absent surfaces keep the long-standing wire rather than
        // guessing into one that would send an unreadable body.
        assert_eq!(
            metered_gateway_wire(Some(&format!("{base}/openai"))),
            CoerceProvider::OpenAiCompat
        );
        assert_eq!(metered_gateway_wire(None), CoerceProvider::OpenAiCompat);
        // `anthropic` must be the surface segment, not a substring of the
        // gateway's own name.
        assert_eq!(
            metered_gateway_wire(Some(
                "https://gateway.ai.cloudflare.com/v1/abc/anthropic-panels/compat"
            )),
            CoerceProvider::OpenAiCompat
        );
    }

    /// Anthropic's native wire splits the prompt across three fields and leaves
    /// `input_tokens` as the uncached remainder. Reported raw this yields
    /// `cached > input`, which the edge rejects as inexact usage — so the wire
    /// that can finally cache would fail every turn it cached on. The projection
    /// must total the three and report cached as a subset.
    #[test]
    fn usage_projection_totals_the_anthropic_native_cache_fields() {
        let projected = project_usage(
            r#"{"usage":{"input_tokens":11,"cache_creation_input_tokens":0,
                "cache_read_input_tokens":3443,"output_tokens":4}}"#,
            "usage:test",
        )
        .expect("usage projection")
        .expect("usage");
        assert_eq!(
            projected,
            HostedUsageObservation {
                usage_ref: "usage:test".to_owned(),
                input_tokens: 3454,
                cached_input_tokens: 3443,
                output_tokens: 4,
                last_input_tokens: 0,
            }
        );
        assert!(
            projected.cached_input_tokens <= projected.input_tokens,
            "the edge rejects a turn whose cached span exceeds its input"
        );
    }

    /// The cache-write round of the same conversation: nothing read, a large
    /// span created. Those tokens are genuinely fresh input and must be counted
    /// as such rather than as cached, or the write round bills at the cached
    /// rate it did not earn.
    #[test]
    fn usage_projection_counts_an_anthropic_cache_write_as_fresh_input() {
        let projected = project_usage(
            r#"{"usage":{"input_tokens":11,"cache_creation_input_tokens":3443,
                "cache_read_input_tokens":0,"output_tokens":4}}"#,
            "usage:test",
        )
        .expect("usage projection")
        .expect("usage");
        assert_eq!(
            projected,
            HostedUsageObservation {
                usage_ref: "usage:test".to_owned(),
                input_tokens: 3454,
                cached_input_tokens: 0,
                output_tokens: 4,
                last_input_tokens: 0,
            }
        );
    }

    /// The Chat Completions wire names every one of these fields differently,
    /// and it is the wire every managed-funded turn runs on. A missed alias here
    /// does not fail — it reports zero cached tokens, and the turn is billed as
    /// if nothing had been cached.
    #[test]
    fn usage_projection_reads_the_chat_completions_names() {
        let projected = project_usage(
            r#"{"usage":{"prompt_tokens":9,"prompt_tokens_details":{"cached_tokens":7},"completion_tokens":2}}"#,
            "usage:test",
        )
        .expect("usage projection")
        .expect("usage");
        assert_eq!(
            projected,
            HostedUsageObservation {
                usage_ref: "usage:test".to_owned(),
                input_tokens: 9,
                cached_input_tokens: 7,
                output_tokens: 2,
                last_input_tokens: 0,
            }
        );
    }

    #[test]
    fn a_message_that_narrates_and_calls_a_tool_keeps_its_narration() {
        // Providers routinely say something and call a tool in the same
        // message. Treating `tool_calls` as a discriminator dropped the text, so
        // the observation reported no answer for a turn that had produced one —
        // and the shell then had nothing authoritative to settle with.
        let events = vec![EventView {
            event_id: "event-1".to_owned(),
            sequence: 1,
            event_type: "agent.turn.brokered.transcript".to_owned(),
            payload_json: json!({
                "effect_id": "turn-1",
                "messages": [
                    {"role": "user", "text": "check the notes"},
                    {
                        "role": "assistant",
                        "text": "Reading the notes now.",
                        "tool_calls": [{
                            "id": "call-1",
                            "name": "read",
                            "arguments": {"path": "notes.md"}
                        }]
                    }
                ]
            })
            .to_string(),
            source: "runtime".to_owned(),
            occurred_at: "2026-08-07T00:00:00Z".to_owned(),
        }];
        let projected = project_output(&events, "turn-1", "label:test")
            .expect("output projection")
            .expect("output");
        assert_eq!(projected.assistant_text, "Reading the notes now.");
        assert_eq!(projected.tool_calls.len(), 1, "the call is still observed");
    }

    #[test]
    fn output_projection_is_runtime_owned_and_correlates_tool_results() {
        let events = vec![EventView {
            event_id: "event-1".to_owned(),
            sequence: 1,
            event_type: "agent.turn.brokered.transcript".to_owned(),
            payload_json: json!({
                "effect_id": "turn-1",
                "messages": [
                    {"role": "user", "text": "inspect"},
                    {
                        "role": "assistant",
                        "text": "",
                        "tool_calls": [{
                            "id": "call-1",
                            "name": "read",
                            "arguments": {"path": "README.md"}
                        }]
                    },
                    {
                        "role": "tool_results",
                        "results": [{
                            "tool_call_id": "call-1",
                            "tool_name": "read",
                            "content": "hello",
                            "is_error": false
                        }]
                    },
                    {"role": "assistant", "text": "done", "tool_calls": []}
                ]
            })
            .to_string(),
            source: "runtime".to_owned(),
            occurred_at: "2026-07-23T00:00:00Z".to_owned(),
        }];
        let projected = project_output(&events, "turn-1", "label:test")
            .expect("output projection")
            .expect("output");
        assert_eq!(projected.label_ref, "label:test");
        assert_eq!(projected.assistant_text, "done");
        assert_eq!(
            projected.tool_calls,
            vec![HostedToolCallObservation {
                call_id: "call-1".to_owned(),
                name: "read".to_owned(),
                arguments: json!({"path": "README.md"}),
                result: Some("hello".to_owned()),
                ok: Some(true),
            }]
        );
    }
}
