//! Observed runtime file-reference uses at one instance event cut (RC-1).
//!
//! This projection classifies the file codec's request and result fields in
//! events already read from one runtime store. It neither issues a Home cut
//! nor proves that this instance, store, or event slice is the Home population.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{files::FileContentReference, EventView};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFileReferenceScope {
    KnownFileCodecEventsV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RuntimeFileReferenceSite {
    ReadRequest,
    ReadResult,
    WriteInput,
    WriteResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFileReferenceUse {
    pub event_id: String,
    pub sequence: i64,
    pub effect_id: String,
    /// Result uses bind the exact dispatch; a queued request has no run yet.
    pub run_id: Option<String>,
    pub site: RuntimeFileReferenceSite,
    /// A request to read a reference has no descriptor until its host result.
    pub reference: Option<FileContentReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFileReferenceGapKind {
    IncompleteEventSequence,
    UnexpectedEventSource,
    MalformedRuleCommit,
    MalformedRunStart,
    MalformedFileTerminal,
    MalformedFileRequest,
    AmbiguousFileRequest,
    MalformedFileResult,
    UnmatchedFileResult,
    UnmatchedRunStart,
    UnmatchedFileTerminal,
    MissingFileResult,
    AmbiguousFileResult,
    TerminalRequestMismatch,
    TerminalResultMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFileReferenceGap {
    pub event_id: String,
    pub sequence: i64,
    pub kind: RuntimeFileReferenceGapKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFileReferenceInventory {
    pub scope: RuntimeFileReferenceScope,
    /// Exactly the supplied event slice. No caller may promote it to a
    /// complete store or Home roster without a separate authoritative cut.
    pub examined_events: Vec<(String, i64)>,
    pub uses: Vec<RuntimeFileReferenceUse>,
    pub gaps: Vec<RuntimeFileReferenceGap>,
}

impl RuntimeFileReferenceInventory {
    pub fn has_no_observed_gaps(&self) -> bool {
        self.gaps.is_empty()
    }
}

struct FileTerminal {
    event_id: String,
    sequence: i64,
    accepted_value: Option<Value>,
}

/// Classify the `file.read` and `file.write` reference codec in one instance's
/// ordered event history. A missing event, malformed codec, or old result that
/// lacks a format is explicit unknown evidence, never an empty reference set.
pub fn capture(events: &[EventView]) -> RuntimeFileReferenceInventory {
    let mut inventory = RuntimeFileReferenceInventory {
        scope: RuntimeFileReferenceScope::KnownFileCodecEventsV1,
        examined_events: Vec::with_capacity(events.len()),
        uses: Vec::new(),
        gaps: Vec::new(),
    };
    if events.is_empty() {
        inventory.gaps.push(RuntimeFileReferenceGap {
            event_id: String::new(),
            sequence: 0,
            kind: RuntimeFileReferenceGapKind::IncompleteEventSequence,
        });
        return inventory;
    }
    let mut seen = BTreeSet::new();
    let mut file_effect_ids = BTreeSet::new();
    let mut run_starts = BTreeMap::new();
    let mut file_terminals = BTreeMap::new();
    let mut result_values = BTreeMap::new();
    let mut reference_result_runs = BTreeSet::new();
    let mut expected_sequence = 1;
    for event in events {
        inventory
            .examined_events
            .push((event.event_id.clone(), event.sequence));
        if event.sequence != expected_sequence
            || event.event_id.is_empty()
            || !seen.insert(&event.event_id)
        {
            gap(
                &mut inventory,
                event,
                RuntimeFileReferenceGapKind::IncompleteEventSequence,
            );
        }
        expected_sequence = event.sequence.saturating_add(1);
        match event.event_type.as_str() {
            "rule.committed" => {
                if event.source == "kernel" {
                    capture_requests(&mut inventory, &mut file_effect_ids, event);
                } else {
                    gap(
                        &mut inventory,
                        event,
                        RuntimeFileReferenceGapKind::UnexpectedEventSource,
                    );
                }
            }
            "effect.run_started" => {
                if event.source == "kernel" {
                    capture_run_start(&mut inventory, &mut run_starts, event);
                } else {
                    gap(
                        &mut inventory,
                        event,
                        RuntimeFileReferenceGapKind::UnexpectedEventSource,
                    );
                }
            }
            "effect.terminal" => {
                capture_terminal(&mut inventory, &mut file_terminals, event);
            }
            "fact.derived" => capture_results(
                &mut inventory,
                &mut result_values,
                &mut reference_result_runs,
                event,
            ),
            _ => {}
        }
    }
    let mut requests = BTreeMap::new();
    for use_site in &inventory.uses {
        match use_site.site {
            RuntimeFileReferenceSite::ReadRequest | RuntimeFileReferenceSite::WriteInput => {
                requests.insert((&use_site.effect_id, use_site.site), use_site.sequence);
            }
            RuntimeFileReferenceSite::ReadResult | RuntimeFileReferenceSite::WriteResult => {
                let request_site = if use_site.site == RuntimeFileReferenceSite::ReadResult {
                    RuntimeFileReferenceSite::ReadRequest
                } else {
                    RuntimeFileReferenceSite::WriteInput
                };
                if requests
                    .get(&(&use_site.effect_id, request_site))
                    .is_none_or(|sequence| *sequence >= use_site.sequence)
                {
                    inventory.gaps.push(RuntimeFileReferenceGap {
                        event_id: use_site.event_id.clone(),
                        sequence: use_site.sequence,
                        kind: RuntimeFileReferenceGapKind::UnmatchedFileResult,
                    });
                }
                if use_site.run_id.as_ref().is_none_or(|run_id| {
                    run_starts
                        .get(&(use_site.effect_id.clone(), run_id.clone()))
                        .is_none_or(|sequence| {
                            *sequence >= use_site.sequence
                                || requests
                                    .get(&(&use_site.effect_id, request_site))
                                    .is_none_or(|request_sequence| *sequence <= *request_sequence)
                        })
                }) {
                    inventory.gaps.push(RuntimeFileReferenceGap {
                        event_id: use_site.event_id.clone(),
                        sequence: use_site.sequence,
                        kind: RuntimeFileReferenceGapKind::UnmatchedRunStart,
                    });
                }
                if use_site.run_id.as_ref().is_none_or(|run_id| {
                    file_terminals
                        .get(&(use_site.effect_id.clone(), run_id.clone()))
                        .is_none_or(|terminal| {
                            terminal.accepted_value.is_none()
                                || terminal.sequence >= use_site.sequence
                                || requests
                                    .get(&(&use_site.effect_id, request_site))
                                    .is_none_or(|request_sequence| {
                                        terminal.sequence <= *request_sequence
                                    })
                                || run_starts
                                    .get(&(use_site.effect_id.clone(), run_id.clone()))
                                    .is_none_or(|start_sequence| {
                                        terminal.sequence <= *start_sequence
                                    })
                        })
                }) {
                    inventory.gaps.push(RuntimeFileReferenceGap {
                        event_id: use_site.event_id.clone(),
                        sequence: use_site.sequence,
                        kind: RuntimeFileReferenceGapKind::UnmatchedFileTerminal,
                    });
                } else if use_site.run_id.as_ref().is_some_and(|run_id| {
                    file_terminals
                        .get(&(use_site.effect_id.clone(), run_id.clone()))
                        .and_then(|terminal| terminal.accepted_value.as_ref())
                        != result_values.get(&use_site.event_id)
                }) {
                    inventory.gaps.push(RuntimeFileReferenceGap {
                        event_id: use_site.event_id.clone(),
                        sequence: use_site.sequence,
                        kind: RuntimeFileReferenceGapKind::TerminalResultMismatch,
                    });
                }
            }
        }
    }
    for ((effect_id, run_id), terminal) in &file_terminals {
        if terminal
            .accepted_value
            .as_ref()
            .is_some_and(|value| value.get("format").and_then(Value::as_str) != Some("reference"))
            && inventory.uses.iter().any(|use_site| {
                use_site.effect_id == *effect_id
                    && use_site.sequence < terminal.sequence
                    && matches!(
                        use_site.site,
                        RuntimeFileReferenceSite::ReadRequest
                            | RuntimeFileReferenceSite::WriteInput
                    )
            })
        {
            inventory.gaps.push(RuntimeFileReferenceGap {
                event_id: terminal.event_id.clone(),
                sequence: terminal.sequence,
                kind: RuntimeFileReferenceGapKind::TerminalRequestMismatch,
            });
        }
        if terminal
            .accepted_value
            .as_ref()
            .and_then(|value| value.get("format"))
            .and_then(Value::as_str)
            == Some("reference")
            && !reference_result_runs.contains(&(effect_id.clone(), run_id.clone()))
        {
            inventory.gaps.push(RuntimeFileReferenceGap {
                event_id: terminal.event_id.clone(),
                sequence: terminal.sequence,
                kind: RuntimeFileReferenceGapKind::MissingFileResult,
            });
        }
    }
    inventory
}

fn capture_run_start(
    inventory: &mut RuntimeFileReferenceInventory,
    starts: &mut BTreeMap<(String, String), i64>,
    event: &EventView,
) {
    let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedRunStart,
        );
        return;
    };
    let (Some(effect_id), Some(run_id), Some(provider)) = (
        payload
            .get("effect_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
        payload
            .get("run_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
        payload.get("provider").and_then(Value::as_str),
    ) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedRunStart,
        );
        return;
    };
    if provider == "files" {
        let key = (effect_id.to_owned(), run_id.to_owned());
        if starts.insert(key, event.sequence).is_some() {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedRunStart,
            );
        }
    }
}

fn capture_terminal(
    inventory: &mut RuntimeFileReferenceInventory,
    terminals: &mut BTreeMap<(String, String), FileTerminal>,
    event: &EventView,
) {
    let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileTerminal,
        );
        return;
    };
    if payload.get("provider").and_then(Value::as_str) != Some("files") {
        return;
    }
    if event.source != "kernel" {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::UnexpectedEventSource,
        );
        return;
    }
    let (Some(effect_id), Some(run_id), Some(status), Some(run_status)) = (
        payload
            .get("effect_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
        payload
            .get("run_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
        payload.get("status").and_then(Value::as_str),
        payload.get("run_status").and_then(Value::as_str),
    ) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileTerminal,
        );
        return;
    };
    let accepted_value = if status == "completed" && run_status == "completed" {
        if payload
            .get("metadata")
            .and_then(Value::as_object)
            .is_none_or(|metadata| metadata.len() != 1 || !metadata.contains_key("value"))
        {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileTerminal,
            );
        }
        let Some(value) = payload
            .get("metadata")
            .and_then(|metadata| metadata.get("value"))
            .filter(|value| value.is_object())
            .cloned()
        else {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileTerminal,
            );
            return;
        };
        if !known_file_value(&value) {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileTerminal,
            );
        }
        Some(value)
    } else {
        if payload
            .get("metadata")
            .is_some_and(|metadata| !known_file_failure_metadata(metadata))
        {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileTerminal,
            );
        }
        None
    };
    if terminals
        .insert(
            (effect_id.to_owned(), run_id.to_owned()),
            FileTerminal {
                event_id: event.event_id.clone(),
                sequence: event.sequence,
                accepted_value,
            },
        )
        .is_some()
    {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileTerminal,
        );
    }
}

fn capture_requests(
    inventory: &mut RuntimeFileReferenceInventory,
    file_effect_ids: &mut BTreeSet<String>,
    event: &EventView,
) {
    let payload = match serde_json::from_str::<Value>(&event.payload_json) {
        Ok(payload) => payload,
        Err(_) => {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedRuleCommit,
            );
            return;
        }
    };
    let Some(effects) = payload.get("effects").and_then(Value::as_array) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedRuleCommit,
        );
        return;
    };
    for effect in effects {
        let Some(kind) = effect.get("kind").and_then(Value::as_str) else {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedRuleCommit,
            );
            continue;
        };
        if kind != "file.read" && kind != "file.write" {
            continue;
        }
        if !known_file_effect(effect) {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        }
        let Some(effect_id) = effect
            .get("effect_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        };
        if !file_effect_ids.insert(effect_id.to_owned()) {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::AmbiguousFileRequest,
            );
        }
        let Some(input) = effect.get("input").and_then(Value::as_object) else {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        };
        let format = match input.get("format") {
            Some(value) => match value.as_str() {
                Some(format) => format,
                None => {
                    gap(
                        inventory,
                        event,
                        RuntimeFileReferenceGapKind::MalformedFileRequest,
                    );
                    continue;
                }
            },
            None => "text",
        };
        if !matches!(format, "text" | "reference") {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        }
        if !known_file_input(input, kind, format) {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        }
        if kind == "file.read" {
            if input.contains_key("content_reference")
                || input.contains_key("body_ref")
                || input.contains_key("label_ref")
                || input.contains_key("content_hash")
            {
                gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::MalformedFileRequest,
                );
            } else if format == "reference" {
                inventory.uses.push(RuntimeFileReferenceUse {
                    event_id: event.event_id.clone(),
                    sequence: event.sequence,
                    effect_id: effect_id.to_owned(),
                    run_id: None,
                    site: RuntimeFileReferenceSite::ReadRequest,
                    reference: None,
                });
            }
            continue;
        }
        if input.contains_key("content_reference")
            || input.contains_key("label_ref")
            || input.contains_key("content_hash")
        {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileRequest,
            );
            continue;
        }
        if format == "reference" || input.contains_key("body_ref") {
            if format != "reference"
                || input.contains_key("body")
                || input.contains_key("body_expr")
            {
                gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::MalformedFileRequest,
                );
                continue;
            }
            match input.get("body_ref").and_then(valid_reference) {
                Some(reference) => inventory.uses.push(RuntimeFileReferenceUse {
                    event_id: event.event_id.clone(),
                    sequence: event.sequence,
                    effect_id: effect_id.to_owned(),
                    run_id: None,
                    site: RuntimeFileReferenceSite::WriteInput,
                    reference: Some(reference),
                }),
                None => gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::MalformedFileRequest,
                ),
            }
        }
    }
}

fn capture_results(
    inventory: &mut RuntimeFileReferenceInventory,
    result_values: &mut BTreeMap<String, Value>,
    reference_result_runs: &mut BTreeSet<(String, String)>,
    event: &EventView,
) {
    let payload = match serde_json::from_str::<Value>(&event.payload_json) {
        Ok(payload) => payload,
        Err(_) => {
            gap(
                inventory,
                event,
                RuntimeFileReferenceGapKind::MalformedFileResult,
            );
            return;
        }
    };
    let site = match payload.get("name").and_then(Value::as_str) {
        Some("file.read.completed") => RuntimeFileReferenceSite::ReadResult,
        Some("file.write.completed") => RuntimeFileReferenceSite::WriteResult,
        Some("file.read.failed" | "file.write.failed") => {
            if event.source != "kernel" {
                gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::UnexpectedEventSource,
                );
            } else if !payload.get("value").is_some_and(known_file_failure_fact) {
                gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::MalformedFileResult,
                );
            }
            return;
        }
        _ => return,
    };
    if event.source != "kernel" {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::UnexpectedEventSource,
        );
        return;
    }
    let Some(fact) = payload.get("value").and_then(Value::as_object) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    };
    if !fact
        .keys()
        .all(|key| matches!(key.as_str(), "effect_id" | "run_id" | "status" | "value"))
    {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    }
    let Some(value) = fact.get("value").and_then(Value::as_object) else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    };
    let Some(format) = value.get("format").and_then(Value::as_str) else {
        // Older file facts cannot establish that no reference was returned.
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    };
    if !matches!(format, "text" | "reference") {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    }
    if !known_file_value(&Value::Object(value.clone())) {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    }
    if format != "reference"
        && !value.contains_key("content_reference")
        && !value.contains_key("label_ref")
    {
        return;
    }
    let Some(effect_id) = payload
        .get("value")
        .and_then(|fact| fact.get("effect_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    };
    let Some(run_id) = payload
        .get("value")
        .and_then(|fact| fact.get("run_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    };
    if payload
        .get("value")
        .and_then(|fact| fact.get("status"))
        .and_then(Value::as_str)
        != Some("completed")
    {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    }
    if format != "reference" {
        gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        );
        return;
    }
    match value.get("content_reference").and_then(valid_reference) {
        Some(reference)
            if value.get("content_hash").and_then(Value::as_str)
                == Some(reference.content_hash.as_str()) =>
        {
            result_values.insert(event.event_id.clone(), Value::Object(value.clone()));
            if !reference_result_runs.insert((effect_id.to_owned(), run_id.to_owned())) {
                gap(
                    inventory,
                    event,
                    RuntimeFileReferenceGapKind::AmbiguousFileResult,
                );
            }
            inventory.uses.push(RuntimeFileReferenceUse {
                event_id: event.event_id.clone(),
                sequence: event.sequence,
                effect_id: effect_id.to_owned(),
                run_id: Some(run_id.to_owned()),
                site,
                reference: Some(reference),
            })
        }
        _ => gap(
            inventory,
            event,
            RuntimeFileReferenceGapKind::MalformedFileResult,
        ),
    }
}

// The current codec's field vocabulary is closed for this projection. A new
// field might carry an external reference even when `format` remains `text`;
// its meaning must be classified before this inventory can report no gaps.
fn known_file_effect(effect: &Value) -> bool {
    effect.as_object().is_some_and(|fields| {
        fields.keys().all(|field| {
            matches!(
                field.as_str(),
                "effect_id"
                    | "kind"
                    | "target"
                    | "input"
                    | "status"
                    | "program_version_id"
                    | "revision_epoch"
                    | "idempotency_key"
                    | "required_capabilities"
                    | "profile"
                    | "correlation_id"
                    | "timeout_seconds"
                    | "source_span"
            )
        })
    })
}

fn known_file_input(input: &Map<String, Value>, kind: &str, format: &str) -> bool {
    input.keys().all(|field| {
        matches!(
            field.as_str(),
            "format" | "store" | "path" | "root" | "allow" | "rule" | "mode"
        ) || (kind == "file.write"
            && ((format == "text" && matches!(field.as_str(), "body" | "body_expr"))
                || (format == "reference" && field == "body_ref")))
    })
}

fn known_file_value(value: &Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let Some(format) = fields.get("format").and_then(Value::as_str) else {
        return false;
    };
    if !matches!(format, "text" | "reference") {
        return false;
    }
    fields.keys().all(|field| {
        matches!(
            field.as_str(),
            "store" | "path" | "format" | "content_hash" | "bytes"
        ) || (format == "text" && matches!(field.as_str(), "content" | "full_path" | "mode"))
            || (format == "reference"
                && matches!(field.as_str(), "content_reference" | "full_path" | "mode"))
    })
}

fn known_file_failure_metadata(metadata: &Value) -> bool {
    let Some(fields) = metadata.as_object() else {
        return false;
    };
    if fields.len() != 1 {
        return false;
    }
    fields.get("failure").is_some_and(|failure| {
        failure.as_object().is_some_and(|failure| {
            failure
                .keys()
                .all(|field| matches!(field.as_str(), "error_kind" | "message"))
        })
    })
}

fn known_file_failure_fact(fact: &Value) -> bool {
    let Some(fields) = fact.as_object() else {
        return false;
    };
    if !fields.keys().all(|field| {
        matches!(
            field.as_str(),
            "effect_id" | "run_id" | "status" | "value" | "error"
        )
    }) {
        return false;
    }
    fields
        .get("value")
        .and_then(Value::as_object)
        .is_some_and(|value| {
            value.keys().all(|field| {
                matches!(
                    field.as_str(),
                    "reason" | "summary" | "effect_id" | "run_id" | "kind"
                )
            })
        })
        && fields
            .get("error")
            .and_then(Value::as_object)
            .is_some_and(|error| error.keys().all(|field| field == "message"))
}

fn valid_reference(value: &Value) -> Option<FileContentReference> {
    let reference = serde_json::from_value::<FileContentReference>(value.clone()).ok()?;
    reference.validate().ok()?;
    Some(reference)
}

fn gap(
    inventory: &mut RuntimeFileReferenceInventory,
    event: &EventView,
    kind: RuntimeFileReferenceGapKind,
) {
    inventory.gaps.push(RuntimeFileReferenceGap {
        event_id: event.event_id.clone(),
        sequence: event.sequence,
        kind,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(sequence: i64, event_type: &str, payload: Value) -> EventView {
        EventView {
            event_id: format!("event-{sequence}"),
            sequence,
            event_type: event_type.into(),
            payload_json: payload.to_string(),
            source: "kernel".into(),
            occurred_at: "2026-10-05T00:00:00Z".into(),
        }
    }

    fn reference(hash: &str, label: &str) -> Value {
        json!({"content_hash":hash,"label_ref":label})
    }

    fn terminal(effect_id: &str, run_id: &str, hash: &str, handle: &Value) -> Value {
        json!({"effect_id":effect_id,"run_id":run_id,"provider":"files",
        "status":"completed","run_status":"completed","metadata":{"value":{
            "format":"reference","content_hash":hash,"content_reference":handle
        }}})
    }

    #[test]
    fn file_reference_requests_and_results_keep_distinct_host_bound_handles() {
        let input_hash = "a".repeat(32);
        let result_hash = "b".repeat(32);
        let input = reference(&input_hash, "input-private");
        let result = reference(&result_hash, "result-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"read","kind":"file.read","input":{"format":"reference"}},
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":input}},
                    {"effect_id":"text","kind":"file.write","input":{"format":"text","body":"ordinary"}}
                ]}),
            ),
            event(
                3,
                "effect.run_started",
                json!({"effect_id":"read","run_id":"read-run","provider":"files"}),
            ),
            event(
                4,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"write-run","provider":"files"}),
            ),
            event(
                5,
                "effect.terminal",
                terminal("read", "read-run", &input_hash, &input),
            ),
            event(
                6,
                "effect.terminal",
                terminal("write", "write-run", &result_hash, &result),
            ),
            event(
                7,
                "fact.derived",
                json!({"name":"file.read.completed","value":{
                    "effect_id":"read","run_id":"read-run","status":"completed","value":{"format":"reference","content_hash":input_hash,"content_reference":input}
                }}),
            ),
            event(
                8,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"write-run","status":"completed","value":{"format":"reference","content_hash":result_hash,"content_reference":result}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert!(inventory.has_no_observed_gaps(), "{:?}", inventory.gaps);
        assert_eq!(inventory.examined_events.len(), 8);
        assert_eq!(inventory.uses.len(), 4);
        assert_eq!(
            inventory.uses[0].site,
            RuntimeFileReferenceSite::ReadRequest
        );
        assert!(inventory.uses[0].reference.is_none());
        assert_eq!(inventory.uses[1].site, RuntimeFileReferenceSite::WriteInput);
        assert_eq!(
            inventory.uses[1].reference.as_ref().unwrap().content_hash,
            input_hash
        );
        assert_eq!(inventory.uses[2].site, RuntimeFileReferenceSite::ReadResult);
        assert_eq!(inventory.uses[2].run_id.as_deref(), Some("read-run"));
        assert_eq!(
            inventory.uses[3].site,
            RuntimeFileReferenceSite::WriteResult
        );
        assert_eq!(
            inventory.uses[3].reference.as_ref().unwrap().content_hash,
            result_hash
        );
        assert_ne!(inventory.uses[1].reference, inventory.uses[3].reference);
    }

    #[test]
    fn missing_events_opaque_handles_and_legacy_results_are_unknown() {
        let events = vec![
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":"opaque"}}
                ]}),
            ),
            event(
                3,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","value":{"content_hash":"a".repeat(32)}
                }}),
            ),
            event(
                4,
                "fact.derived",
                json!({"name":"file.read.completed","value":{
                    "effect_id":"read","value":{"format":"text","content_hash":"a".repeat(32),
                        "content_reference":reference(&"a".repeat(32),"unexpected")}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert!(!inventory.has_no_observed_gaps());
        assert_eq!(inventory.uses.len(), 0);
        assert_eq!(inventory.gaps.len(), 4);
        assert_eq!(
            inventory.gaps[0].kind,
            RuntimeFileReferenceGapKind::IncompleteEventSequence
        );
        assert_eq!(
            inventory.gaps[1].kind,
            RuntimeFileReferenceGapKind::MalformedFileRequest
        );
        assert_eq!(
            inventory.gaps[2].kind,
            RuntimeFileReferenceGapKind::MalformedFileResult
        );
        assert_eq!(
            inventory.gaps[3].kind,
            RuntimeFileReferenceGapKind::MalformedFileResult
        );
        assert!(!capture(&[]).has_no_observed_gaps());
    }

    #[test]
    fn new_format_and_opaque_hash_fields_need_classification() {
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"read","kind":"file.read","input":{"format":"binary"}},
                    {"effect_id":"write","kind":"file.write","input":{"format":"text",
                        "body":"ordinary","content_hash":"a".repeat(32)}}
                ]}),
            ),
            event(
                3,
                "fact.derived",
                json!({"name":"file.read.completed","value":{
                    "effect_id":"read","value":{"format":"binary","content_hash":"a".repeat(32)}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert_eq!(inventory.uses.len(), 0);
        assert_eq!(inventory.gaps.len(), 3);
        assert!(!inventory.has_no_observed_gaps());
    }

    #[test]
    fn new_fields_cannot_hide_references_in_text_file_evidence() {
        let hash = "a".repeat(32);
        let value = json!({"store":"docs","path":"note.txt","format":"text",
            "full_path":"/workspace/note.txt","mode":"upsert","bytes":4,"content_hash":hash});
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{
                        "format":"text","store":"docs","path":"note.txt","root":"/workspace",
                        "allow":["**"],"rule":"r","mode":"upsert","body":"note","body_expr":"note"}}
                ]}),
            ),
            event(
                3,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"run","provider":"files"}),
            ),
            event(
                4,
                "effect.terminal",
                json!({"effect_id":"write","run_id":"run","provider":"files",
                    "status":"completed","run_status":"completed","metadata":{"value":value}}),
            ),
            event(
                5,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"run","status":"completed","value":value}}),
            ),
        ];
        assert!(capture(&events).has_no_observed_gaps());

        let mut changed = events.clone();
        let mut request: Value = serde_json::from_str(&changed[1].payload_json).unwrap();
        request["effects"][0]["input"]["future_blob_ref"] = json!("opaque");
        changed[1].payload_json = request.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileRequest
        );

        let mut changed = events.clone();
        let mut request: Value = serde_json::from_str(&changed[1].payload_json).unwrap();
        request["effects"][0]["future_blob_ref"] = json!("opaque");
        changed[1].payload_json = request.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileRequest
        );

        let mut changed = events.clone();
        let mut terminal: Value = serde_json::from_str(&changed[3].payload_json).unwrap();
        terminal["metadata"]["value"]["body_ref"] = reference(&hash, "unexpected-private");
        changed[3].payload_json = terminal.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileTerminal
        );

        for field in ["body_ref", "future_blob_ref", "receipt"] {
            let mut changed = events.clone();
            let mut fact: Value = serde_json::from_str(&changed[4].payload_json).unwrap();
            fact["value"]["value"][field] = reference(&hash, "unexpected-private");
            changed[4].payload_json = fact.to_string();
            assert_eq!(
                capture(&changed).gaps[0].kind,
                RuntimeFileReferenceGapKind::MalformedFileResult
            );
        }
    }

    #[test]
    fn failed_file_evidence_cannot_hide_a_host_receipt() {
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{
                        "format":"text","body":"draft"}}
                ]}),
            ),
            event(
                3,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"run","provider":"files"}),
            ),
            event(
                4,
                "effect.terminal",
                json!({
                    "effect_id":"write","run_id":"run","provider":"files",
                    "status":"failed","run_status":"failed",
                    "metadata":{"failure":{"error_kind":"file_effect_failed","message":"conflict"}}
                }),
            ),
            event(
                5,
                "fact.derived",
                json!({
                    "name":"file.write.failed","value":{
                        "effect_id":"write","run_id":"run","status":"failed",
                        "value":{"reason":"conflict","summary":"conflict",
                            "effect_id":"write","run_id":"run","kind":"file.write"},
                        "error":{"message":"conflict"}
                    }
                }),
            ),
        ];
        assert!(capture(&events).has_no_observed_gaps());

        let mut changed = events.clone();
        let mut terminal: Value = serde_json::from_str(&changed[3].payload_json).unwrap();
        terminal["metadata"]["failure"]["receipt"] = json!({
            "schema_ref":"host.receipt.v1","label_ref":"private"
        });
        changed[3].payload_json = terminal.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileTerminal
        );

        let mut changed = events.clone();
        let mut fact: Value = serde_json::from_str(&changed[4].payload_json).unwrap();
        fact["value"]["value"]["receipt"] = json!({
            "schema_ref":"host.receipt.v1","label_ref":"private"
        });
        changed[4].payload_json = fact.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileResult
        );

        let mut changed = events;
        let mut fact: Value = serde_json::from_str(&changed[4].payload_json).unwrap();
        fact["value"]["future_ref"] = json!("opaque");
        changed[4].payload_json = fact.to_string();
        assert_eq!(
            capture(&changed).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileResult
        );
    }

    #[test]
    fn reference_result_without_earlier_request_is_unknown() {
        let hash = "c".repeat(32);
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"orphan","run_id":"run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":reference(&hash,"result-private")}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert_eq!(inventory.uses.len(), 1);
        assert_eq!(inventory.gaps.len(), 3);
        assert_eq!(
            inventory.gaps[0].kind,
            RuntimeFileReferenceGapKind::UnmatchedFileResult
        );
        assert_eq!(
            inventory.gaps[1].kind,
            RuntimeFileReferenceGapKind::UnmatchedRunStart
        );
        assert_eq!(
            inventory.gaps[2].kind,
            RuntimeFileReferenceGapKind::UnmatchedFileTerminal
        );
    }

    #[test]
    fn matching_request_without_the_result_run_is_unknown() {
        let hash = "d".repeat(32);
        let handle = reference(&hash, "input-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":handle}}
                ]}),
            ),
            event(
                3,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"missing-run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":handle}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert_eq!(inventory.uses.len(), 2);
        assert_eq!(inventory.gaps.len(), 2);
        assert_eq!(
            inventory.gaps[0].kind,
            RuntimeFileReferenceGapKind::UnmatchedRunStart
        );
        assert_eq!(
            inventory.gaps[1].kind,
            RuntimeFileReferenceGapKind::UnmatchedFileTerminal
        );
    }

    #[test]
    fn reference_result_requires_a_successful_terminal_between_run_and_fact() {
        let hash = "d".repeat(32);
        let handle = reference(&hash, "input-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":handle}}
                ]}),
            ),
            event(
                3,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"run","provider":"files"}),
            ),
            event(
                4,
                "effect.terminal",
                terminal("write", "run", &hash, &handle),
            ),
            event(
                5,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":handle}
                }}),
            ),
        ];
        assert!(capture(&events).has_no_observed_gaps());

        let without_fact = &events[..4];
        assert_eq!(
            capture(without_fact).gaps[0].kind,
            RuntimeFileReferenceGapKind::MissingFileResult
        );

        let mut text_fact = events.clone();
        let mut fact: Value = serde_json::from_str(&text_fact[4].payload_json).unwrap();
        fact["value"]["value"] = json!({"format":"text","content_hash":hash});
        text_fact[4].payload_json = fact.to_string();
        assert_eq!(
            capture(&text_fact).gaps[0].kind,
            RuntimeFileReferenceGapKind::MissingFileResult
        );

        for (value, expected) in [
            (
                json!({"format":"text","content_hash":hash}),
                RuntimeFileReferenceGapKind::TerminalRequestMismatch,
            ),
            (
                json!({"content_hash":hash}),
                RuntimeFileReferenceGapKind::MalformedFileTerminal,
            ),
        ] {
            let mut changed = events[..4].to_vec();
            let mut accepted: Value = serde_json::from_str(&changed[3].payload_json).unwrap();
            accepted["metadata"]["value"] = value;
            changed[3].payload_json = accepted.to_string();
            assert_eq!(capture(&changed).gaps[0].kind, expected);
        }

        let mut changed_value = events.clone();
        let mut accepted: Value = serde_json::from_str(&changed_value[3].payload_json).unwrap();
        accepted["metadata"]["value"]["content_reference"]["label_ref"] = json!("other");
        changed_value[3].payload_json = accepted.to_string();
        assert_eq!(
            capture(&changed_value).gaps[0].kind,
            RuntimeFileReferenceGapKind::TerminalResultMismatch
        );

        for status in [Value::Null, json!("failed")] {
            let mut changed = events.clone();
            let mut fact: Value = serde_json::from_str(&changed[4].payload_json).unwrap();
            fact["value"]["status"] = status;
            changed[4].payload_json = fact.to_string();
            assert!(capture(&changed)
                .gaps
                .iter()
                .any(|gap| gap.kind == RuntimeFileReferenceGapKind::MalformedFileResult));
        }

        let mut duplicate_fact = events.clone();
        let mut second_fact = duplicate_fact[4].clone();
        second_fact.event_id = "event-6".into();
        second_fact.sequence = 6;
        duplicate_fact.push(second_fact);
        assert_eq!(
            capture(&duplicate_fact).gaps[0].kind,
            RuntimeFileReferenceGapKind::AmbiguousFileResult
        );

        let mut no_terminal = events.clone();
        no_terminal.remove(3);
        no_terminal[3].sequence = 4;
        no_terminal[3].event_id = "event-4".into();
        assert_eq!(
            capture(&no_terminal).gaps[0].kind,
            RuntimeFileReferenceGapKind::UnmatchedFileTerminal
        );

        for (provider, status, run_status) in [
            ("other", "completed", "completed"),
            ("files", "failed", "failed"),
            ("files", "completed", "failed"),
        ] {
            let mut changed = events.clone();
            changed[3].payload_json = json!({
                "effect_id":"write","run_id":"run","provider":provider,"status":status,"run_status":run_status
            })
            .to_string();
            assert_eq!(
                capture(&changed).gaps[0].kind,
                RuntimeFileReferenceGapKind::UnmatchedFileTerminal
            );
        }

        let mut duplicate = events.clone();
        duplicate.insert(
            4,
            event(
                5,
                "effect.terminal",
                terminal("write", "run", &hash, &handle),
            ),
        );
        duplicate[5].sequence = 6;
        duplicate[5].event_id = "event-6".into();
        assert_eq!(
            capture(&duplicate).gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileTerminal
        );

        let mut malformed = events;
        malformed[3].payload_json =
            json!({"effect_id":"write","provider":"files","status":"completed"}).to_string();
        let gaps = &capture(&malformed).gaps;
        assert_eq!(
            gaps[0].kind,
            RuntimeFileReferenceGapKind::MalformedFileTerminal
        );
        assert_eq!(
            gaps[1].kind,
            RuntimeFileReferenceGapKind::UnmatchedFileTerminal
        );
    }

    #[test]
    fn a_run_started_before_its_file_request_cannot_prove_the_result() {
        let hash = "e".repeat(32);
        let handle = reference(&hash, "input-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"old-run","provider":"files"}),
            ),
            event(
                3,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":handle}}
                ]}),
            ),
            event(
                4,
                "effect.terminal",
                terminal("write", "old-run", &hash, &handle),
            ),
            event(
                5,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"old-run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":handle}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert_eq!(inventory.uses.len(), 2);
        assert_eq!(inventory.gaps.len(), 1);
        assert_eq!(
            inventory.gaps[0].kind,
            RuntimeFileReferenceGapKind::UnmatchedRunStart
        );
    }

    #[test]
    fn a_reused_file_effect_id_cannot_disambiguate_a_reference_result() {
        let hash = "f".repeat(32);
        let handle = reference(&hash, "input-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":handle}}
                ]}),
            ),
            event(
                3,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"text","body":"ordinary"}}
                ]}),
            ),
            event(
                4,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"run","provider":"files"}),
            ),
            event(
                5,
                "effect.terminal",
                terminal("write", "run", &hash, &handle),
            ),
            event(
                6,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":handle}
                }}),
            ),
        ];
        let inventory = capture(&events);
        assert_eq!(inventory.uses.len(), 2);
        assert_eq!(inventory.gaps.len(), 1);
        assert_eq!(
            inventory.gaps[0].kind,
            RuntimeFileReferenceGapKind::AmbiguousFileRequest
        );
    }

    #[test]
    fn a_non_kernel_file_event_cannot_close_observed_provenance() {
        let hash = "a".repeat(32);
        let handle = reference(&hash, "input-private");
        let events = vec![
            event(1, "instance.created", json!({})),
            event(
                2,
                "rule.committed",
                json!({"effects":[
                    {"effect_id":"write","kind":"file.write","input":{"format":"reference","body_ref":handle}}
                ]}),
            ),
            event(
                3,
                "effect.run_started",
                json!({"effect_id":"write","run_id":"run","provider":"files"}),
            ),
            event(
                4,
                "effect.terminal",
                terminal("write", "run", &hash, &handle),
            ),
            event(
                5,
                "fact.derived",
                json!({"name":"file.write.completed","value":{
                    "effect_id":"write","run_id":"run","status":"completed","value":{"format":"reference",
                        "content_hash":hash,"content_reference":handle}
                }}),
            ),
        ];
        assert!(capture(&events).has_no_observed_gaps());
        for index in 1..=4 {
            let mut changed = events.clone();
            changed[index].source = "external".into();
            assert!(capture(&changed).gaps.iter().any(|gap| {
                gap.kind == RuntimeFileReferenceGapKind::UnexpectedEventSource
                    && gap.event_id == changed[index].event_id
            }));
        }
    }
}
