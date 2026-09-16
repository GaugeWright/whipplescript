//! Controller admission and durable late-delivery fences. This reducer cannot
//! attest process termination: an admitted fence remains FenceRequired until
//! a separately verified execution barrier exists in the host adapter.
use crate::exec_placement::Placement;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROTOCOL: &str = "whipplescript.exec.controller/v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CompletionFence {
    Fencing {
        fence_id: String,
    },
    Terminated {
        fence_id: String,
        barrier_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Termination {
    pub(crate) incarnation: String,
    pub(crate) fence_id: String,
    pub(crate) barrier_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum State {
    Admitted {
        incarnation: String,
    },
    Fencing {
        incarnation: String,
        fence_id: String,
    },
    NotAdmitted {
        fence_id: String,
    },
    Terminated {
        incarnation: String,
        fence_id: String,
        barrier_id: String,
    },
    Completed {
        incarnation: String,
        status: u16,
        body: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fence: Option<CompletionFence>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) protocol: String,
    pub(crate) placement: Placement,
    pub(crate) state: State,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Read,
    Admit {
        incarnation: String,
    },
    Fence {
        fence_id: String,
    },
    EnsureFence {
        fence_id: String,
    },
    Complete {
        incarnation: String,
        status: u16,
        body: Value,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Absent,
    Blocked {
        barrier_id: String,
    },
    Terminated {
        incarnation: String,
        fence_id: String,
        barrier_id: String,
    },
    Execute {
        incarnation: String,
    },
    Pending {
        incarnation: String,
    },
    FenceRequired {
        incarnation: String,
        fence_id: String,
    },
    NotAdmitted {
        fence_id: String,
    },
    Replay {
        status: u16,
        body: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        termination: Option<Termination>,
    },
}

impl State {
    fn incarnation(&self) -> Option<&str> {
        match self {
            Self::Admitted { incarnation }
            | Self::Fencing { incarnation, .. }
            | Self::Completed { incarnation, .. }
            | Self::Terminated { incarnation, .. } => Some(incarnation),
            Self::NotAdmitted { .. } => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.incarnation() == Some("") {
            return Err("controller incarnation is empty".into());
        }
        if matches!(self, Self::Fencing { fence_id, .. } | Self::NotAdmitted { fence_id } | Self::Terminated { fence_id, .. } if fence_id.is_empty())
        {
            return Err("controller fence identity is empty".into());
        }
        if matches!(self, Self::Terminated { barrier_id, .. } if barrier_id.is_empty()) {
            return Err("controller termination barrier identity is empty".into());
        }
        if let Self::Completed {
            fence: Some(fence), ..
        } = self
        {
            match fence {
                CompletionFence::Fencing { fence_id }
                | CompletionFence::Terminated { fence_id, .. }
                    if fence_id.is_empty() =>
                {
                    return Err("controller completion fence identity is empty".into())
                }
                CompletionFence::Terminated { barrier_id, .. } if barrier_id.is_empty() => {
                    return Err("controller completion barrier identity is empty".into())
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn pending_fence(&self) -> Option<(&str, &str)> {
        match self {
            Self::Fencing {
                incarnation,
                fence_id,
            }
            | Self::Completed {
                incarnation,
                fence: Some(CompletionFence::Fencing { fence_id }),
                ..
            } => Some((incarnation, fence_id)),
            _ => None,
        }
    }

    fn read(&self) -> Action {
        match self {
            Self::Admitted { incarnation } => Action::Pending {
                incarnation: incarnation.clone(),
            },
            Self::Fencing {
                incarnation,
                fence_id,
            } => Action::FenceRequired {
                incarnation: incarnation.clone(),
                fence_id: fence_id.clone(),
            },
            Self::NotAdmitted { fence_id } => Action::NotAdmitted {
                fence_id: fence_id.clone(),
            },
            Self::Terminated {
                incarnation,
                fence_id,
                barrier_id,
            } => Action::Terminated {
                incarnation: incarnation.clone(),
                fence_id: fence_id.clone(),
                barrier_id: barrier_id.clone(),
            },
            Self::Completed {
                incarnation,
                status,
                body,
                fence,
            } => Action::Replay {
                status: *status,
                body: body.clone(),
                termination: match fence {
                    Some(CompletionFence::Terminated {
                        fence_id,
                        barrier_id,
                    }) => Some(Termination {
                        incarnation: incarnation.clone(),
                        fence_id: fence_id.clone(),
                        barrier_id: barrier_id.clone(),
                    }),
                    _ => None,
                },
            },
        }
    }
}

/// `container_id` comes from the controlling owner, not the command. The
/// returned record must commit before Execute or NotAdmitted is observable.
/// Read never creates state or grants execution. Only v2 placements qualify;
/// a v1 delivery may already have bypassed this controller entirely.
pub fn transition_json(
    container_id: &str,
    placement: &str,
    stored: Option<&str>,
    operation: &str,
) -> Result<String, String> {
    transition_with_gate_json(container_id, placement, stored, operation, None, "0")
}

/// Host supplies the durable barrier and the generation observed before startup.
pub fn transition_with_gate_json(
    container_id: &str,
    placement: &str,
    stored: Option<&str>,
    operation: &str,
    barrier: Option<&str>,
    observed_generation: &str,
) -> Result<String, String> {
    let placement: Placement = serde_json::from_str(placement).map_err(|e| e.to_string())?;
    placement.validate_controller(container_id)?;
    let mut record: Option<Record> = stored
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| e.to_string())?;
    if let Some(record) = &record {
        if record.protocol != PROTOCOL || record.placement != placement {
            return Err("controller record differs from its placement".into());
        }
        record.state.validate()?;
    }
    let operation: Operation = serde_json::from_str(operation).map_err(|e| e.to_string())?;
    let ensure_fence = matches!(&operation, Operation::EnsureFence { .. });
    let state = record.as_ref().map(|record| &record.state);
    let replacement;
    let action = match operation {
        Operation::Read => {
            replacement = None;
            state.map(State::read).unwrap_or(Action::Absent)
        }
        Operation::Admit { incarnation } => {
            if incarnation.is_empty()
                || state
                    .and_then(State::incarnation)
                    .is_some_and(|original| original != incarnation)
            {
                return Err("controller admission incarnation changed or is empty".into());
            }
            if let Some(state) = state {
                replacement = None;
                state.read()
            } else if let Some(barrier_id) =
                crate::exec_barrier::blocks_admission(container_id, barrier, observed_generation)?
            {
                replacement = None;
                Action::Blocked { barrier_id }
            } else {
                replacement = Some(State::Admitted {
                    incarnation: incarnation.clone(),
                });
                Action::Execute { incarnation }
            }
        }
        Operation::Fence { fence_id } | Operation::EnsureFence { fence_id } => {
            if fence_id.is_empty() {
                return Err("controller fence identity is empty".into());
            }
            let next = match state {
                None => State::NotAdmitted {
                    fence_id: fence_id.clone(),
                },
                Some(State::Admitted { incarnation }) => State::Fencing {
                    incarnation: incarnation.clone(),
                    fence_id: fence_id.clone(),
                },
                Some(
                    state @ (State::Fencing {
                        fence_id: original, ..
                    }
                    | State::NotAdmitted { fence_id: original }),
                ) => {
                    if !ensure_fence && original != &fence_id {
                        return Err("controller fence cannot be replaced".into());
                    }
                    state.clone()
                }
                Some(State::Completed {
                    incarnation,
                    status,
                    body,
                    fence,
                }) => {
                    let next_fence = match fence {
                        None => Some(CompletionFence::Fencing {
                            fence_id: fence_id.clone(),
                        }),
                        Some(CompletionFence::Fencing { fence_id: original }) => {
                            if !ensure_fence && original != &fence_id {
                                return Err("controller completion fence cannot be replaced".into());
                            }
                            fence.clone()
                        }
                        Some(CompletionFence::Terminated { .. }) => fence.clone(),
                    };
                    State::Completed {
                        incarnation: incarnation.clone(),
                        status: *status,
                        body: body.clone(),
                        fence: next_fence,
                    }
                }
                Some(state @ State::Terminated { .. }) => state.clone(),
            };
            let action = match next.pending_fence() {
                Some((incarnation, fence_id)) => Action::FenceRequired {
                    incarnation: incarnation.into(),
                    fence_id: fence_id.into(),
                },
                None => next.read(),
            };
            replacement = Some(next);
            action
        }
        Operation::Complete {
            incarnation,
            status,
            body,
        } => {
            let Some(state) = state else {
                return Err("controller completion requires prior admission".into());
            };
            if matches!(state, State::Terminated { .. }) {
                return Err("controller completion arrived after its termination barrier".into());
            }
            if state.incarnation() != Some(incarnation.as_str()) {
                return Err("controller completion differs from its admitted incarnation".into());
            }
            let fence = match state {
                State::Fencing { fence_id, .. } => Some(CompletionFence::Fencing {
                    fence_id: fence_id.clone(),
                }),
                State::Completed { fence, .. } => fence.clone(),
                _ => None,
            };
            let completed = State::Completed {
                incarnation,
                status,
                body,
                fence,
            };
            if matches!(state, State::Completed { .. }) && state != &completed {
                return Err("controller completion cannot be replaced".into());
            }
            let action = completed.read();
            replacement = Some(completed);
            action
        }
    };
    if let Some(state) = replacement {
        record = Some(Record {
            protocol: PROTOCOL.into(),
            placement: placement.clone(),
            state,
        });
    }
    let key = serde_json::json!([PROTOCOL, container_id, placement.selected]);
    serde_json::to_string(
        &serde_json::json!({"storage_key":key.to_string(), "record":record, "action":action}),
    )
    .map_err(|e| e.to_string())
}

/// The broker validates a private controller reply against its retained
/// placement before considering any completion for provider retention.
pub(crate) fn response_action(placement: &str, response: &str) -> Result<Action, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        protocol: String,
        placement: Placement,
        action: Action,
    }
    let placement: Placement = serde_json::from_str(placement).map_err(|e| e.to_string())?;
    placement.validate_controller(&placement.container_id)?;
    let response: Response = serde_json::from_str(response).map_err(|e| e.to_string())?;
    if response.protocol != "whipplescript.exec.controller.response/v1"
        || response.placement != placement
    {
        return Err("controller reply differs from its retained placement".into());
    }
    Ok(response.action)
}

pub fn result_json(placement: &str, response: &str) -> Result<String, String> {
    let result = match response_action(placement, response)? {
        Action::Replay { status, body, .. } => {
            serde_json::json!({"action":"replay","status":status,"body":body})
        }
        Action::Absent
        | Action::Blocked { .. }
        | Action::Terminated { .. }
        | Action::Pending { .. }
        | Action::FenceRequired { .. }
        | Action::NotAdmitted { .. } => serde_json::json!({"action":"pending"}),
        Action::Execute { .. } => {
            return Err("controller reply cannot grant broker execution".into())
        }
    };
    Ok(result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exec_invocation::{self, Envelope, Invocation},
        exec_placement,
    };
    use serde_json::json;

    fn setup(controller: bool) -> String {
        let selected =
            json!({"instance_id":"i", "effect_id":"e", "attempt_admission_event_id":null})
                .to_string();
        let invocation: Invocation = serde_json::from_str(&selected).unwrap();
        let envelope = serde_json::to_string(
            &Envelope::new(
                invocation,
                json!({"protocol":"whip-executor/1", "effect_id":"e"}),
            )
            .unwrap(),
        )
        .unwrap();
        let claimed: Value =
            serde_json::from_str(&exec_invocation::claim_json(&selected, &envelope, None).unwrap())
                .unwrap();
        let receipt = claimed["decision"]["receipt"].to_string();
        let bind = if controller {
            exec_placement::bind_controller_json
        } else {
            exec_placement::bind_json
        };
        let placement = bind(
            &selected,
            &envelope,
            &receipt,
            None,
            "instance-0",
            "dispatch-1",
        )
        .unwrap();
        if !controller {
            assert!(exec_placement::bind_controller_json(
                &selected,
                &envelope,
                &receipt,
                Some(&placement),
                "instance-0",
                "dispatch-1"
            )
            .is_err());
        }
        placement
    }

    fn step(placement: &str, record: Option<&Value>, op: Value) -> Value {
        serde_json::from_str(
            &transition_json(
                "instance-0",
                placement,
                record.map(Value::to_string).as_deref(),
                &op.to_string(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn exec_controller_broker_validates_query_target_and_retained_reply() {
        let placement = setup(true);
        let parsed: Value = serde_json::from_str(&placement).unwrap();
        let selected = parsed["selected"].to_string();
        let envelope = parsed["envelope"].to_string();
        let claim: Value =
            serde_json::from_str(&exec_invocation::claim_json(&selected, &envelope, None).unwrap())
                .unwrap();
        let receipt = claim["decision"]["receipt"].to_string();
        let target: Value = serde_json::from_str(
            &exec_placement::controller_target_json(&selected, &envelope, &receipt, &placement)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(target["container_id"], "instance-0");
        assert_eq!(target["placement"], parsed);
        let legacy: Value = serde_json::from_str(
            &exec_placement::controller_target_json(&selected, &envelope, &receipt, &setup(false))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(legacy["action"], "legacy_pending");
        let mut altered = parsed.clone();
        altered["protocol"] = json!("unknown");
        assert!(exec_placement::controller_target_json(
            &selected,
            &envelope,
            &receipt,
            &altered.to_string()
        )
        .is_err());
        altered = parsed.clone();
        altered["selected"]["effect_id"] = json!("foreign");
        assert!(exec_placement::controller_target_json(
            &selected,
            &envelope,
            &receipt,
            &altered.to_string()
        )
        .is_err());
        let mut response = json!({"protocol":"whipplescript.exec.controller.response/v1", "placement":parsed,"action":{"action":"replay","status":503,"body":{"original":true}}});
        let result: Value =
            serde_json::from_str(&result_json(&placement, &response.to_string()).unwrap()).unwrap();
        assert_eq!(result, response["action"]);
        response["action"]["termination"] =
            json!({"incarnation":"p", "fence_id":"f", "barrier_id":"b"});
        assert_eq!(
            serde_json::from_str::<Value>(&result_json(&placement, &response.to_string()).unwrap())
                .unwrap(),
            result
        );
        for action in [
            json!({"action":"absent"}),
            json!({"action":"pending","incarnation":"p"}),
            json!({"action":"fence_required","incarnation":"p","fence_id":"f"}),
            json!({"action":"not_admitted","fence_id":"f"}),
        ] {
            response["action"] = action;
            assert_eq!(
                serde_json::from_str::<Value>(
                    &result_json(&placement, &response.to_string()).unwrap()
                )
                .unwrap(),
                json!({"action":"pending"})
            );
        }
        response["action"] = json!({"action":"execute","incarnation":"p"});
        assert!(result_json(&placement, &response.to_string()).is_err());
        response["action"] = json!({"action":"replay","status":200,"body":{}});
        response["placement"]["dispatch_id"] = json!("other");
        assert!(result_json(&placement, &response.to_string()).is_err());
        response["placement"] = parsed;
        response["protocol"] = json!("legacy");
        assert!(result_json(&placement, &response.to_string()).is_err());
        response["protocol"] = json!("whipplescript.exec.controller.response/v1");
        assert!(result_json(&setup(false), &response.to_string()).is_err());
        let legacy = setup(false);
        let mut legacy_reply = response.clone();
        legacy_reply["placement"] = serde_json::from_str::<Value>(&legacy).unwrap();
        assert!(result_json(&legacy, &legacy_reply.to_string()).is_err());
        response["extra"] = json!(true);
        assert!(result_json(&placement, &response.to_string()).is_err());
    }

    #[test]
    fn exec_controller_dispatch_replacement_cannot_select_an_unfenced_slot() {
        let original = setup(true);
        let fenced = step(&original, None, json!({"op":"fence", "fence_id":"f"}));
        let mut replacement: Value = serde_json::from_str(&original).unwrap();
        replacement["dispatch_id"] = json!("replacement-dispatch");
        let inspected = step(&replacement.to_string(), None, json!({"op":"read"}));
        assert_eq!(inspected["storage_key"], fenced["storage_key"]);
        assert!(transition_json(
            "instance-0",
            &replacement.to_string(),
            Some(&fenced["record"].to_string()),
            r#"{"op":"admit","incarnation":"epoch-1"}"#
        )
        .is_err());
        // A new explicit admission is a different invocation and therefore a
        // different slot; changing only a transport dispatch ID is not.
        replacement["selected"]["attempt_admission_event_id"] = json!("explicit-retry");
        let selected: Invocation = serde_json::from_value(replacement["selected"].clone()).unwrap();
        replacement["envelope"]["invocation"] = replacement["selected"].clone();
        replacement["envelope"]["run_id"] = json!(selected.run_id());
        let retry = step(&replacement.to_string(), None, json!({"op":"read"}));
        assert_ne!(retry["storage_key"], fenced["storage_key"]);
    }

    #[test]
    fn exec_controller_fence_before_admission_blocks_late_execution() {
        let placement = setup(true);
        let read = step(&placement, None, json!({"op":"read"}));
        assert_eq!(read["action"]["action"], "absent");
        assert!(read["record"].is_null());
        let fenced = step(&placement, None, json!({"op":"fence", "fence_id":"f"}));
        assert_eq!(fenced["action"]["action"], "not_admitted");
        let cold: Value = serde_json::from_str(&fenced["record"].to_string()).unwrap();
        for op in [
            json!({"op":"read"}),
            json!({"op":"admit", "incarnation":"epoch-1"}),
            json!({"op":"fence", "fence_id":"f"}),
        ] {
            let result = step(&placement, Some(&cold), op);
            assert_eq!(result["action"]["action"], "not_admitted");
            assert_eq!(result["record"], cold);
        }
        assert!(transition_json(
            "instance-0",
            &placement,
            Some(&cold.to_string()),
            &json!({"op":"complete", "incarnation":"epoch-1", "status":200, "body":{}}).to_string()
        )
        .is_err());
    }

    #[test]
    fn exec_controller_admitted_fence_needs_termination_and_retained_completion_wins() {
        let placement = setup(true);
        let admitted = step(
            &placement,
            None,
            json!({"op":"admit", "incarnation":"epoch-1"}),
        );
        assert_eq!(admitted["action"]["action"], "execute");
        let pending = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"admit", "incarnation":"epoch-1"}),
        );
        assert_eq!(pending["action"]["action"], "pending");
        let fence = step(
            &placement,
            Some(&pending["record"]),
            json!({"op":"fence", "fence_id":"f"}),
        );
        assert_eq!(fence["action"]["action"], "fence_required");
        for op in [
            json!({"op":"read"}),
            json!({"op":"admit", "incarnation":"epoch-1"}),
            json!({"op":"fence", "fence_id":"f"}),
        ] {
            assert_eq!(
                step(&placement, Some(&fence["record"]), op)["action"]["action"],
                "fence_required"
            );
        }
        let completion = json!({"op":"complete", "incarnation":"epoch-1", "status":503, "body":{"original":true}});
        let completed = step(&placement, Some(&fence["record"]), completion.clone());
        assert_eq!(completed["action"]["action"], "replay");
        assert_eq!(completed["action"]["status"], 503);
        for op in [json!({"op":"read"}), completion] {
            assert_eq!(step(&placement, Some(&completed["record"]), op), completed);
        }
        let still_fencing = step(
            &placement,
            Some(&completed["record"]),
            json!({"op":"fence", "fence_id":"f"}),
        );
        assert_eq!(still_fencing["action"]["action"], "fence_required");
        assert_eq!(still_fencing["record"], completed["record"]);
        assert!(transition_json(
            "instance-0",
            &placement,
            Some(&completed["record"].to_string()),
            r#"{"op":"fence","fence_id":"later-fence"}"#
        )
        .is_err());
        // No caller-supplied boolean or unrecognized operation attests death.
        assert!(transition_json(
            "instance-0",
            &placement,
            Some(&fence["record"].to_string()),
            r#"{"op":"fence","fence_id":"f","terminated":true}"#
        )
        .is_err());
    }

    #[test]
    fn exec_controller_completed_result_requires_its_own_fence() {
        let placement = setup(true);
        let admitted = step(
            &placement,
            None,
            json!({"op":"admit", "incarnation":"epoch-1"}),
        );
        let completed = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"complete", "incarnation":"epoch-1", "status":200, "body":{"timed_out":true}}),
        );
        assert!(completed["record"]["state"].get("fence").is_none());
        let fenced = step(
            &placement,
            Some(&completed["record"]),
            json!({"op":"fence", "fence_id":"completed-fence"}),
        );
        assert_eq!(
            fenced["action"],
            json!({"action":"fence_required", "incarnation":"epoch-1", "fence_id":"completed-fence"})
        );
        let replay = step(&placement, Some(&fenced["record"]), json!({"op":"read"}));
        assert_eq!(replay["action"], completed["action"]);
        assert!(replay["action"].get("termination").is_none());
    }

    #[test]
    fn exec_controller_refuses_changed_binding_incarnation_fence_and_completion() {
        let placement = setup(true);
        let admitted = step(
            &placement,
            None,
            json!({"op":"admit", "incarnation":"epoch-1"}),
        );
        let fence = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"fence", "fence_id":"f"}),
        );
        let completed = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"complete", "incarnation":"epoch-1", "status":200, "body":{}}),
        );
        for op in [
            json!({"op":"admit","incarnation":""}),
            json!({"op":"admit","incarnation":"other"}),
            json!({"op":"complete","incarnation":"other","status":200,"body":{}}),
            json!({"op":"fence","fence_id":""}),
        ] {
            assert!(transition_json(
                "instance-0",
                &placement,
                Some(&admitted["record"].to_string()),
                &op.to_string()
            )
            .is_err());
        }
        assert!(transition_json(
            "instance-0",
            &placement,
            None,
            r#"{"op":"complete","incarnation":"epoch-1","status":200,"body":{}}"#
        )
        .is_err());
        assert!(transition_json(
            "instance-0",
            &placement,
            Some(&fence["record"].to_string()),
            r#"{"op":"fence","fence_id":"other"}"#
        )
        .is_err());
        for op in [
            json!({"op":"complete","incarnation":"epoch-1","status":503,"body":{}}),
            json!({"op":"complete","incarnation":"epoch-1","status":200,"body":{"changed":true}}),
        ] {
            assert!(transition_json(
                "instance-0",
                &placement,
                Some(&completed["record"].to_string()),
                &op.to_string()
            )
            .is_err());
        }
        assert!(transition_json("other-container", &placement, None, r#"{"op":"read"}"#).is_err());
        assert!(transition_json(
            "instance-0",
            &setup(false),
            None,
            r#"{"op":"fence","fence_id":"f"}"#
        )
        .is_err());
        for pointer in ["/protocol", "/placement/dispatch_id", "/state/incarnation"] {
            let mut corrupt = admitted["record"].clone();
            *corrupt.pointer_mut(pointer).unwrap() = json!("");
            assert!(transition_json(
                "instance-0",
                &placement,
                Some(&corrupt.to_string()),
                r#"{"op":"read"}"#
            )
            .is_err());
        }
        let mut corrupt = fence["record"].clone();
        corrupt["state"]["fence_id"] = json!("");
        assert!(transition_json(
            "instance-0",
            &placement,
            Some(&corrupt.to_string()),
            r#"{"op":"read"}"#
        )
        .is_err());
    }
    #[test]
    fn exec_controller_ensure_fence_joins_original_intent_without_replacement() {
        let placement = setup(true);
        let admitted = step(
            &placement,
            None,
            json!({"op":"admit","incarnation":"process"}),
        );
        let completed = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"complete","incarnation":"process","status":200,"body":{"stdout":"retained"}}),
        );
        for before in [None, Some(&admitted["record"]), Some(&completed["record"])] {
            let original = step(
                &placement,
                before,
                json!({"op":"fence","fence_id":"original"}),
            );
            let joined = step(
                &placement,
                Some(&original["record"]),
                json!({"op":"ensure_fence","fence_id":"proposed"}),
            );
            assert_eq!(joined, original);
            assert_eq!(joined["action"]["fence_id"], "original");
            assert_eq!(
                joined["action"]["action"],
                if before.is_none() {
                    "not_admitted"
                } else {
                    "fence_required"
                }
            );
            assert!(joined["action"].get("barrier_id").is_none());
            assert!(transition_json(
                "instance-0",
                &placement,
                Some(&original["record"].to_string()),
                r#"{"op":"fence","fence_id":"proposed"}"#
            )
            .is_err());
            assert_eq!(
                transition_json(
                    "instance-0",
                    &placement,
                    Some(&original["record"].to_string()),
                    r#"{"op":"ensure_fence","fence_id":""}"#
                )
                .unwrap_err(),
                "controller fence identity is empty"
            );
            let mut foreign: Value = serde_json::from_str(&placement).unwrap();
            foreign["dispatch_id"] = json!("changed");
            assert_eq!(
                transition_json(
                    "instance-0",
                    &foreign.to_string(),
                    Some(&original["record"].to_string()),
                    r#"{"op":"ensure_fence","fence_id":"original"}"#
                )
                .unwrap_err(),
                "controller record differs from its placement"
            );
        }
        let fresh = step(
            &placement,
            Some(&admitted["record"]),
            json!({"op":"ensure_fence","fence_id":"proposed"}),
        );
        assert_eq!(
            fresh["action"],
            json!({"action":"fence_required","incarnation":"process","fence_id":"proposed"})
        );
        let completed_fresh = step(
            &placement,
            Some(&completed["record"]),
            json!({"op":"ensure_fence","fence_id":"proposed"}),
        );
        assert_eq!(completed_fresh["action"], fresh["action"]);
        assert_eq!(
            completed_fresh["record"]["state"]["body"],
            completed["record"]["state"]["body"]
        );
        let absent = step(
            &placement,
            None,
            json!({"op":"ensure_fence","fence_id":"proposed"}),
        );
        assert_eq!(
            absent["action"],
            json!({"action":"not_admitted","fence_id":"proposed"})
        );
    }
}
