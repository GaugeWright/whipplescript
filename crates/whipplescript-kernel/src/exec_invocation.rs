//! Invocation binding for durable executor reconciliation.
//! This envelope is not yet admitted by the stateless executor endpoint.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL: &str = "whipplescript.exec.invocation/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub instance_id: String,
    pub effect_id: String,
    pub attempt_admission_event_id: Option<String>,
}

impl Invocation {
    pub fn run_id(&self) -> String {
        crate::execution_attempt_key(
            &self.instance_id,
            &self.effect_id,
            self.attempt_admission_event_id.as_deref(),
            "exec-run",
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.instance_id.is_empty()
            || self.effect_id.is_empty()
            || self.attempt_admission_event_id.as_deref() == Some("")
        {
            return Err("executor invocation contains an empty identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    protocol: String,
    invocation: Invocation,
    run_id: String,
    dispatch: Value,
}

impl Envelope {
    pub fn new(invocation: Invocation, dispatch: Value) -> Result<Self, String> {
        let envelope = Self {
            protocol: PROTOCOL.into(),
            run_id: invocation.run_id(),
            invocation,
            dispatch,
        };
        envelope.validate(&envelope.invocation)?;
        Ok(envelope)
    }

    /// `selected` comes from authenticated host state, never from this envelope.
    pub fn validate(&self, selected: &Invocation) -> Result<(), String> {
        self.invocation.validate()?;
        if self.protocol != PROTOCOL
            || &self.invocation != selected
            || self.run_id != selected.run_id()
        {
            return Err("executor envelope differs from the selected invocation".into());
        }
        if self.dispatch.get("protocol").and_then(Value::as_str)
            != Some(crate::exec_http::EXECUTOR_PROTOCOL)
            || self.dispatch.get("effect_id").and_then(Value::as_str)
                != Some(selected.effect_id.as_str())
        {
            return Err("executor dispatch differs from its invocation".into());
        }
        Ok(())
    }

    /// Retained material wins. Semantic JSON equality ignores object key order
    /// but preserves every value; no caller-provided digest decides equality.
    pub fn verify_replay(&self, requested: &Self, selected: &Invocation) -> Result<(), String> {
        self.validate(selected)?;
        requested.validate(selected)?;
        if self != requested {
            return Err("executor invocation dispatch cannot be replaced".into());
        }
        Ok(())
    }

    pub fn dispatch(&self, selected: &Invocation) -> Result<&Value, String> {
        self.validate(selected)?;
        Ok(&self.dispatch)
    }
}

/// Durable provider-owned state. Deserialization must still be followed by
/// selection validation through `claim` or `complete`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Receipt {
    Started {
        envelope: Envelope,
        #[serde(default, skip_serializing_if = "is_false")]
        placement_required: bool,
    },
    Completed {
        envelope: Envelope,
        status: u16,
        body: Value,
    },
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Claim {
    Dispatch { receipt: Receipt },
    Pending,
    Replay { status: u16, body: Value },
}

impl Receipt {
    /// The owner executes this decision inside its claim transaction and
    /// commits a Dispatch receipt before assigning placement. New receipts
    /// require a verified placement commit before delivery. This pure function
    /// itself grants no authority to execute and performs no persistence.
    pub fn claim(
        stored: Option<&Self>,
        requested: &Envelope,
        selected: &Invocation,
    ) -> Result<Claim, String> {
        requested.validate(selected)?;
        match stored {
            None => Ok(Claim::Dispatch {
                receipt: Self::Started {
                    envelope: requested.clone(),
                    placement_required: true,
                },
            }),
            Some(Self::Started { envelope, .. }) => {
                envelope.verify_replay(requested, selected)?;
                Ok(Claim::Pending)
            }
            Some(Self::Completed {
                envelope,
                status,
                body,
            }) => {
                envelope.verify_replay(requested, selected)?;
                Ok(Claim::Replay {
                    status: *status,
                    body: body.clone(),
                })
            }
        }
    }

    pub fn complete(
        &self,
        requested: &Envelope,
        selected: &Invocation,
        status: u16,
        body: Value,
    ) -> Result<Self, String> {
        let envelope = match self {
            Self::Started { envelope, .. } | Self::Completed { envelope, .. } => envelope,
        };
        envelope.verify_replay(requested, selected)?;
        let completed = Self::Completed {
            envelope: envelope.clone(),
            status,
            body,
        };
        if matches!(self, Self::Completed { .. }) && self != &completed {
            return Err("executor provider response cannot be replaced".into());
        }
        Ok(completed)
    }
}

/// JSON seam for the broker. The caller supplies selection from its trusted
/// internal host request. A claim decision becomes dispatch authority only
/// after the owning transaction has committed the returned receipt.
pub fn claim_json(selected: &str, requested: &str, stored: Option<&str>) -> Result<String, String> {
    let selected: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let requested: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    let stored: Option<Receipt> = stored
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| e.to_string())?;
    let decision = Receipt::claim(stored.as_ref(), &requested, &selected)?;
    let storage_key = serde_json::json!([PROTOCOL, selected]).to_string();
    Ok(serde_json::json!({"storage_key":storage_key, "decision":decision, "dispatch":requested.dispatch(&selected)?}).to_string())
}

pub fn complete_json(
    selected: &str,
    requested: &str,
    stored: &str,
    status: u16,
    body: &str,
) -> Result<String, String> {
    let selected: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let requested: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    let stored: Receipt = serde_json::from_str(stored).map_err(|e| e.to_string())?;
    let body: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    serde_json::to_string(&stored.complete(&requested, &selected, status, body)?)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn invocation() -> Invocation {
        Invocation {
            instance_id: "instance".into(),
            effect_id: "effect".into(),
            attempt_admission_event_id: None,
        }
    }

    fn envelope() -> Envelope {
        Envelope::new(
            invocation(),
            json!({"protocol":"whip-executor/1", "effect_id":"effect", "stdin":{"n":1}}),
        )
        .unwrap()
    }

    #[test]
    fn exec_invocation_replay_preserves_dispatch_and_separates_attempts() {
        let original = envelope();
        let reopened: Envelope =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        original.verify_replay(&reopened, &invocation()).unwrap();
        assert_eq!(
            original.dispatch(&invocation()).unwrap(),
            reopened.dispatch(&invocation()).unwrap()
        );
        let mut later = invocation();
        later.attempt_admission_event_id = Some("retry-event".into());
        let retry = Envelope::new(later.clone(), original.dispatch.clone()).unwrap();
        assert_ne!(invocation().run_id(), later.run_id());
        assert!(original.dispatch(&later).is_err());
        assert!(original.verify_replay(&retry, &later).is_err());
        retry.verify_replay(&retry, &later).unwrap();
    }

    #[test]
    fn exec_invocation_refuses_replacement_and_identity_substitution() {
        let original = envelope();
        let encoded = serde_json::to_value(&original).unwrap();
        for pointer in [
            "/protocol",
            "/run_id",
            "/invocation/instance_id",
            "/invocation/effect_id",
            "/invocation/attempt_admission_event_id",
            "/dispatch/protocol",
            "/dispatch/effect_id",
            "/dispatch/stdin/n",
        ] {
            let mut altered = encoded.clone();
            *altered.pointer_mut(pointer).unwrap() = json!("replacement");
            let altered: Envelope = serde_json::from_value(altered).unwrap();
            if pointer != "/dispatch/stdin/n" {
                assert!(
                    Receipt::claim(None, &altered, &invocation()).is_err(),
                    "first claim: {pointer}"
                );
                assert!(
                    altered.dispatch(&invocation()).is_err(),
                    "dispatch access: {pointer}"
                );
            } else {
                assert!(matches!(
                    Receipt::claim(None, &altered, &invocation()).unwrap(),
                    Claim::Dispatch { .. }
                ));
            }
            assert!(
                original.verify_replay(&altered, &invocation()).is_err(),
                "{pointer}"
            );
        }
        for field in ["instance_id", "effect_id", "attempt_admission_event_id"] {
            let mut value = serde_json::to_value(invocation()).unwrap();
            value[field] = json!("");
            let selected: Invocation = serde_json::from_value(value).unwrap();
            assert!(Envelope::new(selected, original.dispatch.clone()).is_err());
        }
        let mut unknown = encoded;
        unknown["authority"] = json!("self-grant");
        assert!(serde_json::from_value::<Envelope>(unknown).is_err());
    }
    #[test]
    fn exec_invocation_receipt_cold_replay_never_grants_second_dispatch() {
        let request = envelope();
        let Claim::Dispatch { receipt } = Receipt::claim(None, &request, &invocation()).unwrap()
        else {
            panic!("first invocation must claim dispatch");
        };
        let cold: Receipt =
            serde_json::from_str(&serde_json::to_string(&receipt).unwrap()).unwrap();
        assert_eq!(
            Receipt::claim(Some(&cold), &request, &invocation()).unwrap(),
            Claim::Pending
        );
        for status in [200, 503] {
            let body = json!({"actual":"original", "status":status});
            let completed = cold
                .complete(&request, &invocation(), status, body.clone())
                .unwrap();
            let reopened: Receipt =
                serde_json::from_str(&serde_json::to_string(&completed).unwrap()).unwrap();
            assert_eq!(
                Receipt::claim(Some(&reopened), &request, &invocation()).unwrap(),
                Claim::Replay {
                    status,
                    body: body.clone()
                }
            );
            assert_eq!(
                reopened
                    .complete(&request, &invocation(), status, body.clone())
                    .unwrap(),
                reopened
            );
            assert!(reopened
                .complete(&request, &invocation(), status, json!({"replacement":true}))
                .is_err());
            assert!(reopened
                .complete(&request, &invocation(), status + 1, body)
                .is_err());
            let changed = Envelope::new(
                invocation(),
                json!({"protocol":"whip-executor/1", "effect_id":"effect", "stdin":"different"}),
            )
            .unwrap();
            assert!(Receipt::claim(Some(&reopened), &changed, &invocation()).is_err());
            assert!(cold
                .complete(&changed, &invocation(), status, json!({}))
                .is_err());
        }
    }
}
