//! Provider-owned lifetime evidence, separate from immutable result receipts.
//! Observe is a trusted private controller-transport seam, never a public proof.
use crate::exec_controller::{response_action, Action};
use crate::exec_invocation::{Envelope, Invocation, Receipt};
use crate::exec_placement::{controller_target_json, Placement};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROTOCOL: &str = "whipplescript.exec.resolution/v1";

use whipplescript_store::exec_lifetime::LifetimeEvidence as Lifetime;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    protocol: String,
    placement: Placement,
    requested_fence_id: Option<String>,
    lifetime: Lifetime,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Read,
    Fence { fence_id: String },
    EnsureFence { fence_id: String },
    Observe { response: Value },
}

/// Fence-only preparation, inside the same transaction as resolution intent.
/// No dispatch decision escapes this seam. Old unmarked custody stays unknown.
pub fn prepare_fence_json(
    selected: &str,
    requested: &str,
    receipt: Option<&str>,
    placement: Option<&str>,
    container: &str,
    dispatch: &str,
    operation: &str,
) -> Result<String, String> {
    let op: Operation = serde_json::from_str(operation).map_err(|e| e.to_string())?;
    if !matches!(op, Operation::EnsureFence { fence_id } if !fence_id.is_empty()) {
        return Err("missing provider custody requires an explicit ensure_fence".into());
    }
    if placement.is_some() {
        return Err("fence preparation cannot replace existing placement".into());
    }
    let invocation: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let envelope: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    let receipt = match receipt {
        Some(receipt) => serde_json::from_str::<Receipt>(receipt).map_err(|e| e.to_string())?,
        None => match Receipt::claim(None, &envelope, &invocation)? {
            crate::exec_invocation::Claim::Dispatch { receipt } => receipt,
            _ => unreachable!("an absent claim creates only a guarded started receipt"),
        },
    };
    Receipt::claim(Some(&receipt), &envelope, &invocation)?;
    if !matches!(
        receipt,
        Receipt::Started {
            placement_required: true,
            ..
        }
    ) {
        return Err("provider claim without placement has no guarded custody".into());
    }
    let receipt_json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
    let placement = crate::exec_placement::bind_controller_json(
        selected,
        requested,
        &receipt_json,
        None,
        container,
        dispatch,
    )?;
    Ok(json!({"receipt":receipt,"placement":serde_json::from_str::<Value>(&placement).map_err(|e|e.to_string())?}).to_string())
}

/// Requires an existing provider receipt and immutable v2 placement. The host
/// commits returned record/receipt together before sending `query` or returning
/// `view`. No operation here can originate a claim, placement or dispatch.
pub fn transition_json(
    selected: &str,
    requested: &str,
    receipt: &str,
    placement: &str,
    stored: Option<&str>,
    operation: &str,
) -> Result<String, String> {
    let target: Value = serde_json::from_str(&controller_target_json(
        selected, requested, receipt, placement,
    )?)
    .map_err(|e| e.to_string())?;
    if target["action"] != "query" {
        return Err("provider lifetime requires controller placement".into());
    }
    let selected: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let requested: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    let mut receipt: Receipt = serde_json::from_str(receipt).map_err(|e| e.to_string())?;
    let bound: Placement = serde_json::from_str(placement).map_err(|e| e.to_string())?;
    let mut record = match stored {
        Some(stored) => serde_json::from_str::<Record>(stored).map_err(|e| e.to_string())?,
        None => Record {
            protocol: PROTOCOL.into(),
            placement: bound.clone(),
            requested_fence_id: None,
            lifetime: Lifetime::Pending,
        },
    };
    if record.protocol != PROTOCOL || record.placement != bound {
        return Err("provider lifetime differs from its retained placement".into());
    }
    if record.requested_fence_id.as_deref() == Some("") {
        return Err("provider fence intent identity is empty".into());
    }
    record.lifetime.validate()?;
    let operation: Operation = serde_json::from_str(operation).map_err(|e| e.to_string())?;
    let ensure_fence = matches!(&operation, Operation::EnsureFence { .. });
    let mut query = None;
    match operation {
        Operation::Read => {
            if record.lifetime == Lifetime::Pending {
                query = Some(json!({"op":"read"}));
            }
        }
        Operation::Fence { fence_id } | Operation::EnsureFence { fence_id } => {
            if fence_id.is_empty() {
                return Err("provider fence intent identity is empty".into());
            }
            if record.lifetime == Lifetime::Pending {
                if !ensure_fence
                    && record
                        .requested_fence_id
                        .as_ref()
                        .is_some_and(|old| old != &fence_id)
                {
                    return Err("provider fence intent cannot be replaced".into());
                }
                let retained = record.requested_fence_id.get_or_insert(fence_id);
                query = Some(json!({"op":"fence","fence_id":retained}));
            }
        }
        Operation::Observe { response } => {
            let mut observed = Lifetime::Pending;
            match response_action(placement, &response.to_string())? {
                Action::Replay {
                    status,
                    body,
                    termination,
                } => {
                    receipt = receipt.complete(&requested, &selected, status, body)?;
                    if let Some(proof) = termination {
                        observed = Lifetime::Terminated {
                            incarnation: proof.incarnation,
                            fence_id: proof.fence_id,
                            barrier_id: proof.barrier_id,
                        };
                    }
                }
                Action::NotAdmitted { fence_id } => observed = Lifetime::NotAdmitted { fence_id },
                Action::Terminated {
                    incarnation,
                    fence_id,
                    barrier_id,
                } => {
                    observed = Lifetime::Terminated {
                        incarnation,
                        fence_id,
                        barrier_id,
                    }
                }
                Action::Execute { .. } => {
                    return Err("controller reply cannot grant provider execution".into())
                }
                Action::Absent
                | Action::Blocked { .. }
                | Action::Pending { .. }
                | Action::FenceRequired { .. } => {}
            }
            observed.validate()?;
            if observed != Lifetime::Pending {
                if record.lifetime != Lifetime::Pending && record.lifetime != observed {
                    return Err("provider lifetime proof cannot be replaced".into());
                }
                record.lifetime = observed;
            }
        }
    }
    if matches!(record.lifetime, Lifetime::NotAdmitted { .. })
        && matches!(receipt, Receipt::Completed { .. })
    {
        return Err("provider non-admission contradicts retained completion".into());
    }
    let outcome = match &receipt {
        Receipt::Started { .. } => match record.lifetime {
            Lifetime::Pending => json!({"state":"pending"}),
            Lifetime::NotAdmitted { .. } => json!({"state":"not_executed"}),
            Lifetime::Terminated { .. } => json!({"state":"uncertain"}),
        },
        Receipt::Completed { status, body, .. } => {
            json!({"state":"completed","status":status,"body":body})
        }
    };
    Ok(json!({"record":record, "receipt":receipt, "query":query,
        "view":{"protocol":PROTOCOL,"selected":selected,"placement":bound,
            "lifetime":record.lifetime,"outcome":outcome}})
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{exec_invocation, exec_placement};

    fn fixture() -> (String, String, String, String) {
        let selected = json!({"instance_id":"i","effect_id":"e","attempt_admission_event_id":null})
            .to_string();
        let envelope = serde_json::to_string(
            &Envelope::new(
                serde_json::from_str(&selected).unwrap(),
                json!({"protocol":"whip-executor/1","effect_id":"e"}),
            )
            .unwrap(),
        )
        .unwrap();
        let claim: Value =
            serde_json::from_str(&exec_invocation::claim_json(&selected, &envelope, None).unwrap())
                .unwrap();
        let receipt = claim["decision"]["receipt"].to_string();
        let placement = exec_placement::bind_controller_json(
            &selected,
            &envelope,
            &receipt,
            None,
            "container",
            "dispatch",
        )
        .unwrap();
        (selected, envelope, receipt, placement)
    }

    fn step(
        f: &(String, String, String, String),
        stored: Option<&Value>,
        op: Value,
    ) -> Result<Value, String> {
        serde_json::from_str(&transition_json(
            &f.0,
            &f.1,
            &f.2,
            &f.3,
            stored.map(Value::to_string).as_deref(),
            &op.to_string(),
        )?)
        .map_err(|e| e.to_string())
    }
    fn observe(f: &(String, String, String, String), action: Value) -> Value {
        json!({"op":"observe","response":{"protocol":"whipplescript.exec.controller.response/v1",
            "placement":serde_json::from_str::<Value>(&f.3).unwrap(),"action":action}})
    }
    fn terminated() -> Value {
        json!({"action":"terminated","incarnation":"process","fence_id":"f","barrier_id":"b"})
    }

    #[test]
    fn exec_resolution_preplacement_requires_guarded_custody_and_explicit_fencing() {
        let f = fixture();
        let op = json!({"op":"ensure_fence","fence_id":"host-fence"}).to_string();
        for receipt in [None, Some(f.2.as_str())] {
            let prepared: Value = serde_json::from_str(
                &prepare_fence_json(&f.0, &f.1, receipt, None, "owner", "dispatch", &op).unwrap(),
            )
            .unwrap();
            assert_eq!(prepared["receipt"]["placement_required"], true);
            assert_eq!(
                prepared["placement"]["protocol"],
                "whipplescript.exec.placement/v2"
            );
            assert_eq!(prepared["placement"]["container_id"], "owner");
            let resolution: Value = serde_json::from_str(
                &transition_json(
                    &f.0,
                    &f.1,
                    &prepared["receipt"].to_string(),
                    &prepared["placement"].to_string(),
                    None,
                    &op,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                resolution["query"],
                json!({"op":"fence","fence_id":"host-fence"})
            );
            assert_eq!(resolution["view"]["lifetime"], json!({"state":"pending"}));
            assert!(crate::exec_placement::bind_controller_json(
                &f.0,
                &f.1,
                &prepared["receipt"].to_string(),
                Some(&prepared["placement"].to_string()),
                "owner",
                "late-dispatch"
            )
            .is_err());
        }
        let mut legacy: Value = serde_json::from_str(&f.2).unwrap();
        legacy.as_object_mut().unwrap().remove("placement_required");
        assert!(prepare_fence_json(
            &f.0,
            &f.1,
            Some(&legacy.to_string()),
            None,
            "owner",
            "dispatch",
            &op
        )
        .is_err());
        let pending: Value = serde_json::from_str(
            &crate::exec_invocation::claim_json(&f.0, &f.1, Some(&legacy.to_string())).unwrap(),
        )
        .unwrap();
        assert_eq!(pending["decision"]["action"], "pending");
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<Receipt>(legacy.clone()).unwrap())
                .unwrap(),
            legacy
        );
        let completed = crate::exec_invocation::complete_json(&f.0, &f.1, &f.2, 200, "{}").unwrap();
        assert!(
            prepare_fence_json(&f.0, &f.1, Some(&completed), None, "owner", "dispatch", &op)
                .is_err()
        );
        assert!(
            prepare_fence_json(&f.0, &f.1, None, Some(&f.3), "owner", "dispatch", &op).is_err()
        );
        for operation in [
            json!({"op":"read"}),
            json!({"op":"fence","fence_id":"f"}),
            json!({"op":"ensure_fence","fence_id":""}),
            json!({"op":"ensure_fence","fence_id":"f","response":{}}),
            json!({"op":"observe","response":{}}),
        ] {
            assert!(prepare_fence_json(
                &f.0,
                &f.1,
                None,
                None,
                "owner",
                "dispatch",
                &operation.to_string()
            )
            .is_err());
        }
        for (owner, dispatch) in [("", "dispatch"), ("owner", "")] {
            assert!(prepare_fence_json(&f.0, &f.1, None, None, owner, dispatch, &op).is_err());
        }
        let mut foreign: Value = serde_json::from_str(&f.2).unwrap();
        foreign["envelope"]["dispatch"]["foreign"] = json!(true);
        assert!(prepare_fence_json(
            &f.0,
            &f.1,
            Some(&foreign.to_string()),
            None,
            "owner",
            "dispatch",
            &op
        )
        .is_err());
    }

    #[test]
    fn exec_resolution_host_joins_original_fence_and_validates_closure() {
        let f = fixture();
        let first = step(&f, None, json!({"op":"fence","fence_id":"original"})).unwrap();
        let joined = step(
            &f,
            Some(&first["record"]),
            json!({"op":"ensure_fence","fence_id":"host"}),
        )
        .unwrap();
        assert_eq!(joined["record"], first["record"]);
        assert_eq!(joined["query"], json!({"op":"fence","fence_id":"original"}));
        assert!(step(
            &f,
            Some(&first["record"]),
            json!({"op":"fence","fence_id":"host"})
        )
        .is_err());
        assert!(step(
            &f,
            Some(&first["record"]),
            json!({"op":"ensure_fence","fence_id":""})
        )
        .is_err());
        assert_eq!(
            closure_json(&f.0, &f.1, &joined["view"].to_string()).unwrap(),
            None
        );
        let closed = step(&f, Some(&joined["record"]), observe(&f, terminated())).unwrap();
        let view = &closed["view"];
        let proof = closure_json(&f.0, &f.1, &view.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&proof).unwrap()["lifetime"]["fence_id"],
            "f"
        );
        let mut completed = view.clone();
        completed["outcome"] =
            json!({"state":"completed","status":200,"body":{"result":"original output"}});
        assert_eq!(
            closure_json(&f.0, &f.1, &completed.to_string()).unwrap(),
            Some(proof)
        );
        for pointer in [
            "/protocol",
            "/selected/effect_id",
            "/placement/protocol",
            "/placement/envelope/run_id",
            "/placement/container_id",
            "/placement/dispatch_id",
            "/lifetime/incarnation",
            "/lifetime/fence_id",
            "/lifetime/barrier_id",
        ] {
            let mut bad = view.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("");
            assert!(
                closure_json(&f.0, &f.1, &bad.to_string()).is_err(),
                "{pointer}"
            );
        }
        let mut bad = view.clone();
        bad["outcome"] = json!({"state":"pending"});
        assert!(closure_json(&f.0, &f.1, &bad.to_string()).is_err());
        let mut nonadmitted = view.clone();
        nonadmitted["lifetime"] = json!({"state":"not_admitted","fence_id":"never"});
        nonadmitted["outcome"] = json!({"state":"not_executed"});
        assert!(closure_json(&f.0, &f.1, &nonadmitted.to_string())
            .unwrap()
            .is_some());
        nonadmitted["outcome"] = completed["outcome"].clone();
        assert!(closure_json(&f.0, &f.1, &nonadmitted.to_string()).is_err());
    }

    #[test]
    fn exec_resolution_preserves_completed_output_and_lifetime_independently() {
        let mut f = fixture();
        let replay =
            json!({"action":"replay","status":200,"body":{"timed_out":true,"stdout":"original"}});
        let result = step(&f, None, observe(&f, replay.clone())).unwrap();
        f.2 = result["receipt"].to_string();
        assert_eq!(result["view"]["lifetime"]["state"], "pending");
        let intent = step(
            &f,
            Some(&result["record"]),
            json!({"op":"fence","fence_id":"requested"}),
        )
        .unwrap();
        assert_eq!(
            intent["query"],
            json!({"op":"fence","fence_id":"requested"})
        );
        assert_eq!(intent["record"]["requested_fence_id"], "requested");
        assert_eq!(intent["receipt"], result["receipt"]);
        assert_eq!(
            step(
                &f,
                Some(&intent["record"]),
                json!({"op":"fence","fence_id":"other"})
            )
            .unwrap_err(),
            "provider fence intent cannot be replaced"
        );
        let mut proof = replay.clone();
        proof["termination"] = json!({"incarnation":"process","fence_id":"f","barrier_id":"b"});
        let resolved = step(&f, Some(&intent["record"]), observe(&f, proof.clone())).unwrap();
        assert_eq!(resolved["view"]["lifetime"]["state"], "terminated");
        assert_eq!(resolved["receipt"], result["receipt"]);
        assert_eq!(resolved["view"]["outcome"]["body"], replay["body"]);
        let stale = step(&f, Some(&resolved["record"]), observe(&f, replay)).unwrap();
        assert_eq!(stale["record"], resolved["record"]);
        assert!(
            step(&f, Some(&resolved["record"]), json!({"op":"read"})).unwrap()["query"].is_null()
        );
        proof["body"] = json!({"changed":true});
        assert_eq!(
            step(&f, Some(&resolved["record"]), observe(&f, proof)).unwrap_err(),
            "executor provider response cannot be replaced"
        );
        assert_eq!(
            step(
                &f,
                None,
                observe(&f, json!({"action":"not_admitted","fence_id":"f"}))
            )
            .unwrap_err(),
            "provider non-admission contradicts retained completion"
        );
    }

    #[test]
    fn exec_resolution_requires_exact_proof_and_retains_uncertainty() {
        let f = fixture();
        assert_eq!(
            step(&f, None, json!({"op":"read"})).unwrap()["query"],
            json!({"op":"read"})
        );
        for action in [
            json!({"action":"absent"}),
            json!({"action":"pending","incarnation":"p"}),
            json!({"action":"fence_required","incarnation":"p","fence_id":"f"}),
        ] {
            let result = step(&f, None, observe(&f, action)).unwrap();
            assert_eq!(result["view"]["lifetime"]["state"], "pending");
            assert_eq!(result["view"]["outcome"]["state"], "pending");
        }
        let resolved = step(&f, None, observe(&f, terminated())).unwrap();
        assert_eq!(resolved["view"]["lifetime"]["state"], "terminated");
        assert_eq!(resolved["view"]["outcome"]["state"], "uncertain");
        for field in ["incarnation", "fence_id", "barrier_id"] {
            let mut empty = terminated();
            empty[field] = json!("");
            assert_eq!(
                step(&f, None, observe(&f, empty)).unwrap_err(),
                "provider termination binding is empty"
            );
            let mut changed = terminated();
            changed[field] = json!("foreign");
            assert_eq!(
                step(&f, Some(&resolved["record"]), observe(&f, changed)).unwrap_err(),
                "provider lifetime proof cannot be replaced"
            );
        }
        let not_admitted = step(
            &f,
            None,
            observe(&f, json!({"action":"not_admitted","fence_id":"f"})),
        )
        .unwrap();
        assert_eq!(not_admitted["view"]["lifetime"]["state"], "not_admitted");
        assert_eq!(not_admitted["view"]["outcome"]["state"], "not_executed");
        assert_eq!(
            step(
                &f,
                None,
                observe(&f, json!({"action":"not_admitted","fence_id":""}))
            )
            .unwrap_err(),
            "provider non-admission fence identity is empty"
        );
        assert_eq!(
            step(
                &f,
                None,
                observe(&f, json!({"action":"execute","incarnation":"p"}))
            )
            .unwrap_err(),
            "controller reply cannot grant provider execution"
        );
        let replay = observe(
            &f,
            json!({"action":"replay","status":200,"body":{"stdout":"raced"}}),
        );
        let late = step(&f, Some(&resolved["record"]), replay.clone()).unwrap();
        assert_eq!(late["view"]["outcome"]["state"], "completed");
        assert_eq!(late["record"], resolved["record"]);
        assert_eq!(
            step(&f, Some(&not_admitted["record"]), replay).unwrap_err(),
            "provider non-admission contradicts retained completion"
        );
        for pointer in [
            "/protocol",
            "/placement/dispatch_id",
            "/placement/container_id",
            "/placement/selected/attempt_admission_event_id",
        ] {
            let mut altered = observe(&f, terminated());
            *altered["response"].pointer_mut(pointer).unwrap() = json!("other");
            assert_eq!(
                step(&f, None, altered).unwrap_err(),
                "controller reply differs from its retained placement"
            );
        }
        for pointer in ["/protocol", "/placement/dispatch_id"] {
            let mut altered = resolved["record"].clone();
            *altered.pointer_mut(pointer).unwrap() = json!("other");
            assert_eq!(
                step(&f, Some(&altered), json!({"op":"read"})).unwrap_err(),
                "provider lifetime differs from its retained placement"
            );
        }
        let mut invalid = resolved["record"].clone();
        invalid["requested_fence_id"] = json!("");
        assert_eq!(
            step(&f, Some(&invalid), json!({"op":"read"})).unwrap_err(),
            "provider fence intent identity is empty"
        );
        assert_eq!(
            step(&f, None, json!({"op":"fence","fence_id":""})).unwrap_err(),
            "provider fence intent identity is empty"
        );
        let mut legacy = f.clone();
        let mut placed: Value = serde_json::from_str(&f.3).unwrap();
        placed["protocol"] = json!("whipplescript.exec.placement/v1");
        legacy.3 = placed.to_string();
        assert_eq!(
            step(&legacy, None, json!({"op":"read"})).unwrap_err(),
            "provider lifetime requires controller placement"
        );
    }
    #[test]
    fn exec_resolution_refuses_corrupt_retained_lifetime_before_replay() {
        let f = fixture();
        let original = step(&f, None, observe(&f, terminated())).unwrap();
        for field in ["incarnation", "fence_id", "barrier_id"] {
            let mut corrupt = original["record"].clone();
            corrupt["lifetime"][field] = json!("");
            assert_eq!(
                step(&f, Some(&corrupt), json!({"op":"read"})).unwrap_err(),
                "provider termination binding is empty"
            );
        }
        let original = step(
            &f,
            None,
            observe(&f, json!({"action":"not_admitted","fence_id":"original"})),
        )
        .unwrap();
        let mut corrupt = original["record"].clone();
        corrupt["lifetime"]["fence_id"] = json!("");
        assert_eq!(
            step(&f, Some(&corrupt), json!({"op":"read"})).unwrap_err(),
            "provider non-admission fence identity is empty"
        );
        assert_eq!(
            step(&f, Some(&original["record"]), json!({"op":"read"})).unwrap()["view"]["outcome"]
                ["state"],
            "not_executed"
        );
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    protocol: String,
    selected: Invocation,
    placement: Placement,
    lifetime: Lifetime,
    outcome: Outcome,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Pending,
    NotExecuted,
    Uncertain,
    Completed { status: u16, body: Value },
}

/// Private broker-response validation. Pending is not closure; no caller body
/// outside that transport seam may be passed here as evidence.
fn validated_view(selected: &str, requested: &str, response: &str) -> Result<View, String> {
    let expected: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let envelope: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    envelope.validate(&expected)?;
    let view: View = serde_json::from_str(response).map_err(|e| e.to_string())?;
    if view.protocol != PROTOCOL || view.selected != expected {
        return Err("broker closure view differs from selected invocation".into());
    }
    view.lifetime.validate()?;
    let receipt = match &view.outcome {
        Outcome::Completed { status, body } => Receipt::Completed {
            envelope: envelope.clone(),
            status: *status,
            body: body.clone(),
        },
        _ => Receipt::Started {
            envelope: envelope.clone(),
            placement_required: false,
        },
    };
    let target: Value = serde_json::from_str(&controller_target_json(
        selected,
        requested,
        &serde_json::to_string(&receipt).map_err(|e| e.to_string())?,
        &serde_json::to_string(&view.placement).map_err(|e| e.to_string())?,
    )?)
    .map_err(|e| e.to_string())?;
    if target["action"] != "query" {
        return Err("broker closure requires controller placement".into());
    }
    if !matches!(
        (&view.lifetime, &view.outcome),
        (
            Lifetime::Pending,
            Outcome::Pending | Outcome::Completed { .. }
        ) | (Lifetime::NotAdmitted { .. }, Outcome::NotExecuted)
            | (
                Lifetime::Terminated { .. },
                Outcome::Uncertain | Outcome::Completed { .. }
            )
    ) {
        return Err("broker closure outcome contradicts lifetime evidence".into());
    }
    Ok(view)
}

pub fn closure_json(
    selected: &str,
    requested: &str,
    response: &str,
) -> Result<Option<String>, String> {
    let view = validated_view(selected, requested, response)?;
    if view.lifetime == Lifetime::Pending {
        return Ok(None);
    }
    Ok(Some(
        serde_json::to_string(&whipplescript_store::exec_lifetime::Closure {
            placement: serde_json::to_value(view.placement).map_err(|e| e.to_string())?,
            lifetime: view.lifetime,
        })
        .map_err(|e| e.to_string())?,
    ))
}

/// Retain resolved broker output independently from physical closure.
pub fn outcome_json(
    selected: &str,
    requested: &str,
    response: &str,
) -> Result<Option<Value>, String> {
    let view = validated_view(selected, requested, response)?;
    if matches!(view.outcome, Outcome::Pending) {
        return Ok(None);
    }
    Ok(Some(
        json!({"placement":view.placement,"outcome":view.outcome}),
    ))
}
