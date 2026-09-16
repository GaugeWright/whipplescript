//! A durable owner-wide admission barrier. Finishing is a trusted host seam:
//! the host must drain startup, destroy the container and drain completions
//! before calling it. No wire command here can establish physical termination.
use crate::exec_controller::{CompletionFence, Record, State};
use crate::exec_placement::Placement;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

const PROTOCOL: &str = "whipplescript.exec.barrier/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    placement: Placement,
    incarnation: String,
    fence_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Barrier {
    protocol: String,
    owner: String,
    // Decimal string preserves all u64 generations through JavaScript JSON.
    generation: String,
    barrier_id: String,
    closing: bool,
    targets: Vec<Target>,
}

fn key(placement: &Placement) -> String {
    json!([
        "whipplescript.exec.controller/v1",
        placement.container_id,
        placement.selected
    ])
    .to_string()
}

fn read(owner: &str, stored: Option<&str>) -> Result<Option<Barrier>, String> {
    let barrier: Option<Barrier> = stored
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| e.to_string())?;
    if let Some(barrier) = &barrier {
        let generation = barrier
            .generation
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        // Compare canonical serialized identity bytes, not a JSON array to a string.
        let expected_id = json!([PROTOCOL, owner, barrier.generation]).to_string();
        if owner.is_empty()
            || barrier.protocol != PROTOCOL
            || barrier.owner != owner
            || generation == 0
            || generation.to_string() != barrier.generation
            || barrier.barrier_id != expected_id
            || barrier.targets.is_empty()
        {
            return Err("executor barrier binding is invalid".into());
        }
        let mut unique = BTreeMap::new();
        for target in &barrier.targets {
            target.placement.validate_controller(owner)?;
            if target.incarnation.is_empty()
                || target.fence_id.is_empty()
                || unique.insert(key(&target.placement), ()).is_some()
            {
                return Err("executor barrier target is invalid or duplicated".into());
            }
        }
    } else if owner.is_empty() {
        return Err("executor barrier owner is empty".into());
    }
    Ok(barrier)
}

fn records(owner: &str, encoded: &str) -> Result<BTreeMap<String, Record>, String> {
    let values: Vec<Record> = serde_json::from_str(encoded).map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    for record in values {
        record.placement.validate_controller(owner)?;
        record.state.validate()?;
        if record.protocol != "whipplescript.exec.controller/v1"
            || result.insert(key(&record.placement), record).is_some()
        {
            return Err("executor barrier inventory is invalid or duplicated".into());
        }
    }
    Ok(result)
}

pub fn inspect_json(owner: &str, stored: Option<&str>) -> Result<String, String> {
    let barrier = read(owner, stored)?;
    Ok(match barrier {
        None => json!({"generation":"0","closing":false,"barrier_id":null}),
        Some(value) => json!({"generation":value.generation,"closing":value.closing,"barrier_id":value.barrier_id}),
    }.to_string())
}

pub(crate) fn blocks_admission(
    owner: &str,
    stored: Option<&str>,
    observed: &str,
) -> Result<Option<String>, String> {
    let barrier = read(owner, stored)?;
    let generation = barrier
        .as_ref()
        .map(|b| b.generation.as_str())
        .unwrap_or("0");
    if observed != generation || barrier.as_ref().is_some_and(|b| b.closing) {
        return barrier
            .map(|b| Some(b.barrier_id))
            .ok_or_else(|| "executor barrier generation disappeared".into());
    }
    Ok(None)
}

/// Apply returned inventory changes and barrier atomically before host I/O.
pub fn begin_json(owner: &str, stored: Option<&str>, inventory: &str) -> Result<String, String> {
    let prior = read(owner, stored)?;
    let mut records = records(owner, inventory)?;
    if let Some(prior) = &prior {
        if prior.closing {
            return Ok(json!({"barrier":prior,"updates":[],"closing":true}).to_string());
        }
    }
    let generation = prior
        .as_ref()
        .map(|b| b.generation.parse::<u64>())
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("executor barrier generation exhausted")?
        .to_string();
    let barrier_id = json!([PROTOCOL, owner, generation]).to_string();
    let mut targets = Vec::new();
    let mut updates = Vec::new();
    for (key, record) in &mut records {
        let previous = record.state.clone();
        match &mut record.state {
            State::Admitted { incarnation } => {
                record.state = State::Fencing {
                    incarnation: incarnation.clone(),
                    fence_id: barrier_id.clone(),
                }
            }
            State::Completed { fence, .. } if fence.is_none() => {
                *fence = Some(CompletionFence::Fencing {
                    fence_id: barrier_id.clone(),
                });
            }
            _ => {}
        }
        if record.state != previous {
            updates.push(json!({"storage_key":key,"record":record}));
        }
        if let Some((incarnation, fence_id)) = record.state.pending_fence() {
            targets.push(Target {
                placement: record.placement.clone(),
                incarnation: incarnation.into(),
                fence_id: fence_id.into(),
            });
        }
    }
    if targets.is_empty() {
        return Ok(json!({"barrier":prior,"updates":[],"closing":false}).to_string());
    }
    let barrier = Barrier {
        protocol: PROTOCOL.into(),
        owner: owner.into(),
        generation,
        barrier_id,
        closing: true,
        targets,
    };
    Ok(json!({"barrier":barrier,"updates":updates,"closing":true}).to_string())
}

/// Called only after the owner has completed the physical barrier. No caller
/// boolean or unbound stop observation substitutes for that host obligation.
pub fn finish_json(
    owner: &str,
    stored: &str,
    inventory: &str,
    completed_barrier_id: &str,
) -> Result<String, String> {
    let mut barrier = read(owner, Some(stored))?.ok_or("executor barrier is absent")?;
    if barrier.barrier_id != completed_barrier_id {
        return Err("executor barrier completion identity changed".into());
    }
    let mut records = records(owner, inventory)?;
    let mut targets = BTreeMap::new();
    for target in &barrier.targets {
        targets.insert(key(&target.placement), target);
    }
    for (key, record) in &records {
        if matches!(record.state, State::Admitted { .. } | State::Fencing { .. })
            && !targets.contains_key(key)
        {
            return Err("executor admission escaped the closing barrier".into());
        }
    }
    let mut updates = Vec::new();
    for (key, target) in targets {
        let record = records
            .get_mut(&key)
            .ok_or("executor barrier target disappeared")?;
        if record.placement != target.placement {
            return Err("executor barrier target placement changed".into());
        }
        match &record.state {
            State::Completed {
                incarnation,
                status,
                body,
                fence,
            } if incarnation == &target.incarnation => {
                let attach = match (fence, barrier.closing) {
                    // Older callbacks may have retained a result without the
                    // pending-fence field; the frozen target still binds it.
                    (None, true) => true,
                    (Some(CompletionFence::Fencing { fence_id }), true)
                        if fence_id == &target.fence_id =>
                    {
                        true
                    }
                    (
                        Some(CompletionFence::Terminated {
                            fence_id,
                            barrier_id,
                        }),
                        false,
                    ) if fence_id == &target.fence_id && barrier_id == &barrier.barrier_id => false,
                    _ => return Err("executor completed target fence changed".into()),
                };
                if attach {
                    record.state = State::Completed {
                        incarnation: incarnation.clone(),
                        status: *status,
                        body: body.clone(),
                        fence: Some(CompletionFence::Terminated {
                            fence_id: target.fence_id.clone(),
                            barrier_id: barrier.barrier_id.clone(),
                        }),
                    };
                    updates.push(json!({"storage_key":key,"record":record}));
                }
            }
            State::Fencing {
                incarnation,
                fence_id,
            } if barrier.closing
                && incarnation == &target.incarnation
                && fence_id == &target.fence_id =>
            {
                record.state = State::Terminated {
                    incarnation: incarnation.clone(),
                    fence_id: fence_id.clone(),
                    barrier_id: barrier.barrier_id.clone(),
                };
                updates.push(json!({"storage_key":key,"record":record}));
            }
            State::Terminated {
                incarnation,
                fence_id,
                barrier_id,
            } if !barrier.closing
                && incarnation == &target.incarnation
                && fence_id == &target.fence_id
                && barrier_id == &barrier.barrier_id => {}
            _ => return Err("executor barrier target lifecycle changed".into()),
        }
    }
    barrier.closing = false;
    Ok(json!({"barrier":barrier,"updates":updates,"closing":false}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exec_controller,
        exec_invocation::{self, Envelope, Invocation},
        exec_placement,
    };
    use serde_json::Value;

    fn placement(effect: &str) -> String {
        let selected =
            json!({"instance_id":"i","effect_id":effect,"attempt_admission_event_id":null})
                .to_string();
        let invocation: Invocation = serde_json::from_str(&selected).unwrap();
        let envelope = serde_json::to_string(
            &Envelope::new(
                invocation,
                json!({"protocol":"whip-executor/1","effect_id":effect}),
            )
            .unwrap(),
        )
        .unwrap();
        let claim: Value =
            serde_json::from_str(&exec_invocation::claim_json(&selected, &envelope, None).unwrap())
                .unwrap();
        exec_placement::bind_controller_json(
            &selected,
            &envelope,
            &claim["decision"]["receipt"].to_string(),
            None,
            "instance-0",
            effect,
        )
        .unwrap()
    }
    fn step(placement: &str, stored: Option<&Value>, operation: Value) -> Value {
        serde_json::from_str(
            &exec_controller::transition_json(
                "instance-0",
                placement,
                stored.map(Value::to_string).as_deref(),
                &operation.to_string(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn admitted(placement: &str) -> Value {
        step(
            placement,
            None,
            json!({"op":"admit","incarnation":"process-1"}),
        )["record"]
            .clone()
    }
    fn begin(stored: Option<&Value>, records: &[Value]) -> Value {
        serde_json::from_str(
            &begin_json(
                "instance-0",
                stored.map(Value::to_string).as_deref(),
                &json!(records).to_string(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn apply(records: &mut [Value], result: &Value) {
        for update in result["updates"].as_array().unwrap() {
            let record = records
                .iter_mut()
                .find(|r| r["placement"]["selected"] == update["record"]["placement"]["selected"])
                .unwrap();
            *record = update["record"].clone();
        }
    }

    #[test]
    fn exec_barrier_fences_siblings_and_preserves_completion_before_finish() {
        let a = placement("a");
        let b = placement("b");
        let mut records = vec![admitted(&a), admitted(&b)];
        records[0] = step(
            &a,
            Some(&records[0]),
            json!({"op":"fence","fence_id":"requested-fence"}),
        )["record"]
            .clone();
        let begun = begin(None, &records);
        assert_eq!(begun["barrier"]["generation"], "1");
        assert_eq!(begun["barrier"]["targets"].as_array().unwrap().len(), 2);
        apply(&mut records, &begun);
        assert_eq!(records[0]["state"]["fence_id"], "requested-fence");
        assert_eq!(records[1]["state"]["state"], "fencing");
        assert_eq!(
            begin(Some(&begun["barrier"]), &records)["barrier"],
            begun["barrier"],
            "resumption retains the snapshot"
        );
        records[0] = step(&a,Some(&records[0]),json!({"op":"complete","incarnation":"process-1","status":503,"body":{"original":true}}))["record"].clone();
        let original = records[0].clone();
        let finished: Value = serde_json::from_str(
            &finish_json(
                "instance-0",
                &begun["barrier"].to_string(),
                &json!(records).to_string(),
                begun["barrier"]["barrier_id"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        apply(&mut records, &finished);
        let mut expected = original;
        expected["state"]["fence"] = json!({"state":"terminated", "fence_id":"requested-fence", "barrier_id":begun["barrier"]["barrier_id"]});
        assert_eq!(records[0], expected);
        assert_eq!(records[1]["state"]["state"], "terminated");
        assert_eq!(
            records[1]["state"]["barrier_id"],
            begun["barrier"]["barrier_id"]
        );
        assert_eq!(finished["barrier"]["closing"], false);
        let repeated: Value = serde_json::from_str(
            &finish_json(
                "instance-0",
                &finished["barrier"].to_string(),
                &json!(records).to_string(),
                finished["barrier"]["barrier_id"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated["updates"], json!([]));
        assert_eq!(repeated["barrier"], finished["barrier"]);
        assert!(exec_controller::transition_json(
            "instance-0",
            &b,
            Some(&records[1].to_string()),
            r#"{"op":"complete","incarnation":"process-1","status":200,"body":{}}"#
        )
        .is_err());
        let replay = step(
            &b,
            Some(&records[1]),
            json!({"op":"fence","fence_id":"another-request"}),
        );
        assert_eq!(replay["action"]["action"], "terminated");
        assert_eq!(replay["record"], records[1]);
    }

    #[test]
    fn exec_barrier_attaches_lifetime_proof_to_an_all_completed_inventory() {
        let a = placement("completed-a");
        let b = placement("completed-b");
        let completion = json!({"op":"complete", "incarnation":"process-1", "status":200, "body":{"timed_out":true,"stdout":"retained"}});
        let mut inventory = [&a, &b]
            .map(|p| step(p, Some(&admitted(p)), completion.clone())["record"].clone())
            .to_vec();
        assert!(inventory.iter().all(|r| r["state"].get("fence").is_none()));
        let begun = begin(None, &inventory);
        assert_eq!(begun["barrier"]["targets"].as_array().unwrap().len(), 2);
        apply(&mut inventory, &begun);
        assert!(
            step(&a, Some(&inventory[0]), json!({"op":"read"}))["action"]
                .get("termination")
                .is_none()
        );
        let pending_inventory = inventory.clone();
        let id = begun["barrier"]["barrier_id"].as_str().unwrap();
        let finished: Value = serde_json::from_str(
            &finish_json(
                "instance-0",
                &begun["barrier"].to_string(),
                &json!(inventory).to_string(),
                id,
            )
            .unwrap(),
        )
        .unwrap();
        apply(&mut inventory, &finished);
        for (p, record) in [&a, &b].into_iter().zip(&inventory) {
            let replay = step(p, Some(record), json!({"op":"read"}));
            assert_eq!(replay["action"]["body"], completion["body"]);
            assert_eq!(replay["action"]["status"], 200);
            assert_eq!(
                replay["action"]["termination"],
                json!({"incarnation":"process-1", "fence_id":id, "barrier_id":id})
            );
            assert_eq!(step(p, Some(record), completion.clone()), replay);
            assert_eq!(
                step(p, Some(record), json!({"op":"fence","fence_id":"later"})),
                replay
            );
            for field in ["fence_id", "barrier_id"] {
                let mut corrupt = record.clone();
                corrupt["state"]["fence"][field] = json!("");
                assert!(exec_controller::transition_json(
                    "instance-0",
                    p,
                    Some(&corrupt.to_string()),
                    r#"{"op":"read"}"#
                )
                .is_err());
            }
        }
        assert_eq!(
            begin(Some(&finished["barrier"]), &inventory)["closing"],
            false
        );
        for field in ["fence_id", "barrier_id"] {
            let mut corrupt = inventory.clone();
            corrupt[0]["state"]["fence"][field] = json!("changed");
            assert_eq!(
                finish_json(
                    "instance-0",
                    &finished["barrier"].to_string(),
                    &json!(corrupt).to_string(),
                    id
                )
                .unwrap_err(),
                "executor completed target fence changed"
            );
        }
        let mut legacy_callback = pending_inventory.clone();
        legacy_callback[0]["state"]
            .as_object_mut()
            .unwrap()
            .remove("fence");
        assert!(finish_json(
            "instance-0",
            &begun["barrier"].to_string(),
            &json!(legacy_callback).to_string(),
            id
        )
        .is_ok());
        let mut empty_pending = pending_inventory.clone();
        empty_pending[0]["state"]["fence"]["fence_id"] = json!("");
        assert!(exec_controller::transition_json(
            "instance-0",
            &a,
            Some(&empty_pending[0].to_string()),
            r#"{"op":"read"}"#
        )
        .is_err());
        let mut pending_corrupt = pending_inventory.clone();
        pending_corrupt[0]["state"]["fence"] = json!({"state":"fencing","fence_id":"changed"});
        assert_eq!(
            finish_json(
                "instance-0",
                &begun["barrier"].to_string(),
                &json!(pending_corrupt).to_string(),
                id
            )
            .unwrap_err(),
            "executor completed target fence changed"
        );
    }

    #[test]
    fn exec_barrier_blocks_new_admission_and_stale_startup_after_reopening() {
        let a = placement("a");
        let fresh = placement("fresh");
        let mut records = vec![admitted(&a)];
        let begun = begin(None, &records);
        apply(&mut records, &begun);
        let finished: Value = serde_json::from_str(
            &finish_json(
                "instance-0",
                &begun["barrier"].to_string(),
                &json!(records).to_string(),
                begun["barrier"]["barrier_id"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        for (barrier, observed) in [
            (&begun["barrier"], "0"),
            (&begun["barrier"], "1"),
            (&finished["barrier"], "0"),
        ] {
            let result: Value = serde_json::from_str(
                &exec_controller::transition_with_gate_json(
                    "instance-0",
                    &fresh,
                    None,
                    r#"{"op":"admit","incarnation":"process-1"}"#,
                    Some(&barrier.to_string()),
                    observed,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(result["action"]["action"], "blocked");
            assert!(result["record"].is_null());
        }
        let result: Value = serde_json::from_str(
            &exec_controller::transition_with_gate_json(
                "instance-0",
                &fresh,
                None,
                r#"{"op":"admit","incarnation":"process-2"}"#,
                Some(&finished["barrier"].to_string()),
                "1",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["action"]["action"], "execute");
        assert!(exec_controller::transition_with_gate_json(
            "instance-0",
            &fresh,
            None,
            r#"{"op":"admit","incarnation":"process-2"}"#,
            None,
            "1"
        )
        .is_err());
        apply(&mut records, &finished);
        records.push(result["record"].clone());
        let next = begin(Some(&finished["barrier"]), &records);
        assert_eq!(next["barrier"]["generation"], "2");
        assert!(finish_json(
            "instance-0",
            &next["barrier"].to_string(),
            &json!(records).to_string(),
            finished["barrier"]["barrier_id"].as_str().unwrap()
        )
        .is_err());
        assert_eq!(begin(None, &[])["barrier"], Value::Null);
    }

    #[test]
    fn exec_barrier_refuses_inventory_binding_loss_and_generation_corruption() {
        let a = placement("a");
        let mut inventory = vec![admitted(&a)];
        let begun = begin(None, &inventory);
        apply(&mut inventory, &begun);
        let barrier = begun["barrier"].clone();
        let id = barrier["barrier_id"].as_str().unwrap();
        assert_eq!(
            finish_json(
                "instance-0",
                &barrier.to_string(),
                &json!(inventory).to_string(),
                "wrong-barrier"
            )
            .unwrap_err(),
            "executor barrier completion identity changed"
        );
        let mut escaped = inventory.clone();
        escaped.push(admitted(&placement("escaped")));
        for records in [
            vec![],
            vec![inventory[0].clone(), inventory[0].clone()],
            escaped,
        ] {
            assert!(finish_json(
                "instance-0",
                &barrier.to_string(),
                &json!(records).to_string(),
                id
            )
            .is_err());
        }
        for (pointer, value) in [
            ("/placement/dispatch_id", json!("changed")),
            ("/state/incarnation", json!("other")),
            ("/state/fence_id", json!("other")),
            ("/protocol", json!("legacy")),
            ("/state/state", json!("admitted")),
        ] {
            let mut records = inventory.clone();
            *records[0].pointer_mut(pointer).unwrap() = value;
            assert!(finish_json(
                "instance-0",
                &barrier.to_string(),
                &json!(records).to_string(),
                id
            )
            .is_err());
        }
        // A well-formed regression must reach lifecycle validation rather than
        // being rejected for leftover fields from the fencing variant.
        let regressed = vec![admitted(&a)];
        assert_eq!(
            finish_json(
                "instance-0",
                &barrier.to_string(),
                &json!(regressed).to_string(),
                id
            )
            .unwrap_err(),
            "executor barrier target lifecycle changed"
        );
        for (field, value) in [
            ("owner", json!("other")),
            ("protocol", json!("legacy")),
            ("barrier_id", json!("other")),
            ("generation", json!("01")),
            ("generation", json!("0")),
            ("targets", json!([])),
            ("extra", json!(true)),
        ] {
            let mut corrupt = barrier.clone();
            corrupt[field] = value;
            assert!(inspect_json("instance-0", Some(&corrupt.to_string())).is_err());
        }
        for field in ["incarnation", "fence_id"] {
            let mut corrupt = barrier.clone();
            corrupt["targets"][0][field] = json!("");
            assert!(inspect_json("instance-0", Some(&corrupt.to_string())).is_err());
        }
        let mut duplicate = barrier.clone();
        duplicate["targets"]
            .as_array_mut()
            .unwrap()
            .push(barrier["targets"][0].clone());
        assert!(inspect_json("instance-0", Some(&duplicate.to_string())).is_err());
        assert!(inspect_json("", None).is_err());
        for generation in ["0", "01"] {
            let mut corrupt = barrier.clone();
            corrupt["generation"] = json!(generation);
            corrupt["barrier_id"] = json!(json!([PROTOCOL, "instance-0", generation]).to_string());
            assert!(inspect_json("instance-0", Some(&corrupt.to_string())).is_err());
        }
        let mut terminal = inventory.clone();
        terminal[0]["state"] =
            json!({"state":"terminated","incarnation":"process-1","fence_id":"f","barrier_id":"b"});
        assert!(begin_json("instance-0", None, &json!(terminal).to_string()).is_ok());
        for field in ["incarnation", "fence_id", "barrier_id"] {
            let mut corrupt = terminal.clone();
            corrupt[0]["state"][field] = json!("");
            assert!(begin_json("instance-0", None, &json!(corrupt).to_string()).is_err());
        }
        let mut exhausted = barrier.clone();
        exhausted["closing"] = json!(false);
        exhausted["generation"] = json!(u64::MAX.to_string());
        exhausted["barrier_id"] =
            json!(json!([PROTOCOL, "instance-0", u64::MAX.to_string()]).to_string());
        assert!(begin_json(
            "instance-0",
            Some(&exhausted.to_string()),
            &json!(inventory).to_string()
        )
        .is_err());
    }
}
