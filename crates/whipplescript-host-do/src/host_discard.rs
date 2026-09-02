use whipplescript_kernel::host_protocol::{PolicyEpochRef, StartTurnCommand};
use whipplescript_store::{EffectView, EventView};

pub const DISCARDED_FORK_REASON: &str = "embedding host did not admit fork";

pub fn has_fork_evidence(
    events: &[EventView],
    instance_ref: &str,
    policy: &PolicyEpochRef,
) -> bool {
    let Ok(policy) = serde_json::to_value(policy) else {
        return false;
    };
    events.iter().any(|event| {
        event.event_type == "host.instance.forked"
            && serde_json::from_str::<serde_json::Value>(&event.payload_json)
                .ok()
                .is_some_and(|payload| {
                    payload
                        .get("target_instance_ref")
                        .and_then(serde_json::Value::as_str)
                        == Some(instance_ref)
                        && payload.get("policy") == Some(&policy)
                })
    })
}

pub fn is_admitted_turn(input_json: &str, instance_ref: &str) -> bool {
    serde_json::from_str::<StartTurnCommand>(input_json)
        .ok()
        .is_some_and(|turn| turn.instance_ref == instance_ref)
}

pub fn validate_discard_eligibility(
    instance_ref: &str,
    policy: &PolicyEpochRef,
    metadata: &serde_json::Value,
    events: &[EventView],
    effects: &[EffectView],
) -> Result<(), &'static str> {
    if metadata.get("protocol").and_then(serde_json::Value::as_str)
        != Some(whipplescript_kernel::host_protocol::HOST_PROTOCOL)
        || metadata.get("policy") != serde_json::to_value(policy).ok().as_ref()
    {
        return Err("discarded instance does not belong to the admitted host policy");
    }
    if !has_fork_evidence(events, instance_ref, policy) {
        return Err("only an unadmitted host fork target can be discarded");
    }
    if effects
        .iter()
        .any(|effect| is_admitted_turn(&effect.input_json, instance_ref))
    {
        return Err("a host fork target with an admitted turn cannot be discarded");
    }
    Ok(())
}

pub fn verify_discard_event(
    events: &[EventView],
    event_id: &str,
    instance_ref: &str,
) -> Result<(), &'static str> {
    let event = events
        .iter()
        .find(|event| event.event_id == event_id)
        .ok_or("discard idempotency key names no readable event")?;
    let payload: serde_json::Value = serde_json::from_str(&event.payload_json)
        .map_err(|_| "discard idempotency event payload is invalid")?;
    if event.event_type != "instance.transitioned"
        || payload
            .get("instance_id")
            .and_then(serde_json::Value::as_str)
            != Some(instance_ref)
        || payload.get("status").and_then(serde_json::Value::as_str) != Some("cancelled")
        || payload.get("reason").and_then(serde_json::Value::as_str) != Some(DISCARDED_FORK_REASON)
    {
        return Err("discard idempotency key belongs to a different operation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event_type: &str, payload_json: &str) -> EventView {
        EventView {
            event_id: "event-1".to_owned(),
            sequence: 1,
            event_type: event_type.to_owned(),
            payload_json: payload_json.to_owned(),
            source: "test".to_owned(),
            occurred_at: "t1".to_owned(),
        }
    }

    fn effect(input_json: String) -> EffectView {
        EffectView {
            effect_id: "effect-1".to_owned(),
            kind: "turn".to_owned(),
            target: None,
            input_json,
            status: "queued".to_owned(),
            created_by_rule: "host".to_owned(),
            program_version_id: None,
            revision_epoch: 0,
            profile: None,
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
            policy_block_reason: None,
            policy_block_category: None,
            cancel_requested: false,
        }
    }

    #[test]
    fn discard_replay_accepts_only_the_exact_cancellation_event() {
        let unrelated = event(
            "host.instance.opened",
            r#"{"instance_id":"fork-1","status":"running"}"#,
        );
        assert_eq!(
            verify_discard_event(&[unrelated], "event-1", "fork-1"),
            Err("discard idempotency key belongs to a different operation")
        );

        let cancellation = event(
            "instance.transitioned",
            &serde_json::json!({
                "instance_id": "fork-1",
                "status": "cancelled",
                "reason": DISCARDED_FORK_REASON,
            })
            .to_string(),
        );
        assert_eq!(
            verify_discard_event(&[cancellation], "event-1", "fork-1"),
            Ok(())
        );
    }

    #[test]
    fn discard_eligibility_requires_fork_evidence_and_no_admitted_turn() {
        let policy = PolicyEpochRef {
            epoch: 7,
            envelope_hash: "envelope".to_owned(),
            signer: "gaugedesk".to_owned(),
            key_id: None,
        };
        let fork = event(
            "host.instance.forked",
            &serde_json::json!({
                "target_instance_ref": "fork-1",
                "policy": policy,
            })
            .to_string(),
        );
        assert!(!has_fork_evidence(&[], "root-1", &policy));
        assert!(has_fork_evidence(&[fork], "fork-1", &policy));

        let admitted = serde_json::json!({
            "protocol": "whipplescript.host.v1",
            "command_id": "turn-1",
            "run_ref": "run-1",
            "instance_ref": "fork-1",
            "package_version_ref": "package-1",
            "policy": policy,
            "actor_ref": "user-1",
            "input": { "text": "hello", "images": [] },
            "resources": [],
            "provider_binding": {
                "binding_id": "model",
                "credential": { "credential_id": "managed" }
            },
            "placement_ceiling_ref": "do"
        })
        .to_string();
        assert!(is_admitted_turn(&admitted, "fork-1"));
        assert!(!is_admitted_turn("{}", "fork-1"));

        let metadata = serde_json::json!({
            "protocol": whipplescript_kernel::host_protocol::HOST_PROTOCOL,
            "policy": policy,
        });
        assert_eq!(
            validate_discard_eligibility("fork-1", &policy, &serde_json::json!({}), &[], &[],),
            Err("discarded instance does not belong to the admitted host policy")
        );
        assert_eq!(
            validate_discard_eligibility("fork-1", &policy, &metadata, &[], &[]),
            Err("only an unadmitted host fork target can be discarded")
        );
        let fork = event(
            "host.instance.forked",
            &serde_json::json!({
                "target_instance_ref": "fork-1",
                "policy": policy,
            })
            .to_string(),
        );
        assert_eq!(
            validate_discard_eligibility(
                "fork-1",
                &policy,
                &metadata,
                std::slice::from_ref(&fork),
                &[effect(admitted)],
            ),
            Err("a host fork target with an admitted turn cannot be discarded")
        );
        assert_eq!(
            validate_discard_eligibility("fork-1", &policy, &metadata, &[fork], &[]),
            Ok(())
        );
    }
}
