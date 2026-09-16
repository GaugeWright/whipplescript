//! Immutable provider placement retained before forwarding an invocation.
//! A placement identifies where to reconcile; it is not evidence of worker death.
use crate::exec_invocation::{Claim, Envelope, Invocation, Receipt};
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "whipplescript.exec.placement/v1";
const CONTROLLER_PROTOCOL: &str = "whipplescript.exec.placement/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Placement {
    protocol: String,
    pub(crate) selected: Invocation,
    envelope: Envelope,
    pub(crate) container_id: String,
    pub(crate) dispatch_id: String,
}

/// The broker calls this inside its owning transaction, after scheduler
/// admission and before external I/O. Replaying an acknowledgment never grants
/// another dispatch; only the original claim owner may forward.
pub fn bind_json(
    selected: &str,
    requested: &str,
    receipt: &str,
    stored: Option<&str>,
    container_id: &str,
    dispatch_id: &str,
) -> Result<String, String> {
    bind_with_protocol(
        PROTOCOL,
        selected,
        requested,
        receipt,
        stored,
        container_id,
        dispatch_id,
    )
}

/// New controller-mediated deliveries only. The existing immutable v1
/// placement cannot be upgraded to assert that an old delivery used this gate.
pub fn bind_controller_json(
    selected: &str,
    requested: &str,
    receipt: &str,
    stored: Option<&str>,
    container_id: &str,
    dispatch_id: &str,
) -> Result<String, String> {
    bind_with_protocol(
        CONTROLLER_PROTOCOL,
        selected,
        requested,
        receipt,
        stored,
        container_id,
        dispatch_id,
    )
}

/// Validate a retained placement before a broker status query. Legacy
/// placement cannot acquire controller evidence by being read by newer code.
pub fn controller_target_json(
    selected: &str,
    requested: &str,
    receipt: &str,
    stored: &str,
) -> Result<String, String> {
    let placement: Placement = serde_json::from_str(stored).map_err(|e| e.to_string())?;
    let original = bind_with_protocol(
        &placement.protocol,
        selected,
        requested,
        receipt,
        Some(stored),
        &placement.container_id,
        &placement.dispatch_id,
    )?;
    if placement.protocol == PROTOCOL {
        return Ok(serde_json::json!({"action":"legacy_pending"}).to_string());
    }
    placement.validate_controller(&placement.container_id)?;
    Ok(serde_json::json!({"action":"query","container_id":placement.container_id,"placement":serde_json::from_str::<serde_json::Value>(&original).map_err(|e|e.to_string())?}).to_string())
}

fn bind_with_protocol(
    protocol: &str,
    selected: &str,
    requested: &str,
    receipt: &str,
    stored: Option<&str>,
    container_id: &str,
    dispatch_id: &str,
) -> Result<String, String> {
    let selected: Invocation = serde_json::from_str(selected).map_err(|e| e.to_string())?;
    let envelope: Envelope = serde_json::from_str(requested).map_err(|e| e.to_string())?;
    let receipt: Receipt = serde_json::from_str(receipt).map_err(|e| e.to_string())?;
    let claim = Receipt::claim(Some(&receipt), &envelope, &selected)?;
    if container_id.is_empty() || dispatch_id.is_empty() {
        return Err("executor placement requires a container and dispatch identity".into());
    }
    let requested = Placement {
        protocol: protocol.into(),
        selected,
        envelope,
        container_id: container_id.into(),
        dispatch_id: dispatch_id.into(),
    };
    if let Some(stored) = stored {
        let stored: Placement = serde_json::from_str(stored).map_err(|e| e.to_string())?;
        if stored != requested {
            return Err("executor placement cannot be replaced".into());
        }
    } else if !matches!(claim, Claim::Pending) {
        return Err("executor placement requires an unresolved provider claim".into());
    }
    serde_json::to_string(&requested).map_err(|e| e.to_string())
}

impl Placement {
    pub(crate) fn dispatch(&self) -> Result<&serde_json::Value, String> {
        self.validate_controller(&self.container_id)?;
        self.envelope.dispatch(&self.selected)
    }

    pub(crate) fn validate_controller(&self, container_id: &str) -> Result<(), String> {
        self.envelope.validate(&self.selected)?;
        if self.protocol != CONTROLLER_PROTOCOL
            || self.container_id != container_id
            || container_id.is_empty()
            || self.dispatch_id.is_empty()
        {
            return Err("controller admission requires its own versioned placement".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_invocation;
    use serde_json::{json, Value};

    #[test]
    fn exec_placement_is_immutable_and_bound_to_its_provider_claim() {
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
        let claim: Value =
            serde_json::from_str(&exec_invocation::claim_json(&selected, &envelope, None).unwrap())
                .unwrap();
        let receipt = claim["decision"]["receipt"].to_string();
        let placed = bind_json(
            &selected,
            &envelope,
            &receipt,
            None,
            "instance-0",
            "dispatch-1",
        )
        .unwrap();
        assert_eq!(
            bind_json(
                &selected,
                &envelope,
                &receipt,
                Some(&placed),
                "instance-0",
                "dispatch-1"
            )
            .unwrap(),
            placed
        );
        for (container, dispatch) in [("", "dispatch-1"), ("instance-0", "")] {
            assert!(bind_json(&selected, &envelope, &receipt, None, container, dispatch).is_err());
        }
        for (container, dispatch) in [("instance-1", "dispatch-1"), ("instance-0", "dispatch-2")] {
            assert!(bind_json(
                &selected,
                &envelope,
                &receipt,
                Some(&placed),
                container,
                dispatch
            )
            .is_err());
        }
        for pointer in [
            "/protocol",
            "/selected/instance_id",
            "/selected/attempt_admission_event_id",
            "/envelope/dispatch/effect_id",
        ] {
            let mut replaced: Value = serde_json::from_str(&placed).unwrap();
            *replaced.pointer_mut(pointer).unwrap() = json!("other");
            assert!(bind_json(
                &selected,
                &envelope,
                &receipt,
                Some(&replaced.to_string()),
                "instance-0",
                "dispatch-1"
            )
            .is_err());
        }
        let mut foreign: Value = serde_json::from_str(&selected).unwrap();
        foreign["instance_id"] = json!("other");
        assert!(bind_json(
            &foreign.to_string(),
            &envelope,
            &receipt,
            None,
            "instance-0",
            "dispatch-1"
        )
        .is_err());
        let completed =
            exec_invocation::complete_json(&selected, &envelope, &receipt, 200, "{}").unwrap();
        assert!(bind_json(
            &selected,
            &envelope,
            &completed,
            None,
            "instance-0",
            "dispatch-1"
        )
        .is_err());
        assert_eq!(
            bind_json(
                &selected,
                &envelope,
                &completed,
                Some(&placed),
                "instance-0",
                "dispatch-1"
            )
            .unwrap(),
            placed
        );
        // Old unresolved receipts without placement remain pending. Absence of
        // a placement must never be reinterpreted as permission to dispatch.
        let replay: Value = serde_json::from_str(
            &exec_invocation::claim_json(&selected, &envelope, Some(&receipt)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay["decision"]["action"], "pending");
    }
}
