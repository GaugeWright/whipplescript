//! A currently authorized request to publish one retained tracker result.
use super::{
    action::{canonical_json, ActionAdmissionReceipt, ActionProvenance},
    nonempty, PolicyEpochRef, ProtocolError,
};
use serde::{Deserialize, Serialize};

pub const TRACKER_RECOVERY_PROTOCOL: &str = "whipplescript.tracker-result-delivery.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverTrackerResult {
    pub protocol: String,
    pub issuer: String,
    pub scope: String,
    pub admission: ActionAdmissionReceipt,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub policy: PolicyEpochRef,
    pub provenance: ActionProvenance,
    pub effect_id: String,
    pub run_id: String,
}

/// The signed protocol binds one original effect/run. Each recovery door
/// independently checks the fixed operation kind in its authenticated history.
pub type RecoverTrackerFiling = RecoverTrackerResult;
pub type RecoverTrackerClosure = RecoverTrackerResult;

impl RecoverTrackerResult {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.protocol != TRACKER_RECOVERY_PROTOCOL
            || self.admission.protocol != super::action::HOST_ACTION_PROTOCOL
        {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        for (name, value) in [
            ("tracker recovery issuer", &self.issuer),
            ("tracker recovery scope", &self.scope),
            ("tracker recovery effect", &self.effect_id),
            ("tracker recovery run", &self.run_id),
            ("tracker recovery instance", &self.admission.instance_ref),
            (
                "tracker recovery admission fingerprint",
                &self.admission.fingerprint,
            ),
            (
                "tracker recovery admission digest",
                &self.admission.admitted_at.head_digest,
            ),
        ] {
            nonempty(name, value)?;
        }
        if self.admission.admitted_at.sequence == 0
            || self.admission.admitted_at.instance_ref != self.admission.instance_ref
        {
            return Err(ProtocolError::Mismatch(
                "tracker recovery admission coordinates",
            ));
        }
        self.policy.validate()?;
        self.provenance.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| ProtocolError::Invalid("tracker recovery serialization"))?;
        let mut bytes = b"whipplescript:tracker-result-delivery:request:v1\0".to_vec();
        canonical_json(&value, &mut bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_recovery_wire_requires_complete_original_coordinates() {
        let original = super::super::action::tests::command();
        let request = RecoverTrackerFiling {
            protocol: TRACKER_RECOVERY_PROTOCOL.into(),
            issuer: original.issuer,
            scope: original.scope,
            policy: original.policy,
            provenance: original.provenance,
            effect_id: "effect:1".into(),
            run_id: "run:1".into(),
            admission: ActionAdmissionReceipt {
                protocol: super::super::action::HOST_ACTION_PROTOCOL.into(),
                fingerprint: "original-fingerprint".into(),
                instance_ref: "instance:1".into(),
                admitted_at: super::super::PinnedPosition {
                    instance_ref: "instance:1".into(),
                    sequence: 2,
                    head_digest: "digest".into(),
                },
            },
        };
        request.signing_bytes().unwrap();
        for case in [
            "protocol",
            "admission-protocol",
            "issuer",
            "scope",
            "effect",
            "run",
            "instance",
            "fingerprint",
            "digest",
            "sequence",
            "position-instance",
        ] {
            let mut changed = request.clone();
            match case {
                "protocol" => changed.protocol = "unknown".into(),
                "admission-protocol" => changed.admission.protocol = "unknown".into(),
                "issuer" => changed.issuer.clear(),
                "scope" => changed.scope.clear(),
                "effect" => changed.effect_id.clear(),
                "run" => changed.run_id.clear(),
                "instance" => changed.admission.instance_ref.clear(),
                "fingerprint" => changed.admission.fingerprint.clear(),
                "digest" => changed.admission.admitted_at.head_digest.clear(),
                "sequence" => changed.admission.admitted_at.sequence = 0,
                "position-instance" => {
                    changed.admission.admitted_at.instance_ref = "another".into()
                }
                _ => unreachable!(),
            }
            assert!(changed.signing_bytes().is_err(), "{case}");
        }
        let mut extra = serde_json::to_value(&request).unwrap();
        extra["unexpected"] = true.into();
        assert!(serde_json::from_value::<RecoverTrackerFiling>(extra).is_err());
    }
}
