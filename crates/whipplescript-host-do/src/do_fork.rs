//! Testable admission checks shared by the hosted fork export/import doors.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use whipplescript_kernel::host_protocol::{EventPosition, PolicyEpochRef, HOST_PROTOCOL};
use whipplescript_kernel::ifc::VerifiedEnvelope;
use whipplescript_store::event_chain::{fold_owned, ChainHead, OwnedChainEntry};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct CarriedRead {
    pub handle: String,
    pub resolved: String,
}

pub(crate) fn record_turn_read(
    envelope: &VerifiedEnvelope,
    reads: &mut BTreeMap<String, String>,
    handle: &str,
) -> Result<(), &'static str> {
    if !envelope.governs(handle) {
        return Err("source policy does not govern a carried read");
    }
    let resolved = envelope.resolve_handle(handle).to_owned();
    if reads
        .insert(handle.to_owned(), resolved.clone())
        .is_some_and(|earlier| earlier != resolved)
    {
        return Err("carried read handle changed identity");
    }
    Ok(())
}

pub(crate) fn record_inherited_read(
    reads: &mut BTreeMap<String, String>,
    read: CarriedRead,
) -> Result<(), &'static str> {
    if reads
        .insert(read.handle, read.resolved.clone())
        .is_some_and(|earlier| earlier != read.resolved)
    {
        return Err("carried read handle changed identity");
    }
    Ok(())
}

pub(crate) fn verified_source_chain_digest(
    instance_ref: &str,
    rows: &[OwnedChainEntry],
    recorded_head: &ChainHead,
    source_sequence: i64,
) -> Result<String, &'static str> {
    if fold_owned(instance_ref, rows) != *recorded_head {
        return Err("source event chain differs from its recorded head");
    }
    let cut = rows
        .iter()
        .take_while(|row| row.sequence <= source_sequence)
        .cloned()
        .collect::<Vec<_>>();
    let chain = fold_owned(instance_ref, &cut);
    if chain.sequence != Some(source_sequence) {
        return Err("source event-chain prefix does not reach the requested cut");
    }
    Ok(chain.digest)
}

pub(crate) struct AdoptionEvidence {
    pub source: EventPosition,
    pub source_policy: PolicyEpochRef,
    pub chain_digest: String,
    pub thread: serde_json::Value,
    pub thread_digest: String,
    pub reads: Vec<CarriedRead>,
}

pub(crate) fn validate_adoption(
    command: &whipplescript_kernel::host_protocol::ForkInstanceCommand,
    target_policy: &PolicyEpochRef,
    target_package: &str,
    target_authority: Option<&str>,
    envelope: &VerifiedEnvelope,
    export: &serde_json::Value,
    source_pin: &str,
) -> Result<AdoptionEvidence, &'static str> {
    if command.policy != *target_policy || command.package_version_ref != target_package {
        return Err("adoption target package or policy differs from its command");
    }
    if source_pin.len() != 64
        || !source_pin.bytes().all(|byte| byte.is_ascii_hexdigit())
        || whipplescript_store::items::sha256_hex(&export.to_string()) != source_pin
    {
        return Err("Home source pin differs from the carried checkpoint");
    }
    let source: EventPosition = serde_json::from_value(export["source"].clone())
        .map_err(|_| "adoption has no source coordinate")?;
    let source_policy: PolicyEpochRef = serde_json::from_value(export["policy"].clone())
        .map_err(|_| "adoption has no source policy")?;
    if export["protocol"].as_str() != Some(HOST_PROTOCOL)
        || source != command.source
        || source_policy.signer != command.policy.signer
        || source_policy.epoch > command.policy.epoch
        || (source_policy.epoch == command.policy.epoch && source_policy != command.policy)
        || export["source_authority"].as_str().is_none()
        || export["source_authority"].as_str() != target_authority
    {
        return Err("adoption source is outside the target authority or epoch");
    }
    let chain_digest = export["source_chain_digest"]
        .as_str()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("adoption has no source event-chain digest")?
        .to_owned();
    let thread = export
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or("adoption has no thread")?;
    let thread = serde_json::Value::Array(thread.clone());
    let thread_digest = whipplescript_store::items::sha256_hex(&thread.to_string());
    if export["thread_digest"].as_str() != Some(thread_digest.as_str()) {
        return Err("adoption thread digest does not match the source pin");
    }
    let reads: Vec<CarriedRead> = serde_json::from_value(export["reads"].clone())
        .map_err(|_| "adoption has no recorded read evidence")?;
    let mut handles = BTreeSet::new();
    for read in &reads {
        if read.handle.is_empty()
            || !handles.insert(&read.handle)
            || !envelope.governs(&read.handle)
            || envelope.resolve_handle(&read.handle) != read.resolved
        {
            return Err("a carried read is not admitted under the current policy");
        }
    }
    Ok(AdoptionEvidence {
        source,
        source_policy,
        chain_digest,
        thread,
        thread_digest,
        reads,
    })
}

pub(crate) fn require_distinct_target(source: &str, target: &str) -> Result<(), &'static str> {
    if source == target {
        return Err("adoption target must differ from the source");
    }
    Ok(())
}

pub(crate) fn verify_replay_payload(
    recorded: &str,
    expected: &serde_json::Value,
    kind: &'static str,
) -> Result<(), &'static str> {
    let existing: serde_json::Value = serde_json::from_str(recorded).map_err(|_| match kind {
        "seed" => "recorded adoption seed is invalid",
        _ => "recorded adoption fork is invalid",
    })?;
    if &existing != expected {
        return Err(match kind {
            "seed" => "adoption retry changed the recorded thread seed",
            _ => "adoption retry changed the recorded fork",
        });
    }
    Ok(())
}

pub(crate) fn validate_fork_source_position(source: &EventPosition) -> Result<(), &'static str> {
    if source.sequence == 0 {
        return Err("fork source position must be nonzero");
    }
    Ok(())
}

pub(crate) fn validate_fork_export_admission(
    export: &serde_json::Value,
    exported_source: &EventPosition,
    exported_policy: &PolicyEpochRef,
    expected_source: &EventPosition,
    expected_policy: &PolicyEpochRef,
) -> Result<(), &'static str> {
    if export.get("protocol").and_then(serde_json::Value::as_str) != Some(HOST_PROTOCOL)
        || exported_source != expected_source
        || exported_policy != expected_policy
    {
        return Err("fork export does not match its admitted command");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carried_reads_keep_authorized_identity_across_a_seed() {
        let envelope = VerifiedEnvelope::verify_text(
            r#"{
            "resources":{"readable":{"principal":true,"reader":[],"writer":[]}},
            "bindings":{"alias":"readable"}
        }"#,
        )
        .unwrap();
        let mut reads = BTreeMap::new();
        assert_eq!(record_turn_read(&envelope, &mut reads, "alias"), Ok(()));
        assert_eq!(reads.get("alias").map(String::as_str), Some("readable"));
        assert_eq!(
            record_turn_read(&envelope, &mut reads, "forbidden"),
            Err("source policy does not govern a carried read")
        );
        let mut stale = BTreeMap::from([("alias".to_owned(), "old-address".to_owned())]);
        assert_eq!(
            record_turn_read(&envelope, &mut stale, "alias"),
            Err("carried read handle changed identity")
        );
        assert_eq!(
            record_inherited_read(
                &mut reads,
                CarriedRead {
                    handle: "alias".into(),
                    resolved: "readable".into(),
                }
            ),
            Ok(())
        );
        assert_eq!(
            record_inherited_read(
                &mut reads,
                CarriedRead {
                    handle: "alias".into(),
                    resolved: "changed".into(),
                }
            ),
            Err("carried read handle changed identity")
        );
    }

    #[test]
    fn source_chain_must_match_its_head_and_reach_the_exact_cut() {
        let row = OwnedChainEntry {
            event_id: "event-one".into(),
            sequence: 1,
            event_type: "agent.turn.completed".into(),
            payload_json: "{}".into(),
            occurred_at: "2026-01-01T00:00:00Z".into(),
            source: Some("host".into()),
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            format_version: Some(1),
        };
        let head = fold_owned("source", std::slice::from_ref(&row));
        assert_eq!(
            verified_source_chain_digest("source", std::slice::from_ref(&row), &head, 1),
            Ok(head.digest.clone())
        );
        assert_eq!(
            verified_source_chain_digest("source", std::slice::from_ref(&row), &head, 2),
            Err("source event-chain prefix does not reach the requested cut")
        );
        assert_eq!(
            verified_source_chain_digest("source", &[row], &ChainHead::empty("source"), 1),
            Err("source event chain differs from its recorded head")
        );
    }

    #[test]
    fn adoption_rechecks_pin_authority_epoch_thread_and_read_identity() {
        use whipplescript_kernel::host_protocol::ForkInstanceCommand;
        let envelope = VerifiedEnvelope::verify_text(
            r#"{
            "resources":{"readable":{"principal":true,"reader":[],"writer":[]}},
            "bindings":{"alias":"readable"}
        }"#,
        )
        .unwrap();
        let policy = PolicyEpochRef {
            epoch: 2,
            envelope_hash: "current".into(),
            signer: "governor".into(),
            key_id: None,
        };
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "adopt".into(),
            source: EventPosition {
                instance_ref: "source".into(),
                sequence: 4,
            },
            target_request_id: "target-open".into(),
            package_version_ref: "new-package".into(),
            policy: policy.clone(),
        };
        let source_policy = PolicyEpochRef {
            epoch: 1,
            envelope_hash: "old".into(),
            ..policy.clone()
        };
        let mut export = serde_json::json!({
            "protocol": HOST_PROTOCOL, "source": command.source, "policy": source_policy,
            "source_authority":"gaugedesk", "source_chain_digest":"a".repeat(64),
            "messages":[{"role":"user","content":"prior"}],
            "reads":[{"handle":"alias","resolved":"readable"}],
        });
        export["thread_digest"] = serde_json::json!(whipplescript_store::items::sha256_hex(
            &export["messages"].to_string()
        ));
        let pin =
            |value: &serde_json::Value| whipplescript_store::items::sha256_hex(&value.to_string());
        let admitted = validate_adoption(
            &command,
            &policy,
            "new-package",
            Some("gaugedesk"),
            &envelope,
            &export,
            &pin(&export),
        )
        .unwrap();
        assert_eq!(admitted.source, command.source);
        assert_eq!(admitted.source_policy.epoch, 1);
        assert_eq!(admitted.chain_digest, "a".repeat(64));
        assert_eq!(admitted.thread, export["messages"]);
        assert_eq!(admitted.thread_digest, export["thread_digest"]);
        assert_eq!(admitted.reads[0].resolved, "readable");
        assert_eq!(
            validate_adoption(
                &command,
                &policy,
                "wrong-package",
                Some("gaugedesk"),
                &envelope,
                &export,
                &pin(&export)
            )
            .err(),
            Some("adoption target package or policy differs from its command")
        );
        assert_eq!(
            validate_adoption(
                &command,
                &policy,
                "new-package",
                Some("gaugedesk"),
                &envelope,
                &export,
                &"0".repeat(64)
            )
            .err(),
            Some("Home source pin differs from the carried checkpoint")
        );
        for (field, changed, reason) in [
            (
                "source_authority",
                serde_json::json!("other"),
                "adoption source is outside the target authority or epoch",
            ),
            (
                "thread_digest",
                serde_json::json!("0".repeat(64)),
                "adoption thread digest does not match the source pin",
            ),
            (
                "reads",
                serde_json::json!([{"handle":"alias","resolved":"other"}]),
                "a carried read is not admitted under the current policy",
            ),
        ] {
            let mut altered = export.clone();
            altered[field] = changed;
            assert_eq!(
                validate_adoption(
                    &command,
                    &policy,
                    "new-package",
                    Some("gaugedesk"),
                    &envelope,
                    &altered,
                    &pin(&altered)
                )
                .err(),
                Some(reason)
            );
        }
        export["reads"] = serde_json::json!([{"handle":"alias","resolved":"readable"},
            {"handle":"alias","resolved":"readable"}]);
        assert_eq!(
            validate_adoption(
                &command,
                &policy,
                "new-package",
                Some("gaugedesk"),
                &envelope,
                &export,
                &pin(&export)
            )
            .err(),
            Some("a carried read is not admitted under the current policy")
        );
    }

    #[test]
    fn adoption_replay_keeps_exact_seed_and_fork() {
        let seed =
            serde_json::json!({"agent":"editor","messages":[{"role":"user","content":"prior"}]});
        assert_eq!(
            verify_replay_payload(&seed.to_string(), &seed, "seed"),
            Ok(())
        );
        assert_eq!(
            verify_replay_payload("{}", &seed, "seed"),
            Err("adoption retry changed the recorded thread seed")
        );
        let fork = serde_json::json!({"source_pin":"pin","target_instance_ref":"target"});
        assert_eq!(
            verify_replay_payload(&fork.to_string(), &fork, "fork"),
            Ok(())
        );
        assert_eq!(
            verify_replay_payload("{}", &fork, "fork"),
            Err("adoption retry changed the recorded fork")
        );
        assert_eq!(require_distinct_target("source", "target"), Ok(()));
        assert_eq!(
            require_distinct_target("source", "source"),
            Err("adoption target must differ from the source")
        );
    }

    #[test]
    fn fork_source_must_name_a_nonzero_event() {
        let mut source = EventPosition {
            instance_ref: "source".into(),
            sequence: 0,
        };
        assert_eq!(
            validate_fork_source_position(&source),
            Err("fork source position must be nonzero")
        );
        source.sequence = 1;
        assert_eq!(validate_fork_source_position(&source), Ok(()));
    }

    #[test]
    fn fork_export_must_match_the_admitted_source_and_policy() {
        let source = EventPosition {
            instance_ref: "source".into(),
            sequence: 1,
        };
        let policy = PolicyEpochRef {
            epoch: 1,
            envelope_hash: "hash".into(),
            signer: "signer".into(),
            key_id: None,
        };
        let mut export = serde_json::json!({"protocol": HOST_PROTOCOL});
        assert_eq!(
            validate_fork_export_admission(&export, &source, &policy, &source, &policy),
            Ok(())
        );
        export["protocol"] = serde_json::json!("wrong");
        assert_eq!(
            validate_fork_export_admission(&export, &source, &policy, &source, &policy),
            Err("fork export does not match its admitted command")
        );
        export["protocol"] = serde_json::json!(HOST_PROTOCOL);
        let another_source = EventPosition {
            sequence: 2,
            ..source.clone()
        };
        assert!(validate_fork_export_admission(
            &export,
            &source,
            &policy,
            &another_source,
            &policy,
        )
        .is_err());
        let another_policy = PolicyEpochRef {
            epoch: 2,
            ..policy.clone()
        };
        assert!(validate_fork_export_admission(
            &export,
            &source,
            &policy,
            &source,
            &another_policy,
        )
        .is_err());
    }
}
