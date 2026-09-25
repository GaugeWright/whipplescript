//! Testable admission checks shared by the hosted fork export/import doors.

use whipplescript_kernel::host_protocol::{EventPosition, PolicyEpochRef, HOST_PROTOCOL};

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
