//! Canonical artifact manifest metadata for provider runs.

use serde_json::{json, Value};

use crate::harness::ProviderArtifact;

pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: &str = "whipplescript.artifact_manifest.v1";
/// The registered runtime code for a failed artifact capture.
///
/// The event type is DERIVED from it rather than written twice: the two are the
/// same string by construction, so a rename cannot move one and leave the other
/// naming a code the register no longer carries.
pub const ARTIFACT_CAPTURE_FAILED_CODE: whipplescript_core::RuntimeDiagnosticCode =
    whipplescript_core::runtime_diagnostic_code!("artifact.capture.failed");
pub const ARTIFACT_CAPTURE_FAILED_EVENT: &str = ARTIFACT_CAPTURE_FAILED_CODE.as_str();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactCaptureFailure<'a> {
    pub provider: &'a str,
    pub adapter: &'a str,
    pub run_id: &'a str,
    pub artifact_ref: &'a str,
    pub error_kind: &'a str,
    pub recoverable: bool,
    pub message: &'a str,
    pub transcript_ref: Option<&'a str>,
    pub stderr_ref: Option<&'a str>,
}

pub fn provider_artifact_manifest(
    artifact_ids: &[String],
    artifacts: &[ProviderArtifact],
) -> Value {
    let entries = artifact_ids
        .iter()
        .zip(artifacts.iter())
        .map(|(artifact_id, artifact)| {
            json!({
                "artifact_id": artifact_id,
                "kind": artifact.kind,
                "uri": {
                    "type": artifact_uri_type(&artifact.path),
                    "value": artifact.path,
                },
                "content_hash": artifact.content_hash.as_ref().map(|hash| json!({
                    "algorithm": "provider",
                    "value": hash,
                })),
                "mime_type": artifact.mime_type,
                "size_bytes": null,
                "redaction_status": "unredacted_metadata_only",
                "retention_policy": "provider_default",
                "required": false,
                "source_provider_event": null,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "entry_count": entries.len(),
        "entries": entries,
    })
}

pub fn validate_artifact_manifest(manifest: &Value) -> Result<(), String> {
    let schema_version = manifest
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| "artifact manifest missing schema_version".to_owned())?;
    if schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported artifact manifest schema_version `{schema_version}`"
        ));
    }

    let entries = manifest
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "artifact manifest entries must be an array".to_owned())?;
    let entry_count = manifest
        .get("entry_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "artifact manifest missing entry_count".to_owned())?;
    if entry_count as usize != entries.len() {
        return Err("artifact manifest entry_count does not match entries".to_owned());
    }

    for entry in entries {
        require_string(entry, "artifact_id")?;
        require_string(entry, "kind")?;
        validate_uri(entry.get("uri"))?;
        validate_content_hash(entry.get("content_hash"))?;
        validate_optional_string(entry, "mime_type")?;
        validate_optional_u64(entry, "size_bytes")?;
        validate_enum(
            entry,
            "redaction_status",
            &["redacted", "unredacted_metadata_only", "reference_only"],
        )?;
        validate_enum(
            entry,
            "retention_policy",
            &[
                "ephemeral",
                "provider_default",
                "retain",
                "delete_after_run",
            ],
        )?;
        entry
            .get("required")
            .and_then(Value::as_bool)
            .ok_or_else(|| "artifact manifest entry required must be a boolean".to_owned())?;
        validate_optional_string(entry, "source_provider_event")?;
    }

    Ok(())
}

pub fn artifact_capture_failed_payload(
    failure: ArtifactCaptureFailure<'_>,
) -> Result<Value, String> {
    validate_capture_failure_kind(failure.error_kind)?;
    Ok(json!({
        "event_type": ARTIFACT_CAPTURE_FAILED_EVENT,
        "provider": failure.provider,
        "adapter": failure.adapter,
        "run_id": failure.run_id,
        "artifact_ref": {
            "type": artifact_uri_type(failure.artifact_ref),
            "value": failure.artifact_ref,
        },
        "error_kind": failure.error_kind,
        "recoverable": failure.recoverable,
        "message": redacted_message_metadata(failure.message),
        "transcript_ref": failure.transcript_ref,
        "stderr_ref": failure.stderr_ref,
    }))
}

fn validate_capture_failure_kind(error_kind: &str) -> Result<(), String> {
    if [
        "missing",
        "unreadable",
        "oversized",
        "hash_mismatch",
        "redaction_failed",
    ]
    .contains(&error_kind)
    {
        Ok(())
    } else {
        Err(format!(
            "unsupported artifact capture failure kind `{error_kind}`"
        ))
    }
}

fn redacted_message_metadata(message: &str) -> Value {
    json!({
        "redacted": true,
        "bytes": message.len(),
        "chars": message.chars().count(),
    })
}

fn require_string(value: &Value, field: &str) -> Result<(), String> {
    let string = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("artifact manifest entry missing {field}"))?;
    if string.trim().is_empty() {
        return Err(format!("artifact manifest entry {field} must not be empty"));
    }
    Ok(())
}

fn validate_optional_string(value: &Value, field: &str) -> Result<(), String> {
    match value.get(field) {
        Some(Value::Null) | None => Ok(()),
        Some(Value::String(_)) => Ok(()),
        _ => Err(format!("artifact manifest entry {field} must be a string")),
    }
}

fn validate_optional_u64(value: &Value, field: &str) -> Result<(), String> {
    match value.get(field) {
        Some(Value::Null) | None => Ok(()),
        Some(Value::Number(number)) if number.as_u64().is_some() => Ok(()),
        _ => Err(format!(
            "artifact manifest entry {field} must be an unsigned integer"
        )),
    }
}

fn validate_enum(value: &Value, field: &str, allowed: &[&str]) -> Result<(), String> {
    let actual = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("artifact manifest entry missing {field}"))?;
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(format!(
            "artifact manifest entry {field} has unsupported value `{actual}`"
        ))
    }
}

fn validate_uri(uri: Option<&Value>) -> Result<(), String> {
    let uri = uri.ok_or_else(|| "artifact manifest entry missing uri".to_owned())?;
    let uri_type = uri
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "artifact manifest entry uri missing type".to_owned())?;
    if !["path", "ref"].contains(&uri_type) {
        return Err(format!(
            "artifact manifest entry uri has unsupported type `{uri_type}`"
        ));
    }
    require_string(uri, "value")
}

fn validate_content_hash(content_hash: Option<&Value>) -> Result<(), String> {
    let Some(content_hash) = content_hash else {
        return Ok(());
    };
    if content_hash.is_null() {
        return Ok(());
    }
    require_string(content_hash, "algorithm")?;
    require_string(content_hash, "value")
}

fn artifact_uri_type(path: &str) -> &'static str {
    if path.contains("://") {
        "ref"
    } else {
        "path"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ProviderArtifact {
        ProviderArtifact {
            kind: "transcript".to_owned(),
            path: "artifacts/run.txt".to_owned(),
            content_hash: Some("sha256:abc".to_owned()),
            mime_type: Some("text/plain".to_owned()),
        }
    }

    #[test]
    fn provider_artifact_manifest_uses_canonical_schema() {
        let manifest = provider_artifact_manifest(&["art_1".to_owned()], &[artifact()]);

        validate_artifact_manifest(&manifest).expect("manifest validates");
        assert_eq!(
            manifest.get("schema_version").and_then(Value::as_str),
            Some(ARTIFACT_MANIFEST_SCHEMA_VERSION)
        );
        assert_eq!(
            manifest
                .pointer("/entries/0/artifact_id")
                .and_then(Value::as_str),
            Some("art_1")
        );
        assert_eq!(
            manifest
                .pointer("/entries/0/redaction_status")
                .and_then(Value::as_str),
            Some("unredacted_metadata_only")
        );
    }

    #[test]
    fn validate_artifact_manifest_rejects_invalid_entry_count() {
        let mut manifest = provider_artifact_manifest(&["art_1".to_owned()], &[artifact()]);
        manifest["entry_count"] = json!(2);

        let error = validate_artifact_manifest(&manifest).expect_err("manifest should fail");
        assert!(error.contains("entry_count"));
    }

    #[test]
    fn validate_artifact_manifest_rejects_invalid_policy() {
        let mut manifest = provider_artifact_manifest(&["art_1".to_owned()], &[artifact()]);
        manifest["entries"][0]["retention_policy"] = json!("forever");

        let error = validate_artifact_manifest(&manifest).expect_err("manifest should fail");
        assert!(error.contains("retention_policy"));
    }

    #[test]
    fn provider_artifact_manifest_classifies_external_refs() {
        let mut artifact = artifact();
        artifact.path = "provider://codex/runs/run-1/transcript_ref".to_owned();
        let manifest = provider_artifact_manifest(&["art_1".to_owned()], &[artifact]);

        validate_artifact_manifest(&manifest).expect("manifest validates");
        assert_eq!(
            manifest
                .pointer("/entries/0/uri/type")
                .and_then(Value::as_str),
            Some("ref")
        );
    }

    #[test]
    fn artifact_capture_failed_payload_classifies_known_failure_kinds() {
        for error_kind in [
            "missing",
            "unreadable",
            "oversized",
            "hash_mismatch",
            "redaction_failed",
        ] {
            let payload = artifact_capture_failed_payload(ArtifactCaptureFailure {
                provider: "codex",
                adapter: "app_server",
                run_id: "run-1",
                artifact_ref: "provider://codex/runs/run-1/diff",
                error_kind,
                recoverable: true,
                message: "secret failure text",
                transcript_ref: Some("provider://codex/runs/run-1/transcript_ref"),
                stderr_ref: None,
            })
            .expect("failure payload builds");

            assert_eq!(
                payload.get("event_type").and_then(Value::as_str),
                Some(ARTIFACT_CAPTURE_FAILED_EVENT)
            );
            assert_eq!(
                payload.get("error_kind").and_then(Value::as_str),
                Some(error_kind)
            );
            assert_eq!(
                payload
                    .pointer("/artifact_ref/type")
                    .and_then(Value::as_str),
                Some("ref")
            );
            assert_eq!(
                payload
                    .pointer("/message/redacted")
                    .and_then(Value::as_bool),
                Some(true)
            );
            assert!(!payload.to_string().contains("secret failure text"));
        }
    }

    #[test]
    fn artifact_capture_failed_payload_rejects_unknown_failure_kind() {
        let error = artifact_capture_failed_payload(ArtifactCaptureFailure {
            provider: "codex",
            adapter: "app_server",
            run_id: "run-1",
            artifact_ref: "target/output.txt",
            error_kind: "bad",
            recoverable: false,
            message: "bad",
            transcript_ref: None,
            stderr_ref: None,
        })
        .expect_err("unknown kind fails");

        assert!(error.contains("unsupported artifact capture failure kind"));
    }
}
