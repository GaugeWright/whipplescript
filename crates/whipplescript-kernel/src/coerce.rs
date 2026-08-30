//! Coerce effect provider abstraction.
//!
//! `run_coerce` (see `lib.rs`) drives a coerce effect through a `CoerceClient`.
//! The in-tree client is `FakeCoerceClient`, used by the fixture provider and
//! tests. The real, provider-native structured-output client (OpenAI Responses /
//! Anthropic Messages) is a separate, credential-gated build; the earlier
//! bridge-server placeholders (`HttpCoerceClient`/`ManagedCoerceService`) were a
//! fictional design and have been removed (no real provider implements a
//! `/coerce` POST). See `spec/coerce.md`.

use crate::rule_lowering::json_from_str;
use serde_json::json;

/// The coercion-config fingerprint folded into `schema.coerce` effect
/// admission keys (DR-0014 amendment; spec/std-coercion.md "Idempotency And
/// Replay"): H(provider_kind, provider_id, backend, model). Hosts compute it
/// at kernel construction — native from the resolved coerce config, the
/// durable object from `coerce_config_json` — and the fixture path uses the
/// literal `"fixture"` instead so tests stay deterministic. Credentials are
/// deliberately excluded: a rotated key must not rekey admissions.
pub fn coercion_config_fingerprint(
    provider_kind: &str,
    provider_id: &str,
    backend: &str,
    model: &str,
) -> String {
    crate::idempotency_key(&[
        "coercion-config",
        provider_kind,
        provider_id,
        backend,
        model,
    ])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoerceRequest {
    pub function_name: String,
    pub arguments_json: String,
    pub output_type: String,
    pub generated_coerce_source_hash: String,
    pub input_schema_hash: String,
    pub output_schema_hash: String,
}

impl CoerceRequest {
    /// Build a request whose three evidence hashes are REAL, content-derived
    /// digests of the coercion identity and input shape — replacing the former
    /// placeholder strings (`"fixture"`/`"do"`/`"coerce"`) that surfaced on the
    /// coerce fact (spec/std-coercion.md: "the placeholder hash fields … are
    /// replaced by the real hashes"). `generated_coerce_source_hash` = H(coercion
    /// name), `input_schema_hash` = H(normalized named-args JSON), and
    /// `output_schema_hash` = H(output-type identity). These are EVIDENCE
    /// digests; the load-bearing admission-key commitments (declared prompt
    /// template + IR-synthesized output JSON Schema + config fingerprint) are
    /// computed IR-faithfully at lowering (`effect_admission_key`, DR-0014).
    pub fn with_evidence_hashes(
        function_name: String,
        arguments_json: String,
        output_type: String,
    ) -> Self {
        use crate::rule_lowering::stable_hash_hex;
        let generated_coerce_source_hash = stable_hash_hex(&function_name);
        let input_schema_hash = stable_hash_hex(&arguments_json);
        let output_schema_hash = stable_hash_hex(&output_type);
        Self {
            function_name,
            arguments_json,
            output_type,
            generated_coerce_source_hash,
            input_schema_hash,
            output_schema_hash,
        }
    }

    /// Fold the exact normalized provider derivatives into the existing input
    /// evidence commitment without adding media bodies to evidence. This keeps
    /// resumed `coerce`/`prompt` calls bound to what the provider actually saw.
    pub fn commit_media(mut self, media: &[crate::harness_loop::MediaInput]) -> Self {
        let normalized = crate::media::normalize_provider_media(media);
        let summary = serde_json::to_string(&normalized.observations).unwrap_or_default();
        self.input_schema_hash = crate::rule_lowering::stable_hash_hex(&format!(
            "{}\nnormalized_media={summary}",
            self.input_schema_hash
        ));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoerceStatus {
    Succeeded,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoerceResult {
    pub status: CoerceStatus,
    pub value_json: Option<String>,
    pub error_json: Option<String>,
    pub summary: String,
    pub transcript: String,
    pub usage_json: String,
}

pub trait CoerceClient {
    fn coerce(&self, request: &CoerceRequest) -> CoerceResult;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeCoerceClient {
    result: CoerceResult,
}

impl FakeCoerceClient {
    pub fn succeeds(value_json: impl Into<String>) -> Self {
        Self {
            result: CoerceResult {
                status: CoerceStatus::Succeeded,
                value_json: Some(value_json.into()),
                error_json: None,
                summary: "coerce succeeded".to_owned(),
                transcript: "fake coerce transcript\n".to_owned(),
                usage_json: r#"{"input_tokens":1,"output_tokens":1}"#.to_owned(),
            },
        }
    }

    pub fn fails(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            result: CoerceResult {
                status: CoerceStatus::Failed,
                value_json: None,
                error_json: Some(
                    json!({
                        "reason": reason,
                        "recoverable": true,
                        "error_class": "provider_error",
                    })
                    .to_string(),
                ),
                summary: "coerce failed".to_owned(),
                transcript: "fake coerce failure transcript\n".to_owned(),
                usage_json: r#"{"input_tokens":1,"output_tokens":0}"#.to_owned(),
            },
        }
    }

    pub fn times_out(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            result: CoerceResult {
                status: CoerceStatus::TimedOut,
                value_json: None,
                error_json: Some(
                    json!({
                        "reason": reason,
                        "recoverable": true,
                    })
                    .to_string(),
                ),
                summary: "coerce timed out".to_owned(),
                transcript: "fake coerce timeout transcript\n".to_owned(),
                usage_json: r#"{"input_tokens":1,"output_tokens":0}"#.to_owned(),
            },
        }
    }
}

impl CoerceClient for FakeCoerceClient {
    fn coerce(&self, request: &CoerceRequest) -> CoerceResult {
        let mut result = self.result.clone();
        let request_json = json!({
            "function_name": request.function_name,
            "arguments": json_from_str(&request.arguments_json),
            "output_type": request.output_type,
        });
        result.transcript.push_str(&request_json.to_string());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_coerce_client_returns_typed_value() {
        let client = FakeCoerceClient::succeeds(r#"{"status":"Accept"}"#);
        let result = client.coerce(&CoerceRequest {
            function_name: "reviewWork".to_owned(),
            arguments_json: r#"{"summary":"done"}"#.to_owned(),
            output_type: "WorkReview".to_owned(),
            generated_coerce_source_hash: "coerce".to_owned(),
            input_schema_hash: "input".to_owned(),
            output_schema_hash: "output".to_owned(),
        });

        assert_eq!(result.status, CoerceStatus::Succeeded);
        assert_eq!(result.value_json.as_deref(), Some(r#"{"status":"Accept"}"#));
        assert!(result.transcript.contains("reviewWork"));
    }

    #[test]
    fn evidence_hashes_are_content_derived_not_placeholders() {
        let request = CoerceRequest::with_evidence_hashes(
            "classifyMessage".to_owned(),
            r#"{"title":"pager"}"#.to_owned(),
            "MessageClassification".to_owned(),
        );
        // No more literal "fixture"/"do"/"coerce" placeholders — each field is a
        // real digest of its input.
        for hash in [
            &request.generated_coerce_source_hash,
            &request.input_schema_hash,
            &request.output_schema_hash,
        ] {
            assert!(!["fixture", "do", "coerce", ""].contains(&hash.as_str()));
        }
        // Deterministic, and each commits to a DISTINCT input (identity / args /
        // output), so a changed field changes its digest.
        let same = CoerceRequest::with_evidence_hashes(
            "classifyMessage".to_owned(),
            r#"{"title":"pager"}"#.to_owned(),
            "MessageClassification".to_owned(),
        );
        assert_eq!(request, same);
        let changed_args = CoerceRequest::with_evidence_hashes(
            "classifyMessage".to_owned(),
            r#"{"title":"outage"}"#.to_owned(),
            "MessageClassification".to_owned(),
        );
        assert_ne!(request.input_schema_hash, changed_args.input_schema_hash);
        assert_eq!(request.output_schema_hash, changed_args.output_schema_hash);
    }
}
