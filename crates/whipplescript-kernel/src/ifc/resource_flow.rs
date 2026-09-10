//! Raw flows for additional resources read by trusted effect adapters.
use super::VerifiedEnvelope;

impl VerifiedEnvelope {
    /// Check a raw resource flow using this envelope's existing confidentiality
    /// and integrity algebra. Both handles must resolve to governed resources;
    /// explicit public grants are allowed, unknown resources are not.
    ///
    /// This is a policy query, not access or execution authority. The caller
    /// must bind the actual resources and current authority independently, and
    /// check every affected output and evidence sink before accessing the extra
    /// input. It does not replace the program check or a multi-party meet.
    /// Downgrade grants alone cannot declassify or endorse this raw influence.
    pub fn check_resource_flow(&self, source: &str, sink: &str) -> Result<(), String> {
        let envelope = self.envelope();
        if !envelope.governs(source) {
            return Err("resource flow source is not governed".into());
        }
        if !envelope.governs(sink) {
            return Err("resource flow sink is not governed".into());
        }
        if envelope.leaks(source, sink) {
            return Err("resource flow violates confidentiality".into());
        }
        if !envelope.dominates(
            &envelope.integrity_set(source),
            &envelope.integrity_sink(sink),
        ) {
            return Err("resource flow violates integrity".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gov::SignedEnvelope;
    use serde_json::{json, Value};

    fn verified(policy: Value) -> VerifiedEnvelope {
        let signed = SignedEnvelope::sign_for_test(&policy.to_string(), "resource-flow-fixture");
        VerifiedEnvelope::verify_signed_text(&signed.to_json()).expect("verified policy")
    }

    fn policy(
        source_reader: Value,
        source_writer: Value,
        sink_reader: Value,
        sink_writer: Value,
    ) -> Value {
        json!({
            "resources": {
                "memory:resolutions": {"reader": source_reader, "writer": source_writer},
                "file:/target": {"reader": sink_reader, "writer": sink_writer}
            },
            "bindings": {"remembered": "memory:resolutions", "target": "file:/target"}
        })
    }

    #[test]
    fn resource_flow_requires_both_exact_governed_resources_even_when_public() {
        let envelope = verified(policy(json!([]), json!([]), json!([]), json!([])));
        assert_eq!(envelope.check_resource_flow("remembered", "target"), Ok(()));
        assert_eq!(
            envelope.check_resource_flow("memory:resolutions", "file:/target"),
            Ok(())
        );
        for unknown in [
            "",
            "missing",
            "memory:resolutions/child",
            "file:/target/child",
        ] {
            assert_eq!(
                envelope.check_resource_flow(unknown, "target"),
                Err("resource flow source is not governed".into())
            );
            assert_eq!(
                envelope.check_resource_flow("remembered", unknown),
                Err("resource flow sink is not governed".into())
            );
        }
    }

    #[test]
    fn resource_flow_obeys_both_axes_over_all_two_role_sets() {
        let roles = |bits: u8| -> Value {
            json!(["A", "B"]
                .into_iter()
                .enumerate()
                .filter(|(bit, _)| bits & (1 << bit) != 0)
                .map(|(_, role)| role)
                .collect::<Vec<_>>())
        };
        for source_reader in 0..4 {
            for source_writer in 0..4 {
                for sink_reader in 0..4 {
                    for sink_writer in 0..4 {
                        let mut document = policy(
                            roles(source_reader),
                            roles(source_writer),
                            roles(sink_reader),
                            roles(sink_writer),
                        );
                        let envelope = verified(document.clone());
                        // Independent finite-set oracle: confidentiality flows
                        // upward, integrity downward. No delegation in this set.
                        let expected = if source_reader & !sink_reader != 0 {
                            Err("resource flow violates confidentiality".into())
                        } else if sink_writer & !source_writer != 0 {
                            Err("resource flow violates integrity".into())
                        } else {
                            Ok(())
                        };
                        assert_eq!(envelope.check_resource_flow("remembered", "target"), expected,
                            "reader {source_reader}->{sink_reader}, writer {source_writer}->{sink_writer}");
                        // Reverse-facing labels do not govern this direction.
                        // Include explicit public on either side, then sign and
                        // verify the full policy again before querying it.
                        document["resources"]["memory:resolutions"]["reader_sink"] =
                            roles(!source_reader);
                        document["resources"]["memory:resolutions"]["writer_sink"] =
                            roles(!source_writer);
                        document["resources"]["file:/target"]["reader"] = roles(!sink_reader);
                        document["resources"]["file:/target"]["writer"] = roles(!sink_writer);
                        document["resources"]["file:/target"]["reader_sink"] = roles(sink_reader);
                        document["resources"]["file:/target"]["writer_sink"] = roles(sink_writer);
                        assert_eq!(verified(document).check_resource_flow("remembered", "target"), expected,
                            "directional reader {source_reader}->{sink_reader}, writer {source_writer}->{sink_writer}");
                    }
                }
            }
        }
    }

    #[test]
    fn resource_flow_honors_transitive_delegation_without_reversing_it() {
        let mut document = policy(json!(["A"]), json!(["C"]), json!(["C"]), json!(["A"]));
        assert!(verified(document.clone())
            .check_resource_flow("remembered", "target")
            .is_err());
        document["delegations"] = json!([["C", "B"], ["B", "A"], ["B", "C"]]);
        let envelope = verified(document);
        assert_eq!(envelope.check_resource_flow("remembered", "target"), Ok(()));
        assert_eq!(
            envelope.check_resource_flow("target", "remembered"),
            Err("resource flow violates confidentiality".into())
        );
        let mut integrity = policy(json!([]), json!(["A"]), json!([]), json!(["C"]));
        integrity["delegations"] = json!([["C", "B"], ["B", "A"]]);
        assert_eq!(
            verified(integrity).check_resource_flow("remembered", "target"),
            Err("resource flow violates integrity".into())
        );
    }

    #[test]
    fn resource_flow_uses_directional_labels_and_does_not_arm_downgrades() {
        let mut document = policy(json!(["Private"]), json!([]), json!([]), json!(["Trusted"]));
        document["declassifications"] = json!([["remembered", "public"]]);
        document["endorsements"] = json!([["remembered", "Trusted"]]);
        assert_eq!(
            verified(document.clone()).check_resource_flow("remembered", "target"),
            Err("resource flow violates confidentiality".into())
        );
        document["resources"]["file:/target"]["reader_sink"] = json!(["Private"]);
        assert_eq!(
            verified(document.clone()).check_resource_flow("remembered", "target"),
            Err("resource flow violates integrity".into())
        );
        document["resources"]["file:/target"]["writer_sink"] = json!([]);
        assert_eq!(
            verified(document).check_resource_flow("remembered", "target"),
            Ok(())
        );
    }

    #[test]
    fn resource_flow_rejects_malformed_directions_before_signing() {
        for field in ["reader_sink", "writer_sink"] {
            for malformed in [
                json!(null),
                json!(false),
                json!(7),
                json!({}),
                json!(""),
                json!("  "),
                json!([null]),
                json!(["A", false]),
                json!([""]),
            ] {
                let mut document = policy(json!(["A"]), json!(["A"]), json!(["A"]), json!(["A"]));
                document["resources"]["file:/target"][field] = malformed.clone();
                assert_eq!(crate::gov::canonicalize(&document.to_string()),
                    Err("invalid IFC envelope: directional labels must be nonblank roles or arrays of nonblank roles".into()),
                    "{field}: {malformed}");
            }
            for public in [json!([]), json!("public"), json!(["public"])] {
                let mut document = policy(json!([]), json!([]), json!(["A"]), json!(["A"]));
                document["resources"]["file:/target"][field] = public;
                let envelope = verified(document);
                if field == "writer_sink" {
                    assert_eq!(envelope.check_resource_flow("remembered", "target"), Ok(()));
                } else {
                    assert_eq!(
                        envelope.check_resource_flow("remembered", "target"),
                        Err("resource flow violates integrity".into())
                    );
                }
            }
        }
    }

    #[test]
    fn resource_flow_agrees_with_a_compiled_file_flow() {
        let source = r#"use std.files
workflow ResourceFlowFixture
input content Draft
output result Saved
failure error Failed
class Draft { ready bool }
class Saved { hash string }
class Failed { reason string }
file store remembered { root "/memory" allow read ["content"] }
file store target { root "/target" allow write ["content"] }
rule save
  when Draft as draft
=> {
  read text from remembered at "content" as loaded
  after loaded succeeds as body {
    write text to target at "content" { body body.content mode upsert } as written
    after written succeeds as saved { complete result { hash saved.content_hash } }
    after written fails as failed { fail error { reason failed.reason } }
  }
  after loaded fails as failed { fail error { reason failed.reason } }
}
"#;
        let action = crate::host_action::CompiledHostAction::compile("file.save", source, None)
            .expect("compiled file flow");
        for (readers, writers) in [
            (json!([]), json!([])),
            (json!(["Private"]), json!([])),
            (json!([]), json!(["Trusted"])),
            (json!(["Private"]), json!(["Trusted"])),
        ] {
            let mut document = policy(json!(["Private"]), json!(["Trusted"]), readers, writers);
            document["resources"]["result"] = json!({"reader": ["Private"], "writer": []});
            document["resources"]["error"] = json!({"reader": ["Private"], "writer": []});
            document["capabilities"] = json!(["file.read", "file.write"]);
            let envelope = verified(document);
            let query = envelope.check_resource_flow("remembered", "target");
            let diagnostics = super::super::check_with_envelope(action.program(), &envelope);
            assert_eq!(
                query.is_ok(),
                diagnostics.is_empty(),
                "query {query:?}; compiler {diagnostics:?}"
            );
        }
    }
}
