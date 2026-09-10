use super::*;
use serde_json::json;
use whipplescript_parser::compile_program;

fn compiled(source: &str) -> IrProgram {
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "fixture must compile: {:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("compiled fixture")
}

fn verified(reader: &[&str], writer: &[&str]) -> VerifiedEnvelope {
    let policy = json!({
        "resources": {
            "file:/source": {"reader": ["Private"], "writer": []},
            "result": {"reader": ["Private"], "writer": []},
            "error": {"reader": reader, "writer": writer}
        },
        "bindings": {"source": "file:/source"},
        "capabilities": ["file.read"]
    });
    let signed =
        crate::gov::SignedEnvelope::sign_for_test(&policy.to_string(), "failure-egress-fixture");
    VerifiedEnvelope::verify_signed_text(&signed.to_json()).expect("verified policy")
}

fn local_failure(terminal: &str) -> IrProgram {
    compiled(&format!(
        r#"
workflow FailureEgress
input request Req
output result Answer
failure error Problem
class Req {{ ready bool }}
class Answer {{ text string }}
class Problem {{ reason string }}
file store source {{ root "/source" allow read ["data"] }}
rule inspect
  when Req as request
=> {{
  read text from source at "data" as loaded
  after loaded succeeds as value {{
    {terminal}
  }}
  after loaded fails as problem {{ fail error {{ reason problem.reason }} }}
}}
"#
    ))
}

#[test]
fn declared_failure_is_a_sink_on_both_axes_in_nested_continuations() {
    for terminal in [
        r#"fail error { reason value.content }"#,
        r#"case request.ready {
            true => { fail error { reason value.content } }
            false => { complete result { text value.content } }
        }"#,
    ] {
        let ir = local_failure(terminal);
        let permitted = check_with_envelope(&ir, &verified(&["Private"], &[]));
        assert!(permitted.is_empty(), "{permitted:?}");
        for (reader, writer, axis) in [
            (&[][..], &[][..], "flow"),
            (&["Private"][..], &["Trusted"][..], "integrity"),
        ] {
            let diagnostics = check_with_envelope(&ir, &verified(reader, writer));
            assert!(
                diagnostics
                    .iter()
                    .any(|item| item.message.contains("error") && item.message.contains(axis)),
                "{terminal}/{axis} must refuse the error sink: {diagnostics:?}"
            );
        }
    }
}

fn mixed_tool_source() -> &'static str {
    r#"@tool
workflow FailureTool
input request Req
output result Answer
failure error Problem
class Req { ready bool }
class Answer { text string }
class Problem { reason string }
class PrivateFailure { reason string }
file store secret { root "/secret" allow read ["data"] }
rule public_success
  when Req as request where request.ready == true
=> { complete result { text "public" } }
rule private_read
  when Req as request where request.ready == false
=> {
  read text from secret at "data" as loaded
  after loaded succeeds as value { record PrivateFailure { reason value.content } }
  after loaded fails as problem { record PrivateFailure { reason problem.reason } }
}
rule private_failure
  when PrivateFailure as problem
=> { fail error { reason problem.reason } }
"#
}

fn mixed_tool() -> IrProgram {
    compiled(mixed_tool_source())
}

#[test]
fn a_public_success_does_not_erase_an_imported_tools_private_failure_dependency() {
    let tool = mixed_tool();
    assert!(
        result_dependency_reads(&tool).contains(&"secret".into()),
        "failure-only reads must reach the imported outcome"
    );
    let consumer = compiled(
        r#"@service
workflow FailureConsumer
output result Answer
class Answer { ok bool }
class Req { id string }
agent worker { provider fixture profile "p" capacity 1 tools [FailureTool] }
table seed as Req [ { id "one" } ]
rule use
  when Req as request
  when worker is available
=> {
  tell worker as turn "go"
  after turn succeeds as outcome { complete result { ok true } }
}
"#,
    );
    let policy = |provider: &str| {
        let envelope = Envelope::from_dsl(&format!(
            "grant file_store secret -> file:/secret readable by Private\n\
             grant fact PrivateFailure -> fact:PrivateFailure readable by Private\n\
             grant provider fixture -> selfhost:model readable by {provider}\n\
             grant output result -> result readable by Private\n"
        ))
        .expect("tool policy");
        VerifiedEnvelope::for_test(envelope)
    };
    let denied =
        check_with_envelope_imports(&consumer, &policy("public"), std::slice::from_ref(&tool));
    assert!(
        denied
            .iter()
            .any(|item| item.message.contains("uncleared") && item.message.contains("secret")),
        "{denied:?}"
    );
    let allowed = check_with_envelope_imports(&consumer, &policy("Private"), &[tool]);
    assert!(allowed.is_empty(), "{allowed:?}");
}

#[test]
fn failure_fields_have_their_own_audit_dependency_signature() {
    let signatures = result_field_dependency_reads(&mixed_tool());
    assert!(
        signatures.iter().any(|(port, field, reads)| port == "error"
            && field == "reason"
            && reads.contains(&"secret".into())),
        "{signatures:?}"
    );
}

#[test]
fn executor_output_cannot_vouch_for_failure_payloads_selectors_or_projections() {
    for (name, executor, body) in [
        (
            "payload",
            "fixture",
            r#"fail error { reason outcome.summary }"#,
        ),
        (
            "selector",
            "model",
            r#"
          coerce judge(outcome.summary) as verdict
          after verdict succeeds as got {
            case got.choice {
              "yes" => { fail error { reason "yes" } }
              "no" => { fail error { reason "no" } }
            }
          }
        "#,
        ),
        (
            "projected",
            "model",
            r#"
          coerce clean(outcome.summary) as cleaned
          after cleaned succeeds as got {
            redact got keep [reason] as projected
            fail error { reason projected.reason }
          }
        "#,
        ),
    ] {
        let ir = compiled(&format!(
            r#"@service
workflow ExecutorFailure
failure error Problem
class Tick {{ id string }}
class Verdict {{ choice "yes" | "no" }}
class Problem {{ reason string }}
class Draft {{ reason string internal string }}
agent scribe {{ provider fixture profile "no-repo" capacity 1 }}
table seed as Tick [ {{ id "one" }} ]
coerce judge(text string) -> Verdict {{
  prompt """markdown
  Judge: {{{{ text }}}}
  """
}}
coerce clean(text string) -> Draft {{
  prompt """markdown
  Clean: {{{{ text }}}}
  """
}}
rule work
  when Tick as tick
=> {{
  tell scribe as turn "Draft a note."
  after turn succeeds as outcome {{ {body} }}
}}
"#
        ));
        let policy = |untrusted: Option<&str>| {
            let mut document = json!({"resources": {}});
            for resource in ["fixture", "model", "error", "fact:Tick"] {
                document["resources"][resource] = json!({
                    "reader": [],
                    "writer": if untrusted == Some(resource) { vec![] } else { vec!["Trusted"] }
                });
            }
            let signed = crate::gov::SignedEnvelope::sign_for_test(
                &document.to_string(),
                "failure-output-fixture",
            );
            VerifiedEnvelope::verify_signed_text(&signed.to_json()).expect("signed output policy")
        };
        let allowed = check_with_envelope(&ir, &policy(None));
        assert!(allowed.is_empty(), "{name}: {allowed:?}");
        let denied = check_with_envelope(&ir, &policy(Some(executor)));
        assert!(
            denied
                .iter()
                .any(|item| item.message.contains("output of executor")
                    && item.message.contains(executor)
                    && item.message.contains("error")),
            "{name}: {denied:?}"
        );
    }
}

#[test]
fn shared_success_and_failure_field_names_union_their_dependencies() {
    // Contract names are unique within their kind, not across terminal kinds.
    let source = mixed_tool_source()
        .replace("output result Answer", "output error Problem")
        .replace(
            "complete result { text \"public\" }",
            "complete error { reason \"public\" }",
        );
    let signatures = result_field_dependency_reads(&compiled(&source));
    assert_eq!(
        signatures,
        vec![("error".into(), "reason".into(), vec!["secret".into()])]
    );
}
