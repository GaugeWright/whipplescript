use super::*;
use whipplescript_parser::action_plan::resolved::{resolve_rule_types, TypedActionPlan};
use whipplescript_parser::{compile_program, parse_program};

fn declarations(tools: bool) -> String {
    let tools = if tools { "tools [Fetcher]" } else { "" };
    format!("workflow Demo\nagent safe {{ provider trusted_model {tools} }}\nagent unsafe {{ provider public_model {tools} }}\nfile store secret {{ root \"./secret\" allow read [\"**\"] }}\n")
}
fn compiled(source: &str) -> IrProgram {
    let compiled = compile_program(source);
    compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics))
}
fn context(tools: bool) -> IrProgram {
    compiled(&format!(
        "{}rule run when started => {{ timer 1s as wait }}",
        declarations(tools)
    ))
}
fn typed(source: &str) -> TypedActionPlan {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed = resolve_rule_types(&parsed.program, "run").unwrap();
    let captured = crate::source_action::plan_artifact::encode_typed(&typed).unwrap();
    crate::source_action::plan_artifact::decode_typed(&captured).unwrap()
}
fn policy(clear_public: bool) -> VerifiedEnvelope {
    let public = if clear_public {
        ", \"public_model\": { \"reader\": \"confidential\" }"
    } else {
        ""
    };
    VerifiedEnvelope::for_test(Envelope::from_json(&format!(r#"{{ "resources": {{ "secret": {{ "confidential": true }}, "trusted_model": {{ "reader": "confidential" }} {public} }} }}"#)).unwrap())
}
fn source(tools: bool, grant: bool) -> String {
    let grant = if grant {
        "with access to secret { read [\"**\"] }"
    } else {
        ""
    };
    format!("{}action work(target AgentRef<safe | unsafe>) -> null {{\n tell target as turn\n {grant}\n \"Work\"\n return null\n}}\naction wrap(target AgentRef<safe | unsafe>) -> null {{ work(target) as value\n return value }}\nrule run when started => {{ wrap(safe) as first\n wrap(unsafe) as second }}", declarations(tools))
}
fn tool() -> IrProgram {
    compiled(
        r#"@tool
workflow Fetcher {
 input request Req
 output result R
 class Req { id string }
 class R { data string }
 file store secret { root "./secret" allow read ["**"] }
 rule fetch when Req as request => {
  read text from secret at "in.txt" as loaded
  after loaded succeeds as value { complete result { data value.content } }
 }
}"#,
    )
}
#[test]
fn managed_provider_egress_checks_every_target_and_preserves_nested_call_diagnostics() {
    let source = source(false, true);
    let typed = typed(&source);
    let errors = check_managed(&typed, &context(false), &policy(false), &[]);
    assert_eq!(errors.len(), 2, "{errors:?}");
    let mut callers = Vec::new();
    for error in errors {
        assert_eq!(error.code.as_str(), "security.provider_egress_leak");
        assert!(error.message.contains("public_model"));
        assert!(source[error.span.start..error.span.end].contains("tell target"));
        assert!(error
            .related
            .iter()
            .any(|r| r.message.contains("unsafe") && r.message.contains("provider")));
        for action in ["work", "wrap"] {
            assert!(error
                .related
                .iter()
                .any(|r| r.message == format!("action `{action}` defined here")));
            let call = error
                .related
                .iter()
                .find(|r| r.message == format!("call to action `{action}`"))
                .unwrap();
            assert!(source[call.span.start..call.span.end].contains(action));
            if action == "wrap" {
                callers.push(call.span);
            }
        }
    }
    assert_ne!(callers[0], callers[1]);
    assert!(check_managed(&typed, &context(false), &policy(true), &[]).is_empty());
}
#[test]
fn managed_provider_egress_preserves_narrowing_and_checked_empty_domains() {
    let source = format!("{}action work(target AgentRef<safe | unsafe>) -> null {{\n case target {{\n safe => {{ tell target as turn\n with access to secret {{ read [\"**\"] }}\n \"Read\" }}\n unsafe => {{ timer 1s as wait }}\n _ => {{ tell target as turn\n with access to secret {{ read [\"**\"] }}\n \"Unreachable\" }}\n }}\n return null\n}}\nrule run when started => {{ work(unsafe) as result }}", declarations(false));
    let typed = typed(&source);
    assert_eq!(typed.effects.len(), 3);
    assert!(check_managed(&typed, &context(false), &policy(false), &[]).is_empty());
}
#[test]
fn managed_provider_egress_includes_imported_tool_results_without_turn_grants() {
    let typed = typed(&source(true, false));
    let tool = tool();
    let errors = check_managed(
        &typed,
        &context(true),
        &policy(false),
        std::slice::from_ref(&tool),
    );
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors
        .iter()
        .all(|d| d.code.as_str() == "security.provider_egress_leak"
            && d.message.contains("tool `Fetcher`")
            && d.message.contains("secret")
            && d.message.contains("public_model")));
    assert!(check_managed(&typed, &context(true), &policy(true), &[tool]).is_empty());
}
#[test]
fn managed_provider_egress_refuses_missing_plan_declarations_and_tool_analysis() {
    let original = typed(&source(true, true));
    for which in 0..7 {
        let mut typed = original.clone();
        let mut ir = context(true);
        let mut imports = if which == 3 { Vec::new() } else { vec![tool()] };
        let expected = match which {
            0 => {
                typed.effects.clear();
                "valid typed plan"
            }
            1 => {
                ir.rules.clear();
                "matching root declaration"
            }
            2 => {
                ir.agents.retain(|agent| agent.name != "unsafe");
                "matching agent declaration"
            }
            3 => "exactly one imported program",
            4 => {
                ir.agents.push(ir.agents[0].clone());
                "exactly one matching agent declaration"
            }
            5 => {
                imports.push(tool());
                "exactly one imported program"
            }
            _ => {
                ir.rules.push(ir.rules[0].clone());
                "matching root declaration"
            }
        };
        let errors = check_managed(&typed, &ir, &policy(true), &imports);
        assert!(!errors.is_empty(), "{which}");
        assert!(
            errors.iter().all(|d| d.message.contains(expected)),
            "{errors:?}"
        );
    }
}
#[test]
fn managed_provider_egress_shared_legacy_checks_retain_policy_messages_and_tool_reads() {
    let ir = compiled(&format!("{}rule run when started => {{ tell unsafe as turn\n with access to secret {{ read [\"**\"] }}\n \"Read\" }}", declarations(true)));
    let tool = tool();
    let errors =
        super::super::check_with_envelope_imports(&ir, &policy(false), std::slice::from_ref(&tool));
    assert!(errors
        .iter()
        .any(|d| d.code.as_str() == "security.provider_egress_leak"
            && d.message.contains("this turn's context")));
    assert!(errors
        .iter()
        .any(|d| d.code.as_str() == "security.provider_egress_leak"
            && d.message.contains("tool `Fetcher`")));
    assert!(
        !super::super::check_with_envelope_imports(&ir, &policy(true), &[tool])
            .iter()
            .any(|d| d.code.as_str() == "security.provider_egress_leak")
    );
}

#[test]
fn managed_provider_egress_shared_legacy_retains_tool_read_carriage() {
    let ir = compiled(&format!("{}file store outbox {{ root \"./outbox\" allow write [\"**\"] }}\nrule run when started => {{ tell unsafe as turn \"Work\"\n after turn succeeds as answer {{ write text to outbox at \"out.txt\" {{ body \"constant\" mode replace }} as written }} }}", declarations(true)));
    let imported = tool();
    let errors = super::super::check_with_envelope_imports(
        &ir,
        &policy(true),
        std::slice::from_ref(&imported),
    );
    assert!(
        errors
            .iter()
            .any(|d| d.code.as_str() == "security.confidentiality_leak"
                && d.message.contains("secret")
                && d.message.contains("outbox")),
        "{errors:?}"
    );
    let public = VerifiedEnvelope::for_test(Envelope::from_json("{}").unwrap());
    assert!(
        !super::super::check_with_envelope_imports(&ir, &public, &[imported])
            .iter()
            .any(|d| d.code.as_str() == "security.confidentiality_leak")
    );
}
