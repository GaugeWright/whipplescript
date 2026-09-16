use super::*;

const HEADER: &str = "workflow Demo\nclass Input { value string }\nagent coder { provider fixture profile \"writer\" capacity 1 }\n";
const DECLARATIONS: &str = "file store files { root \".\" }\nmemory pool memo {}\ncredential key { kind ed25519 }\nvault keys { kind ed25519 allow [sign] }\n";
fn tell(resource: &str, operations: &str) -> String {
    format!("tell coder with access to {resource} {{ {operations} }} \"Work\"")
}
fn source(effect: &str, calls: &str) -> String {
    // Deliberately after the body: order must not change the declared resource.
    format!("{HEADER}action helper() -> null {{ {effect}\nreturn null }}\nrule run when started => {{ {calls} }}\n{DECLARATIONS}")
}
fn direct(source: &str) -> Vec<Diagnostic> {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let rules = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .collect::<Vec<_>>();
    validate_composition(&parsed.program, &actions, &rules)
}

#[test]
fn action_resource_grants_extraction_preserves_every_declared_resource_refusal() {
    for (resource, operation, code) in [
        ("files", "sing", "capability.invalid_grant_operation"),
        ("memo", "read", "capability.invalid_grant_operation"),
        ("vault missing", "generate", "type.unknown_resource"),
        ("vault keys", "sing", "capability.invalid_grant_operation"),
        ("vault keys", "sign", "capability.invalid_narrowing"),
        (
            "credential key",
            "unwrap for Input",
            "capability.credential_kind_mismatch",
        ),
    ] {
        let effect = tell(resource, operation);
        let inline = format!("{HEADER}rule run when started => {{ {effect} }}\n{DECLARATIONS}");
        let ordinary = compile_program(&inline).diagnostics;
        assert_eq!(ordinary.len(), 1, "{inline}: {ordinary:?}");
        assert_eq!(ordinary[0].code.as_str(), code);
        for calls in ["", "helper()", "helper()\nhelper()"] {
            let extracted = source(&effect, calls);
            let diagnostics = compile_program(&extracted).diagnostics;
            assert_eq!(diagnostics.len(), 1, "{extracted}: {diagnostics:?}");
            let expected = Diagnostic {
                span: diagnostics[0].span,
                message: ordinary[0]
                    .message
                    .replacen("rule `run`", "action `helper`", 1),
                ..ordinary[0].clone()
            };
            assert_eq!(diagnostics[0], expected);
            assert_eq!(
                &extracted[diagnostics[0].span.start..diagnostics[0].span.end],
                effect
            );
            assert_eq!(diagnostics, direct(&extracted));
        }
    }
}

#[test]
fn action_resource_grants_shared_visitor_reaches_all_controls_and_callers() {
    let effect = tell("memo", "write");
    for wrapper in [
        effect.clone(),
        format!("then work <- {effect}"),
        format!("timer 1s as pause\nafter pause succeeds {{ {effect} }}"),
        format!("case true {{ true => {{ }} false => {{ {effect} }} }}"),
        format!("during Input {{ {effect} }} on lapse {{ }}"),
        format!("during Input {{ }} on lapse {{ {effect} }}"),
    ] {
        for in_action in [false, true] {
            let wrapper = if in_action && wrapper.starts_with("during Input") {
                if wrapper.contains("on lapse { }") {
                    wrapper.replace("on lapse { }", "on lapse { return null }")
                } else {
                    format!(
                        "{}\nreturn null }}",
                        wrapper.strip_suffix(" }").expect("region wrapper")
                    )
                }
            } else {
                wrapper.clone()
            };
            let text = if in_action {
                source(&wrapper, "helper()")
            } else {
                source("", &wrapper)
            };
            let errors = direct(&text);
            assert_eq!(errors.len(), 1, "{text}: {errors:?}");
            assert!(errors[0].message.starts_with(if in_action {
                "action `helper`"
            } else {
                "rule `run`"
            }));
            assert_eq!(&text[errors[0].span.start..errors[0].span.end], effect);
            let compiled = compile_program(&text).diagnostics;
            assert_eq!(compiled, errors);
        }
    }
}

#[test]
fn action_resource_grants_valid_operations_reach_managed_output_and_kind_normalization() {
    for (resource, operations) in [
        (
            "files",
            "read [\"docs/**\"] write [\"out/**\"] import export",
        ),
        ("memo", "recall learn curate"),
        ("vault keys", "generate revoke"),
        ("credential key", "sign"),
        ("package_resource", "package_operation"),
    ] {
        let text = source(&tell(resource, operations), "helper()");
        assert!(direct(&text).is_empty());
        let output = compile_program(&text);
        assert!(
            output.diagnostics.is_empty(),
            "{text}: {:?}",
            output.diagnostics
        );
        assert!(output.ir.is_some());
        assert!(output.typed_actions.is_some());
    }
    let text = source(&tell("credential key", "sign"), "helper()").replace(
        "credential key { kind ed25519 }",
        "credential key { kind hmac_sha256 }",
    );
    assert!(
        direct(&text).is_empty(),
        "underscored source kind uses custody's normalized name"
    );
}

#[test]
fn action_resource_grants_earlier_errors_keep_priority() {
    let bad = tell("memo", "write");
    for text in [
        source(&format!("missing()\n{bad}"), "helper()"),
        source(&bad, "helper(1)"),
        source(&tell("memo", ""), "helper()"),
        source(&bad.replace("tell coder", "tell unknown_agent"), "helper()"),
    ] {
        let output = compile_program(&text);
        assert!(output.ir.is_none());
        assert!(!output.diagnostics.is_empty());
        assert!(
            output
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("not a memory operation")),
            "{:?}",
            output.diagnostics
        );
    }
    let text = source(&tell("credential key", "unwrap"), "helper()");
    let errors = compile_program(&text).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        errors[0].code,
        diagnostic_code!("capability.invalid_narrowing")
    );
}

#[test]
fn action_resource_grants_do_not_invent_ownership_of_other_validators() {
    for (resource, operation) in [
        ("credential missing", "sign"),
        ("credential key", "unknown_operation"),
        ("other_files", "read"),
        ("other_memory", "recall"),
    ] {
        // These isolated resource checks deliberately defer to declaration,
        // registry and effective-authority owners; absence of a finding here
        // does not make any of these sources executable.
        assert!(direct(&source(&tell(resource, operation), "helper()")).is_empty());
    }
    let malformed = source(&tell("credential key", "unwrap for Input"), "helper()").replace(
        "credential key { kind ed25519 }",
        "credential key { kind made_up }",
    );
    assert!(
        direct(&malformed).is_empty(),
        "declaration owns malformed kind"
    );
}

#[test]
fn action_resource_grants_normalized_kind_still_refuses_unsupported_operations() {
    let text = source(&tell("credential key", "unwrap for Input"), "helper()").replace(
        "credential key { kind ed25519 }",
        "credential key { kind jwt_rs256 }",
    );
    let errors = compile_program(&text).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        errors[0].code,
        diagnostic_code!("capability.credential_kind_mismatch")
    );
    assert!(errors[0].message.contains("jwt-rs256"));
}

#[test]
fn action_resource_grants_ordinary_diagnostic_order_is_preserved() {
    let memory = tell("memo", "write");
    let files = tell("files", "recall");
    let text = format!("{HEADER}rule run when started => {{ {memory}\n{files} }}\n{DECLARATIONS}");
    let errors = compile_program(&text).diagnostics;
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].message.contains("file store"));
    assert!(errors[1].message.contains("memory pool"));
    assert_eq!(&text[errors[0].span.start..errors[0].span.end], files);
    assert_eq!(&text[errors[1].span.start..errors[1].span.end], memory);
}
