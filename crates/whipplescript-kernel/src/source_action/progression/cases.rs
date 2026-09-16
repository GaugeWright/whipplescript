//! Nominal case selection uses captured compiler types and pinned schemas.
use serde_json::Value;
use whipplescript_parser::{IrProgram, IrSchema, IrType};

pub(super) fn validate(ir: &IrProgram, ty: &IrType, value: &Value) -> Result<(), String> {
    if is_terminal_outcome(ty) {
        let Some(tag) = crate::rule_lowering::terminal_case_tag(value) else {
            return Err("managed terminal outcome has no recognized tag".into());
        };
        if !matches!(tag, "Completed" | "Failed" | "TimedOut" | "Cancelled") {
            return Err(format!("managed terminal outcome has unknown tag `{tag}`"));
        }
        return Ok(());
    }
    let mut errors = Vec::new();
    crate::rule_lowering::validate_json_for_ir_type(ir, value, ty, "$", &mut errors);
    if !errors.is_empty() {
        let details = errors.join("; ");
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err(format!("case value violates its captured type: {details}"));
    }
    let mut ty = ty;
    while let IrType::Optional(inner) = ty {
        ty = inner;
    }
    if value.is_object() && matches!(ty, IrType::Union(_)) {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("managed class-union selection requires concrete nominal type evidence".into());
    }
    Ok(())
}

pub(super) fn matches(
    ir: &IrProgram,
    ty: &IrType,
    pattern: &str,
    value: &Value,
) -> Result<bool, String> {
    if matches!(pattern, "_" | "default") {
        return Ok(true);
    }
    if is_terminal_outcome(ty) {
        return Ok(crate::rule_lowering::terminal_case_tag(value) == Some(pattern));
    }
    if pattern == "null" {
        return Ok(value.is_null());
    }
    use whipplescript_parser::case_pattern::{optional_presence, PresencePattern};
    match optional_presence(ty, pattern) {
        Some(PresencePattern::Absent) => return Ok(value.is_null()),
        Some(PresencePattern::Present) => return Ok(!value.is_null()),
        None => {}
    }
    if let IrType::Optional(inner) = ty {
        if value.is_null() {
            return Ok(false);
        }
        return matches(ir, inner, pattern, value);
    }
    if let IrType::Ref(name) = ty {
        if ir
            .schemas
            .iter()
            .any(|schema| matches!(schema, IrSchema::Class(class) if &class.name == name))
        {
            return Ok(pattern == name);
        }
        if let Some(enumeration) = ir.schemas.iter().find_map(|schema| match schema {
            IrSchema::Enum(enumeration) if &enumeration.name == name => Some(enumeration),
            _ => None,
        }) {
            let selected = value
                .as_str()
                .or_else(|| value.get("variant").and_then(Value::as_str));
            return Ok(selected.is_some_and(|selected| {
                enumeration
                    .variants
                    .iter()
                    .any(|variant| variant == selected)
                    && crate::rule_lowering::parse_guard_literal(pattern).as_str() == Some(selected)
            }));
        }
        // MUTATION-SUCCESS-EXPR: Ok(true)
        return Err(format!("case type `{name}` missing from pinned schemas"));
    }
    if value.is_object() {
        // MUTATION-SUCCESS-EXPR: Ok(true)
        return Err("managed object pattern has no nominal class type".into());
    }
    Ok(crate::rule_lowering::parse_guard_literal(pattern) == *value)
}

pub(super) fn is_terminal_outcome(ty: &IrType) -> bool {
    matches!(ty, IrType::Ref(name) if name == "TerminalOutcome")
}

pub(super) fn terminal_payload(pattern: &str, value: &Value) -> Value {
    if matches!(pattern, "_" | "default") {
        value.clone()
    } else {
        crate::rule_lowering::terminal_payload_for_tag(value, pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_action::{
        arguments::{Bindings, Slot},
        journal::{Frame, Journal},
        progression::advance_typed,
        Boundary,
    };
    use serde_json::json;
    use whipplescript_parser::action_plan::resolved::{resolve_rule_types, TypedActionPlan};
    const DECLARATIONS: &str = "workflow Demo\nclass Ticket { title string status string variant string }\nclass Other { title string }\nenum Status { ready\nwaiting }\n";
    fn ir() -> IrProgram {
        whipplescript_parser::compile_program(&format!("{DECLARATIONS}output result Other\nrule finish when started => {{ complete result {{ title \"done\" }} }}")).ir.expect("declarations")
    }
    fn typed() -> TypedActionPlan {
        let source = format!("{DECLARATIONS}action label(x Ticket) -> string {{ case x {{ Ticket as t where t.title == \"yes\" => {{ return t.title }} _ => {{ return \"fallback\" }} }} }}\nrule run when Ticket as ticket => {{ label(ticket) as result }}");
        let parsed = whipplescript_parser::parse_program(&source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        resolve_rule_types(&parsed.program, "run").expect("typed plan")
    }
    #[test]
    fn resolved_case_nominal_selection_ignores_status_and_variant_fields() {
        let typed = typed();
        let frame = Frame {
            version: "v".into(),
            revision: "0".into(),
            rule: "run".into(),
            identity: Some("ticket".into()),
            trigger_event: Some("admit".into()),
        };
        for (title, expected) in [("yes", "yes"), ("no", "fallback")] {
            let input = json!({"title":title,"status":"completed","variant":"Other"});
            let inputs = Bindings::from([(typed.plan.root_inputs[0], Slot::Ready(input.into()))]);
            let p = advance_typed(
                &typed,
                &ir(),
                "i",
                &frame,
                3,
                &inputs,
                &Journal::default(),
                |_| Err("unexpected leaf".into()),
            )
            .unwrap();
            assert!(
                matches!(p.scopes[&whipplescript_parser::action_plan::ScopeId(0)].boundary, Boundary::Succeeded(ref value) if value.value == expected)
            );
        }
        // A fallback cannot turn an ill-typed value into a successful result.
        let inputs = Bindings::from([(
            typed.plan.root_inputs[0],
            Slot::Ready(json!({"title":false,"status":"completed","variant":"Other"}).into()),
        )]);
        assert!(advance_typed(
            &typed,
            &ir(),
            "i",
            &frame,
            3,
            &inputs,
            &Journal::default(),
            |_| Err("unexpected leaf".into())
        )
        .unwrap_err()
        .message
        .contains("captured type"));
        let mut damaged = typed;
        damaged.case_types.clear();
        assert!(advance_typed(
            &damaged,
            &ir(),
            "i",
            &frame,
            3,
            &inputs,
            &Journal::default(),
            |_| Err("unexpected leaf".into())
        )
        .is_err());
    }
    #[test]
    fn resolved_case_null_narrowing_selects_absence_and_preserves_real_helper_values() {
        let source = "workflow Demo\nclass Input { values int[] }\naction first(xs int[]) -> int? { timer 1s as delay\nreturn xs[0] }\naction required(xs int[]) -> int { first(xs) as x\ncase x { null => { return 10 } _ => { return x + 1 } } }\nrule run when Input as input => { required(input.values) as answer }";
        let parsed = whipplescript_parser::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let typed = resolve_rule_types(&parsed.program, "run").unwrap();
        let ir = whipplescript_parser::compile_program("workflow Demo\nclass Input { values int[] }\noutput result Result\nclass Result { ok bool }\nrule finish when started => { complete result { ok true } }").ir.unwrap();
        let frame = Frame {
            version: "v".into(),
            revision: "0".into(),
            rule: "run".into(),
            identity: Some("input".into()),
            trigger_event: Some("admit".into()),
        };
        let leaf = |state| crate::source_action::progression::Leaf::Ready {
            lowering: Box::default(),
            value: (state == crate::source_action::WorkState::Succeeded)
                .then(|| Value::Null.into()),
            work: Some(crate::source_action::OwnedWork {
                state,
                causes: Default::default(),
            }),
        };
        for (values, expected) in [(json!([]), 10), (json!([5]), 6)] {
            let inputs = Bindings::from([(
                typed.plan.root_inputs[0],
                Slot::Ready(json!({"values":values}).into()),
            )]);
            let p = advance_typed(
                &typed,
                &ir,
                "i",
                &frame,
                3,
                &inputs,
                &Journal::default(),
                |_| Ok(leaf(crate::source_action::WorkState::Succeeded)),
            )
            .unwrap();
            assert!(
                matches!(p.scopes[&whipplescript_parser::action_plan::ScopeId(0)].boundary, Boundary::Succeeded(ref value) if value.value == expected),
                "{p:?}"
            );
        }
        let pending = Bindings::from([(
            typed.plan.root_inputs[0],
            Slot::Ready(json!({"values":[]}).into()),
        )]);
        let p = advance_typed(
            &typed,
            &ir,
            "i",
            &frame,
            3,
            &pending,
            &Journal::default(),
            |_| Ok(leaf(crate::source_action::WorkState::Pending)),
        )
        .unwrap();
        assert!(matches!(p.root.boundary, Boundary::Waiting(_)));
        assert!(!p
            .scopes
            .values()
            .any(|scope| matches!(scope.boundary, Boundary::Succeeded(_))));
        let optional = IrType::Optional(Box::new(whipplescript_parser::IrType::Primitive(
            whipplescript_parser::IrPrimitiveType::String,
        )));
        assert!(matches(&ir, &optional, "null", &Value::Null).unwrap());
        assert!(!matches(&ir, &optional, "\"null\"", &Value::Null).unwrap());
        assert!(matches(&ir, &optional, "\"null\"", &json!("null")).unwrap());
        assert!(!matches(&ir, &optional, "null", &json!("null")).unwrap());
    }

    #[test]
    fn resolved_case_presence_words_respect_the_captured_value_domain() {
        for (header, value_type) in [
            ("workflow Demo\nenum Choice { Some\nNone\nOther }\n", "Choice"),
            ("workflow Demo\nagent Some { provider fixture profile \"some\" capacity 1 capabilities [] }\nagent None { provider fixture profile \"none\" capacity 1 capabilities [] }\nagent Other { provider fixture profile \"other\" capacity 1 capabilities [] }\n", "AgentRef<Some | None | Other>"),
        ] {
        let optional = format!("{value_type}?");
        let union = format!("{value_type} | null");
        for (ty, arms, samples) in [
            (value_type, "Some => { return 1 } None => { return 2 } _ => { return 3 }", vec![(json!("Some"), 1), (json!("None"), 2), (json!("Other"), 3)]),
            (optional.as_str(), "Some => { return 1 } None => { return 2 }", vec![(json!("Some"), 1), (json!("None"), 1), (json!("Other"), 1), (Value::Null, 2)]),
            (optional.as_str(), "\"Some\" => { return 1 } \"None\" => { return 2 } null => { return 0 } _ => { return 3 }", vec![(json!("Some"), 1), (json!("None"), 2), (json!("Other"), 3), (Value::Null, 0)]),
            (union.as_str(), "Some => { return 1 } None => { return 2 } null => { return 0 } _ => { return 3 }", vec![(json!("Some"), 1), (json!("None"), 2), (json!("Other"), 3), (Value::Null, 0)]),
        ] {
            let declarations = format!("{header}class Input {{ value {ty} }}\n");
            let source = format!("{declarations}action choose(x {ty}) -> int {{ case x {{ {arms} }} }}\nrule run when Input as input => {{ choose(input.value) as answer }}");
            let parsed = whipplescript_parser::parse_program(&source);
            assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
            let typed = resolve_rule_types(&parsed.program, "run").unwrap();
            let compiled = whipplescript_parser::compile_program(&format!("{declarations}output result Result\nclass Result {{ ok bool }}\nrule finish when started => {{ complete result {{ ok true }} }}"));
            let ir = compiled.ir.expect("declarations");
            let frame = Frame { version: "v".into(), revision: "0".into(), rule: "run".into(), identity: Some("input".into()), trigger_event: Some("admit".into()) };
            for (value, expected) in samples {
                let inputs = Bindings::from([(typed.plan.root_inputs[0], Slot::Ready(json!({"value":value}).into()))]);
                let p = advance_typed(&typed, &ir, "i", &frame, 3, &inputs, &Journal::default(), |_| Err("unexpected leaf".into())).unwrap();
                assert!(matches!(p.scopes[&whipplescript_parser::action_plan::ScopeId(0)].boundary, Boundary::Succeeded(ref value) if value.value == expected), "{ty} {value}: expected {expected}, got {p:?}");
            }
        }
        }
    }

    #[test]
    fn resolved_case_presence_named_classes_bind_after_a_null_guard() {
        for class in ["Some", "None"] {
            let declarations = format!("workflow Demo\nclass {class} {{ value string }}\nclass Input {{ item {class}? }}\n");
            let source = format!("{declarations}action choose(x {class}?) -> string {{ case true {{ _ where x != null => {{ case x {{ {class} as item => {{ return item.value }} }} }} _ => {{ return \"absent\" }} }} }}\nrule run when Input as input => {{ choose(input.item) }}");
            let typed =
                resolve_rule_types(&whipplescript_parser::parse_program(&source).program, "run")
                    .unwrap();
            let ir = whipplescript_parser::compile_program(&format!("{declarations}output result Result\nclass Result {{ ok bool }}\nrule finish when started => {{ complete result {{ ok true }} }}")).ir.unwrap();
            let frame = Frame {
                version: "v".into(),
                revision: "0".into(),
                rule: "run".into(),
                identity: Some("input".into()),
                trigger_event: Some("admit".into()),
            };
            for (value, expected) in [
                (json!({"value":"chosen"}), "chosen"),
                (Value::Null, "absent"),
            ] {
                let inputs = Bindings::from([(
                    typed.plan.root_inputs[0],
                    Slot::Ready(json!({"item":value}).into()),
                )]);
                let p = advance_typed(
                    &typed,
                    &ir,
                    "i",
                    &frame,
                    3,
                    &inputs,
                    &Journal::default(),
                    |_| Err("unexpected leaf".into()),
                )
                .unwrap();
                assert!(
                    matches!(p.scopes[&whipplescript_parser::action_plan::ScopeId(0)].boundary, Boundary::Succeeded(ref value) if value.value == expected),
                    "{class} {p:?}"
                );
            }
        }
    }

    #[test]
    fn resolved_case_validation_refuses_missing_types_and_nominal_union_guessing() {
        let ir = ir();
        let value = json!({"title":"yes","status":"completed","variant":"Other"});
        assert!(validate(&ir, &IrType::Ref("Absent".into()), &value).is_err());
        assert!(matches(&ir, &IrType::Ref("Absent".into()), "Absent", &value).is_err());
        assert!(validate(
            &ir,
            &IrType::Union(vec![
                IrType::Ref("Ticket".into()),
                IrType::Ref("Other".into())
            ]),
            &value
        )
        .is_err());
        assert!(matches(&ir, &IrType::Object(vec![]), "Ticket", &value).is_err());
        assert!(!matches(&ir, &IrType::Ref("Ticket".into()), "Other", &value).unwrap());
    }

    #[test]
    fn terminal_outcome_case_validation_refuses_missing_and_unknown_tags() {
        let ir = ir();
        let ty = IrType::Ref("TerminalOutcome".into());
        assert_eq!(
            validate(&ir, &ty, &json!({"value":null, "error":null})),
            Err("managed terminal outcome has no recognized tag".into())
        );
        assert_eq!(
            validate(
                &ir,
                &ty,
                &json!({"tag":"Other", "value":null, "error":null})
            ),
            Err("managed terminal outcome has unknown tag `Other`".into())
        );
    }

    #[test]
    fn resolved_case_scalar_enum_optional_and_tagged_values_keep_their_types() {
        let ir = ir();
        let status = IrType::Ref("Status".into());
        validate(&ir, &status, &json!("ready")).unwrap();
        assert!(matches(&ir, &status, "ready", &json!("ready")).unwrap());
        assert!(matches(&ir, &status, "\"ready\"", &json!("ready")).unwrap());
        assert!(!matches(&ir, &status, "waiting", &json!("ready")).unwrap());
        assert!(validate(&ir, &status, &json!("outside")).is_err());
        let optional = IrType::Optional(Box::new(IrType::Ref("Ticket".into())));
        validate(&ir, &optional, &Value::Null).unwrap();
        assert!(matches(&ir, &optional, "None", &Value::Null).unwrap());
        assert!(!matches(&ir, &optional, "Some", &Value::Null).unwrap());
        assert!(!matches(&ir, &optional, "Ticket", &Value::Null).unwrap());
        let value = json!({"title":"yes","status":"completed","variant":"Other"});
        validate(&ir, &optional, &value).unwrap();
        assert!(matches(&ir, &optional, "Ticket", &value).unwrap());
        let ir = whipplescript_parser::compile_program("workflow Sum\nenum Choice { Yes { value string }\nNo }\noutput result Result\nclass Result { ok bool }\nrule finish when started => { complete result { ok true } }").ir.unwrap();
        let ty = IrType::Ref("Choice".into());
        let value = json!({"variant":"Yes","value":"ok"});
        validate(&ir, &ty, &value).unwrap();
        assert!(matches(&ir, &ty, "Yes", &value).unwrap());
        assert!(!matches(&ir, &ty, "No", &value).unwrap());
        assert!(validate(&ir, &ty, &json!({"variant":"Yes","value":42})).is_err());
    }
}
