//! Captured syntax-plan component, not a complete executable program or a
//! supported execution-semantics tag. Never use the diagnostic IR decoder here.
use serde::{Deserialize, Serialize};
use whipplescript_parser::action_plan::ActionPlan;

const FORMAT: &str = "whipplescript-source-plan/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    format: String,
    plan: ActionPlan,
}

/// Refuses before publishing bytes that this component reader cannot restore.
/// JSON's bounded nesting is retained; flat call graphs do not use that depth.
pub fn encode(plan: &ActionPlan) -> Result<String, String> {
    plan.validate_structure().map_err(|e| e.to_string())?;
    let bytes = serde_json::to_string(&Artifact {
        format: FORMAT.into(),
        plan: plan.clone(),
    })
    .map_err(|e| format!("plan artifact: {e}"))?;
    decode(&bytes)?;
    Ok(bytes)
}

/// The storage owner must additionally authenticate and bind these bytes to
/// the checked program version. Structural validity is not authority to run.
pub fn decode(bytes: &str) -> Result<ActionPlan, String> {
    let artifact: Artifact =
        serde_json::from_str(bytes).map_err(|e| format!("plan artifact: {e}"))?;
    if artifact.format != FORMAT {
        // MUTATION-SUCCESS-EXPR: Ok(artifact.plan)
        return Err(format!(
            "unsupported plan artifact format `{}`",
            artifact.format
        ));
    }
    artifact
        .plan
        .validate_structure()
        .map_err(|e| e.to_string())?;
    Ok(artifact.plan)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedArtifact {
    format: String,
    typed: whipplescript_parser::action_plan::resolved::TypedActionPlan,
}

pub fn encode_typed(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
) -> Result<String, String> {
    typed.validate_structure()?;
    let bytes = serde_json::to_string(&TypedArtifact {
        format: "whipplescript-typed-source-plan/v2".into(),
        typed: typed.clone(),
    })
    .map_err(|e| e.to_string())?;
    decode_typed(&bytes)?;
    Ok(bytes)
}

pub fn decode_typed(
    bytes: &str,
) -> Result<whipplescript_parser::action_plan::resolved::TypedActionPlan, String> {
    let artifact: TypedArtifact = serde_json::from_str(bytes).map_err(|e| e.to_string())?;
    if artifact.format != "whipplescript-typed-source-plan/v2" {
        // MUTATION-SUCCESS-EXPR: Ok(artifact.typed)
        return Err("unsupported typed source plan artifact format".into());
    }
    artifact.typed.validate_structure()?;
    Ok(artifact.typed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use whipplescript_parser::{action_plan::expand_syntax, parse_program, Expr, Item};

    fn plan(source: &str) -> ActionPlan {
        let parsed = parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let actions: Vec<_> = parsed
            .program
            .items
            .into_iter()
            .filter_map(|item| match item {
                Item::Action(action) => Some(action),
                _ => None,
            })
            .collect();
        expand_syntax(&actions, "root").unwrap()
    }
    #[test]
    fn plan_artifact_preserves_contracts_grants_payloads_and_provenance() {
        let p = plan(
            r#"workflow Demo
        action leaf(text string) -> string ! string {
          coerce classify(text) with access to files { read ["docs/**"] } as answer
          return answer
        }
        action root(text string) -> string ! string {
          leaf(text) as first
          then next <- leaf(first)
          after next fails as problem { fail problem }
          return next
        }"#,
        );
        let bytes = encode(&p).unwrap();
        assert_eq!(decode(&bytes).unwrap(), p);
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
        assert!(bytes.contains("docs/**"));
        assert!(bytes.contains("definition_span"));
        let mut changed = p.clone();
        changed.scopes[0].definition_span.end += 1;
        assert_ne!(
            encode(&changed).unwrap(),
            bytes,
            "provenance is preserved in artifact bytes"
        );
    }
    #[test]
    fn plan_artifact_refuses_unknown_and_damaged_input() {
        let p = plan("workflow Demo\naction root() -> null { return null }");
        let bytes = encode(&p).unwrap();
        let value: Value = serde_json::from_str(&bytes).unwrap();
        for (path, replacement) in [
            ("/format", json!("future")),
            ("/format", json!(null)),
            ("/plan/root", json!(999)),
            ("/plan/nodes/0/kind", json!({"Future": null})),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(path).unwrap() = replacement;
            assert!(decode(&bad.to_string()).is_err(), "{path}");
        }
        for path in [
            "",
            "/plan",
            "/plan/blocks/0",
            "/plan/nodes/0",
            "/plan/nodes/0/kind/Return",
        ] {
            let mut bad = value.clone();
            let target = path;
            bad.pointer_mut(target)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("future".into(), json!(true));
            assert!(decode(&bad.to_string()).is_err(), "{target}");
        }
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode(&(bytes.clone() + " null")).is_err());
        let mut bad = p;
        bad.scopes[0]
            .operations
            .push(whipplescript_parser::action_plan::NodeId(0));
        assert!(encode(&bad).unwrap_err().contains("owned operations"));
    }
    #[test]
    fn plan_artifact_flat_calls_round_trip_and_nested_ast_limit_is_symmetric() {
        let mut source = String::from("workflow Demo\naction root(value string) -> string { f0(value) as answer\nreturn answer }\n");
        for n in 0..1024 {
            source.push_str(&format!("action f{n}(value string) -> string {{ "));
            if n == 1023 {
                source.push_str("return value");
            } else {
                source.push_str(&format!("f{}(value) as next\nreturn next", n + 1));
            }
            source.push_str(" }\n");
        }
        let p = plan(&source);
        assert_eq!(decode(&encode(&p).unwrap()).unwrap(), p);
        let mut deep = plan("workflow Demo\naction root() -> null { return null }");
        let whipplescript_parser::action_plan::NodeKind::Return(value) = &mut deep.nodes[0].kind
        else {
            panic!("return")
        };
        for _ in 0..100 {
            value.expr = Expr::Array(vec![value.expr.clone()]);
        }
        assert!(encode(&deep).unwrap_err().contains("recursion limit"));
        let bytes = serde_json::to_string(&Artifact {
            format: FORMAT.into(),
            plan: deep,
        })
        .unwrap();
        assert!(decode(&bytes).unwrap_err().contains("recursion limit"));
    }
}

#[cfg(test)]
mod typed_tests {
    use super::*;
    use whipplescript_parser::Expr;
    #[test]
    fn managed_effect_contract_artifact_requires_v2_and_complete_policy() {
        let program = whipplescript_parser::parse_program("workflow Demo\nagent worker { provider mock capabilities [\"read\"] }\nrule run when started => { tell worker requires [\"read\"] \"Work\" as turn }").program;
        let typed =
            whipplescript_parser::action_plan::resolved::resolve_rule_types(&program, "run")
                .unwrap();
        assert_eq!(
            typed.effects.values().next().unwrap().agent_targets,
            Some(vec!["worker".into()])
        );
        let encoded = encode_typed(&typed).unwrap();
        assert_eq!(decode_typed(&encoded).unwrap(), typed);
        assert!(encoded.contains("whipplescript-typed-source-plan/v2"));
        let wrong_version = encoded.replace(
            "whipplescript-typed-source-plan/v2",
            "whipplescript-typed-source-plan/v1",
        );
        assert!(decode_typed(&wrong_version)
            .unwrap_err()
            .contains("unsupported typed source plan"));
        let mut old: serde_json::Value = serde_json::from_str(&wrong_version).unwrap();
        old["typed"].as_object_mut().unwrap().remove("effects");
        assert!(decode_typed(&old.to_string()).is_err());
        for which in 0..3 {
            let mut bad = typed.clone();
            match which {
                0 => bad.effects.clear(),
                1 => bad
                    .effects
                    .values_mut()
                    .next()
                    .unwrap()
                    .contract
                    .required_capabilities
                    .clear(),
                _ => bad.effects.values_mut().next().unwrap().agent_targets = None,
            }
            assert!(encode_typed(&bad).is_err());
            let bytes = serde_json::to_string(&TypedArtifact {
                format: "whipplescript-typed-source-plan/v2".into(),
                typed: bad,
            })
            .unwrap();
            assert!(decode_typed(&bytes).is_err());
        }
    }

    use serde_json::{json, Value};
    #[test]
    fn resolved_case_artifact_roundtrips_and_refuses_incomplete_or_future_metadata() {
        let program = whipplescript_parser::parse_program("workflow Demo\nclass Ticket { title string }\naction label(x Ticket) -> string { case x { Ticket as t => { return t.title } } }\nrule run when Ticket as ticket => { label(ticket) as answer }").program;
        let typed =
            whipplescript_parser::action_plan::resolved::resolve_rule_types(&program, "run")
                .unwrap();
        let encoded = encode_typed(&typed).unwrap();
        assert_eq!(decode_typed(&encoded).unwrap(), typed);
        assert_eq!(
            encode_typed(&decode_typed(&encoded).unwrap()).unwrap(),
            encoded
        );
        assert!(decode(&encoded).is_err());
        assert!(decode_typed(&encode(&typed.plan).unwrap()).is_err());
        let value: Value = serde_json::from_str(&encoded).unwrap();
        for (path, replacement) in [
            ("/format", json!("future")),
            ("/typed/case_types", json!({})),
            ("/typed/case_types", json!({"999":{"Ref":"Ticket"}})),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(path).unwrap() = replacement;
            assert!(decode_typed(&bad.to_string()).is_err(), "{path}");
        }
        for path in ["", "/typed"] {
            let mut bad = value.clone();
            bad.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("future".into(), json!(true));
            assert!(decode_typed(&bad.to_string()).is_err());
        }
        let mut bad = typed;
        bad.case_types.clear();
        assert!(encode_typed(&bad).is_err());
    }

    #[test]
    fn parameterized_views_roundtrip_and_damaged_composition_is_refused() {
        let compiled = whipplescript_parser::compile_program(
            r#"workflow Views
class Ticket { owner string }
view owned(wanted string) -> bool { return exists(Ticket where owner == wanted) }
view answer(wanted string) -> bool { return owned(wanted) }
action inspect(wanted string) -> bool { return answer(wanted) }
rule run when Ticket as ticket => { inspect(ticket.owner) as result }
"#,
        );
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let typed = compiled
            .typed_actions
            .unwrap()
            .into_values()
            .next()
            .unwrap();
        let encoded = encode_typed(&typed).unwrap();
        assert!(encoded.contains("\"views\""));
        assert_eq!(decode_typed(&encoded).unwrap(), typed);

        for damage in 0..3 {
            let mut bad = typed.clone();
            match damage {
                0 => bad.views.get_mut("owned").unwrap().parameters = vec!["x".into(), "x".into()],
                1 => {
                    bad.views.get_mut("answer").unwrap().expression = Expr::Call {
                        name: "answer".into(),
                        args: vec![Expr::Literal(whipplescript_parser::ExprLiteral::String(
                            "cycle".into(),
                        ))],
                    }
                }
                _ => {
                    bad.views.get_mut("answer").unwrap().expression = Expr::Call {
                        name: "missing".into(),
                        args: Vec::new(),
                    }
                }
            }
            assert!(encode_typed(&bad).is_err(), "damage {damage}");
            let bytes = serde_json::to_string(&TypedArtifact {
                format: "whipplescript-typed-source-plan/v2".into(),
                typed: bad,
            })
            .unwrap();
            assert!(decode_typed(&bytes).is_err(), "damage {damage}");
        }
    }
}
