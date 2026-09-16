//! One interpretation of existing optional presence words for source and runtime.
//! This classifies presence aliases; the case checker still resolves all union
//! alternatives and validates ordinary literal and nominal patterns.
use crate::{parse_expression, Expr, ExprLiteral, IrType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresencePattern {
    Present,
    Absent,
}

pub fn optional_presence(ty: &IrType, pattern: &str) -> Option<PresencePattern> {
    fn has_optional(ty: &IrType) -> bool {
        match ty {
            IrType::Optional(_) => true,
            IrType::Union(variants) => variants.iter().any(has_optional),
            _ => false,
        }
    }
    if !has_optional(ty) {
        return None;
    }
    match parse_expression(pattern).ok()? {
        Expr::Literal(ExprLiteral::Ident(name)) if name == "Some" => Some(PresencePattern::Present),
        Expr::Literal(ExprLiteral::Ident(name)) if name == "None" => Some(PresencePattern::Absent),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IrPrimitiveType;
    #[test]
    fn optional_presence_words_are_unquoted_and_belong_to_the_outer_domain() {
        let scalar = IrType::Primitive(IrPrimitiveType::Int);
        let optional = IrType::Optional(Box::new(scalar.clone()));
        for ty in [
            optional.clone(),
            IrType::Union(vec![scalar.clone(), optional.clone()]),
        ] {
            assert_eq!(
                optional_presence(&ty, "Some"),
                Some(PresencePattern::Present)
            );
            assert_eq!(
                optional_presence(&ty, " None "),
                Some(PresencePattern::Absent)
            );
            for pattern in ["\"Some\"", "\"None\"", "null", "Other", "Some == None", "("] {
                assert_eq!(optional_presence(&ty, pattern), None, "{pattern}");
            }
        }
        for ty in [
            scalar.clone(),
            IrType::Ref("Some".into()),
            IrType::AgentRef(vec!["Some".into(), "None".into()]),
            IrType::Union(vec![scalar, IrType::Primitive(IrPrimitiveType::Null)]),
            IrType::Array(Box::new(optional.clone())),
            IrType::Map(Box::new(optional.clone())),
            IrType::Sealed(Box::new(optional)),
            IrType::Union(vec![]),
        ] {
            for pattern in ["Some", "None"] {
                assert_eq!(optional_presence(&ty, pattern), None, "{ty:?} {pattern}");
            }
        }
    }
    fn resolve(
        source: &str,
    ) -> Result<crate::action_plan::resolved::TypedActionPlan, Vec<crate::Diagnostic>> {
        let parsed = crate::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        crate::action_plan::resolved::resolve_rule_types(&parsed.program, "run")
    }
    #[test]
    fn optional_presence_does_not_hide_a_competing_union_interpretation() {
        let source = "workflow Demo\nenum Choice { Some\nNone }\nclass Input { value int? | Choice }\naction choose(x int? | Choice) -> int { case x { Some => { return 1 } _ => { return 0 } } }\nrule run when Input as input => { choose(input.value) }";
        let errors = resolve(source).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("does not match the type")),
            "{errors:?}"
        );
    }
    #[test]
    fn optional_presence_cannot_fabricate_a_nominal_class_alias() {
        for class in ["Some", "None"] {
            let declarations = format!("workflow Demo\nclass {class} {{ value string }}\nclass Input {{ item {class}? }}\n");
            let source = format!("{declarations}action choose(x {class}?) -> string {{ case x {{ {class} as item => {{ return item.value }} _ => {{ return \"absent\" }} }} }}\nrule run when Input as input => {{ choose(input.item) }}");
            let errors = resolve(&source).unwrap_err();
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert!(errors[0].message.contains("presence pattern"), "{errors:?}");
            assert!(errors[0].message.contains("null guard"), "{errors:?}");
            assert!(source[errors[0].span.start..errors[0].span.end].contains("as item"));
            let source = format!("{declarations}action choose(x {class}?) -> string {{ case true {{ _ where x != null => {{ case x {{ {class} as item => {{ return item.value }} }} }} _ => {{ return \"absent\" }} }} }}\nrule run when Input as input => {{ choose(input.item) }}");
            assert!(resolve(&source).is_ok(), "{source}: {:?}", resolve(&source));
        }
    }
}
