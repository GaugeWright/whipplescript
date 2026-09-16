//! Shared lexical interpretation for static and managed record construction.
use super::{FieldAssign, FieldValue};
use crate::{Expr, ExprLiteral, ExprObjectField};

impl FieldAssign {
    pub fn record_expression(
        &self,
        from: Option<&str>,
        is_binding: &impl Fn(&str) -> bool,
    ) -> Result<Expr, String> {
        match &self.value {
            FieldValue::Expr {
                expr: Expr::Literal(ExprLiteral::Ident(name)),
                ..
            } if from.is_some() && !is_binding(name) => Ok(Expr::Path(vec![
                from.expect("projection source").into(),
                name.clone(),
            ])),
            FieldValue::Expr { expr, .. } => Ok(expr.clone()),
            FieldValue::Shorthand => Ok(Expr::Path(vec![
                from.ok_or("record shorthand requires a projection source")?
                    .into(),
                self.name.clone(),
            ])),
            FieldValue::Nested { schema, fields } => {
                let mut result = vec![ExprObjectField {
                    key: "variant".into(),
                    value: Expr::Literal(ExprLiteral::String(schema.clone())),
                }];
                for field in fields {
                    if result.iter().any(|existing| existing.key == field.name) {
                        return Err(format!(
                            "variant field `{}` is reserved or duplicated",
                            field.name
                        ));
                    }
                    result.push(ExprObjectField {
                        key: field.name.clone(),
                        value: field.record_expression(None, is_binding)?,
                    });
                }
                Ok(Expr::Object(result))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{parse_action_body, BodyStmt};
    use crate::SourceSpan;

    #[test]
    fn record_expression_resolves_projection_scope_and_refuses_forged_constructors() {
        let field = FieldAssign {
            name: "name".into(),
            value: FieldValue::Shorthand,
            span: SourceSpan { start: 0, end: 4 },
        };
        assert!(field.record_expression(None, &|_| false).is_err());
        assert_eq!(
            field.record_expression(Some("source"), &|_| false).unwrap(),
            Expr::Path(vec!["source".into(), "name".into()])
        );
        for source in [
            "record Out { value Named { variant \"Other\" } }",
            "record Out { value Named { name \"a\" name \"b\" } }",
        ] {
            let (body, errors) = parse_action_body(source, 0);
            assert!(errors.is_empty(), "{errors:?}");
            let BodyStmt::Record(record) = &body.statements[0] else {
                panic!("not a record")
            };
            assert!(record.fields[0]
                .record_expression(None, &|_| false)
                .is_err());
        }
        let (body, errors) = parse_action_body(
            "record Out from source { name alternate value Named { name alternate } }",
            0,
        );
        assert!(errors.is_empty(), "{errors:?}");
        let BodyStmt::Record(record) = &body.statements[0] else {
            panic!("not a record")
        };
        assert_eq!(
            record.fields[0]
                .record_expression(record.from.as_deref(), &|_| false)
                .unwrap(),
            Expr::Path(vec!["source".into(), "alternate".into()])
        );
        let ident = Expr::Literal(ExprLiteral::Ident("alternate".into()));
        assert_eq!(
            record.fields[0]
                .record_expression(record.from.as_deref(), &|_| true)
                .unwrap(),
            ident
        );
        assert_eq!(
            record.fields[1]
                .record_expression(record.from.as_deref(), &|_| false)
                .unwrap(),
            Expr::Object(vec![
                ExprObjectField {
                    key: "variant".into(),
                    value: Expr::Literal(ExprLiteral::String("Named".into()))
                },
                ExprObjectField {
                    key: "name".into(),
                    value: ident
                },
            ])
        );
    }
}
