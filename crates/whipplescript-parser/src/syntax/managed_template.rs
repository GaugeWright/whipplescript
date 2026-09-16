//! Authored interpolation boundaries, shared by managed typing and evaluation.
//! Text inserted at runtime never re-enters this parser.
use crate::{Expr, SourceSpan};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Segment<'a> {
    Text(&'a str),
    Expression {
        source: &'a str,
        expr: Expr,
        span: SourceSpan,
    },
}

pub fn parse(source: &str) -> Result<Vec<Segment<'_>>, String> {
    let mut segments = Vec::new();
    let mut offset = 0;
    while let Some(open) = source[offset..].find("{{") {
        let open = offset + open;
        segments.push(Segment::Text(&source[offset..open]));
        let start = open + 2;
        let tokens = super::lex(&source[start..]).tokens;
        let mut depth = 0usize;
        let mut end = None;
        for (index, token) in tokens.iter().enumerate() {
            match token.kind {
                super::TokenKind::Symbol('{') => depth += 1,
                super::TokenKind::Symbol('}') if depth > 0 => depth -= 1,
                super::TokenKind::Symbol('}') => {
                    if tokens.get(index + 1).is_some_and(|next| {
                        next.kind == super::TokenKind::Symbol('}')
                            && next.span.start == token.span.end
                    }) {
                        end = Some(start + token.span.start);
                    }
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or("managed prompt interpolation has no closing `}}`")?;
        let expression = &source[start..end];
        let expr = crate::parse_expression(expression)
            .map_err(|issue| format!("invalid managed prompt interpolation: {issue}"))?;
        segments.push(Segment::Expression {
            source: expression,
            expr,
            span: SourceSpan { start, end },
        });
        offset = end + 2;
    }
    segments.push(Segment::Text(&source[offset..]));
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_template_uses_authored_expression_boundaries_only() {
        let source = r#"Unicode 🦀 {{ { text "}}" } }} / {{ ticket.title }} end"#;
        let parts = parse(source).unwrap();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], Segment::Text("Unicode 🦀 "));
        let Segment::Expression {
            source: expression,
            span,
            ..
        } = &parts[1]
        else {
            panic!("expression")
        };
        assert_eq!(*expression, &source[span.start..span.end]);
        assert_eq!(*expression, r#" { text "}}" } "#);
        assert_eq!(parts[4], Segment::Text(" end"));
        assert_eq!(
            parse("literal ticket.secret").unwrap(),
            vec![Segment::Text("literal ticket.secret")]
        );
        for invalid in ["{{", "{{ }}", "{{ x + }}", "{{ { x 1 } }} trailing {{"] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }
}
