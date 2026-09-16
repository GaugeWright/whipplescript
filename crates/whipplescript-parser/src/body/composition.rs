//! Typed action syntax in the shared body parser. These nodes are expanded
//! before ordinary rule lowering; parsing one never creates executable work.

use super::{BodyParser, BodyStmt, Expr, SourceSpan};
use crate::diagnostic_code;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionExpr {
    pub source: String,
    pub expr: Expr,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CompositionStmt {
    Call {
        name: String,
        name_span: SourceSpan,
        arguments: Vec<CompositionExpr>,
        binding: Option<String>,
        span: SourceSpan,
    },
    Return(CompositionExpr),
    Fail(CompositionExpr),
    OnFailure {
        alias: String,
        body: Vec<BodyStmt>,
        span: SourceSpan,
    },
    Then {
        binding: String,
        operation: Box<BodyStmt>,
        span: SourceSpan,
    },
}

impl CompositionStmt {
    pub fn span(&self) -> SourceSpan {
        match self {
            Self::Call { span, .. } | Self::OnFailure { span, .. } | Self::Then { span, .. } => {
                *span
            }
            Self::Return(value) | Self::Fail(value) => value.span,
        }
    }
}

impl BodyParser<'_> {
    pub(super) fn parse_composition_statement(&mut self, keyword: &str) -> Option<BodyStmt> {
        let start = self.pos;
        let statement = match keyword {
            "on" if self.mode != super::BodyMode::LegacyRule => {
                self.pos += 1;
                if !self.consume_ident("failure") {
                    self.error(
                        diagnostic_code!("construct.unknown_clause"),
                        self.span_here(),
                        "`on` in a composed body must declare `on failure`",
                        Some("write `on failure as problem { ... }`".to_owned()),
                    );
                    return None;
                }
                if !self.consume_ident("as") {
                    self.error(
                        diagnostic_code!("parse.unexpected_token"),
                        self.span_here(),
                        "expected `as` and a binding after `on failure`",
                        Some("write `on failure as problem { ... }`".to_owned()),
                    );
                    return None;
                }
                let alias = self.ident_text("failure handler binding")?;
                let opened_at = self.span_here();
                if !self.composition_symbol('{', "expected `{` to open the failure handler") {
                    return None;
                }
                let body = self.parse_statements(Some(opened_at));
                CompositionStmt::OnFailure {
                    alias,
                    body,
                    span: self.span_from(start),
                }
            }
            "return" if self.mode == super::BodyMode::ComposedRule => {
                self.pos += 1;
                let value = self.composition_expression()?;
                self.error(
                    diagnostic_code!("construct.invalid_expansion"),
                    value.span,
                    "a rule cannot return an action result",
                    Some("return from an action, or use the workflow terminal contract".to_owned()),
                );
                return None;
            }
            "return" | "fail" => {
                self.pos += 1;
                let value = self.composition_expression()?;
                if keyword == "return" {
                    CompositionStmt::Return(value)
                } else {
                    CompositionStmt::Fail(value)
                }
            }
            "then" => return self.parse_composition_then(),
            "complete" => {
                let span = self.span_here();
                self.parse_terminal();
                self.error(
                    diagnostic_code!("construct.invalid_expansion"),
                    span,
                    "an action cannot complete its containing workflow",
                    Some("use `return value` to supply this action's result".to_owned()),
                );
                return None;
            }
            _ => {
                let name_span = self.span_here();
                let name = self.ident_text("action name")?;
                if !self.composition_symbol('(', "expected `(` after action name") {
                    return None;
                }
                let mut arguments = Vec::new();
                while self.peek().is_some() && !self.at_sym(')') {
                    arguments.push(self.composition_expression()?);
                    if !self.at_sym(')')
                        && !self.composition_symbol(',', "separate action arguments with `,`")
                    {
                        return None;
                    }
                }
                if !self.composition_symbol(')', "expected `)` after action arguments") {
                    return None;
                }
                let binding = if self.consume_ident("as") {
                    Some(self.ident_text("action result binding")?)
                } else {
                    None
                };
                CompositionStmt::Call {
                    name,
                    name_span,
                    arguments,
                    binding,
                    span: self.span_from(start),
                }
            }
        };
        Some(BodyStmt::Composition(statement))
    }

    fn composition_expression(&mut self) -> Option<CompositionExpr> {
        let start = self.pos;
        let (source, expr) = self.parse_value_expression()?;
        Some(CompositionExpr {
            source,
            expr,
            span: self.span_from(start),
        })
    }

    fn composition_symbol(&mut self, symbol: char, message: &str) -> bool {
        if self.consume_sym(symbol) {
            return true;
        }
        self.error(
            diagnostic_code!("parse.unexpected_token"),
            self.span_here(),
            message,
            None,
        );
        false
    }

    fn parse_composition_then(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1;
        let binding = self.ident_text("result binding after `then`")?;
        if !self.composition_symbol('<', "expected `<-` after `then` binding")
            || !self.composition_symbol('-', "expected `<-` after `then` binding")
        {
            return None;
        }
        let previous = std::mem::replace(&mut self.implicit_result_binding, true);
        let operation = self.parse_statement();
        self.implicit_result_binding = previous;
        let operation = operation?;
        let existing = match &operation {
            BodyStmt::Effect(effect) => &effect.binding,
            BodyStmt::Composition(CompositionStmt::Call { binding, .. }) => binding,
            _ => {
                self.error(
                    diagnostic_code!("construct.invalid_expansion"),
                    self.span_from(start),
                    "`then` must sequence an effect or action call",
                    Some("write a return, record or branch directly in the action body".to_owned()),
                );
                return None;
            }
        };
        if let Some(existing) = existing {
            self.error(
                diagnostic_code!("construct.invalid_expansion"),
                self.span_from(start),
                format!("`then {binding} <-` already binds the result; remove `as {existing}`"),
                None,
            );
            return None;
        }
        Some(BodyStmt::Composition(CompositionStmt::Then {
            binding,
            operation: Box::new(operation),
            span: self.span_from(start),
        }))
    }
}

#[cfg(test)]
mod tests;
