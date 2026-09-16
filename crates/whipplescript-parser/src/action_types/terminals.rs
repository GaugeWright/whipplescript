//! Workflow egress consumes the same managed value contracts as action returns.
use super::*;
use body::{FieldValue, RecordStmt, TerminalKind, TerminalStmt};
impl Checker<'_> {
    pub(super) fn terminal_payload(
        &mut self,
        owner: Owner<'_>,
        terminal: &TerminalStmt,
        environment: &Environment,
    ) {
        let Owner::Rule(_) = owner else {
            self.scope_error(
                terminal.span,
                "an action cannot terminate its workflow".into(),
                owner,
            );
            return;
        };
        let wanted = match terminal.kind {
            TerminalKind::Complete => WorkflowContractKind::Output,
            TerminalKind::Fail => WorkflowContractKind::Failure,
        };
        let Some(contract) = self
            .semantic
            .workflow_terminals
            .iter()
            .find(|contract| contract.name.name == terminal.name && contract.kind == wanted)
            .cloned()
        else {
            self.scope_error(
                terminal.span,
                format!(
                    "workflow has no {} contract `{}`",
                    wanted.as_str(),
                    terminal.name
                ),
                owner,
            );
            return;
        };
        if let Some(value) = &terminal.scalar {
            let FieldValue::Expr { source, expr } = value else {
                self.scope_error(
                    terminal.span,
                    "workflow terminal value must be an expression".into(),
                    owner,
                );
                return;
            };
            self.check_value(
                &CompositionExpr {
                    source: source.clone(),
                    expr: expr.clone(),
                    span: terminal.span,
                },
                &contract.ty,
                environment,
                &format!("workflow {} `{}`", wanted.as_str(), terminal.name),
            );
        } else if let IrType::Ref(schema) = lower_type(contract.ty.clone()) {
            if !self.semantic.schemas.classes.contains_key(&schema) {
                self.scope_error(
                    terminal.span,
                    "workflow terminal field block requires a class contract".into(),
                    owner,
                );
                return;
            }
            self.record_payload(
                &RecordStmt {
                    schema,
                    from: terminal.from.clone(),
                    fields: terminal.fields.clone(),
                    span: terminal.span,
                },
                environment,
            );
        } else {
            self.scope_error(terminal.span, "workflow terminal field block requires a class contract; supply a value expression for this contract".into(), owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{action_plan::resolved::resolve_rule_types, parse_program};
    fn check(body: &str) -> Result<(), Vec<crate::Diagnostic>> {
        let source=format!("workflow Demo\noutput result Answer\nfailure rejected string\nclass Answer {{ text string }}\naction answer() -> Answer {{ return {{ text \"yes\" }} }}\nrule run when started => {{ {body} }}");
        let parsed = parse_program(&source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        resolve_rule_types(&parsed.program, "run").map(|_| ())
    }
    #[test]
    fn managed_terminal_types_accept_action_results_and_field_projection() {
        for body in [
            "answer() as value\ncomplete result value",
            "answer() as value\ncomplete result from value {}",
            "answer() as value\ncomplete result { text value.text }",
            "fail rejected \"no\"",
        ] {
            assert!(check(body).is_ok(), "{body}: {:?}", check(body));
        }
    }
    #[test]
    fn managed_terminal_types_refuse_wrong_names_types_and_fields() {
        for (body, message) in [
            ("complete absent {}", "no output contract"),
            ("fail result \"bad\"", "no failure contract"),
            ("complete result 42", "expects Answer"),
            ("fail rejected 42", "expects string"),
            ("complete result { text 42 }", "expects string"),
            ("complete result {}", "does not guarantee required field"),
            ("complete result { text \"yes\" extra 42 }", "has no field"),
            ("fail rejected {}", "requires a class contract"),
        ] {
            let diagnostics = check(body).unwrap_err();
            assert!(
                diagnostics.iter().any(|d| d.message.contains(message)),
                "{body}: {diagnostics:?}"
            );
        }
    }
}
