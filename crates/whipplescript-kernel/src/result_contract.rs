//! An agent turn's result contract: the one definition both hosts use.
//!
//! `agent <name> { returns <Class> }` settles a turn on the model calling a
//! TERMINAL TOOL whose input schema is that class. The name of the tool, the
//! schema offered for it, and the validation applied on the way in all live
//! here rather than in either host, because a turn that asserted a result on
//! one host and settled on silence on the other would be one program meaning
//! two things -- the exact divergence the durable object used to refuse
//! `returns` outright to avoid.

use whipplescript_parser::{IrProgram, IrType};

use crate::harness_loop::ToolSpec;

/// The terminal tool's name. Offered before any program-granted tool, so a
/// program cannot shadow the call its own contract settles on.
pub const TOOL_SUBMIT_RESULT: &str = "submit_result";

/// The class a turn's result must match, with the program that declares it.
#[derive(Clone, Debug)]
pub struct ResultContract {
    pub class: String,
    pub ir: IrProgram,
}

impl ResultContract {
    pub fn new(class: impl Into<String>, ir: IrProgram) -> Self {
        Self {
            class: class.into(),
            ir,
        }
    }

    fn ir_type(&self) -> IrType {
        IrType::Ref(self.class.clone())
    }

    /// The tool as the model sees it: the declared class IS the input schema,
    /// so a provider that enforces tool schemas rejects the wrong shape before
    /// whip does, and one that does not is caught by [`Self::validate`].
    pub fn tool_spec(&self) -> ToolSpec {
        ToolSpec {
            name: TOOL_SUBMIT_RESULT.to_owned(),
            description: format!(
                "Submit this turn's result as a `{}`. The turn is not finished until you \
                 call this, and calling it ends the turn.",
                self.class
            ),
            input_schema: crate::coerce_native::json_schema_for_type(
                &self.ir_type(),
                &self.ir.schemas,
            ),
        }
    }

    /// Validate an asserted result and echo it back canonically.
    ///
    /// `Err` is NOT a turn failure: it becomes a tool error, the model sees
    /// what was wrong with the shape it sent, and it gets another round. A turn
    /// only settles on the call that succeeds.
    pub fn validate(&self, args: &serde_json::Value) -> Result<String, String> {
        let mut errors = Vec::new();
        crate::rule_lowering::validate_json_for_ir_type(
            &self.ir,
            args,
            &self.ir_type(),
            "result",
            &mut errors,
        );
        if errors.is_empty() {
            serde_json::to_string(args).map_err(|error| format!("result is not JSON: {error}"))
        } else {
            Err(format!(
                "the result does not match `{}`: {}",
                self.class,
                errors.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's refusal has to be measured HERE. It was covered from the
    /// CLI while it lived there, and lifting it into the kernel so both hosts
    /// share one definition moved the code away from its only test -- the sweep
    /// mutates a file and runs its OWN crate's tests, so a shared rule needs a
    /// test in the crate that now owns it.
    #[test]
    fn a_result_is_refused_unless_it_matches_the_declared_class() {
        let source = "workflow W\n\n\
             output result Done\n\n\
             class Done {\n  ok int\n}\n\n\
             class ReviewResult {\n  verdict string\n  findings int\n}\n\n\
             rule go\n  when started\n=> {\n  complete result { ok 1 }\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("the contract program compiles");
        let contract = ResultContract::new("ReviewResult", ir);

        let mistyped = contract
            .validate(&serde_json::json!({ "verdict": "keep", "findings": "many" }))
            .expect_err("`findings` is an int");
        assert!(
            mistyped.contains("the result does not match `ReviewResult`"),
            "the refusal names the class the turn declared: {mistyped}"
        );

        let absent = contract
            .validate(&serde_json::json!({ "verdict": "keep" }))
            .expect_err("a declared field is missing");
        assert!(
            absent.contains("the result does not match `ReviewResult`"),
            "an absent field is as unacceptable as a mistyped one: {absent}"
        );

        // The control: a validator that refused everything would pass both
        // assertions above, and settle no turn ever.
        let accepted = contract
            .validate(&serde_json::json!({ "verdict": "keep", "findings": 2 }))
            .expect("the declared shape is accepted");
        assert!(accepted.contains("keep"), "echoed canonically: {accepted}");

        // The tool the model is offered carries the class as its schema, which
        // is what lets a schema-enforcing provider reject the wrong shape before
        // this validation ever runs.
        let spec = contract.tool_spec();
        assert_eq!(spec.name, TOOL_SUBMIT_RESULT);
        assert!(
            spec.description.contains("ReviewResult"),
            "the model is told which class to submit: {}",
            spec.description
        );
    }
}
