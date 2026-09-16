//! Actual per-rule body inventories over one compiler-derived source analysis.
//! This result is neither complete IFC nor permission to execute a program.
use super::*;
use whipplescript_parser::action_plan::analysis::{CompositionAnalysis, RuleAnalysis};
mod dependencies;

pub struct RuleBodyAnalysis<'a> {
    pub rule: &'a RuleAnalysis,
    pub inventory: ManagedStatementSinks,
}
pub struct CompositionBodies<'a> {
    source: &'a CompositionAnalysis,
    rules: Vec<RuleBodyAnalysis<'a>>,
}
impl<'a> CompositionBodies<'a> {
    pub fn source(&self) -> &'a CompositionAnalysis {
        self.source
    }
    pub fn rules(&self) -> &[RuleBodyAnalysis<'a>] {
        &self.rules
    }

    /// Possible activation couplings only; query validity, effect readiness,
    /// pacing and termination are separate obligations.
    pub fn rule_dependencies(&self) -> Vec<whipplescript_parser::IrRuleDependency> {
        dependencies::build(self.source, &self.rules)
    }

    /// All local executor sinks, with producer reach derived from these same
    /// bodies. Other IFC axes and package/admission obligations remain open.
    pub fn check_local_executor_integrity(&self, verified: &VerifiedEnvelope) -> Vec<Diagnostic> {
        let facts = match fact_producers::reach(self, verified) {
            Ok(facts) => facts,
            Err(errors) => return errors,
        };
        let context = program_context::ProgramContext::Composition(self.source);
        let facts = &facts;
        self.rules
            .iter()
            .flat_map(|body| {
                body.inventory.local.iter().flat_map(move |sink| {
                    output_integrity::managed::check_sink_in(
                        &body.rule.typed,
                        context,
                        verified,
                        sink.as_sink(),
                        facts,
                    )
                })
            })
            .collect()
    }

    /// Source confidentiality/input integrity and model egress at local doors.
    /// Includes inherited input-selector constraints and additive field clearance.
    /// Package and complete admission obligations remain separate.
    pub fn check_source_flows(
        &self,
        verified: &VerifiedEnvelope,
        imports: &[IrProgram],
    ) -> Vec<Diagnostic> {
        source_inputs::check(self, verified, imports)
    }

    /// Read ceiling for an explicitly product-authenticated identity. No ambient
    /// identity lookup; no party map retains the existing gradual behavior.
    pub fn check_principal_ceiling_for_identity(
        &self,
        verified: &VerifiedEnvelope,
        identity: &str,
        imports: &[IrProgram],
    ) -> Vec<Diagnostic> {
        composition_authority::principal(self, verified, identity, imports)
    }

    /// Static credential/type scope only; custody still checks each actual opener.
    pub fn check_turn_unwrap_scoping(&self, verified: &VerifiedEnvelope) -> Vec<Diagnostic> {
        composition_authority::unwrap(self, verified)
    }

    /// The provider-egress portion only; imports retain their full checked IR.
    pub fn check_provider_egress(
        &self,
        verified: &VerifiedEnvelope,
        imports: &[IrProgram],
    ) -> Vec<Diagnostic> {
        let context = program_context::ProgramContext::Composition(self.source);
        self.rules
            .iter()
            .flat_map(|rule| {
                provider_egress::check_in(&rule.rule.typed, context, verified, imports)
            })
            .collect()
    }
}

pub fn analyze(source: &CompositionAnalysis) -> Result<CompositionBodies<'_>, Vec<Diagnostic>> {
    let context = program_context::ProgramContext::Composition(source);
    let mut rules = Vec::new();
    let mut diagnostics = Vec::new();
    for rule in source.rules() {
        match output_integrity::managed::sinks::inventory_in(&rule.typed, context) {
            Ok(inventory) => rules.push(RuleBodyAnalysis { rule, inventory }),
            Err(error) => diagnostics.push(*error),
        }
    }
    if !diagnostics.is_empty() {
        // MUTATION-SUCCESS-EXPR: Ok(CompositionBodies { source, rules })
        return Err(diagnostics);
    }
    Ok(CompositionBodies { source, rules })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod producers_tests;

#[cfg(test)]
mod source_tests;

#[cfg(test)]
mod authority_tests;

#[cfg(test)]
mod claim_tests;

#[cfg(test)]
mod selector_tests;

#[cfg(test)]
mod field_tests;

#[cfg(test)]
mod dependency_tests;

#[cfg(test)]
mod region_exit_tests;
