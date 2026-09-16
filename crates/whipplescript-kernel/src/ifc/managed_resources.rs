//! Kernel adapters for the compiler-owned managed resource proof.
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::action_plan::resources;
use whipplescript_parser::action_plan::NodeId;

pub use resources::ResolvedEffect;

pub fn resolve(
    typed: &TypedActionPlan,
    ir: &IrProgram,
) -> Result<BTreeMap<NodeId, ResolvedEffect>, Box<Diagnostic>> {
    resources::resolve(typed, ir)
}

pub(super) fn resolve_in(
    typed: &TypedActionPlan,
    context: ProgramContext<'_>,
) -> Result<BTreeMap<NodeId, ResolvedEffect>, Box<Diagnostic>> {
    match context {
        ProgramContext::Legacy(ir) => resources::resolve(typed, ir),
        ProgramContext::Composition(analysis) => resources::resolve_composition(typed, analysis),
    }
}

#[cfg(test)]
mod tests;
