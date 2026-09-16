//! Selected-program composition analysis. Body-linked declarations, whole-program IFC,
//! termination, admission and executable-version checks remain compiler duties.
use super::*;
pub use crate::action_subjects::{FactWrite, RuleFactFlow};
use crate::lowering::tables::{self, PreparedRule, TableOrigin};
use crate::{
    action_signature, action_subjects, action_types, effect_grants, Item, Program, SemanticContext,
    WorkflowInputSurface,
};
use resolved::{RuleRoot, TypedActionPlan};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableProvenance {
    pub name: Ident,
    pub records: BTreeMap<NodeId, crate::IrRecordSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleAnalysis {
    pub root: RuleRoot,
    pub typed: TypedActionPlan,
    /// Checked source result types; not part of the captured typed-plan format.
    pub value_types: BTreeMap<NodeId, crate::IrType>,
    pub fact_flow: RuleFactFlow,
    pub table: Option<TableProvenance>,
}

/// A compiler-derived result, deliberately not a captured executable format.
/// Its rule set cannot be replaced or shortened through this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionAnalysis {
    rules: Vec<RuleAnalysis>,
    declarations: crate::DeclarationAnalysis,
    shared_coordination_usage: Vec<crate::IrSharedCoordinationUsage>,
}
impl CompositionAnalysis {
    pub fn shared_coordination_usage(&self) -> &[crate::IrSharedCoordinationUsage] {
        &self.shared_coordination_usage
    }
    pub fn declarations(&self) -> &crate::DeclarationAnalysis {
        &self.declarations
    }
    pub fn rules(&self) -> &[RuleAnalysis] {
        &self.rules
    }
}

/// Analyze authored rules and table seeders after workflow/root and pattern selection.
/// Tables use the shared source elaborator. All rules and
/// definitions are checked together, even when a consumer needs only one rule.
/// This does not select a source dialect or enable typed execution.
pub fn analyze_composition(program: &Program) -> Result<CompositionAnalysis, Vec<Diagnostic>> {
    analyze_selected(
        program,
        BTreeMap::new(),
        crate::collect_shared_coordination_usage(program),
    )
}

pub(crate) fn analyze_selected(
    program: &Program,
    workflow_inputs: BTreeMap<String, WorkflowInputSurface>,
    shared_coordination_usage: Vec<crate::IrSharedCoordinationUsage>,
) -> Result<CompositionAnalysis, Vec<Diagnostic>> {
    let actions: Vec<_> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    checked(action_signature::validate(&actions))?;
    let semantic = SemanticContext::from_program(program, workflow_inputs);
    let (errors, mut types) = action_types::definition_types(&actions, &semantic, false);
    checked(errors)?;
    let mut errors = Vec::new();
    let prepared = tables::prepare_rules(program, &semantic, &mut errors);
    checked(errors)?;
    let rules: Vec<_> = prepared.iter().map(|prepared| &prepared.rule).collect();
    let (errors, callers) = action_types::rule_types(&actions, &rules, &semantic, false);
    checked(errors)?;
    types.cases.extend(callers.cases);
    types.values.extend(callers.values);
    types.roots = callers.roots;
    checked(effect_grants::validate_composition(&actions, &rules))?;
    let (errors, authority) = action_types::authority_types(&actions, &rules, &semantic);
    checked(errors)?;
    checked(effect_grants::resources::validate_composition(
        program, &actions, &rules,
    ))?;
    let (errors, flows) = action_subjects::analyze(&actions, &rules, &semantic);
    checked(errors)?;
    let rules = assemble(&actions, &prepared, types, &authority.tell_targets, flows)?;
    let declarations = crate::lowering::declarations::analyze(program, &semantic)?;
    Ok(CompositionAnalysis {
        rules,
        declarations,
        shared_coordination_usage,
    })
}

fn assemble(
    actions: &[ActionDecl],
    rules: &[PreparedRule],
    mut types: action_types::SourceTypes,
    targets: &BTreeMap<SourceSite, Vec<String>>,
    mut flows: BTreeMap<String, RuleFactFlow>,
) -> Result<Vec<RuleAnalysis>, Vec<Diagnostic>> {
    let mut analyzed = Vec::new();
    for prepared in rules {
        let rule = &prepared.rule;
        let root = types.roots.remove(&rule.name.name).ok_or_else(|| {
            vec![error(
                rule.name.span,
                format!("rule `{}` has no checked root analysis", rule.name.name),
            )]
        })?;
        let fact_flow = flows.remove(&rule.name.name).ok_or_else(|| {
            vec![error(
                rule.name.span,
                format!(
                    "rule `{}` has no checked fact-flow analysis",
                    rule.name.name
                ),
            )]
        })?;
        let (typed, value_types) = resolved::resolve_checked_rule(actions, rule, &types, targets)?;
        let table = prepared
            .table
            .as_ref()
            .map(|origin| table_provenance(origin, &typed))
            .transpose()?;
        analyzed.push(RuleAnalysis {
            root,
            typed,
            value_types,
            fact_flow,
            table,
        });
    }
    Ok(analyzed)
}
/// Join by the generated root's record order, never by diagnostic spans:
/// every synthesized statement can honestly share the table fallback span.
fn table_provenance(
    origin: &TableOrigin,
    typed: &TypedActionPlan,
) -> Result<TableProvenance, Vec<Diagnostic>> {
    typed.validate_structure().map_err(|reason| {
        vec![error(
            origin.name.span,
            format!(
                "table `{}` has an invalid generated plan: {reason}",
                origin.name.name
            ),
        )]
    })?;
    if typed.plan.root_rule.as_ref().map(|rule| rule.name.as_str())
        != Some(format!("table_{}", origin.name.name).as_str())
    {
        return Err(vec![error(
            origin.name.span,
            format!(
                "table `{}` provenance names a different generated rule",
                origin.name.name
            ),
        )]);
    }
    let nodes = &typed.plan.blocks[typed.plan.root.0].nodes;
    if nodes.len() != origin.records.len() || typed.plan.nodes.len() != nodes.len() {
        return Err(vec![error(
            origin.name.span,
            format!(
                "table `{}` has incomplete generated record provenance",
                origin.name.name
            ),
        )]);
    }
    let mut records = BTreeMap::new();
    for (id, source) in nodes.iter().zip(&origin.records) {
        let node = &typed.plan.nodes[id.0];
        if !matches!(&node.kind, NodeKind::Statement(statement) if matches!(statement.as_ref(), BodyStmt::Record(record) if record.schema == source.schema))
        {
            return Err(vec![error(
                source.span,
                format!(
                    "table `{}` row provenance does not match its generated record",
                    origin.name.name
                ),
            )]);
        }
        records.insert(*id, source.clone());
    }
    Ok(TableProvenance {
        name: origin.name.clone(),
        records,
    })
}

fn checked(errors: Vec<Diagnostic>) -> Result<(), Vec<Diagnostic>> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod table_tests;
