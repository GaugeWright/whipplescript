//! Actual destinations with explicit remaining effect/package obligations.
//! This inventory is not a whole-program IFC or admission verdict.
use super::*;
use crate::ifc::program_context::ProgramContext;
use whipplescript_parser::body::{FieldValue, RecordStmt, TerminalKind, TerminalStmt};
use whipplescript_parser::IrType;
mod effects;

#[derive(Debug)]
pub struct OwnedSink {
    pub node: NodeId,
    pub resource: String,
    pub payload: Vec<Expr>,
    pub selection: Vec<Control>,
}
impl OwnedSink {
    pub fn as_sink(&self) -> Sink<'_> {
        Sink {
            node: self.node,
            resource: &self.resource,
            payload: &self.payload,
            selection: &self.selection,
        }
    }
}

/// Full effect IFC and package terminals are explicit remaining obligations.
/// Effects carry derived resource identities, not an admission verdict.
/// An empty `local` list is not a whole-program IFC verdict. The compiler must
/// supply authenticated types and matching declarations, as for the per-sink API.
#[derive(Debug, Default)]
pub struct Inventory {
    pub local: Vec<OwnedSink>,
    pub effects: BTreeMap<NodeId, crate::ifc::ManagedEffectResources>,
    /// Projected resource payloads only. A missing node remains uncovered.
    /// This does not cover provider, grant, signal or ingestion policies.
    pub resource_payloads: BTreeMap<NodeId, Vec<Expr>>,
    pub package_terminals: Vec<OwnedSink>,
}

pub fn inventory(typed: &TypedActionPlan, ir: &IrProgram) -> Result<Inventory, Box<Diagnostic>> {
    inventory_in(typed, ProgramContext::Legacy(ir))
}

pub(in crate::ifc) fn inventory_in(
    typed: &TypedActionPlan,
    ir: ProgramContext<'_>,
) -> Result<Inventory, Box<Diagnostic>> {
    typed
        .validate_structure()
        .map_err(|message| incomplete(&message))?;
    let Some(root) = typed.plan.root_rule.as_ref() else {
        // MUTATION-SUCCESS-EXPR: Ok(Inventory::default())
        return Err(incomplete("managed sink inventory requires a root rule"));
    };
    if ir.root(&root.name).is_none() {
        let message = "managed sink inventory requires one matching rule declaration";
        // MUTATION-SUCCESS-EXPR: Ok(Inventory::default())
        return Err(incomplete(message));
    }
    let is_tool = ir
        .source_tags()
        .iter()
        .any(|tag| tag.target_kind == "workflow" && tag.name == "tool");
    let mut result = Inventory {
        effects: crate::ifc::managed_resources::resolve_in(typed, ir)?,
        ..Inventory::default()
    };
    let shared = shared_coordination_resources_in(ir);
    for (index, node) in typed.plan.nodes.iter().enumerate() {
        let id = NodeId(index);
        let NodeKind::Statement(statement) = &node.kind else {
            continue;
        };
        let env = &typed.plan.blocks[node.block.0].environment;
        let sink = (|| {
            let (resource, payload) = match statement.as_ref() {
                BodyStmt::Record(record)
                | BodyStmt::Done {
                    replacement: Some(record),
                    ..
                } => (
                    format!("fact:{}", record.schema),
                    record_payload(record, ir, env)?,
                ),
                BodyStmt::Milestone {
                    name,
                    payload_class,
                    fields,
                    span,
                } => {
                    let payload = if let Some(schema) = payload_class {
                        record_payload(
                            &RecordStmt {
                                schema: schema.clone(),
                                from: None,
                                fields: fields.clone(),
                                span: *span,
                            },
                            ir,
                            env,
                        )?
                    } else {
                        fields
                            .iter()
                            .map(|field| {
                                field
                                    .record_expression(None, &|name| env.contains_key(name))
                                    .map_err(|message| incomplete(&message))
                            })
                            .collect::<Result<_, _>>()?
                    };
                    (format!("milestone:{name}"), payload)
                }
                BodyStmt::Terminal(terminal) => {
                    (terminal.name.clone(), terminal_payload(terminal, ir, env)?)
                }
                BodyStmt::Effect(effect) => {
                    if let Some(payload) = effects::resource_payload(effect, env)? {
                        let resolved = &result.effects[&id];
                        if effect_flow(&resolved.kind).writes_resource {
                            if matches!(
                                typed.effects[&id].contract.resource,
                                whipplescript_parser::effect_contract::Resource::None
                            ) {
                                let message =
                                    "managed resource payload requires a resolved destination";
                                // MUTATION-SUCCESS-EXPR: Ok(None)
                                return Err(incomplete(message));
                            }
                            for resource in &resolved.resources {
                                if let Some(resource) =
                                    resource_for_ifc(&resolved.kind, resource, &shared)
                                {
                                    result.local.push(OwnedSink {
                                        node: id,
                                        resource: resource.into(),
                                        payload: payload.clone(),
                                        selection: resolved.controls.iter().cloned().collect(),
                                    });
                                }
                            }
                        }
                        result.resource_payloads.insert(id, payload);
                    }
                    return Ok(None);
                }
                BodyStmt::Done {
                    replacement: None, ..
                }
                | BodyStmt::Cancel { .. }
                | BodyStmt::Redact { .. }
                | BodyStmt::Declassify { .. } => return Ok(None),
                // Structural validation excludes unexpanded control statements.
                BodyStmt::Composition(_)
                | BodyStmt::After(_)
                | BodyStmt::Case(_)
                | BodyStmt::Region(_) => {
                    unreachable!("validated leaf statement")
                }
            };
            Ok(Some(OwnedSink {
                node: id,
                resource,
                payload,
                selection: Vec::new(),
            }))
        })()
        .map_err(|mut diagnostic: Box<Diagnostic>| {
            diagnostic.span = node.span;
            managed_call_context(&mut diagnostic, &typed.plan, id);
            diagnostic
        })?;
        if let Some(sink) = sink {
            if is_tool && matches!(statement.as_ref(), BodyStmt::Terminal(_)) {
                result.package_terminals.push(sink);
            } else {
                result.local.push(sink);
            }
        }
    }
    Ok(result)
}

fn record_payload(
    record: &RecordStmt,
    ir: ProgramContext<'_>,
    env: &whipplescript_parser::action_plan::Environment,
) -> Result<Vec<Expr>, Box<Diagnostic>> {
    Ok(record_fields(record, ir, env)?
        .into_iter()
        .map(|(_, expr)| expr)
        .collect())
}

pub(in crate::ifc) fn record_fields(
    record: &RecordStmt,
    ir: ProgramContext<'_>,
    env: &whipplescript_parser::action_plan::Environment,
) -> Result<Vec<(String, Expr)>, Box<Diagnostic>> {
    let class = unique(ir.schemas().iter().filter_map(|schema| match schema {
        IrSchema::Class(class) if class.name == record.schema => Some(class),
        _ => None,
    }));
    let Some(class) = class else {
        let message = format!(
            "managed sink requires one class declaration for `{}`",
            record.schema
        );
        // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
        return Err(incomplete(&message));
    };
    let projection =
        crate::source_action::records::projection(record, class, &|name| env.contains_key(name))
            .map_err(|message| incomplete(&message))?;
    let copied = projection.copied.into_iter().map(|name| {
        (
            name.clone(),
            Expr::Path(vec![
                record
                    .from
                    .as_ref()
                    .expect("copied projection source")
                    .clone(),
                name,
            ]),
        )
    });
    Ok(copied.chain(projection.fields).collect())
}

fn terminal_payload(
    terminal: &TerminalStmt,
    ir: ProgramContext<'_>,
    env: &whipplescript_parser::action_plan::Environment,
) -> Result<Vec<Expr>, Box<Diagnostic>> {
    let kind = match terminal.kind {
        TerminalKind::Complete => IrWorkflowContractKind::Output,
        TerminalKind::Fail => IrWorkflowContractKind::Failure,
    };
    let contract = unique(
        ir.workflow_contracts()
            .iter()
            .filter(|contract| contract.name == terminal.name && contract.kind == kind),
    );
    let Some(contract) = contract else {
        let message = "managed terminal sink requires one matching contract";
        // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
        return Err(incomplete(message));
    };
    if let Some(value) = &terminal.scalar {
        if terminal.from.is_some() || !terminal.fields.is_empty() {
            let message = "managed terminal sink mixes a value with field construction";
            // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
            return Err(incomplete(message));
        }
        let FieldValue::Expr { expr, .. } = value else {
            let message = "managed terminal sink value must be an expression";
            // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
            return Err(incomplete(message));
        };
        return Ok(vec![expr.clone()]);
    }
    let IrType::Ref(name) = &contract.ty else {
        let message = "managed terminal sink field construction requires a class contract";
        // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
        return Err(incomplete(message));
    };
    record_payload(
        &RecordStmt {
            schema: name.clone(),
            from: terminal.from.clone(),
            fields: terminal.fields.clone(),
            span: terminal.span,
        },
        ir,
        env,
    )
}

#[cfg(test)]
#[path = "sinks_tests.rs"]
mod tests;
