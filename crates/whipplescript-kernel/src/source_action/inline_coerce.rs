//! Managed inline model operations use one schema-coerce projection and
//! settlement protocol. Their authored template is durable; interpolation
//! values carry the exact freshness premises that made the rendered prompt
//! ready. `prompt` answers in the type its `-> <Type>` annotation names and
//! `string` when it names none (DR-0120); `decide` carries its inline result
//! shape as a structural type.
use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, EffectStmt};
use whipplescript_parser::managed_template::Segment;
use whipplescript_parser::{IrPrimitiveType, IrProgram, IrType};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{strict, Argument, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use super::{OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, EvalValue, ParsedEffect};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub frame: &'a Frame,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub coercion_config_fingerprint: &'a str,
    pub source_path: Option<&'a Path>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Expected {
    Prompt,
    Decide,
}

struct Contract {
    function: &'static str,
    output: IrType,
    target: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PromptPart {
    Text { text: String },
    Value { argument: usize },
}

fn leaf(lowering: OwnedLowering, state: WorkState) -> Leaf {
    Leaf::Ready {
        lowering: Box::new(lowering),
        value: None,
        work: Some(OwnedWork {
            state,
            causes: BTreeMap::new(),
        }),
    }
}

pub fn project_prompt(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    project(statement, context, Expected::Prompt)
}

pub fn project_decide(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    project(statement, context, Expected::Decide)
}

fn source_contract(
    effect: &EffectStmt,
    expected: Expected,
    ir: &IrProgram,
) -> Result<Contract, String> {
    match (&effect.kind, expected) {
        (
            BodyEffectKind::Prompt {
                provider,
                result_type,
            },
            Expected::Prompt,
        ) => Ok(Contract {
            function: "prompt",
            // The type the prompt NAMED, resolved the way the legacy lowering
            // resolves it (DR-0120). Both machines read the same annotation off
            // the same statement, so answering `string` here would have the two
            // ask the provider for different things from one program.
            output: result_type
                .as_deref()
                .and_then(|name| lowering::named_ir_type(name, ir))
                .unwrap_or(IrType::Primitive(IrPrimitiveType::String)),
            target: provider.clone(),
        }),
        (BodyEffectKind::Decide { result_fields }, Expected::Decide) => {
            effect
                .binding
                .as_deref()
                .ok_or("managed decide has no result binding")?;
            Ok(Contract {
                function: "decide",
                output: whipplescript_parser::inline_decide_output_type(result_fields, effect.span),
                target: None,
            })
        }
        (_, Expected::Prompt) => {
            // MUTATION-SUCCESS-EXPR: Ok(Contract { function: "prompt", output: IrType::Primitive(IrPrimitiveType::String), target: None })
            Err("inline prompt projector requires an inline prompt statement".into())
        }
        (_, Expected::Decide) => {
            // MUTATION-SUCCESS-EXPR: Ok(Contract { function: "decide", output: IrType::Primitive(IrPrimitiveType::Json), target: None })
            Err("inline decide projector requires an inline decide statement".into())
        }
    }
}

fn project(
    statement: Statement<'_>,
    context: Context<'_>,
    expected: Expected,
) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
        return Err("inline coerce projector requires an effect statement".into());
    };
    let contract = source_contract(effect, expected, context.ir)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
        return Err("managed inline coerce requires its pinned root rule".into());
    }
    let template = effect
        .prompt
        .as_ref()
        .ok_or("managed inline coerce has no authored template")?;
    let output_type = lowering::ir_type_name(&contract.output);
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "schema.coerce"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target != contract.target
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
            return Err("recorded inline coerce differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded inline coerce input")?;
        if input["function_name"] != contract.function
            || input["output_type"] != output_type
            || input["output_schema"]
                != crate::coerce_native::output_schema_envelope(
                    &contract.output,
                    &context.ir.schemas,
                )
                .0
            || input["prompt_template"] != template.text
            || input["prompt"].as_str().is_none()
            || !input["action_arguments"].is_array()
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
            return Err("recorded inline coerce input differs from its source contract".into());
        }
        if let Some(target) = &contract.target {
            if input["provider"] != *target {
                // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
                return Err(
                    "recorded inline coerce provider differs from its source contract".into(),
                );
            }
        } else if input.get("provider").is_some() {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
            return Err("recorded inline coerce gained a provider absent from source".into());
        }
        match &template.content_type {
            Some(content_type) if input["prompt_content_type"] != *content_type => {
                // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
                return Err("recorded inline coerce content type differs from source".into());
            }
            None if input.get("prompt_content_type").is_some() => {
                // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending))
                return Err(
                    "recorded inline coerce gained a content type absent from source".into(),
                );
            }
            _ => {}
        }
        return super::coerce::observe(
            context.ir,
            contract.function,
            &contract.output,
            existing,
            context.events,
        );
    }
    let mut inputs = Vec::new();
    let mut parts = Vec::new();
    for segment in whipplescript_parser::managed_template::parse(&template.text)? {
        match segment {
            Segment::Text(text) => parts.push(PromptPart::Text { text: text.into() }),
            Segment::Expression { expr, .. } => {
                parts.push(PromptPart::Value {
                    argument: inputs.len(),
                });
                inputs.push(statement.evaluate(&expr));
            }
        }
    }
    let evaluated = strict(inputs.clone(), |values| {
        EvalValue::Json(Value::Array(values))
    });
    let State::Ready(Value::Array(values)) = &evaluated.state else {
        return Ok(Leaf::Waiting(evaluated));
    };
    let arguments = inputs
        .iter()
        .zip(values)
        .map(|(input, value)| Argument {
            value: value.clone(),
            sources: input.sources.clone(),
            subjects: input.subjects.clone(),
            validity: input.validity.clone(),
        })
        .collect::<Vec<_>>();
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed inline coerce timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "schema.coerce".into(),
        target: contract.target.clone(),
        name: Some(contract.function.into()),
        binding: effect.binding.clone(),
        args: Vec::new(),
        prompt: None,
        prompt_content_type: template.content_type.clone(),
        prompt_template: Some(template.text.clone()),
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let mut input = json!({
        "function_name": contract.function, "arguments": {}, "output_type": output_type,
        "output_schema": crate::coerce_native::output_schema_envelope(
            &contract.output, &context.ir.schemas,
        ).0,
        "rule": context.frame.rule, "media": [], "managed_prompt": parts,
        "action_arguments": arguments, "prompt_template": template.text,
        "access_grants": [],
    });
    if let Some(target) = &contract.target {
        input["provider"] = json!(target);
    }
    if let Some(content_type) = &template.content_type {
        input["prompt_content_type"] = json!(content_type);
    }
    super::tell::materialize_prompt(&mut input)?;
    let key = lowering::inline_coerce_admission_key(
        context.ir,
        &context.frame.rule,
        &parsed,
        &statement.identity,
        context.coercion_config_fingerprint,
        &contract.output,
    );
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity,
                kind: "schema.coerce".into(),
                target: contract.target,
                input_json: input.to_string(),
                status: "queued".into(),
                idempotency_key: key,
                required_capabilities_json: parsed.required_capabilities_json(),
                profile: None,
                correlation_id: context.frame.identity.clone(),
                source_span_json: Some(lowering::source_span_json(
                    context.source_path,
                    effect.span,
                    "effect",
                )),
                timeout_seconds,
            }],
            ..Default::default()
        },
        WorkState::Pending,
    ))
}

#[cfg(test)]
mod tests;
