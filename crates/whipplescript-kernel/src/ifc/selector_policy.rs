//! Existing input-selector classification and policy shared by both consumers.
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::{IrWhen, SourceSpan};

#[derive(Clone, Debug)]
pub(super) struct Input {
    resource: String,
    message: bool,
    invocation: bool,
}
impl Input {
    fn integrity(&self, envelope: &Envelope, marked: bool) -> BTreeSet<String> {
        let mut roles = if self.message {
            BTreeSet::new()
        } else {
            envelope.integrity_set(&self.resource)
        };
        if marked {
            roles.extend(
                envelope
                    .endorse
                    .iter()
                    .filter(|(resource, role)| {
                        role != PUBLIC
                            && envelope.resolve(resource) == envelope.resolve(&self.resource)
                    })
                    .map(|(_, role)| role.clone()),
            );
        }
        roles
    }
}
pub(super) fn inputs(context: ProgramContext<'_>, whens: &[IrWhen]) -> BTreeMap<String, Input> {
    let mut result = BTreeMap::new();
    for when in whens {
        let text = when.pattern.trim_start();
        let Some(binding) = binding_after_as(text) else {
            continue;
        };
        let (resource, message) = if let Some(rest) = text.strip_prefix("message from ") {
            let Some(channel) = rest.split_whitespace().next() else {
                continue;
            };
            (channel.to_owned(), true)
        } else if let Some(name) = text
            .split_whitespace()
            .next()
            .filter(|name| context.events().iter().any(|event| event.name == *name))
        {
            (format!("signal:{name}"), false)
        } else {
            continue;
        };
        result.insert(
            binding.into(),
            Input {
                resource,
                message,
                invocation: false,
            },
        );
    }
    for contract in context
        .workflow_contracts()
        .iter()
        .filter(|c| c.kind == IrWorkflowContractKind::Input)
    {
        result.insert(
            contract.name.clone(),
            Input {
                resource: format!("invoke:{}", context.workflow()),
                message: false,
                invocation: true,
            },
        );
    }
    result
}

pub(super) struct Selection<'a> {
    pub rule: &'a str,
    pub span: SourceSpan,
    pub scrutinee: &'a str,
    pub pattern: &'a str,
}
impl Selection<'_> {
    pub fn crossing(
        &self,
        input: &Input,
        marked: bool,
        declassified: bool,
        envelope: &Envelope,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        if !input.integrity(envelope, marked).is_empty() {
            return;
        }
        let Self {
            rule,
            span,
            scrutinee,
            pattern,
        } = self;
        let root = scrutinee.split('.').next().unwrap_or(scrutinee);
        let crossing = if declassified {
            "declassify"
        } else {
            "endorse"
        };
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("security.untrusted_selector"),
            severity: Severity::Error,
            span: *span,
            message: format!(
                "denied influence in rule `{rule}`: the low-integrity discriminant \
                         `{scrutinee}` (arm `{pattern}`) may not select a {crossing} crossing — an \
                         attacker could steer the crossing (the checker denies every crossing \
                         selected by untrusted data; NMIF-on-the-selector)"
            ),
            suggestion: suggest(format!(
                "do not branch a crossing on untrusted `{scrutinee}`; gate the `case` on \
                         high-integrity data, or endorse `{root}` before the `case`"
            )),
            related: Vec::new(),
            fixits: Vec::new(),
        });
    }
    pub fn invocation(
        &self,
        input: &Input,
        marked: bool,
        sink: &str,
        envelope: &Envelope,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        if !input.invocation
            || envelope.dominates(
                &input.integrity(envelope, marked),
                &envelope.integrity_sink(sink),
            )
        {
            return;
        }
        let Self {
            rule,
            span,
            scrutinee,
            pattern,
        } = self;
        let invoke_selector_port = &input.resource;
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("security.untrusted_selector"),
            severity: Severity::Error,
            span: *span,
            message: format!(
                "denied influence in rule `{rule}`: the low-integrity selector \
                         `{scrutinee}` (arm `{pattern}`) may not control `{sink}`, which requires \
                         integrity {sink_int} (the checker denies every effect selection by data \
                         below the effect's integrity; NMIF-on-invoke-selector)",
                sink_int = envelope.integrity_label(sink)
            ),
            suggestion: suggest(format!(
                "do not let `{scrutinee}` select a higher-integrity effect; vouch the \
                         inbound invoke port `{invoke_selector_port}` with `grant invoke ... from \
                         <role>`, or move the effect outside the untrusted `case`"
            )),
            related: Vec::new(),
            fixits: Vec::new(),
        });
    }
}
