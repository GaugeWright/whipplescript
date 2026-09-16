//! Declaration/root-only view. No body metadata or executable-program accessor:
//! a consumer needing producer reach cannot mistake this for complete legacy IR.
use super::*;
use whipplescript_parser::action_plan::analysis::CompositionAnalysis;
use whipplescript_parser::{
    IrAgent, IrChannel, IrCoerce, IrCounter, IrCredential, IrEvent, IrFileStore, IrHarness,
    IrLease, IrLedger, IrMemoryPool, IrSchema, IrSharedCoordinationUsage, IrSourceTag, IrStream,
    IrTracker, IrWhen, IrWorkflowContract,
};

#[derive(Clone, Copy)]
pub(super) enum ProgramContext<'a> {
    Legacy(&'a IrProgram),
    Composition(&'a CompositionAnalysis),
}
#[derive(Clone, Copy)]
pub(super) struct RuleContext<'a> {
    pub whens: &'a [IrWhen],
}
macro_rules! declarations {
    ($($field:ident: $ty:ty),* $(,)?) => {
        impl<'a> ProgramContext<'a> {
            $(pub fn $field(self) -> &'a [$ty] {
                match self {
                    Self::Legacy(program) => &program.$field,
                    Self::Composition(program) => program.declarations().$field(),
                }
            })*
        }
    };
}
declarations! {
    file_stores: IrFileStore, channels: IrChannel, memory_pools: IrMemoryPool,
    streams: IrStream, credentials: IrCredential, coerces: IrCoerce,
    agents: IrAgent, schemas: IrSchema, trackers: IrTracker, events: IrEvent,
    leases: IrLease, ledgers: IrLedger, counters: IrCounter,
    source_tags: IrSourceTag, workflow_contracts: IrWorkflowContract,
    harnesses: IrHarness,
}
impl<'a> ProgramContext<'a> {
    /// The model endpoint an agent reaches, resolved in ONE place for both
    /// program shapes. An agent bound `using <harness>` leaves
    /// `IrAgent::provider` empty and reaches the harness's kind, so reading
    /// that field alone gives such an agent no provider door at all -- no
    /// egress check on its context. The legacy walk learned this as
    /// `agent_provider_kind`; the managed walk asks the same question here.
    pub fn provider_kind(self, agent: &'a IrAgent) -> Option<&'a str> {
        agent.provider.as_deref().or_else(|| {
            agent.harness.as_deref().and_then(|name| {
                self.harnesses()
                    .iter()
                    .find(|harness| harness.name == name)
                    .map(|harness| harness.kind.as_str())
            })
        })
    }

    pub fn workflow(self) -> &'a str {
        match self {
            Self::Legacy(program) => &program.workflow,
            Self::Composition(program) => program.declarations().workflow(),
        }
    }
    pub fn shared_coordination_usage(self) -> &'a [IrSharedCoordinationUsage] {
        match self {
            Self::Legacy(program) => &program.shared_coordination_usage,
            Self::Composition(program) => program.shared_coordination_usage(),
        }
    }
    pub fn roots(self) -> Vec<(&'a str, &'a [IrWhen])> {
        match self {
            Self::Legacy(program) => program
                .rules
                .iter()
                .map(|rule| (rule.name.as_str(), rule.whens.as_slice()))
                .collect(),
            Self::Composition(program) => program
                .rules()
                .iter()
                .map(|rule| (rule.root.name.name.as_str(), rule.root.whens.as_slice()))
                .collect(),
        }
    }
    pub fn root(self, name: &str) -> Option<RuleContext<'a>> {
        match self {
            Self::Legacy(program) => {
                let mut roots = program.rules.iter().filter(|rule| rule.name == name);
                let root = roots.next()?;
                roots
                    .next()
                    .is_none()
                    .then_some(RuleContext { whens: &root.whens })
            }
            Self::Composition(program) => {
                let mut roots = program
                    .rules()
                    .iter()
                    .filter(|rule| rule.root.name.name == name);
                let root = roots.next()?;
                roots.next().is_none().then_some(RuleContext {
                    whens: &root.root.whens,
                })
            }
        }
    }
}
