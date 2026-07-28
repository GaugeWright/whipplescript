//! Rule-lowering output types (DR-0033 instance-scheduler full lift, chunk 1).
//!
//! These are the owned, store-independent data the rule pass produces when it
//! lowers a ready rule context: the facts/effects/dependencies/terminal a commit
//! will persist, plus the branch-selection reports that surface in a step report.
//! They were lifted out of the CLI (`main.rs`) so the rule engine can move into
//! this wasm-clean kernel behind the host-agnostic instance step machine; the
//! native CLI now imports them from here.
//!
//! Each `Owned*` type borrows into the corresponding store `New*` / `Workflow…`
//! type via an `as_*` method, so a `commit_rule` call site turns a batch of these
//! into the borrowed forms the store trait consumes. Fields are `pub` because the
//! lowering code (still in the CLI for now) constructs and reads them across the
//! crate boundary; they are plain data-transfer records.

use serde_json::Value;
use whipplescript_store::{
    NewEffect, NewEffectDependency, NewFact, WorkflowTerminal, WorkflowTerminalKind,
};

/// A fact a lowered rule will derive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedFact {
    pub fact_id: String,
    pub name: String,
    pub key: String,
    pub value_json: String,
    pub schema_id: Option<String>,
    pub provenance_class: String,
    pub correlation_id: Option<String>,
    pub source_span_json: Option<String>,
}

impl OwnedFact {
    pub fn as_new_fact(&self) -> NewFact<'_> {
        NewFact {
            fact_id: &self.fact_id,
            name: &self.name,
            key: &self.key,
            value_json: &self.value_json,
            schema_id: self.schema_id.as_deref(),
            provenance_class: &self.provenance_class,
            correlation_id: self.correlation_id.as_deref(),
            source_span_json: self.source_span_json.as_deref(),
        }
    }
}

/// An effect a lowered rule will queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedEffect {
    pub effect_id: String,
    pub kind: String,
    pub target: Option<String>,
    pub input_json: String,
    pub status: String,
    pub idempotency_key: String,
    pub required_capabilities_json: String,
    pub profile: Option<String>,
    pub correlation_id: Option<String>,
    pub source_span_json: Option<String>,
    pub timeout_seconds: Option<i64>,
}

impl OwnedEffect {
    pub fn as_new_effect(&self) -> NewEffect<'_> {
        NewEffect {
            timeout_seconds: self.timeout_seconds,
            effect_id: &self.effect_id,
            kind: &self.kind,
            target: self.target.as_deref(),
            input_json: &self.input_json,
            status: &self.status,
            idempotency_key: &self.idempotency_key,
            required_capabilities_json: &self.required_capabilities_json,
            profile: self.profile.as_deref(),
            correlation_id: self.correlation_id.as_deref(),
            source_span_json: self.source_span_json.as_deref(),
        }
    }
}

/// A dependency edge between two lowered effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedDependency {
    pub dependency_id: String,
    pub upstream_effect_id: String,
    pub downstream_effect_id: String,
    pub predicate: String,
}

impl OwnedDependency {
    pub fn as_new_dependency(&self) -> NewEffectDependency<'_> {
        NewEffectDependency {
            dependency_id: &self.dependency_id,
            upstream_effect_id: &self.upstream_effect_id,
            downstream_effect_id: &self.downstream_effect_id,
            predicate: &self.predicate,
        }
    }
}

/// The workflow terminal a lowered rule reaches, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedWorkflowTerminal {
    pub kind: WorkflowTerminalKind,
    pub name: String,
    pub payload_json: String,
    pub idempotency_key: String,
}

impl OwnedWorkflowTerminal {
    pub fn as_workflow_terminal(&self) -> WorkflowTerminal<'_> {
        WorkflowTerminal {
            kind: self.kind,
            name: &self.name,
            payload_json: &self.payload_json,
            idempotency_key: Some(&self.idempotency_key),
        }
    }
}

/// Everything one lowered rule context produces: the facts/effects/dependencies
/// to commit, the ids to consume, an optional terminal, the branch-selection
/// reports, any lowering errors, cancel targets, and the 503 auto-fail signal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnedLowering {
    pub facts: Vec<OwnedFact>,
    pub consumed_fact_ids: Vec<String>,
    pub effects: Vec<OwnedEffect>,
    pub dependencies: Vec<OwnedDependency>,
    pub terminal: Option<OwnedWorkflowTerminal>,
    pub branch_reports: Vec<BranchReport>,
    pub errors: Vec<String>,
    /// Effect ids targeted by `cancel <binding>` operations in live scopes.
    pub cancels: Vec<String>,
    /// Auto-fail (R1): an unhandled effect failure in a self-terminating
    /// workflow. The string is the failure reason. This routes to the kernel
    /// `fail_instance_internal` terminal (a generic failed status with no typed
    /// `failure` payload) rather than the typed terminal commit path. Set by
    /// the rule-level net: an effect at terminal `failed`/`timed_out` with no
    /// observing `after` block on its binding.
    pub internal_fail: Option<String>,
    /// Auto-fail (R1) in a `@service` workflow: a service can never auto-fail,
    /// so each unhandled effect failure is surfaced as a durable diagnostic
    /// (recorded idempotently per effect in rule_pass) and the service keeps
    /// running.
    pub unhandled_failures: Vec<OwnedUnhandledFailure>,
}

/// One unhandled effect failure observed by the rule-level auto-fail net in a
/// `@service` workflow (see `OwnedLowering::unhandled_failures`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedUnhandledFailure {
    pub rule: String,
    pub binding: String,
    pub effect_id: String,
    /// The effect's terminal status (`failed` | `timed_out`).
    pub status: String,
}

/// A record of how a `case`/`decide` scrutinee resolved during lowering, surfaced
/// in the step report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchReport {
    pub scrutinee: String,
    pub status: BranchStatus,
    pub matched: bool,
    pub tag: Option<String>,
    pub actual: Value,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchStatus {
    Matched,
    NoMatch,
    Error,
}

impl BranchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::NoMatch => "no_match",
            Self::Error => "error",
        }
    }
}
