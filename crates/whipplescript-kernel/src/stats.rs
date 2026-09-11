//! The stats fold: an aggregate is a projection of the log.
//!
//! [DR-0114](../../../spec/decision-records/0114-an-aggregate-is-a-projection-of-the-log.md)
//! decides that an aggregate WhippleScript reports is a pure fold over records
//! it already keeps durably — no counter beside the log, no stored aggregate
//! that cannot be recomputed. This module is that fold.
//!
//! Three records govern what it may produce:
//!
//! - DR-0114: every number is reachable from `whip trace` on the instances that
//!   produced it. The fold therefore reads only durable rows and derives
//!   everything else.
//! - [DR-0116]: a measure is either complete over the row it appears in, or it
//!   is null. Unrecorded is never rendered as zero, and `grain` sits in the
//!   group key of every query so a row cannot be complete for some of its runs
//!   and unrecorded for the rest.
//! - [DR-0117]: a row carries structural identifiers, statuses and counts, and
//!   nothing else. The dimension vocabulary is closed and [`Dimension::parse`]
//!   refuses anything outside it.
//!
//! The fold takes plain input structs rather than store rows so that it is a
//! pure function the CLI, the hosted host and a fixture assertion can all run,
//! and so its properties can be tested without a store. `models/maude/stats-fold.maude`
//! models the three properties before this code existed.

use serde_json::Value;
use std::collections::BTreeMap;
use whipplescript_parser::IrEffectKind;

// ---------------------------------------------------------------------------
// Usage normalisation
// ---------------------------------------------------------------------------

/// One provider reply's token usage in DISJOINT buckets.
///
/// `input_uncached` excludes cache traffic, `cache_read` / `cache_write` are the
/// prompt-cache buckets, and `output` is completion. The cache fields are `None`
/// when the provider reported no cache accounting AT ALL — which is not the same
/// as an honest zero, and DR-0116 is the record that makes that distinction
/// load-bearing rather than decorative.
///
/// Normalisation keys on the usage object's SHAPE, never on the provider name,
/// because a gateway can put an Anthropic model behind an OpenAI-shaped wire:
///
/// - Anthropic shape: `input_tokens` EXCLUDES cache traffic, which arrives in
///   `cache_read_input_tokens` / `cache_creation_input_tokens`.
/// - OpenAI shape: `prompt_tokens` / `input_tokens` INCLUDES the cached subset,
///   which arrives in `*_tokens_details.cached_tokens`, so it is subtracted.
///
/// This is the repository's one implementation of that rule. `whip improve`'s
/// `TurnUsage` delegates here rather than keeping a second copy — DR-0118 asks
/// for reuse, and the hosted `project_usage` normalises to the opposite
/// convention, which is a divergence the provider-contract tracker owns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageBuckets {
    pub input_uncached: i64,
    pub output: i64,
    pub cache_read: Option<i64>,
    pub cache_write: Option<i64>,
}

impl UsageBuckets {
    /// Normalise a provider `usage` object.
    pub fn from_usage_json(usage: &Value) -> Self {
        let raw_input = usage
            .get("input_tokens")
            .or_else(|| usage.get("prompt_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let output = usage
            .get("output_tokens")
            .or_else(|| usage.get("completion_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let anthropic_read = usage.get("cache_read_input_tokens").and_then(Value::as_i64);
        let cache_write = usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_i64);
        let openai_cached = usage
            .get("prompt_tokens_details")
            .or_else(|| usage.get("input_tokens_details"))
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_i64);
        let (input_uncached, cache_read) = match (anthropic_read, openai_cached) {
            (Some(read), _) => (raw_input, Some(read)),
            (None, Some(cached)) => ((raw_input - cached).max(0), Some(cached)),
            (None, None) => (raw_input, None),
        };
        Self {
            input_uncached,
            output,
            cache_read,
            cache_write,
        }
    }

    /// Input-side tokens the provider processed: uncached plus cache traffic.
    pub fn input_side(&self) -> i64 {
        self.input_uncached + self.cache_read.unwrap_or(0) + self.cache_write.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Measures: zero and unrecorded are different numbers
// ---------------------------------------------------------------------------

/// One measure of one row. `None` is UNRECORDED — the log does not carry it —
/// and is not the number zero, which is a fact the log CAN establish.
///
/// Folding is the whole rule: two recorded values add; anything folded with an
/// unrecorded value is unrecorded. That is stated per MEASURE rather than per
/// population because recordedness belongs to a call, so one row at one grain
/// can still hold a call whose provider reported usage and one that did not.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Measure(Option<i64>);

impl Measure {
    /// A count the log establishes, including an honest zero.
    pub fn recorded(value: i64) -> Self {
        Self(Some(value))
    }

    /// The log does not carry this. Never rendered as zero.
    pub fn unrecorded() -> Self {
        Self(None)
    }

    pub fn value(self) -> Option<i64> {
        self.0
    }

    /// Fold another contribution in. Completeness propagates.
    #[must_use]
    pub fn fold(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(left), Some(right)) => Self(Some(left + right)),
            _ => Self(None),
        }
    }

    /// Fold by taking the larger of two recorded values; unrecorded still wins,
    /// because a maximum over an incomplete set is not the set's maximum.
    #[must_use]
    pub fn fold_max(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(left), Some(right)) => Self(Some(left.max(right))),
            _ => Self(None),
        }
    }
}

// ---------------------------------------------------------------------------
// The closed dimension vocabulary
// ---------------------------------------------------------------------------

/// The dimensions a stats row may be grouped by.
///
/// Closed and enumerated per DR-0117. Every one is a structural identifier, a
/// status, or a derived bucket; none can carry a fact value, an effect target,
/// effect input, or free text. `effects.target` is absent deliberately: it can
/// hold a URL.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Dimension {
    ProgramId,
    ProgramVersionId,
    InstanceId,
    RevisionEpoch,
    Rule,
    EffectKind,
    EffectId,
    RunId,
    Agent,
    Profile,
    Provider,
    Model,
    Status,
    BlockCategory,
    Step,
    Day,
    Grain,
}

impl Dimension {
    /// Every dimension, in report order. Exhaustive by construction: the match
    /// in [`Dimension::name`] does not compile when a variant is added without
    /// a name, and this list is checked against it by test.
    pub const ALL: &'static [Self] = &[
        Self::ProgramId,
        Self::ProgramVersionId,
        Self::InstanceId,
        Self::RevisionEpoch,
        Self::Rule,
        Self::EffectKind,
        Self::EffectId,
        Self::RunId,
        Self::Agent,
        Self::Profile,
        Self::Provider,
        Self::Model,
        Self::Status,
        Self::BlockCategory,
        Self::Step,
        Self::Day,
        Self::Grain,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::ProgramId => "program_id",
            Self::ProgramVersionId => "program_version_id",
            Self::InstanceId => "instance_id",
            Self::RevisionEpoch => "revision_epoch",
            Self::Rule => "rule",
            Self::EffectKind => "effect_kind",
            Self::EffectId => "effect_id",
            Self::RunId => "run_id",
            Self::Agent => "agent",
            Self::Profile => "profile",
            Self::Provider => "provider",
            Self::Model => "model",
            Self::Status => "status",
            Self::BlockCategory => "block_category",
            Self::Step => "step",
            Self::Day => "day",
            Self::Grain => "grain",
        }
    }

    /// Resolve a requested dimension name, or refuse it.
    ///
    /// ONE membership check, deliberately. A per-name refusal would be a dozen
    /// refusal sites in one file and `scripts/check-new-refusals.sh` sweeps only
    /// the first `CAP` touched sites in diff order, so the ones past the cap
    /// would go unswept. The message names the offending dimension and the legal
    /// set, because a group-by that silently drops an unknown name lets an
    /// operator read a total as a breakdown.
    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .iter()
            .copied()
            .find(|dimension| dimension.name() == name)
            .ok_or_else(|| {
                let legal: Vec<&str> = Self::ALL.iter().map(|d| d.name()).collect();
                format!(
                    "unknown stats dimension `{name}`; a stats row carries structural \
                     identifiers only (DR-0117), and the dimensions are: {}",
                    legal.join(", ")
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Grain
// ---------------------------------------------------------------------------

/// Which population a row's model-call measures come from.
///
/// Always part of the group key, whether or not the caller names it, so a row
/// can never be complete for some of its runs and unrecorded for the rest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Grain {
    /// The run carries one row per model call: `calls`, `model` and `step` are
    /// known. Produced once DR-0115 lands.
    Call,
    /// The run carries only the turn-level sum: tokens are known, the call count
    /// is not.
    Turn,
    /// The effect cannot make a model call at all — most effect kinds, and every
    /// effect blocked before it ran. Its call count is `0` and COMPLETE, which
    /// is what makes the zero-versus-unrecorded distinction concrete.
    None,
}

impl Grain {
    pub fn name(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Turn => "turn",
            Self::None => "none",
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One instance, as the fold reads it.
#[derive(Clone, Debug)]
pub struct InstanceInput {
    pub instance_id: String,
    pub program_id: String,
    pub program_version_id: String,
}

/// One effect, as the fold reads it. `target` and `input_json` are deliberately
/// absent: DR-0117 refuses them as dimensions, so the fold never receives them.
#[derive(Clone, Debug)]
pub struct EffectInput {
    pub effect_id: String,
    pub instance_id: String,
    pub kind: String,
    pub status: String,
    pub created_by_rule: String,
    pub program_version_id: Option<String>,
    pub revision_epoch: i64,
    pub profile: Option<String>,
    pub policy_block_category: Option<String>,
}

impl EffectInput {
    /// Whether an effect of this kind reaches a language model.
    ///
    /// A kind this build does not know — a snapshot written by a newer compiler
    /// can legitimately carry one — is treated as POSSIBLY model-calling, so its
    /// call count is unrecorded rather than a confident zero. Guessing zero for
    /// an unknown kind is precisely the lie DR-0116 forbids.
    fn makes_model_call(&self) -> Option<bool> {
        IrEffectKind::from_kind_str(&self.kind).map(|kind| kind.makes_model_call())
    }
}

/// One run, as the fold reads it. `metadata_json` is parsed here rather than by
/// each caller so the native and hosted doors cannot disagree about what a run
/// records.
#[derive(Clone, Debug)]
pub struct RunInput {
    pub run_id: String,
    pub effect_id: String,
    pub provider: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub metadata_json: String,
}

/// What a run's metadata carries about the model work it did.
struct RunMetadata {
    agent: Option<String>,
    model: Option<String>,
    usage: Option<UsageBuckets>,
    steps: Option<i64>,
    last_input_tokens: Option<i64>,
}

impl RunInput {
    fn metadata(&self) -> RunMetadata {
        let parsed: Value = serde_json::from_str(&self.metadata_json).unwrap_or(Value::Null);
        let usage_value = parsed
            .get("usage")
            .or_else(|| parsed.get("usage_json"))
            .filter(|usage| usage.is_object());
        RunMetadata {
            agent: parsed
                .get("agent")
                .and_then(Value::as_str)
                .map(str::to_owned),
            model: parsed
                .get("model")
                .and_then(Value::as_str)
                .or_else(|| {
                    usage_value.and_then(|usage| usage.get("model").and_then(Value::as_str))
                })
                .map(str::to_owned),
            usage: usage_value.map(UsageBuckets::from_usage_json),
            steps: parsed.get("steps").and_then(Value::as_i64),
            last_input_tokens: usage_value
                .and_then(|usage| usage.get("last_input_tokens"))
                .and_then(Value::as_i64),
        }
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// Every measure of one row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measures {
    /// Logical count: one per effect row.
    pub effects: Measure,
    /// Physical count: one per run row.
    pub runs: Measure,
    /// `runs - effects`, the mechanism behind exactly-once made legible.
    pub retries: Measure,
    /// Runs of a model-calling effect.
    pub turns: Measure,
    /// Model calls. Unrecorded at turn grain: `steps` counts ROUNDS, and a
    /// provider retry inside a round is invisible to it.
    pub calls: Measure,
    /// Model rounds, where the owned harness recorded them.
    pub steps: Measure,
    pub input_uncached: Measure,
    pub input_cache_read: Measure,
    pub input_cache_write: Measure,
    pub output: Measure,
    pub completed: Measure,
    pub failed: Measure,
    pub timed_out: Measure,
    pub cancelled: Measure,
    pub blocked: Measure,
    /// Context size at a turn's final reply, folded by maximum.
    pub last_input_tokens: Measure,
}

impl Measures {
    /// The identity for folding: every measure a RECORDED zero.
    ///
    /// Deliberately not `Default`. `Measure`'s default is `unrecorded`, which is
    /// the right default for one measure and exactly the wrong seed for an
    /// accumulator — folding anything into it makes the whole group unrecorded,
    /// which is how this fold first reported null for every row it built.
    pub fn zero() -> Self {
        Self {
            effects: Measure::recorded(0),
            runs: Measure::recorded(0),
            retries: Measure::recorded(0),
            turns: Measure::recorded(0),
            calls: Measure::recorded(0),
            steps: Measure::recorded(0),
            input_uncached: Measure::recorded(0),
            input_cache_read: Measure::recorded(0),
            input_cache_write: Measure::recorded(0),
            output: Measure::recorded(0),
            completed: Measure::recorded(0),
            failed: Measure::recorded(0),
            timed_out: Measure::recorded(0),
            cancelled: Measure::recorded(0),
            blocked: Measure::recorded(0),
            last_input_tokens: Measure::recorded(0),
        }
    }

    fn fold(self, other: Self) -> Self {
        Self {
            effects: self.effects.fold(other.effects),
            runs: self.runs.fold(other.runs),
            retries: self.retries.fold(other.retries),
            turns: self.turns.fold(other.turns),
            calls: self.calls.fold(other.calls),
            steps: self.steps.fold(other.steps),
            input_uncached: self.input_uncached.fold(other.input_uncached),
            input_cache_read: self.input_cache_read.fold(other.input_cache_read),
            input_cache_write: self.input_cache_write.fold(other.input_cache_write),
            output: self.output.fold(other.output),
            completed: self.completed.fold(other.completed),
            failed: self.failed.fold(other.failed),
            timed_out: self.timed_out.fold(other.timed_out),
            cancelled: self.cancelled.fold(other.cancelled),
            blocked: self.blocked.fold(other.blocked),
            last_input_tokens: self.last_input_tokens.fold_max(other.last_input_tokens),
        }
    }
}

/// One row of the report: a group key and its measures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    /// The selected dimensions and their values, in report order. A `None` value
    /// is unrecorded, never an empty string.
    pub key: Vec<(Dimension, Option<String>)>,
    pub measures: Measures,
}

/// What the fold was asked for.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Dimensions to group by. `Grain` is added if absent — it is part of the
    /// group key of every query (DR-0116), so naming it is a no-op.
    pub by: Vec<Dimension>,
    /// Restrict to one instance.
    pub instance_id: Option<String>,
    /// Restrict to one program.
    pub program_id: Option<String>,
    /// Inclusive lower bound on a run's start, as an RFC 3339 prefix comparison.
    pub since: Option<String>,
    /// Exclusive upper bound on a run's start.
    pub until: Option<String>,
}

impl Query {
    /// The effective group key: what was asked for, plus grain.
    fn group_key(&self) -> Vec<Dimension> {
        let mut key: Vec<Dimension> = self.by.clone();
        if !key.contains(&Dimension::Grain) {
            key.push(Dimension::Grain);
        }
        key
    }
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// One contribution before grouping: the dimension values it carries and the
/// measures it adds.
struct Contribution {
    values: BTreeMap<Dimension, Option<String>>,
    measures: Measures,
}

/// Fold the durable rows into report rows.
///
/// Pure: the same inputs always produce the same rows, which is what lets a
/// fixture assert a token budget and what makes the additivity property
/// testable.
pub fn fold(instances: &[InstanceInput], effects: &[EffectInput], runs: &[RunInput]) -> Folded {
    Folded {
        instances: instances.to_vec(),
        effects: effects.to_vec(),
        runs: runs.to_vec(),
    }
}

/// The fold's inputs, ready to answer a query.
pub struct Folded {
    instances: Vec<InstanceInput>,
    effects: Vec<EffectInput>,
    runs: Vec<RunInput>,
}

impl Folded {
    /// Answer one query.
    pub fn rows(&self, query: &Query) -> Vec<Row> {
        let by_instance: BTreeMap<&str, &InstanceInput> = self
            .instances
            .iter()
            .map(|instance| (instance.instance_id.as_str(), instance))
            .collect();
        let mut runs_by_effect: BTreeMap<&str, Vec<&RunInput>> = BTreeMap::new();
        for run in &self.runs {
            runs_by_effect
                .entry(run.effect_id.as_str())
                .or_default()
                .push(run);
        }

        let mut contributions: Vec<Contribution> = Vec::new();
        for effect in &self.effects {
            let Some(instance) = by_instance.get(effect.instance_id.as_str()) else {
                continue;
            };
            if query
                .instance_id
                .as_deref()
                .is_some_and(|wanted| wanted != effect.instance_id)
            {
                continue;
            }
            if query
                .program_id
                .as_deref()
                .is_some_and(|wanted| wanted != instance.program_id)
            {
                continue;
            }
            let effect_runs = runs_by_effect
                .get(effect.effect_id.as_str())
                .cloned()
                .unwrap_or_default();
            let in_window = |run: &RunInput| {
                query
                    .since
                    .as_deref()
                    .is_none_or(|since| run.started_at.as_str() >= since)
                    && query
                        .until
                        .as_deref()
                        .is_none_or(|until| run.started_at.as_str() < until)
            };
            let windowed: Vec<&&RunInput> =
                effect_runs.iter().filter(|run| in_window(run)).collect();

            if windowed.is_empty() {
                // An effect whose runs all fall outside the window is out of
                // scope entirely: the window scopes the report, and counting its
                // logical half while dropping its physical half would make
                // `retries` a difference between two different populations.
                if !effect_runs.is_empty() {
                    continue;
                }
                // An effect that never ran has no timestamp to filter on, so a
                // windowed query cannot honestly place it.
                if query.since.is_some() || query.until.is_some() {
                    continue;
                }
                // It contributes its logical count, and it made no model call —
                // a zero that is COMPLETE rather than a guess.
                contributions.push(self.effect_only_contribution(instance, effect));
                continue;
            }

            for (index, run) in windowed.iter().enumerate() {
                let mut contribution = self.run_contribution(instance, effect, run);
                // The logical count belongs to the EFFECT, so it is added once
                // however many times the effect ran. Adding it per run would
                // make `retries` (runs - effects) always zero, hiding the
                // mechanism behind exactly-once rather than showing it.
                if index == 0 {
                    contribution.measures.effects = Measure::recorded(1);
                }
                contributions.push(contribution);
            }
        }

        self.group(query, contributions)
    }

    /// An effect with no run: a logical count, and nothing a model did.
    fn effect_only_contribution(
        &self,
        instance: &InstanceInput,
        effect: &EffectInput,
    ) -> Contribution {
        let blocked = i64::from(effect.status.starts_with("blocked"));
        // An effect that never ran made no model call, whatever its kind, so
        // zero here is complete rather than a guess.
        let mut measures = Measures {
            effects: Measure::recorded(1),
            blocked: Measure::recorded(blocked),
            ..Measures::zero()
        };
        if effect.status == "cancelled" {
            measures.cancelled = Measure::recorded(1);
        }
        Contribution {
            values: self.dimension_values(
                instance,
                effect,
                None,
                &RunMetadata {
                    agent: None,
                    model: None,
                    usage: None,
                    steps: None,
                    last_input_tokens: None,
                },
                Grain::None,
            ),
            measures,
        }
    }

    /// One run of one effect.
    fn run_contribution(
        &self,
        instance: &InstanceInput,
        effect: &EffectInput,
        run: &RunInput,
    ) -> Contribution {
        let metadata = run.metadata();
        let model_calling = effect.makes_model_call();
        let grain = match (model_calling, metadata.usage.is_some()) {
            // Per-call rows are DR-0115's work; until they exist, a
            // model-calling run with usage is turn grain.
            (Some(true) | None, true) => Grain::Turn,
            // A model-calling run whose usage the log does not carry is still
            // turn grain — the population is right, the measures are unrecorded.
            (Some(true) | None, false) => Grain::Turn,
            (Some(false), _) => Grain::None,
        };

        let calls_and_tokens_known = metadata.usage.is_some();
        let usage = metadata.usage.unwrap_or_default();
        let measures = Measures {
            effects: Measure::recorded(0),
            runs: Measure::recorded(1),
            retries: Measure::recorded(0),
            turns: Measure::recorded(i64::from(matches!(grain, Grain::Turn | Grain::Call))),
            // A true call count needs DR-0115's per-call rows. `steps` counts
            // ROUNDS and misses provider retries, so it is not that count and
            // must not be reported as one.
            calls: match grain {
                Grain::None => Measure::recorded(0),
                _ => Measure::unrecorded(),
            },
            steps: match (grain, metadata.steps) {
                (Grain::None, _) => Measure::recorded(0),
                (_, Some(steps)) => Measure::recorded(steps),
                // A delegate-provider run records no step count at all.
                (_, None) => Measure::unrecorded(),
            },
            input_uncached: token_measure(grain, calls_and_tokens_known, usage.input_uncached),
            input_cache_read: cache_measure(grain, calls_and_tokens_known, usage.cache_read),
            input_cache_write: cache_measure(grain, calls_and_tokens_known, usage.cache_write),
            output: token_measure(grain, calls_and_tokens_known, usage.output),
            completed: Measure::recorded(i64::from(run.status == "completed")),
            failed: Measure::recorded(i64::from(run.status == "failed")),
            timed_out: Measure::recorded(i64::from(run.status == "timed_out")),
            cancelled: Measure::recorded(i64::from(run.status == "cancelled")),
            blocked: Measure::recorded(0),
            last_input_tokens: match (grain, metadata.last_input_tokens) {
                (Grain::None, _) => Measure::recorded(0),
                (_, Some(tokens)) => Measure::recorded(tokens),
                (_, None) => Measure::unrecorded(),
            },
        };
        Contribution {
            values: self.dimension_values(instance, effect, Some(run), &metadata, grain),
            measures,
        }
    }

    fn dimension_values(
        &self,
        instance: &InstanceInput,
        effect: &EffectInput,
        run: Option<&RunInput>,
        metadata: &RunMetadata,
        grain: Grain,
    ) -> BTreeMap<Dimension, Option<String>> {
        let mut values = BTreeMap::new();
        values.insert(Dimension::ProgramId, Some(instance.program_id.clone()));
        values.insert(
            Dimension::ProgramVersionId,
            effect
                .program_version_id
                .clone()
                .or_else(|| Some(instance.program_version_id.clone())),
        );
        values.insert(Dimension::InstanceId, Some(instance.instance_id.clone()));
        values.insert(
            Dimension::RevisionEpoch,
            Some(effect.revision_epoch.to_string()),
        );
        values.insert(Dimension::Rule, Some(effect.created_by_rule.clone()));
        values.insert(Dimension::EffectKind, Some(effect.kind.clone()));
        values.insert(Dimension::EffectId, Some(effect.effect_id.clone()));
        values.insert(Dimension::RunId, run.map(|run| run.run_id.clone()));
        values.insert(Dimension::Agent, metadata.agent.clone());
        values.insert(Dimension::Profile, effect.profile.clone());
        values.insert(Dimension::Provider, run.map(|run| run.provider.clone()));
        values.insert(Dimension::Model, metadata.model.clone());
        values.insert(
            Dimension::Status,
            Some(run.map_or_else(|| effect.status.clone(), |run| run.status.clone())),
        );
        values.insert(
            Dimension::BlockCategory,
            effect.policy_block_category.clone(),
        );
        // `step` is a per-call dimension. Until DR-0115 lands there are no
        // per-call rows, so it is unrecorded rather than invented.
        values.insert(Dimension::Step, None);
        values.insert(
            Dimension::Day,
            run.map(|run| run.started_at.chars().take(10).collect::<String>()),
        );
        values.insert(Dimension::Grain, Some(grain.name().to_owned()));
        values
    }

    fn group(&self, query: &Query, contributions: Vec<Contribution>) -> Vec<Row> {
        let key_dimensions = query.group_key();
        let mut grouped: BTreeMap<Vec<Option<String>>, Measures> = BTreeMap::new();
        for contribution in contributions {
            let key: Vec<Option<String>> = key_dimensions
                .iter()
                .map(|dimension| contribution.values.get(dimension).cloned().unwrap_or(None))
                .collect();
            let entry = grouped.entry(key).or_insert_with(Measures::zero);
            *entry = entry.fold(contribution.measures);
        }

        grouped
            .into_iter()
            .map(|(key, mut measures)| {
                // `retries` is derived rather than accumulated: physical runs
                // beyond the logical effects that asked for them.
                measures.retries = match (measures.runs.value(), measures.effects.value()) {
                    (Some(runs), Some(effects)) => Measure::recorded((runs - effects).max(0)),
                    _ => Measure::unrecorded(),
                };
                Row {
                    key: key_dimensions.iter().copied().zip(key).collect(),
                    measures,
                }
            })
            .collect()
    }
}

/// A token measure: zero and complete where no model call is possible,
/// unrecorded where one happened and the log does not carry its usage.
fn token_measure(grain: Grain, known: bool, value: i64) -> Measure {
    match (grain, known) {
        (Grain::None, _) => Measure::recorded(0),
        (_, true) => Measure::recorded(value),
        (_, false) => Measure::unrecorded(),
    }
}

/// A cache measure. A provider that reports no cache accounting leaves these
/// `None`, which stays unrecorded rather than becoming an invented zero.
fn cache_measure(grain: Grain, known: bool, value: Option<i64>) -> Measure {
    match (grain, known, value) {
        (Grain::None, _, _) => Measure::recorded(0),
        (_, true, Some(value)) => Measure::recorded(value),
        _ => Measure::unrecorded(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn instance(id: &str) -> InstanceInput {
        InstanceInput {
            instance_id: id.to_owned(),
            program_id: "prog".to_owned(),
            program_version_id: "ver".to_owned(),
        }
    }

    fn effect(id: &str, instance_id: &str, rule: &str, kind: &str) -> EffectInput {
        EffectInput {
            effect_id: id.to_owned(),
            instance_id: instance_id.to_owned(),
            kind: kind.to_owned(),
            status: "completed".to_owned(),
            created_by_rule: rule.to_owned(),
            program_version_id: Some("ver".to_owned()),
            revision_epoch: 0,
            profile: None,
            policy_block_category: None,
        }
    }

    fn run(id: &str, effect_id: &str, metadata: Value) -> RunInput {
        RunInput {
            run_id: id.to_owned(),
            effect_id: effect_id.to_owned(),
            provider: "owned-harness".to_owned(),
            status: "completed".to_owned(),
            started_at: "2026-09-11T10:00:00Z".to_owned(),
            completed_at: Some("2026-09-11T10:00:05Z".to_owned()),
            metadata_json: metadata.to_string(),
        }
    }

    fn by_rule() -> Query {
        Query {
            by: vec![Dimension::Rule],
            ..Query::default()
        }
    }

    fn measure_of(row: &Row, pick: fn(&Measures) -> Measure) -> Option<i64> {
        pick(&row.measures).value()
    }

    // -- normalisation, one fixture per wire shape -------------------------

    #[test]
    fn anthropic_shape_keeps_input_exclusive_of_cache() {
        let usage = json!({
            "input_tokens": 100,
            "output_tokens": 20,
            "cache_read_input_tokens": 900,
            "cache_creation_input_tokens": 50
        });
        let buckets = UsageBuckets::from_usage_json(&usage);
        assert_eq!(buckets.input_uncached, 100);
        assert_eq!(buckets.cache_read, Some(900));
        assert_eq!(buckets.cache_write, Some(50));
        assert_eq!(buckets.output, 20);
        assert_eq!(buckets.input_side(), 1050);
    }

    #[test]
    fn openai_chat_shape_subtracts_the_cached_subset_from_input() {
        // `prompt_tokens` INCLUDES the cached subset on this wire, so folding it
        // in as-is would count the cached span twice — once in input, once in
        // cache_read — in the one field whose purpose is to be cheaper.
        let usage = json!({
            "prompt_tokens": 1000,
            "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 900}
        });
        let buckets = UsageBuckets::from_usage_json(&usage);
        assert_eq!(buckets.input_uncached, 100);
        assert_eq!(buckets.cache_read, Some(900));
        assert_eq!(buckets.input_side(), 1000);
    }

    #[test]
    fn openai_responses_shape_reads_the_same_way() {
        let usage = json!({
            "input_tokens": 1000,
            "output_tokens": 7,
            "input_tokens_details": {"cached_tokens": 250}
        });
        let buckets = UsageBuckets::from_usage_json(&usage);
        assert_eq!(buckets.input_uncached, 750);
        assert_eq!(buckets.cache_read, Some(250));
    }

    #[test]
    fn a_provider_reporting_no_cache_accounting_leaves_it_unrecorded() {
        // Not zero: "this engine does not report caching" is a different fact
        // from "no caching happened", and the report must not merge them.
        let buckets =
            UsageBuckets::from_usage_json(&json!({"input_tokens": 10, "output_tokens": 2}));
        assert_eq!(buckets.cache_read, None);
        assert_eq!(buckets.cache_write, None);
    }

    // -- the closed vocabulary (DR-0117) -----------------------------------

    #[test]
    fn an_unknown_dimension_is_refused_by_name_with_the_legal_set() {
        let error = Dimension::parse("fact_key").expect_err("a fact key is not a dimension");
        assert!(error.contains("unknown stats dimension `fact_key`"));
        assert!(error.contains("DR-0117"));
        assert!(error.contains("program_id"));
        // The refusal exists so a group-by cannot silently become a total.
        assert!(Dimension::parse("target").is_err());
        assert!(Dimension::parse("value_json").is_err());
        assert_eq!(Dimension::parse("rule"), Ok(Dimension::Rule));
    }

    #[test]
    fn every_dimension_is_named_and_listed() {
        for dimension in Dimension::ALL {
            assert_eq!(Dimension::parse(dimension.name()), Ok(*dimension));
        }
        assert_eq!(Dimension::ALL.len(), 17);
    }

    // -- grain (DR-0116) ---------------------------------------------------

    #[test]
    fn grouping_by_rule_alone_never_collapses_two_grains_into_one_row() {
        // The test DR-0116 names. One rule, two populations: a model-calling
        // effect and one that cannot call a model. Folded into one row, `output`
        // would cover both while `calls` covered one.
        let instances = vec![instance("i1")];
        let effects = vec![
            effect("e1", "i1", "review", "agent.tell"),
            effect("e2", "i1", "review", "exec.command"),
        ];
        let runs = vec![
            run(
                "r1",
                "e1",
                json!({"usage": {"input_tokens": 10, "output_tokens": 2}}),
            ),
            run("r2", "e2", json!({})),
        ];
        let rows = fold(&instances, &effects, &runs).rows(&by_rule());
        assert_eq!(rows.len(), 2, "one rule, two grains, two rows: {rows:#?}");
        let grains: Vec<Option<String>> = rows
            .iter()
            .map(|row| {
                row.key
                    .iter()
                    .find(|(dimension, _)| *dimension == Dimension::Grain)
                    .and_then(|(_, value)| value.clone())
            })
            .collect();
        assert_eq!(
            grains,
            vec![Some("none".to_owned()), Some("turn".to_owned())]
        );
    }

    #[test]
    fn a_turn_grain_row_reports_calls_as_unrecorded_and_not_as_zero() {
        // `steps` counts model ROUNDS and misses provider retries, so it is not
        // a call count and must not be reported as one.
        let rows = fold(
            &[instance("i1")],
            &[effect("e1", "i1", "review", "agent.tell")],
            &[run(
                "r1",
                "e1",
                json!({"steps": 3, "usage": {"input_tokens": 10, "output_tokens": 2}}),
            )],
        )
        .rows(&by_rule());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            measure_of(&rows[0], |m| m.calls),
            None,
            "calls must be null"
        );
        assert_eq!(measure_of(&rows[0], |m| m.steps), Some(3));
        assert_eq!(measure_of(&rows[0], |m| m.output), Some(2));
    }

    #[test]
    fn an_effect_that_cannot_call_a_model_reports_zero_calls_and_it_is_complete() {
        let rows = fold(
            &[instance("i1")],
            &[effect("e1", "i1", "write", "file.write")],
            &[run("r1", "e1", json!({}))],
        )
        .rows(&by_rule());
        assert_eq!(rows.len(), 1);
        assert_eq!(measure_of(&rows[0], |m| m.calls), Some(0));
        assert_eq!(measure_of(&rows[0], |m| m.output), Some(0));
    }

    #[test]
    fn one_unrecorded_contribution_makes_the_whole_measure_unrecorded() {
        // The per-measure clause. Both runs sit in ONE row at ONE grain, so
        // population tagging alone does not reach this: completeness is a
        // property of the measure, not of the population.
        let rows = fold(
            &[instance("i1")],
            &[
                effect("e1", "i1", "review", "agent.tell"),
                effect("e2", "i1", "review", "agent.tell"),
            ],
            &[
                run(
                    "r1",
                    "e1",
                    json!({"usage": {"input_tokens": 10, "output_tokens": 2}}),
                ),
                // Same rule, same grain, and the provider reported no usage.
                run("r2", "e2", json!({"steps": 1})),
            ],
        )
        .rows(&by_rule());
        assert_eq!(rows.len(), 1, "same rule and same grain is one row");
        assert_eq!(
            measure_of(&rows[0], |m| m.output),
            None,
            "a recorded value folded with an unrecorded one is unrecorded"
        );
        assert_eq!(measure_of(&rows[0], |m| m.runs), Some(2));
    }

    // -- DR-0114's properties ---------------------------------------------

    #[test]
    fn the_whole_store_fold_equals_the_sum_of_per_instance_folds() {
        // Additivity, over the count and token measures. Durations and `day`
        // are outside the property by decision: replay does not restore
        // timestamps.
        let instances = vec![instance("i1"), instance("i2")];
        let effects = vec![
            effect("e1", "i1", "review", "agent.tell"),
            effect("e2", "i2", "review", "agent.tell"),
        ];
        let runs = vec![
            run(
                "r1",
                "e1",
                json!({"usage": {"input_tokens": 10, "output_tokens": 2}}),
            ),
            run(
                "r2",
                "e2",
                json!({"usage": {"input_tokens": 30, "output_tokens": 5}}),
            ),
        ];
        let whole = fold(&instances, &effects, &runs).rows(&by_rule());
        assert_eq!(whole.len(), 1);
        let whole_output = measure_of(&whole[0], |m| m.output).expect("recorded");

        let mut summed = 0;
        for one in ["i1", "i2"] {
            let scoped = Query {
                by: vec![Dimension::Rule],
                instance_id: Some(one.to_owned()),
                ..Query::default()
            };
            let rows = fold(&instances, &effects, &runs).rows(&scoped);
            assert_eq!(rows.len(), 1);
            summed += measure_of(&rows[0], |m| m.output).expect("recorded");
        }
        assert_eq!(whole_output, summed);
        assert_eq!(whole_output, 7);
    }

    #[test]
    fn a_run_is_counted_once_and_retries_are_the_difference() {
        // Logical and physical counts stay distinct: two runs of one effect is
        // one retry, not two effects.
        let rows = fold(
            &[instance("i1")],
            &[effect("e1", "i1", "review", "agent.tell")],
            &[
                run(
                    "r1",
                    "e1",
                    json!({"usage": {"input_tokens": 10, "output_tokens": 2}}),
                ),
                run(
                    "r2",
                    "e1",
                    json!({"usage": {"input_tokens": 10, "output_tokens": 3}}),
                ),
            ],
        )
        .rows(&by_rule());
        assert_eq!(rows.len(), 1);
        assert_eq!(measure_of(&rows[0], |m| m.effects), Some(1));
        assert_eq!(measure_of(&rows[0], |m| m.runs), Some(2));
        assert_eq!(measure_of(&rows[0], |m| m.retries), Some(1));
        assert_eq!(measure_of(&rows[0], |m| m.output), Some(5));
    }

    #[test]
    fn grain_is_in_the_group_key_whether_or_not_it_is_named() {
        let named = Query {
            by: vec![Dimension::Rule, Dimension::Grain],
            ..Query::default()
        };
        let instances = vec![instance("i1")];
        let effects = vec![
            effect("e1", "i1", "review", "agent.tell"),
            effect("e2", "i1", "review", "exec.command"),
        ];
        let runs = vec![
            run(
                "r1",
                "e1",
                json!({"usage": {"input_tokens": 1, "output_tokens": 1}}),
            ),
            run("r2", "e2", json!({})),
        ];
        let folded = fold(&instances, &effects, &runs);
        assert_eq!(folded.rows(&named), folded.rows(&by_rule()));
    }

    #[test]
    fn an_unknown_effect_kind_leaves_its_call_count_unrecorded() {
        // A snapshot written by a newer compiler can carry a kind this build
        // does not know. Guessing zero would claim it made no model call.
        let rows = fold(
            &[instance("i1")],
            &[effect("e1", "i1", "review", "future.kind")],
            &[run("r1", "e1", json!({}))],
        )
        .rows(&by_rule());
        assert_eq!(rows.len(), 1);
        assert_eq!(measure_of(&rows[0], |m| m.calls), None);
        assert_eq!(measure_of(&rows[0], |m| m.output), None);
    }
}
