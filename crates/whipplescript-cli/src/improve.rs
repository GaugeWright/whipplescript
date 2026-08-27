//! The improve engine: gauge scoring, pinned scenarios, and `whip improve`
//! campaigns (`spec/improve-design-note.md`; parent surface
//! `spec/experimentation-subsystem-research-note.md`).
//!
//! v1 shape, on the settled ground only:
//! - The campaign partition is expressed by which gauges you name (no
//!   modes): named gauges ascend toward better, unnamed gauges are guarded
//!   within indifference bands, `--sacrifice` releases, declared bars are
//!   always hard. Bare `whip improve` is repair mode.
//! - Acceptance is the dominance invariant of
//!   `models/maude/improve-acceptance.maude`: never surface a dominated
//!   candidate. Genuine tradeoffs are surfaced as decisions, never
//!   auto-resolved (the local utility model is future work — v1 always
//!   asks).
//! - Holdout sealing per `models/maude/improve-holdout.maude`: sealed
//!   scenarios never reach the proposer (aggregates only), promotion gates
//!   wear seals out (k=3, cumulative across campaigns), and below the floor
//!   the campaign runs anyway tagged `unheld-out` — progressive rigor,
//!   never entry rigor.
//! - Propose, don't apply: the terminal state is an evidence card per
//!   candidate; `whip adopt` is the explicit human act, and it refuses when
//!   mainline moved under the campaign (the certified-merge rebase is the
//!   principled upgrade).
//! - Candidate evaluation regenerates pinned scenarios in DISPOSABLE temp
//!   stores (never the workspace store); evidence rows carry
//!   `execution_mode = regen`. Egress-door diversion for regenerated runs
//!   inherits the versioned-workspace containment posture when it lands and
//!   is not enforced here yet.
//!
//! Honest v1 gaps (all tagged, none silent): `coerce` judges are declared
//! but not yet scoreable (parameter binding needs program context); `prompt`
//! judges need a configured native coerce provider and are skipped
//! (`judge-unscored`) without one; spend accounting records what is
//! derivable and the cap applies to recorded cost, with provider price
//! tables a follow-on.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{json, Value};
use whipplescript_parser::{IrGauge, IrProgram, BUILTIN_GAUGES};
use whipplescript_store::improve::{
    fold_campaign_event, CampaignSummary, ImproveStore, NewEvidence, ScenarioRow,
};
use whipplescript_store::items::sha256_hex;
use whipplescript_store::SqliteStore;

use crate::{emit_json, CliOptions};

/// Promotion-gate wear-out threshold (design note §8, k=3).
const WEAR_OUT_AT: i64 = 3;
/// Sealed fraction and floor (design note §8: 20% / floor 2). Below
/// MIN_SCENARIOS_FOR_SEALING the campaign runs `unheld-out`: sealing 2 of 3
/// scenarios would leave the proposer almost blind, which fabricates
/// neither rigor nor progress.
const SEALED_FRACTION: f64 = 0.2;
const SEALED_FLOOR: usize = 2;
const MIN_SCENARIOS_FOR_SEALING: usize = 4;
/// Internal stopping backstop for the propose→evaluate loop. Deliberately
/// NOT a surface: the operator's levers are the spend cap and the campaign
/// verbs, never a sample count.
const MAX_PROPOSAL_ROUNDS: usize = 4;
/// Default relative indifference band for the built-in resource gauges
/// (design note §2 amendment: their noise floor degenerates toward zero).
const RESOURCE_BAND_PERCENT: f64 = 5.0;
/// Minimum absolute band for quality gauges when the sample is too small
/// for a meaningful noise floor.
const QUALITY_BAND_FLOOR: f64 = 0.02;

pub(crate) fn improve_store_path() -> PathBuf {
    std::env::var("WHIPPLESCRIPT_IMPROVE_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".whipplescript/improve.sqlite"))
}

fn open_improve_store() -> Result<ImproveStore, String> {
    ImproveStore::open(improve_store_path())
        .map_err(|error| format!("failed to open improve store: {error:?}"))
}

/// Evidence-ledger program identity (DR-0054): the canonical program hash —
/// sorted (identity, canon_hash) pairs — so formatting, comments,
/// declaration reordering, and rule-binding renames stop orphaning the
/// ledger. A source with no canonical form (does not parse) falls back to
/// the byte hash: deterministic per content, fail-closed continuity.
/// Pre-DR byte-hash rows simply re-earn evidence (the SHA re-key
/// precedent); nothing aliases.
/// `pub(crate)` because every ledger writer must key identically — the
/// reopener and the warm scope join campaign and ambient rows on this
/// hash, so a byte-hashing caller would silently unlink the streams.
pub(crate) fn program_hash(source: &str) -> String {
    whipplescript_parser::canonical_program_hash(source)
        .unwrap_or_else(|| crate::sha256_hex(source.as_bytes()))
}

// ---------------------------------------------------------------------------
// Priced spend: the provider-config `prices` block (record-time, config-only)
// ---------------------------------------------------------------------------

/// One provider turn's token usage, carried to the spend ledger, normalized
/// into DISJOINT buckets (spec/inference-cache-note.md G2):
/// `input_tokens` = UNCACHED input, `cache_read_tokens` / `cache_write_tokens`
/// = provider prompt-cache traffic, `output_tokens` = completion. The cache
/// fields are `None` when the provider reported no cache usage at all —
/// distinct from an honest 0 — so observability can tell "no caching
/// happening" from "engine doesn't report caching". `total_tokens` is the
/// provider's own total when reported, else the disjoint sum — never an
/// overlapping sum.
#[derive(Clone, Debug, Default, PartialEq)]
struct TurnUsage {
    provider: String,
    model: String,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: Option<i64>,
    cache_write_tokens: Option<i64>,
    total_tokens: i64,
}

impl TurnUsage {
    /// Normalize a provider `usage` object by FIELD SHAPE, not provider name,
    /// so future OpenAI-compatible / self-hosted engines that mimic either
    /// wire family work without a whip change:
    /// - Anthropic shape: `input_tokens` EXCLUDES cache traffic;
    ///   `cache_read_input_tokens` / `cache_creation_input_tokens` are separate.
    /// - OpenAI shape: `prompt_tokens` (chat) / `input_tokens` (responses)
    ///   INCLUDES cached tokens; `prompt_tokens_details.cached_tokens` /
    ///   `input_tokens_details.cached_tokens` is the cached subset (no
    ///   write-side field — OpenAI cache writes are automatic and unbilled).
    fn from_usage_json(provider: &str, model: &str, usage: &Value) -> Self {
        let raw_input = usage
            .get("input_tokens")
            .or_else(|| usage.get("prompt_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let output_tokens = usage
            .get("output_tokens")
            .or_else(|| usage.get("completion_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        // Anthropic-shape cache fields: input is already exclusive of these.
        let anthropic_read = usage.get("cache_read_input_tokens").and_then(Value::as_i64);
        let cache_write_tokens = usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_i64);
        // OpenAI-shape cached subset: input INCLUDES it, so subtract below.
        let openai_cached = usage
            .get("prompt_tokens_details")
            .or_else(|| usage.get("input_tokens_details"))
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_i64);
        let (input_tokens, cache_read_tokens) = match (anthropic_read, openai_cached) {
            (Some(read), _) => (raw_input, Some(read)),
            (None, Some(cached)) => ((raw_input - cached).max(0), Some(cached)),
            (None, None) => (raw_input, None),
        };
        let total_tokens = usage.get("total_tokens").and_then(Value::as_i64).unwrap_or(
            input_tokens
                + cache_read_tokens.unwrap_or(0)
                + cache_write_tokens.unwrap_or(0)
                + output_tokens,
        );
        Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
            total_tokens,
        }
    }

    /// Input-side tokens the provider processed: uncached + cache traffic.
    fn input_side_tokens(&self) -> i64 {
        self.input_tokens
            + self.cache_read_tokens.unwrap_or(0)
            + self.cache_write_tokens.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Belief-update estimator (DR-0041): two families over paired evidence,
// Jeffreys priors. The certification rule stays the settle walk
// (settle-stopping.maude); these posteriors are the READOUT.
// ---------------------------------------------------------------------------

/// ln Γ(x) (Lanczos), the workhorse under both families.
fn ln_gamma(x: f64) -> f64 {
    const COEFFS: [f64; 6] = [
        76.180_091_729_471_46,
        -86.505_320_329_416_77,
        24.014_098_240_830_91,
        -1.231_739_572_450_155,
        0.120_865_097_386_617_9e-2,
        -0.539_523_938_495_3e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = tmp - (x + 0.5) * tmp.ln();
    let mut series = 1.000_000_000_190_015;
    for coeff in COEFFS {
        y += 1.0;
        series += coeff / y;
    }
    -tmp + (2.506_628_274_631_000_5 * series / x).ln()
}

/// The incomplete-beta continued fraction (Lentz's method).
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const EPS: f64 = 3e-14;
    const FPMIN: f64 = 1e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=200 {
        let m = m as f64;
        let m2 = 2.0 * m;
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Regularized incomplete beta I_x(a, b) — the Beta posterior CDF.
fn betainc(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_front = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let front = ln_front.exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        front * betacf(a, b, x) / a
    } else {
        1.0 - front * betacf(b, a, 1.0 - x) / b
    }
}

/// Student-t CDF via the incomplete beta.
fn student_t_cdf(t: f64, df: f64) -> f64 {
    let tail = 0.5 * betainc(df / 2.0, 0.5, df / (df + t * t));
    if t >= 0.0 {
        1.0 - tail
    } else {
        tail
    }
}

/// Family A (pass/fail evidence): the Bayesian sign test over paired
/// verdicts, Jeffreys prior. `pairs` = (control passed, treatment
/// passed); concordant pairs are uninformative about the sign, exactly
/// as a sign test wants. P(better) = P(θ > ½), θ ~ Beta(½+wins, ½+losses).
fn p_better_sign(pairs: &[(bool, bool)]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let wins = pairs
        .iter()
        .filter(|(control, treat)| *treat && !control)
        .count() as f64;
    let losses = pairs
        .iter()
        .filter(|(control, treat)| !treat && *control)
        .count() as f64;
    Some(1.0 - betainc(0.5 + wins, 0.5 + losses, 0.5))
}

/// Family B (continuous evidence): posterior P(the mean paired delta
/// favors the gauge's better direction) under the Jeffreys prior on
/// (μ, σ²) — the Student-t posterior. Needs ≥ 2 deltas (one delta has no
/// scale — the honest refusal); zero variance is the deterministic case.
fn p_better_t(deltas: &[f64], direction_up: bool) -> Option<f64> {
    if deltas.len() < 2 {
        return None;
    }
    let n = deltas.len() as f64;
    let signed: Vec<f64> = deltas
        .iter()
        .map(|delta| if direction_up { *delta } else { -*delta })
        .collect();
    let mean = signed.iter().sum::<f64>() / n;
    let variance = signed.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / (n - 1.0);
    if variance == 0.0 {
        return Some(if mean > 0.0 {
            1.0
        } else if mean < 0.0 {
            0.0
        } else {
            0.5
        });
    }
    Some(student_t_cdf(mean / (variance / n).sqrt(), n - 1.0))
}

/// The reopener's contradiction posterior, family A: P(the pass rate
/// sits BELOW `reference`) from Jeffreys + verdicts. The reference (the
/// answer-time operating point) is clamped off the degenerate endpoints
/// so a perfect recorded rate still leaves a contradiction expressible.
fn p_rate_below(passes: usize, fails: usize, reference: f64) -> f64 {
    betainc(
        0.5 + passes as f64,
        0.5 + fails as f64,
        reference.clamp(0.01, 0.99),
    )
}

/// The reopener's contradiction posterior, family B: P(the mean sits on
/// the WORSE side of `reference`), Student-t posterior over raw scores.
fn p_mean_worse(scores: &[f64], reference: f64, direction_up: bool) -> Option<f64> {
    if scores.len() < 2 {
        return None;
    }
    let n = scores.len() as f64;
    let mean = scores.iter().sum::<f64>() / n;
    let variance = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (n - 1.0);
    if variance == 0.0 {
        let worse = if direction_up {
            mean < reference
        } else {
            mean > reference
        };
        return Some(if worse {
            1.0
        } else if mean == reference {
            0.5
        } else {
            0.0
        });
    }
    let t = (mean - reference) / (variance / n).sqrt();
    Some(if direction_up {
        student_t_cdf(-t, n - 1.0)
    } else {
        student_t_cdf(t, n - 1.0)
    })
}

/// Price rates from the provider-config `prices` block: USD per million
/// tokens, per (provider, model), input and output priced separately.
/// Config-only by decision (Jack, 2026-07-14): no shipped defaults — a
/// stale built-in number would misprice spend silently, while an absent
/// table degrades to the honest `unpriced` posture (cost 0, tokens
/// recorded, the cap unable to bind). Pricing happens at RECORD time: the
/// spend event stores the computed cost and history is never repriced.
#[derive(Clone, Debug, Default)]
struct PriceTable {
    /// (provider, model) → per-Mtok USD rates.
    rates: BTreeMap<(String, String), PriceRate>,
}

/// Per-(provider, model) USD-per-Mtok rates. The cache rates are optional:
/// providers bill cache reads/writes differently (Anthropic ~0.1× input for
/// reads, 1.25× for writes; OpenAI ~0.5× for cached input, writes unbilled) —
/// whip ships NO multipliers (same no-invented-prices posture), so an entry
/// without cache rates prices cache traffic at the input rate, a conservative
/// overestimate for reads.
#[derive(Clone, Copy, Debug)]
struct PriceRate {
    input: f64,
    output: f64,
    cache_read: Option<f64>,
    cache_write: Option<f64>,
}

impl PriceTable {
    /// Load the union of every `--provider-config` file's `prices` block.
    /// A malformed entry is an error, never a silent unpriced: the user
    /// wrote a table and deserves to know it isn't being used.
    fn load(paths: &[PathBuf]) -> Result<Self, String> {
        let mut table = PriceTable::default();
        for path in paths {
            let raw = std::fs::read_to_string(path).map_err(|error| {
                format!("cannot read provider config {}: {error}", path.display())
            })?;
            let parsed: Value = serde_json::from_str(&raw)
                .map_err(|error| format!("invalid provider config {}: {error}", path.display()))?;
            for entry in parsed
                .get("prices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let provider = entry.get("provider").and_then(Value::as_str);
                let model = entry.get("model").and_then(Value::as_str);
                let input = entry.get("input_per_mtok_usd").and_then(Value::as_f64);
                let output = entry.get("output_per_mtok_usd").and_then(Value::as_f64);
                // Optional cache rates (spec/inference-cache-note.md G2): a
                // present-but-invalid value is a hard error like any other
                // malformed entry; an absent one falls back to the input rate
                // at cost time (conservative for cache reads — providers
                // discount them — so the cap binds sooner, never later).
                let cache_rate = |key: &str| -> Result<Option<f64>, String> {
                    match entry.get(key) {
                        None => Ok(None),
                        Some(value) => match value.as_f64() {
                            Some(rate) if rate >= 0.0 && rate.is_finite() => Ok(Some(rate)),
                            _ => Err(format!(
                                "invalid `{key}` in price entry in {} (need a non-negative \
                                 number): {entry}",
                                path.display()
                            )),
                        },
                    }
                };
                let cache_read = cache_rate("cache_read_per_mtok_usd")?;
                let cache_write = cache_rate("cache_write_per_mtok_usd")?;
                match (provider, model, input, output) {
                    (Some(provider), Some(model), Some(input), Some(output))
                        if input >= 0.0
                            && output >= 0.0
                            && input.is_finite()
                            && output.is_finite() =>
                    {
                        table.rates.insert(
                            (provider.to_owned(), model.to_owned()),
                            PriceRate {
                                input,
                                output,
                                cache_read,
                                cache_write,
                            },
                        );
                    }
                    _ => {
                        return Err(format!(
                            "invalid price entry in {} (need provider, model, \
                             input_per_mtok_usd, output_per_mtok_usd, all non-negative): {entry}",
                            path.display()
                        ));
                    }
                }
            }
        }
        Ok(table)
    }

    /// Record-time cost in USD micros; `None` = unpriced (no table entry
    /// for this provider/model, or no tokens to price). Cache traffic prices
    /// at its own rate when the entry declares one, else at the input rate
    /// (a conservative overestimate for reads — every provider discounts
    /// them — so an underspecified table can only over-count toward a cap).
    fn cost_micros(&self, usage: &TurnUsage) -> Option<i64> {
        if usage.input_tokens == 0
            && usage.output_tokens == 0
            && usage.cache_read_tokens.unwrap_or(0) == 0
            && usage.cache_write_tokens.unwrap_or(0) == 0
        {
            return None;
        }
        let rate = self
            .rates
            .get(&(usage.provider.clone(), usage.model.clone()))?;
        let usd = (usage.input_tokens as f64 * rate.input
            + usage.output_tokens as f64 * rate.output
            + usage.cache_read_tokens.unwrap_or(0) as f64 * rate.cache_read.unwrap_or(rate.input)
            + usage.cache_write_tokens.unwrap_or(0) as f64
                * rate.cache_write.unwrap_or(rate.input))
            / 1_000_000.0;
        Some((usd * 1_000_000.0).round() as i64)
    }
}

/// A spend cap binds only PRICED cost (the deliberate no-default-prices posture,
/// DR-0037): an unpriced model records $0 and never advances the cap. Keep the
/// posture — whip invents no price — but make it LOUD rather than passive: at
/// campaign end, if a cap was set and any spend went unpriced, tell the operator
/// their cap could not account for it and how to fix it. This matters now that any
/// OpenAI-compatible model is trivially wireable: a paid-but-unpriced model would
/// otherwise silently disable the cap. Also records a `campaign.spend_cap_unpriced`
/// event so the gap is in the record, not just on stderr.
fn warn_on_unpriced_spend_under_cap(
    store: &mut ImproveStore,
    campaign_id: &str,
    spend_cap_micros: Option<i64>,
) {
    let Some(cap) = spend_cap_micros else {
        return;
    };
    let Ok(events) = store.list_campaign_events(campaign_id) else {
        return;
    };
    let mut unpriced_events = 0i64;
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for event in &events {
        if event.event_type != "campaign.spend" {
            continue;
        }
        // Absent `priced` defaults to true (a real priced event always sets it);
        // only an explicit `priced: false` is an unpriced turn.
        if event
            .payload
            .get("priced")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            continue;
        }
        unpriced_events += 1;
        if let Some(what) = event.payload.get("what").and_then(Value::as_str) {
            sources.insert(what.to_owned());
        }
    }
    if unpriced_events == 0 {
        return;
    }
    let cap_usd = cap as f64 / 1_000_000.0;
    let sources = sources.into_iter().collect::<Vec<_>>().join(", ");
    eprintln!(
        "warning: --spend-cap ${cap_usd:.2} could not account for {unpriced_events} unpriced \
         spend event(s) ({sources}): the model has no `prices` entry, so its cost recorded as $0 \
         and did not bind the cap. Add a `prices` block entry (use 0 for a genuinely-free local \
         model) to make the cap enforceable."
    );
    let _ = store.append_campaign_event(
        campaign_id,
        "campaign.spend_cap_unpriced",
        &json!({
            "unpriced_spend_events": unpriced_events,
            "spend_cap_micros": cap,
        }),
    );
}

/// The standalone coerce request shell for judge/proposer turns: the
/// NativeCoerceClient carries the real prompt/schema; these identity fields
/// exist for effect-shaped callers and are unused on this path.
fn compile_failure_summary(failure: &crate::CompileFailure) -> String {
    match failure {
        crate::CompileFailure::Io(error) => error.to_string(),
        crate::CompileFailure::Diagnostics { diagnostics, .. } => diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
            .join("; "),
    }
}

fn judge_request() -> whipplescript_kernel::coerce::CoerceRequest {
    whipplescript_kernel::coerce::CoerceRequest {
        function_name: String::new(),
        arguments_json: String::new(),
        output_type: String::new(),
        generated_coerce_source_hash: String::new(),
        input_schema_hash: String::new(),
        output_schema_hash: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Gauge specs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum JudgeSpec {
    Exec(String),
    Labels(String),
    Prompt(String),
    Coerce(String, Vec<String>),
    Builtin,
}

#[derive(Clone, Debug)]
struct BarSpec {
    /// `Some(field)` for chance-shaped bars (`P(field)`), else the stat name.
    chance_field: Option<String>,
    stat: Option<String>,
    ge: bool,
    threshold: f64,
}

#[derive(Clone, Debug)]
struct GaugeSpec {
    name: String,
    judge: JudgeSpec,
    bar: Option<BarSpec>,
    inputs: Vec<String>,
    /// "Better" direction: quality up, resources down (design note §3);
    /// a user gauge with an `at most` bar is descend-toward-better.
    direction_up: bool,
    builtin: bool,
}

fn bar_from_ir(bar: &whipplescript_parser::IrGaugeBar) -> Option<BarSpec> {
    let threshold = bar.threshold.parse::<f64>().ok()?;
    Some(BarSpec {
        chance_field: (bar.form == "chance").then(|| bar.subject.clone()),
        stat: (bar.form == "stat").then(|| bar.subject.clone()),
        ge: bar.op == ">=",
        threshold,
    })
}

fn collect_gauge_specs(ir: &IrProgram) -> Vec<GaugeSpec> {
    let mut specs: Vec<GaugeSpec> = ir
        .gauges
        .iter()
        .map(|gauge: &IrGauge| {
            let bar = gauge.expect.as_ref().and_then(bar_from_ir);
            let direction_up = bar.as_ref().map(|b| b.ge).unwrap_or(true);
            GaugeSpec {
                name: gauge.name.clone(),
                judge: match gauge.judge_kind.as_str() {
                    "exec" => JudgeSpec::Exec(gauge.judge_target.clone()),
                    "labels" => JudgeSpec::Labels(gauge.judge_target.clone()),
                    "prompt" => JudgeSpec::Prompt(gauge.judge_target.clone()),
                    _ => JudgeSpec::Coerce(gauge.judge_target.clone(), gauge.judge_args.clone()),
                },
                bar,
                inputs: gauge.inputs.clone(),
                direction_up,
                builtin: false,
            }
        })
        .collect();
    for name in BUILTIN_GAUGES {
        specs.push(GaugeSpec {
            name: (*name).to_owned(),
            judge: JudgeSpec::Builtin,
            bar: None,
            inputs: Vec::new(),
            // Resource gauges are lower-is-better (spend/latency/tokens);
            // the cache-hit RATE is higher-is-better.
            direction_up: *name == "std.cache_hit",
            builtin: true,
        });
    }
    specs
}

// ---------------------------------------------------------------------------
// Campaign spec (the partition)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
struct ReachTarget {
    ge: bool,
    threshold: f64,
    raw: String,
}

#[derive(Clone, Debug, Default)]
struct CampaignSpec {
    /// Named (ascending) gauges of the ACTIVE stage, with optional reach
    /// targets. Later `then` stages are recorded as raw target tokens and
    /// EXECUTE with ratchet semantics: when every ascend gauge in the
    /// active stage has a reach target the baseline already meets, the
    /// stage's achieved levels become hard guard floors and the next
    /// stage's gauges become the ascend set (improve note §3).
    ascend: Vec<(String, Option<ReachTarget>)>,
    later_stages: Vec<Vec<String>>,
    /// Stage-ratchet floors from completed earlier stages: gauge → (higher
    /// -is-better, achieved level). A floored gauge regressing past its
    /// floor refuses the candidate even inside the indifference band.
    floors: BTreeMap<String, (bool, f64)>,
    sacrifice: Vec<String>,
    /// Band overrides in percent of the baseline operating point.
    within_percent: BTreeMap<String, f64>,
    spend_cap_micros: Option<i64>,
    /// Campaign-attached stratified reflection (leakage policy, improve
    /// note §7, settled 2026-07-11): the proposer sees aggregates only —
    /// never scenario names, inputs, traces, or judge rationales.
    redacted_view: bool,
    /// Repair mode: restore violated bars, touch nothing else.
    repair: bool,
    /// `Some(name)` when adopted from a declared `campaign` block.
    declared: Option<String>,
}

impl CampaignSpec {
    fn to_json(&self) -> Value {
        json!({
            "ascend": self.ascend.iter().map(|(name, reach)| json!({
                "gauge": name,
                "reach": reach.as_ref().map(|r| json!({
                    "op": if r.ge { ">=" } else { "<=" },
                    "threshold": r.threshold,
                    "raw": r.raw,
                })),
            })).collect::<Vec<_>>(),
            "later_stages": self.later_stages,
            "floors": self.floors.iter().map(|(gauge, (ge, floor))| json!({
                "gauge": gauge,
                "ge": ge,
                "floor": floor,
            })).collect::<Vec<_>>(),
            "sacrifice": self.sacrifice,
            "within_percent": self.within_percent,
            "spend_cap_micros": self.spend_cap_micros,
            "redacted_view": self.redacted_view,
            "repair": self.repair,
            "declared": self.declared,
        })
    }
}

/// Rehydrate a CampaignSpec from its `to_json` record (the campaign.opened
/// payload) — what `--resume` continues from. Fallible on purpose: a field
/// this converter cannot read must never silently become a default that
/// weakens a guard.
fn campaign_spec_from_json(value: &Value) -> Result<CampaignSpec, String> {
    let mut spec = CampaignSpec::default();
    for entry in value
        .get("ascend")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = entry
            .get("gauge")
            .and_then(Value::as_str)
            .ok_or("malformed campaign record: ascend entry without a gauge")?;
        let reach = match entry.get("reach") {
            None | Some(Value::Null) => None,
            Some(reach) => Some(ReachTarget {
                ge: reach.get("op").and_then(Value::as_str) == Some(">="),
                threshold: reach
                    .get("threshold")
                    .and_then(Value::as_f64)
                    .ok_or("malformed campaign record: reach without a threshold")?,
                raw: reach
                    .get("raw")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            }),
        };
        spec.ascend.push((name.to_owned(), reach));
    }
    for stage in value
        .get("later_stages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        spec.later_stages.push(
            stage
                .as_array()
                .ok_or("malformed campaign record: later stage is not a list")?
                .iter()
                .map(|token| {
                    token
                        .as_str()
                        .map(str::to_owned)
                        .ok_or("malformed campaign record: stage token is not a string")
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    for floor in value
        .get("floors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let gauge = floor
            .get("gauge")
            .and_then(Value::as_str)
            .ok_or("malformed campaign record: floor without a gauge")?;
        let ge = floor
            .get("ge")
            .and_then(Value::as_bool)
            .ok_or("malformed campaign record: floor without a direction")?;
        let level = floor
            .get("floor")
            .and_then(Value::as_f64)
            .ok_or("malformed campaign record: floor without a level")?;
        spec.floors.insert(gauge.to_owned(), (ge, level));
    }
    for gauge in value
        .get("sacrifice")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        spec.sacrifice.push(
            gauge
                .as_str()
                .ok_or("malformed campaign record: sacrifice is not a string")?
                .to_owned(),
        );
    }
    if let Some(bands) = value.get("within_percent").and_then(Value::as_object) {
        for (gauge, band) in bands {
            spec.within_percent.insert(
                gauge.clone(),
                band.as_f64()
                    .ok_or("malformed campaign record: band is not a number")?,
            );
        }
    }
    spec.spend_cap_micros = value.get("spend_cap_micros").and_then(Value::as_i64);
    spec.redacted_view = value
        .get("redacted_view")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    spec.repair = value
        .get("repair")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    spec.declared = value
        .get("declared")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(spec)
}

/// Parse a positional improve target: `name`, `name>=0.9`, `name<=800ms`.
/// The CLI sees real operators (only the .whip declaration tokenizer drops
/// them).
fn parse_target(token: &str) -> Result<(String, Option<ReachTarget>), String> {
    for (op, ge) in [(">=", true), ("<=", false)] {
        if let Some((name, rest)) = token.split_once(op) {
            let raw = rest.trim().to_owned();
            let numeric: String = raw
                .chars()
                .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
                .collect();
            let threshold = numeric
                .parse::<f64>()
                .map_err(|_| format!("invalid target `{token}`: `{raw}` is not a number"))?;
            return Ok((
                name.trim().to_owned(),
                Some(ReachTarget { ge, threshold, raw }),
            ));
        }
    }
    Ok((token.to_owned(), None))
}

fn parse_percent(raw: &str) -> Result<f64, String> {
    raw.trim()
        .trim_end_matches('%')
        .parse::<f64>()
        .map_err(|_| format!("invalid band `{raw}` (use e.g. `2%`)"))
}

fn parse_spend_cap(raw: &str) -> Result<i64, String> {
    let cleaned = raw.trim().trim_start_matches('$');
    let dollars = cleaned
        .parse::<f64>()
        .map_err(|_| format!("invalid spend cap `{raw}` (use e.g. `$4`)"))?;
    if !dollars.is_finite() || dollars <= 0.0 {
        return Err(format!(
            "invalid spend cap `{raw}` (must be a positive amount)"
        ));
    }
    Ok((dollars * 1_000_000.0) as i64)
}

struct ImproveArgs {
    spec: CampaignSpec,
    proposer: String,
    provider: String,
    provider_config_paths: Vec<PathBuf>,
    root: Option<String>,
    /// `--resume <campaign-id>`: continue a parked campaign under a fresh
    /// per-invocation spend allowance (the spec comes from the record).
    resume: Option<String>,
}

fn parse_improve_args(
    args: &[String],
    ir_campaigns: &[(String, CampaignSpec)],
) -> Result<ImproveArgs, String> {
    let mut spec = CampaignSpec::default();
    let mut stages: Vec<Vec<(String, Option<ReachTarget>)>> = vec![Vec::new()];
    let mut resume: Option<String> = None;
    let mut proposer = std::env::var("WHIPPLESCRIPT_IMPROVE_PROPOSER").unwrap_or_default();
    let mut provider = "fixture".to_owned();
    let mut provider_config_paths: Vec<PathBuf> = Vec::new();
    let mut root = None;
    let mut declared: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            // --program is consumed here but owned by run_improve's probe
            // scan (it must resolve before compilation, which happens
            // before this parse).
            "--program" => {
                index += 1;
                args.get(index).ok_or("--program requires a path")?;
            }
            "--root" => {
                index += 1;
                root = Some(args.get(index).ok_or("--root requires a path")?.clone());
            }
            "--sacrifice" => {
                index += 1;
                spec.sacrifice.push(
                    args.get(index)
                        .ok_or("--sacrifice requires a gauge name")?
                        .clone(),
                );
            }
            "--within" => {
                index += 1;
                let raw = args.get(index).ok_or("--within requires <gauge>=<band>")?;
                let (gauge, band) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("invalid --within `{raw}` (use `<gauge>=2%`)"))?;
                spec.within_percent
                    .insert(gauge.to_owned(), parse_percent(band)?);
            }
            "--spend-cap" => {
                index += 1;
                spec.spend_cap_micros = Some(parse_spend_cap(
                    args.get(index).ok_or("--spend-cap requires an amount")?,
                )?);
            }
            "--redacted-view" => {
                spec.redacted_view = true;
            }
            "--proposer" => {
                index += 1;
                proposer = args
                    .get(index)
                    .ok_or("--proposer requires `fixture` or `native`")?
                    .clone();
            }
            "--provider" => {
                index += 1;
                provider = args
                    .get(index)
                    .ok_or("--provider requires a provider name")?
                    .clone();
            }
            "--provider-config" => {
                index += 1;
                provider_config_paths.push(PathBuf::from(
                    args.get(index).ok_or("--provider-config requires a path")?,
                ));
            }
            "then" => stages.push(Vec::new()),
            "--resume" => {
                index += 1;
                resume = Some(
                    args.get(index)
                        .ok_or("--resume requires a campaign id")?
                        .clone(),
                );
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown improve flag `{flag}`"));
            }
            target => {
                // A single bare positional naming a declared campaign adopts
                // its spec ("adopted from `release_tuning`").
                if stages.len() == 1
                    && stages[0].is_empty()
                    && declared.is_none()
                    && ir_campaigns.iter().any(|(name, _)| name == target)
                {
                    declared = Some(target.to_owned());
                } else {
                    stages
                        .last_mut()
                        .expect("stages always has one entry")
                        .push(parse_target(target)?);
                }
            }
        }
        index += 1;
    }
    if let Some(name) = &declared {
        if stages.iter().any(|stage| !stage.is_empty()) {
            return Err(format!(
                "campaign `{name}` cannot be combined with inline gauge targets"
            ));
        }
        let (_, mut adopted) = ir_campaigns
            .iter()
            .find(|(candidate, _)| candidate == name)
            .cloned()
            .expect("declared campaign resolved above");
        adopted.declared = Some(name.clone());
        // CLI flags refine the declared spec (spend cap, extra sacrifices).
        adopted.sacrifice.extend(spec.sacrifice);
        adopted.within_percent.extend(spec.within_percent);
        adopted.spend_cap_micros = spec.spend_cap_micros.or(adopted.spend_cap_micros);
        // A CLI flag may TIGHTEN a declared campaign to redacted view,
        // never loosen a declared `proposer redacted`.
        adopted.redacted_view |= spec.redacted_view;
        spec = adopted;
    } else {
        let mut stages_iter = stages.into_iter().filter(|stage| !stage.is_empty());
        spec.ascend = stages_iter.next().unwrap_or_default();
        // Later stages keep their raw target tokens so activation
        // re-parses them faithfully (a `then std.latency<=800ms` target
        // survives until its stage runs).
        spec.later_stages = stages_iter
            .map(|stage| {
                stage
                    .into_iter()
                    .map(|(name, reach)| match reach {
                        Some(reach) => {
                            format!("{name}{}{}", if reach.ge { ">=" } else { "<=" }, reach.raw)
                        }
                        None => name,
                    })
                    .collect()
            })
            .collect();
        spec.repair = resume.is_none() && spec.ascend.is_empty() && spec.later_stages.is_empty();
    }
    if proposer.is_empty() {
        proposer = "native".to_owned();
    }
    if resume.is_some() && (!spec.ascend.is_empty() || !spec.later_stages.is_empty()) {
        return Err(
            "--resume continues the parked campaign's own spec; it cannot be combined with \
             inline gauge targets or a declared campaign"
                .to_owned(),
        );
    }
    Ok(ImproveArgs {
        spec,
        proposer,
        provider,
        provider_config_paths,
        root,
        resume,
    })
}

fn declared_campaign_specs(ir: &IrProgram) -> Result<Vec<(String, CampaignSpec)>, String> {
    ir.campaigns
        .iter()
        .map(|campaign| {
            let mut spec = CampaignSpec {
                ascend: campaign
                    .ascend
                    .iter()
                    .map(|name| (name.clone(), None))
                    .collect(),
                ..Default::default()
            };
            for reach in &campaign.reach {
                // Fallible on purpose: a threshold this converter cannot
                // parse must never silently become 0.0 (a trivially-met
                // target).
                let threshold = reach.threshold.parse::<f64>().map_err(|_| {
                    format!(
                        "campaign `{}`: reach threshold `{}` for `{}` is not a number",
                        campaign.name, reach.threshold, reach.gauge
                    )
                })?;
                spec.ascend.push((
                    reach.gauge.clone(),
                    Some(ReachTarget {
                        ge: reach.op == ">=",
                        threshold,
                        raw: format!("{}{}", reach.threshold, reach.unit.as_deref().unwrap_or("")),
                    }),
                ));
            }
            for guard in &campaign.guard {
                let percent = guard.band_percent.parse::<f64>().map_err(|_| {
                    format!(
                        "campaign `{}`: guard band `{}` for `{}` is not a number",
                        campaign.name, guard.band_percent, guard.gauge
                    )
                })?;
                spec.within_percent.insert(guard.gauge.clone(), percent);
            }
            spec.sacrifice = campaign.sacrifice.clone();
            spec.redacted_view = campaign.proposer_redacted;
            Ok((campaign.name.clone(), spec))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scoring: one completed instance -> gauge readings
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct GaugeReading {
    score: f64,
    passed: Option<bool>,
    tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct RunObservation {
    scenario: Option<String>,
    readings: BTreeMap<String, GaugeReading>,
    skipped: Vec<(String, String)>,
    /// Provider usage of the judge turns that scored this observation
    /// (prompt/coerce judges): priced into spend accounting by the
    /// caller that holds the campaign record.
    judge_usage: Vec<TurnUsage>,
}

/// Score every scoreable gauge against one completed instance in `store`.
/// `ambient` restricts to judges that are free and deterministic (exec +
/// labels-with-scenario + builtins); campaign evaluation also scores prompt
/// judges when a native coerce provider is configured.
/// `std.spend`'s priced observable: Σ price(run usage) over the runs that
/// carry usage, in USD. Strict by design (DR-0037: absent, never
/// fabricated) — if ANY usage-bearing run cannot price (no table entry,
/// no recorded model, no input/output split), the reading is skipped with
/// the reason rather than reported as a partial total wearing a full one.
fn total_spend_usd(
    runs: &[whipplescript_store::RunView],
    prices: &PriceTable,
) -> Result<Option<f64>, String> {
    let mut total_micros: i64 = 0;
    let mut any = false;
    for run in runs {
        let Ok(metadata) = serde_json::from_str::<Value>(&run.metadata_json) else {
            continue;
        };
        let Some(usage) = metadata
            .get("usage")
            .or_else(|| metadata.get("usage_json"))
            .filter(|usage| !usage.is_null())
        else {
            continue;
        };
        let model = metadata
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| usage.get("model").and_then(Value::as_str))
            .unwrap_or("");
        let turn = TurnUsage::from_usage_json(&run.provider, model, usage);
        if turn.total_tokens == 0 {
            continue;
        }
        any = true;
        match prices.cost_micros(&turn) {
            Some(cost) => total_micros += cost,
            None => {
                return Err(format!(
                    "unpriced usage (no price for provider `{}` model `{}`)",
                    run.provider,
                    if model.is_empty() {
                        "<unrecorded>"
                    } else {
                        model
                    }
                ))
            }
        }
    }
    Ok(any.then(|| total_micros as f64 / 1_000_000.0))
}

fn score_instance(
    store: &SqliteStore,
    instance_id: &str,
    specs: &[GaugeSpec],
    scenario: Option<&str>,
    ambient: bool,
    ir: &IrProgram,
    prices: &PriceTable,
) -> RunObservation {
    let mut readings: BTreeMap<String, GaugeReading> = BTreeMap::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut judge_usage: Vec<TurnUsage> = Vec::new();
    let instance = store.get_instance(instance_id).ok().flatten();
    // Consumed facts are still facts the run produced; judges must see
    // the whole record, not the un-consumed residue.
    let facts = store
        .list_facts_including_consumed(instance_id)
        .unwrap_or_default();
    let runs = store.list_runs(instance_id).unwrap_or_default();
    let facts_json: Vec<Value> = facts
        .iter()
        .map(|fact| {
            json!({
                "name": fact.name,
                "key": fact.key,
                "value": serde_json::from_str::<Value>(&fact.value_json)
                    .unwrap_or(Value::Null),
            })
        })
        .collect();
    let judge_input = json!({
        "schema": "whipplescript.judge_input.v0",
        "scenario": scenario,
        "status": instance.as_ref().map(|i| i.status.clone()),
        "input": instance
            .as_ref()
            .and_then(|i| serde_json::from_str::<Value>(&i.input_json).ok())
            .unwrap_or(Value::Null),
        "facts": facts_json,
    });

    // Builtins first (they may feed derived gauges).
    for spec in specs.iter().filter(|spec| spec.builtin) {
        match spec.name.as_str() {
            "std.latency" => {
                if let Some(ms) = total_latency_ms(&runs) {
                    readings.insert(
                        spec.name.clone(),
                        GaugeReading {
                            score: ms,
                            passed: None,
                            tags: Vec::new(),
                        },
                    );
                }
            }
            "std.tokens" => {
                if let Some(tokens) = total_tokens(&runs) {
                    readings.insert(
                        spec.name.clone(),
                        GaugeReading {
                            score: tokens,
                            passed: None,
                            tags: Vec::new(),
                        },
                    );
                }
            }
            "std.spend" => match total_spend_usd(&runs, prices) {
                Ok(Some(usd)) => {
                    readings.insert(
                        spec.name.clone(),
                        GaugeReading {
                            score: usd,
                            passed: None,
                            tags: Vec::new(),
                        },
                    );
                }
                Ok(None) => {}
                Err(reason) => skipped.push((spec.name.clone(), reason)),
            },
            "std.cache_hit" => {
                if let Some(rate) = total_cache_hit_rate(&runs) {
                    readings.insert(
                        spec.name.clone(),
                        GaugeReading {
                            score: rate,
                            passed: None,
                            tags: Vec::new(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    // Declared gauges as a worklist: a derived gauge scores once every
    // input gauge has scored, so derived-of-derived chains resolve in
    // later passes regardless of declaration order; whatever never becomes
    // ready is skipped honestly.
    let mut pending: Vec<&GaugeSpec> = specs.iter().filter(|spec| !spec.builtin).collect();
    loop {
        let (ready, waiting): (Vec<&GaugeSpec>, Vec<&GaugeSpec>) = pending
            .into_iter()
            .partition(|spec| spec.inputs.iter().all(|input| readings.contains_key(input)));
        pending = waiting;
        if ready.is_empty() {
            break;
        }
        for spec in ready {
            score_one_gauge(
                spec,
                &judge_input,
                scenario,
                ambient,
                ir,
                &mut readings,
                &mut skipped,
                &mut judge_usage,
            );
        }
    }
    for spec in pending {
        skipped.push((spec.name.clone(), "inputs unscored on this run".to_owned()));
    }
    RunObservation {
        scenario: scenario.map(str::to_owned),
        readings,
        skipped,
        judge_usage,
    }
}

/// Score one non-builtin gauge whose inputs (if any) are all present in
/// `readings`.
#[allow(clippy::too_many_arguments)]
fn score_one_gauge(
    spec: &GaugeSpec,
    judge_input: &Value,
    scenario: Option<&str>,
    ambient: bool,
    ir: &IrProgram,
    readings: &mut BTreeMap<String, GaugeReading>,
    skipped: &mut Vec<(String, String)>,
    judge_usage: &mut Vec<TurnUsage>,
) {
    {
        let mut input = judge_input.clone();
        if !spec.inputs.is_empty() {
            let scores: BTreeMap<&String, f64> = spec
                .inputs
                .iter()
                .map(|name| (name, readings[name].score))
                .collect();
            input["inputs"] = json!(scores);
        }
        match &spec.judge {
            JudgeSpec::Exec(command) => match run_exec_judge(command, &input, spec) {
                Ok(reading) => {
                    readings.insert(spec.name.clone(), reading);
                }
                Err(reason) => skipped.push((spec.name.clone(), reason)),
            },
            JudgeSpec::Labels(source) => match lookup_label(source, scenario, spec) {
                Ok(Some(reading)) => {
                    readings.insert(spec.name.clone(), reading);
                }
                Ok(None) => skipped.push((spec.name.clone(), "no label for this run".to_owned())),
                Err(reason) => skipped.push((spec.name.clone(), reason)),
            },
            JudgeSpec::Prompt(template) => {
                if ambient {
                    skipped.push((
                        spec.name.clone(),
                        "prompt judges are scored during campaigns/settle, not ambiently (v1)"
                            .to_owned(),
                    ));
                } else {
                    match run_prompt_judge(template, &input, spec) {
                        Ok((reading, usage)) => {
                            readings.insert(spec.name.clone(), reading);
                            judge_usage.push(usage);
                        }
                        Err(reason) => skipped.push((spec.name.clone(), reason)),
                    }
                }
            }
            JudgeSpec::Coerce(target, args) => {
                if ambient {
                    skipped.push((
                        spec.name.clone(),
                        "coerce judges are scored during campaigns/settle, not ambiently (v1)"
                            .to_owned(),
                    ));
                } else {
                    match run_coerce_judge(target, args, &input, ir, spec) {
                        Ok((reading, usage)) => {
                            readings.insert(spec.name.clone(), reading);
                            judge_usage.push(usage);
                        }
                        Err(reason) => skipped.push((spec.name.clone(), reason)),
                    }
                }
            }
            JudgeSpec::Builtin => {}
        }
    }
}

fn parse_store_timestamp(raw: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f"))
        .ok()
        .or_else(|| {
            // Other store columns carry RFC3339; tolerate it here so a
            // storage-format change never silently vanishes std.latency.
            chrono::DateTime::parse_from_rfc3339(raw)
                .map(|instant| instant.naive_utc())
                .ok()
        })
}

fn total_latency_ms(runs: &[whipplescript_store::RunView]) -> Option<f64> {
    let mut total = 0.0;
    let mut any = false;
    for run in runs {
        let (Some(started), Some(completed)) = (
            parse_store_timestamp(&run.started_at),
            run.completed_at.as_deref().and_then(parse_store_timestamp),
        ) else {
            continue;
        };
        total += (completed - started).num_milliseconds().max(0) as f64;
        any = true;
    }
    any.then_some(total)
}

fn total_tokens(runs: &[whipplescript_store::RunView]) -> Option<f64> {
    let mut total = 0.0;
    let mut any = false;
    for run in runs {
        let Ok(metadata) = serde_json::from_str::<Value>(&run.metadata_json) else {
            continue;
        };
        // One usage object per run; prefer the provider's own total, else
        // the disjoint sum — never sum overlapping fields. The Anthropic
        // shape has no `total_tokens` and its `input_tokens` EXCLUDES cache
        // traffic, so the fallback must add the cache fields or cached runs
        // undercount (spec/inference-cache-note.md G2).
        let usage = metadata.get("usage").or_else(|| metadata.get("usage_json"));
        if let Some(usage) = usage {
            if let Some(count) = usage.get("total_tokens").and_then(Value::as_f64) {
                total += count;
                any = true;
            } else {
                for tokens_key in [
                    "input_tokens",
                    "output_tokens",
                    "cache_read_input_tokens",
                    "cache_creation_input_tokens",
                ] {
                    if let Some(count) = usage.get(tokens_key).and_then(Value::as_f64) {
                        total += count;
                        any = true;
                    }
                }
            }
        }
    }
    any.then_some(total)
}

/// `std.cache_hit`'s observable: cache-read tokens over all input-side tokens
/// (uncached + cache read + cache write), across the instance's provider runs.
/// `None` when NO run reported any cache usage fields at all — an engine that
/// doesn't report caching yields an honest absence, not a fake 0%.
fn total_cache_hit_rate(runs: &[whipplescript_store::RunView]) -> Option<f64> {
    let mut cache_read = 0i64;
    let mut input_side = 0i64;
    let mut any_cache_reporting = false;
    for run in runs {
        let Ok(metadata) = serde_json::from_str::<Value>(&run.metadata_json) else {
            continue;
        };
        let Some(usage) = metadata
            .get("usage")
            .or_else(|| metadata.get("usage_json"))
            .filter(|usage| !usage.is_null())
        else {
            continue;
        };
        let model = metadata
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| usage.get("model").and_then(Value::as_str))
            .unwrap_or("");
        let turn = TurnUsage::from_usage_json(&run.provider, model, usage);
        if turn.cache_read_tokens.is_some() || turn.cache_write_tokens.is_some() {
            any_cache_reporting = true;
        }
        cache_read += turn.cache_read_tokens.unwrap_or(0);
        input_side += turn.input_side_tokens();
    }
    (any_cache_reporting && input_side > 0).then(|| cache_read as f64 / input_side as f64)
}

fn reading_from_judge_output(output: &Value, spec: &GaugeSpec) -> Result<GaugeReading, String> {
    let passed = if let Some(bar) = &spec.bar {
        if let Some(field) = &bar.chance_field {
            Some(
                output
                    .get(field)
                    .and_then(Value::as_bool)
                    .ok_or_else(|| format!("judge output has no boolean field `{field}`"))?,
            )
        } else {
            output.get("passed").and_then(Value::as_bool)
        }
    } else {
        output.get("passed").and_then(Value::as_bool)
    };
    let score = output
        .get("score")
        .and_then(Value::as_f64)
        .or(passed.map(|p| if p { 1.0 } else { 0.0 }))
        .ok_or("judge output has neither `score` nor a bar verdict")?;
    Ok(GaugeReading {
        score,
        passed,
        tags: Vec::new(),
    })
}

/// Run a deterministic exec judge: the shipped det-validation pattern with
/// the run context on stdin and a JSON object on stdout. Governed by the
/// same operator-config-only allowlist as `exec` effects
/// (`WHIPPLESCRIPT_EXEC_ALLOW`): source declares, config grants.
fn run_exec_judge(command: &str, input: &Value, spec: &GaugeSpec) -> Result<GaugeReading, String> {
    if !crate::exec_command_granted(command) {
        return Err(format!(
            "exec judge `{command}` is not granted (WHIPPLESCRIPT_EXEC_ALLOW)"
        ));
    }
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to spawn exec judge: {error}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(error) = stdin.write_all(input.to_string().as_bytes()) {
            // A judge that decides without reading stdin can exit before the
            // write lands; EPIPE means "input not consumed", not a failed
            // judge — its own output and exit code decide.
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                let _ = child.kill();
                return Err(format!("failed to write judge input: {error}"));
            }
        }
    }
    // Close stdin so a judge reading to EOF can proceed (wait_with_output
    // would do this implicitly; the bounded wait below runs first).
    drop(child.stdin.take());
    // Bounded wait: a wedged judge must never hang the dev loop or a
    // campaign; kill and skip (the gauge lands in `skipped`, tagged).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err("exec judge timed out after 60s".to_owned());
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => return Err(format!("exec judge failed: {error}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("exec judge failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "exec judge exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("exec judge emitted invalid JSON: {error}"))?;
    reading_from_judge_output(&parsed, spec)
}

/// Wholesale anchors: a user-owned JSON label file mapping scenario name to
/// `{"passed": bool}` / `{"score": n}`. Labels are trusted by declaration
/// and parsed once per process (they cannot change mid-campaign
/// meaningfully; a campaign re-reads by restarting).
fn lookup_label(
    source: &str,
    scenario: Option<&str>,
    spec: &GaugeSpec,
) -> Result<Option<GaugeReading>, String> {
    static LABELS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Value>>> =
        std::sync::OnceLock::new();
    let Some(scenario) = scenario else {
        return Ok(None);
    };
    let cache = LABELS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut cache = cache.lock().map_err(|_| "labels cache poisoned")?;
    if !cache.contains_key(source) {
        let raw = std::fs::read_to_string(source)
            .map_err(|error| format!("labels source `{source}`: {error}"))?;
        let labels: Value = serde_json::from_str(&raw)
            .map_err(|error| format!("labels source `{source}` is not JSON: {error}"))?;
        cache.insert(source.to_owned(), labels);
    }
    let labels = cache.get(source).expect("inserted above");
    let Some(entry) = labels.get(scenario) else {
        return Ok(None);
    };
    let mut reading = reading_from_judge_output(entry, spec)?;
    reading.tags.push("wholesale-anchor".to_owned());
    Ok(Some(reading))
}

/// Evidence provenance for the scorer column — ONE mapping, shared by the
/// campaign (regen) and ambient (live) recorders so the same instrument
/// never splits into two scorer identities.
fn scorer_label(judge: &JudgeSpec) -> String {
    match judge {
        JudgeSpec::Exec(command) => format!("exec:{command}"),
        JudgeSpec::Labels(source) => format!("labels:{source}"),
        JudgeSpec::Prompt(_) => "prompt".to_owned(),
        JudgeSpec::Coerce(name, _) => format!("coerce:{name}"),
        JudgeSpec::Builtin => "builtin".to_owned(),
    }
}

/// One structured native-coerce turn (the judge/proposer transport shell):
/// prompt + object schema in, parsed value + total token usage out.
fn native_coerce_turn(
    purpose: &str,
    prompt: String,
    schema: Value,
    schema_name: &str,
    codex_label: &str,
    wrapped: bool,
) -> Result<(Value, TurnUsage), String> {
    let config = crate::coerce_runtime::resolve_native_coerce_config()
        .map_err(|error| format!("{purpose} provider: {error}"))?
        .ok_or_else(|| {
            format!(
                "{purpose} needs a native coerce provider (set \
                 WHIPPLESCRIPT_COERCE_PROVIDER or run `whip auth`)"
            )
        })?;
    let transport = crate::coerce_runtime::UreqCoerceTransport::new(
        std::time::Duration::from_secs(config.timeout_secs),
    );
    let client = whipplescript_kernel::coerce_native::NativeCoerceClient {
        provider: config.backend,
        base_url: config.base_url.clone(),
        api_key: config.api_key.clone(),
        model: config.model.clone(),
        prompt,
        output_schema: schema,
        wrapped,
        schema_name: schema_name.to_owned(),
        max_tokens: config.max_tokens,
        codex: config
            .codex_account_id
            .as_ref()
            .map(|account| (account.clone(), codex_label.to_owned())),
        idempotency_key: String::new(),
        transport: &transport,
    };
    let result = whipplescript_kernel::coerce::CoerceClient::coerce(&client, &judge_request());
    if !matches!(
        result.status,
        whipplescript_kernel::coerce::CoerceStatus::Succeeded
    ) {
        return Err(format!("{purpose} failed: {}", result.summary));
    }
    let usage_json: Value = serde_json::from_str(&result.usage_json).unwrap_or(Value::Null);
    // Price-table provider names match what the operator configures in
    // WHIPPLESCRIPT_COERCE_PROVIDER (`openai-generic`, not a synonym).
    let provider_name = match client.provider {
        whipplescript_kernel::coerce_native::CoerceProvider::OpenAi => "openai",
        whipplescript_kernel::coerce_native::CoerceProvider::OpenAiCompat => "openai-generic",
        whipplescript_kernel::coerce_native::CoerceProvider::Anthropic => "anthropic",
        whipplescript_kernel::coerce_native::CoerceProvider::Xai => "xai",
    };
    let usage = TurnUsage::from_usage_json(provider_name, &client.model, &usage_json);
    let value: Value = result
        .value_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .ok_or_else(|| format!("{purpose} returned no value"))?;
    Ok((value, usage))
}

/// LLM prompt judge via the native coerce path; requires a configured
/// provider (WHIPPLESCRIPT_COERCE_PROVIDER / `whip auth`).
/// Resolve one declared judge-argument path against the judge-input
/// record: `record` (the whole record), `input.<path>`, or
/// `facts.<Class>.<field...>` (the LAST recorded fact of the class — the
/// run's final state). None = the path names nothing on this record.
fn resolve_judge_argument(path: &str, record: &Value) -> Option<Value> {
    if path == "record" {
        return Some(record.clone());
    }
    let mut segments = path.split('.');
    let mut current = match segments.next()? {
        "input" => record.get("input")?.clone(),
        "facts" => {
            let class = segments.next()?;
            record
                .get("facts")?
                .as_array()?
                .iter()
                .rev()
                .find(|fact| fact.get("name").and_then(Value::as_str) == Some(class))?
                .get("value")?
                .clone()
        }
        _ => return None,
    };
    for segment in segments {
        current = current.get(segment)?.clone();
    }
    Some(current)
}

/// Execute a coerce judge (explicit-argument binding, settled
/// 2026-07-14): resolve each declared path against the record, render
/// the SAME prompt and schema the runtime would for a `coerce` call
/// (`build_coerce_call_parts`), run one native turn, and read the
/// verdict off the coerce's own output value.
fn run_coerce_judge(
    name: &str,
    args: &[String],
    input: &Value,
    ir: &IrProgram,
    spec: &GaugeSpec,
) -> Result<(GaugeReading, TurnUsage), String> {
    if args.is_empty() {
        return Err(format!(
            "coerce judge `{name}` declares no arguments; bind its parameters \
             (`judge via coerce {name}(input.…, facts.<Class>.<field>)`, or `{name}(record)`)"
        ));
    }
    let mut arguments = serde_json::Map::new();
    for (index, arg) in args.iter().enumerate() {
        let value = resolve_judge_argument(arg, input)
            .ok_or_else(|| format!("judge argument `{arg}` resolves to nothing on this record"))?;
        arguments.insert(format!("arg{index}"), value);
    }
    let (prompt, schema, wrapped, schema_name) =
        whipplescript_kernel::coerce_native::build_coerce_call_parts(
            ir,
            name,
            &Value::Object(arguments),
        )?;
    let (value, usage) = native_coerce_turn(
        "coerce judge",
        prompt,
        schema,
        &schema_name,
        &format!("improve-judge-{}", spec.name),
        wrapped,
    )?;
    let mut reading = reading_from_judge_output(&value, spec)?;
    reading.tags.push("judge-unanchored".to_owned());
    Ok((reading, usage))
}

fn run_prompt_judge(
    template: &str,
    input: &Value,
    spec: &GaugeSpec,
) -> Result<(GaugeReading, TurnUsage), String> {
    let prompt = format!(
        "{template}\n\nJudge the following run record. Respond with the JSON schema \
         provided.\n\n{input}"
    );
    let schema = json!({
        "type": "object",
        "properties": {
            "passed": {"type": "boolean"},
            "score": {"type": "number"},
            "rationale": {"type": "string"},
        },
        "required": ["passed", "score", "rationale"],
        "additionalProperties": false,
    });
    let (value, usage) = native_coerce_turn(
        "prompt judge",
        prompt,
        schema,
        "GaugeJudgeVerdict",
        &format!("improve-judge-{}", spec.name),
        false,
    )?;
    let mut reading = reading_from_judge_output(&value, spec)?;
    reading.tags.push("judge-unanchored".to_owned());
    Ok((reading, usage))
}

/// The v1 MI lower bound at the review surface (leakage policy, improve
/// note §7): verbatim scenario-payload fragments appearing in the proposed
/// source but NOT in the baseline. A flag, never a block — adoption stays
/// the audited declassification act.
fn leakage_overlap(
    candidate_source: &str,
    baseline_source: &str,
    scenarios: &[&ScenarioRow],
) -> Vec<String> {
    fn payload_strings(value: &Value, into: &mut Vec<String>) {
        match value {
            Value::String(text) => {
                let trimmed = text.trim();
                if trimmed.len() >= 12 {
                    into.push(trimmed.to_owned());
                }
            }
            Value::Array(items) => {
                for item in items {
                    payload_strings(item, into);
                }
            }
            Value::Object(fields) => {
                for item in fields.values() {
                    payload_strings(item, into);
                }
            }
            _ => {}
        }
    }
    let mut fragments = Vec::new();
    for scenario in scenarios {
        if let Ok(input) = serde_json::from_str::<Value>(&scenario.input_json) {
            payload_strings(&input, &mut fragments);
        }
    }
    fragments.sort();
    fragments.dedup();
    fragments
        .into_iter()
        .filter(|fragment| {
            candidate_source.contains(fragment.as_str())
                && !baseline_source.contains(fragment.as_str())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Evaluation: run a program over scenarios in disposable stores
// ---------------------------------------------------------------------------

/// v1 storage-plane containment: for the rest of this process every
/// workspace-scoped side store (coordination leases/counters/ledgers,
/// backlog items, harness content) resolves into the eval scratch, so a
/// counterfactual run's writes land nowhere near the workspace stores.
/// Shared by `whip improve` and `whip suppose`.
fn contain_side_stores() {
    std::env::set_var(
        "WHIPPLESCRIPT_COORDINATION_STORE",
        eval_scratch_dir().join("coordination.sqlite"),
    );
    std::env::set_var(
        "WHIPPLESCRIPT_ITEMS_STORE",
        eval_scratch_dir().join("items.sqlite"),
    );
    std::env::set_var(
        "WHIPPLESCRIPT_CONTENT_STORE",
        eval_scratch_dir().join("content.sqlite"),
    );
}

fn eval_scratch_dir_path() -> PathBuf {
    std::env::temp_dir().join(format!("whip-improve-{}", std::process::id()))
}

fn eval_scratch_dir() -> PathBuf {
    let dir = eval_scratch_dir_path();
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Reclaims the process's evaluation scratch tree when the command returns.
///
/// `eval_scratch_dir()` hands out paths under one per-process directory.
/// Individual eval/replay stores were unlinked on some paths, but the
/// directory itself, the sqlite `-shm`/`-wal` sidecars, the side stores, and
/// the candidate `.whip` files never were — so every invocation left a tree
/// behind (3,123 of them had accumulated in the tmpfs before this was added).
/// Bind this at the top of any command that evaluates scenarios; `Drop` then
/// covers every return path, including the error ones and a panic unwind.
struct EvalScratchGuard;

impl Drop for EvalScratchGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(eval_scratch_dir_path());
    }
}

/// Regenerate one scenario under `program_path` in a disposable store and
/// score it. The temp store is the v1 storage-plane containment: a
/// counterfactual run's writes land nowhere near the workspace store.
#[allow(clippy::too_many_arguments)]
fn evaluate_scenario(
    program_path: &str,
    root: Option<&str>,
    provider: &str,
    provider_config_paths: &[PathBuf],
    scenario: &ScenarioRow,
    specs: &[GaugeSpec],
    ir: &IrProgram,
    seq: usize,
    prices: &PriceTable,
) -> Result<RunObservation, String> {
    // Mark-pinned scenarios regenerate from the frozen prefix (paired at
    // the cut); a replay failure degrades honestly to input replay with a
    // `replay-fallback` tag rather than sinking the campaign.
    if scenario.cut_sequence.is_some() {
        match replay_scenario(
            program_path,
            root,
            provider,
            provider_config_paths,
            scenario,
            specs,
            ir,
            seq,
            prices,
        ) {
            // Mid-drive errors are HARD: suffix provider work already ran,
            // so a fallback would execute it twice.
            Ok(outcome) => return outcome,
            Err(reason) => {
                eprintln!(
                    "scenario `{}`: prefix replay unavailable ({reason}); falling back to input replay",
                    scenario.name
                );
                let mut observation = input_replay_scenario(
                    program_path,
                    root,
                    provider,
                    provider_config_paths,
                    scenario,
                    specs,
                    ir,
                    seq,
                    prices,
                )?;
                for reading in observation.readings.values_mut() {
                    reading.tags.push("replay-fallback".to_owned());
                }
                return Ok(observation);
            }
        }
    }
    input_replay_scenario(
        program_path,
        root,
        provider,
        provider_config_paths,
        scenario,
        specs,
        ir,
        seq,
        prices,
    )
}

/// Drive one instance to idle inside a disposable store: the shared suffix
/// of both regeneration modes.
#[allow(clippy::too_many_arguments)]
fn drive_to_idle(
    store_path: &Path,
    instance_id: &str,
    program_path: &str,
    root: Option<&str>,
    provider: &str,
    provider_config_paths: &[PathBuf],
    ir: &IrProgram,
    version_guard: Option<&str>,
    side_stores: &crate::SideStorePaths,
) -> Result<(), String> {
    for _ in 0..16 {
        let step_report = crate::step_instance(
            store_path,
            instance_id,
            ir,
            Some(Path::new(program_path)),
            version_guard,
            Some(side_stores),
        )
        .map_err(|error| format!("evaluation step failed: {error:?}"))?;
        let worker_report = crate::run_worker_once(
            store_path,
            &crate::WorkerOptions {
                instance_id: instance_id.to_owned(),
                provider: provider.to_owned(),
                exec_profile: crate::ExecProfile::from_env(),
                script_manifest_path: None,
                package_lock_path: None,
                outcome: crate::FixtureOutcome::default(),
                variant: None,
                program_path: Some(PathBuf::from(program_path)),
                root: root.map(str::to_owned),
                provider_config_paths: provider_config_paths.to_vec(),
                max_child_iterations: 8,
                agent_outcomes: BTreeMap::new(),
                coerce_outputs: BTreeMap::new(),
                virtual_now: None,
                work_unit_root: None,
                side_stores: Some(side_stores.clone()),
            },
        )
        .map_err(|error| format!("evaluation worker failed: {error:?}"))?;
        if crate::drive_pass_idle(&step_report, &worker_report) {
            break;
        }
    }
    Ok(())
}

/// Whole-run regeneration: re-run the workflow on the scenario's frozen
/// input in a disposable store (the v1 default; matched on input).
#[allow(clippy::too_many_arguments)]
fn input_replay_scenario(
    program_path: &str,
    root: Option<&str>,
    provider: &str,
    provider_config_paths: &[PathBuf],
    scenario: &ScenarioRow,
    specs: &[GaugeSpec],
    ir: &IrProgram,
    seq: usize,
    prices: &PriceTable,
) -> Result<RunObservation, String> {
    let side_stores = eval_side_stores(seq);
    let store_path = eval_scratch_dir().join(format!("eval-{seq}.sqlite"));
    let _ = std::fs::remove_file(&store_path);
    let eval_options = CliOptions {
        command: Some("improve".to_owned()),
        args: Vec::new(),
        store_path: store_path.clone(),
        json: true,
        input_json: Some(scenario.input_json.clone()),
    };
    let started = crate::start_workflow_instance(
        program_path,
        root,
        None,
        Some(scenario.input_json.as_str()),
        &eval_options,
    )
    .map_err(|_| {
        format!(
            "failed to start evaluation instance for `{}`",
            scenario.name
        )
    })?;
    drive_to_idle(
        &store_path,
        &started.instance_id,
        program_path,
        root,
        provider,
        provider_config_paths,
        ir,
        None,
        &side_stores,
    )?;
    let store = SqliteStore::open(&store_path)
        .map_err(|error| format!("failed to reopen evaluation store: {error:?}"))?;
    let mut observation = score_instance(
        &store,
        &started.instance_id,
        specs,
        Some(&scenario.name),
        false,
        ir,
        prices,
    );
    // A run that never settled (wedged effect, exhausted drive budget)
    // must not pass for a finished regeneration.
    let incomplete = store
        .list_effects(&started.instance_id)
        .map_err(|error| format!("failed to read effects: {error:?}"))?
        .iter()
        .any(|effect| {
            matches!(effect.status.as_str(), "running" | "queued")
                || effect.status.starts_with("blocked")
        });
    if incomplete {
        for reading in observation.readings.values_mut() {
            reading.tags.push("drive-incomplete".to_owned());
        }
        observation
            .skipped
            .push(("drive".to_owned(), "drive incomplete".to_owned()));
    }
    let _ = std::fs::remove_file(&store_path);
    Ok(observation)
}

/// Prefix regeneration for a mark-pinned scenario: snapshot the source
/// store (`VACUUM INTO` — consistent against live writers), truncate the
/// instance's log to the cut, rebuild the projections (the frozen prefix
/// — settled effects unclaimable, `prefix-replay.maude`), then drive only
/// the suffix under the given program. When the program differs from the
/// recorded version it is activated as a revision (compatibility-
/// checked); the epoch bump means a pre-cut NON-consuming rule can
/// re-derive a distinct effect id and refire — detected post-drive by
/// exact identity and tagged `replay-refire` (the documented
/// cross-revision residual). Errors before the drive begins are safe to
/// fall back from; a mid-drive error is NOT (provider work already
/// executed) and surfaces as a hard failure.
#[allow(clippy::too_many_arguments)]
fn replay_scenario(
    program_path: &str,
    root: Option<&str>,
    provider: &str,
    provider_config_paths: &[PathBuf],
    scenario: &ScenarioRow,
    specs: &[GaugeSpec],
    ir: &IrProgram,
    seq: usize,
    prices: &PriceTable,
) -> Result<Result<RunObservation, String>, String> {
    // Outer Err = pre-drive (fallback-safe); inner Err = mid-drive (hard).
    let cut = scenario
        .cut_sequence
        .ok_or("scenario carries no cut sequence")?;
    let source_store = scenario
        .store_path
        .as_deref()
        .ok_or("scenario carries no source store path")?;
    if !Path::new(source_store).exists() {
        return Err(format!("source store `{source_store}` no longer exists"));
    }
    let side_stores = eval_side_stores(seq);
    let store_path = eval_scratch_dir().join(format!("replay-{seq}.sqlite"));
    let _ = std::fs::remove_file(&store_path);
    // A transactionally-consistent snapshot (VACUUM INTO): a plain file
    // copy of a WAL-mode store loses un-checkpointed commits and can tear
    // against a live writer.
    SqliteStore::open(source_store)
        .map_err(|error| format!("failed to open source store: {error:?}"))?
        .snapshot_to(&store_path)
        .map_err(|error| format!("failed to snapshot source store: {error:?}"))?;
    let mut store = SqliteStore::open(&store_path)
        .map_err(|error| format!("failed to open replay store: {error:?}"))?;
    // A `cancels` consequence of the marked commit lands AFTER the mark
    // event, so the cut would resurrect an effect the recorded run
    // cancelled. Detect it against the un-truncated log and refuse.
    let full_events = store
        .list_events(&scenario.instance_id)
        .map_err(|error| format!("failed to read source events: {error:?}"))?;
    let post_cut_cancels = full_events
        .iter()
        .any(|event| event.sequence > cut && event.event_type == "effect.cancelled");
    if post_cut_cancels {
        return Err(
            "the recorded run cancelled effects after the cut; replay would resurrect them \
             (place the mark after the cancelling consequence settles)"
                .to_owned(),
        );
    }
    store
        .truncate_instance_events_after(&scenario.instance_id, cut)
        .map_err(|error| format!("failed to truncate to the cut: {error:?}"))?;
    store
        .rebuild_projections(&scenario.instance_id)
        .map_err(|error| format!("failed to fold the prefix: {error:?}"))?;
    // A cut that CONTAINS the workflow terminal has no suffix to
    // regenerate — refuse (the mark rode a terminal-committing site).
    let folded = store
        .get_instance(&scenario.instance_id)
        .map_err(|error| format!("failed to read instance: {error:?}"))?
        .ok_or("instance missing from the cloned store")?;
    if matches!(folded.status.as_str(), "completed" | "failed") {
        return Err(
            "the cut contains the workflow terminal; there is no suffix to regenerate".to_owned(),
        );
    }
    // A live activation AFTER the cut stamped the row with a version the
    // truncated log no longer contains; reconcile the pointer to the
    // prefix's own version (replayed activations already re-stamped it if
    // any were in the prefix).
    let prefix_events = store
        .list_events(&scenario.instance_id)
        .map_err(|error| format!("failed to read prefix events: {error:?}"))?;
    let prefix_has_activation = prefix_events
        .iter()
        .any(|event| event.event_type == "workflow.revision_activated");
    if !prefix_has_activation {
        let facts = store
            .list_facts_including_consumed(&scenario.instance_id)
            .map_err(|error| format!("failed to read prefix facts: {error:?}"))?;
        if let Some(fact) = facts.first() {
            if let Some(version) = fact.program_version_id.as_deref() {
                if version != folded.version_id || fact.revision_epoch != folded.revision_epoch {
                    store
                        .set_instance_version(&scenario.instance_id, version, fact.revision_epoch)
                        .map_err(|error| {
                            format!("failed to reconcile the version pointer: {error:?}")
                        })?;
                }
            }
        }
    }
    store
        .reset_instance_to_running(&scenario.instance_id)
        .map_err(|error| format!("failed to reopen the instance: {error:?}"))?;
    // Quiescence at the cut: a mid-flight effect would fold as `running`
    // — unclaimable and never completing — so the suffix would hang.
    // Refuse (mirroring capture_checkpoint) and let the caller fall back.
    let effects = store
        .list_effects(&scenario.instance_id)
        .map_err(|error| format!("failed to read folded effects: {error:?}"))?;
    if effects.iter().any(|effect| effect.status == "running") {
        return Err("the cut lands mid-effect (a run was in flight at the mark)".to_owned());
    }
    // Snapshot the settled prefix effects (ids + exact identity) for
    // refire detection: a NEW effect (id not in the prefix) with an
    // IDENTICAL (rule, kind, input) identity is a pre-cut site
    // re-executing; a loop iteration with new input is not.
    let prefix_ids: BTreeSet<String> = effects
        .iter()
        .map(|effect| effect.effect_id.clone())
        .collect();
    let prefix_triples: BTreeSet<(String, String, String)> = effects
        .iter()
        .map(|effect| {
            (
                effect.created_by_rule.clone(),
                effect.kind.clone(),
                effect.input_json.clone(),
            )
        })
        .collect();
    // Live (unconsumed) fact names at the cut, for the pre-flight refire
    // check below (the store moves into the kernel next).
    let live_fact_names: BTreeSet<String> = store
        .list_facts(&scenario.instance_id)
        .map_err(|error| format!("failed to read live facts: {error:?}"))?
        .into_iter()
        .map(|fact| fact.name)
        .collect();
    let replayed_events = prefix_events.len();
    let instance = store
        .get_instance(&scenario.instance_id)
        .map_err(|error| format!("failed to read instance: {error:?}"))?
        .ok_or("instance missing from the cloned store")?;
    // Register the candidate program; identical content resolves to the
    // recorded version (idempotent per source/ir hash) and drives without
    // activation. A different program is activated as a revision after a
    // compatibility check.
    let source = std::fs::read_to_string(program_path)
        .map_err(|error| format!("failed to read `{program_path}`: {error}"))?;
    let snapshot = ir.to_snapshot();
    let stores = whipplescript_store::native_stores::NativeStores {
        runtime: store,
        coord: open_scratch_coord(seq)?,
        items: open_scratch_items(seq)?,
    };
    let mut kernel = whipplescript_kernel::RuntimeKernel::new(stores);
    let version = kernel
        .create_program_version_for_program(
            whipplescript_kernel::ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &whipplescript_kernel::rule_lowering::stable_hash_hex(&source),
                ir_hash: &whipplescript_kernel::rule_lowering::stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            ir,
        )
        .map_err(|error| format!("failed to register the candidate version: {error:?}"))?;
    if version.version_id != instance.version_id {
        // Pre-flight refire refusal (DR-0038's recorded upgrade):
        // activation bumps the revision epoch, and a pre-cut
        // NON-consuming rule whose trigger facts are still live
        // re-derives its settled effects under fresh ids — refiring
        // provider work the recorded run already paid for. Detect the
        // shape BEFORE any suffix work runs and refuse; the caller
        // degrades to input replay.
        let refire_shaped: Vec<String> = ir
            .rules
            .iter()
            .filter(|rule| {
                effects
                    .iter()
                    .any(|effect| effect.created_by_rule == rule.name)
            })
            .filter(|rule| {
                rule.metadata.fact_reads.iter().any(|read| {
                    read.strip_prefix("schema:").is_some_and(|fact| {
                        live_fact_names.contains(fact)
                            && !rule.metadata.fact_consumes.contains(read)
                    })
                })
            })
            .map(|rule| rule.name.clone())
            .collect();
        if !refire_shaped.is_empty() {
            return Err(format!(
                "candidate activation would refire pre-cut effect site{} `{}` (non-consuming \
                 rule with live trigger facts at the cut); place the mark at a consumption \
                 boundary",
                if refire_shaped.len() == 1 { "" } else { "s" },
                refire_shaped.join("`, `"),
            ));
        }
        use whipplescript_store::RuntimeStore as _;
        let report = kernel
            .store()
            .analyze_revision_compatibility(&scenario.instance_id, &version.version_id)
            .map_err(|error| format!("revision compatibility analysis failed: {error:?}"))?;
        if !report.diagnostics.is_empty() {
            return Err(format!(
                "candidate is not revision-compatible with the frozen prefix: {}",
                report
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        kernel
            .activate_revision(whipplescript_store::RevisionActivation {
                instance_id: &scenario.instance_id,
                from_version_id: &instance.version_id,
                to_version_id: &version.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                rule_carries_json: "[]",
                rule_correspondence_json: "null",
                idempotency_key: Some(&format!("replay-activate-{}", scenario.name)),
            })
            .map_err(|error| format!("failed to activate the candidate: {error:?}"))?;
    }
    drop(kernel);
    // Everything below has executed suffix work: errors are HARD (inner
    // Err) — a fallback here would re-run provider effects.
    Ok(replay_drive_and_score(
        &store_path,
        program_path,
        root,
        provider,
        provider_config_paths,
        scenario,
        specs,
        ir,
        &version.version_id,
        &prefix_ids,
        &prefix_triples,
        replayed_events,
        prices,
        &side_stores,
    ))
}

/// The mid-drive half of replay: drive the suffix, score, tag.
#[allow(clippy::too_many_arguments)]
fn replay_drive_and_score(
    store_path: &Path,
    program_path: &str,
    root: Option<&str>,
    provider: &str,
    provider_config_paths: &[PathBuf],
    scenario: &ScenarioRow,
    specs: &[GaugeSpec],
    ir: &IrProgram,
    version_id: &str,
    prefix_ids: &BTreeSet<String>,
    prefix_triples: &BTreeSet<(String, String, String)>,
    replayed_events: usize,
    prices: &PriceTable,
    side_stores: &crate::SideStorePaths,
) -> Result<RunObservation, String> {
    drive_to_idle(
        store_path,
        &scenario.instance_id,
        program_path,
        root,
        provider,
        provider_config_paths,
        ir,
        Some(version_id),
        side_stores,
    )?;
    let store = SqliteStore::open(store_path)
        .map_err(|error| format!("failed to reopen replay store: {error:?}"))?;
    let mut observation = score_instance(
        &store,
        &scenario.instance_id,
        specs,
        Some(&scenario.name),
        false,
        ir,
        prices,
    );
    // std.latency is unmeasurable under prefix replay: folded prefix runs
    // carry fold-time timestamps, so the prefix's real duration is gone.
    // Remove the reading on BOTH arms (symmetric) rather than report a
    // fabricated improvement.
    if observation.readings.remove("std.latency").is_some() {
        observation.skipped.push((
            "std.latency".to_owned(),
            "unmeasurable under prefix replay (folded prefix timestamps)".to_owned(),
        ));
    }
    let post_effects = store
        .list_effects(&scenario.instance_id)
        .map_err(|error| format!("failed to read effects: {error:?}"))?;
    // Refire detection by exact identity: new id, identical triple.
    let refires = post_effects
        .iter()
        .filter(|effect| !prefix_ids.contains(&effect.effect_id))
        .filter(|effect| {
            prefix_triples.contains(&(
                effect.created_by_rule.clone(),
                effect.kind.clone(),
                effect.input_json.clone(),
            ))
        })
        .count();
    // Completeness: a suffix that never settled (wedged effect, exhausted
    // drive budget) must not pass for a finished regeneration.
    let incomplete = post_effects.iter().any(|effect| {
        matches!(effect.status.as_str(), "running" | "queued")
            || effect.status.starts_with("blocked")
    });
    for reading in observation.readings.values_mut() {
        reading.tags.push("prefix-replay".to_owned());
        if refires > 0 {
            reading.tags.push("replay-refire".to_owned());
        }
        if incomplete {
            reading.tags.push("drive-incomplete".to_owned());
        }
        if ir.sources.iter().any(|source| source.is_clock) {
            // The virtual-clock hazard (research note §9.6): a suffix
            // regenerated later runs under a different clock.
            reading.tags.push("clock-sensitive".to_owned());
        }
    }
    observation.skipped.push((
        "replay".to_owned(),
        format!(
            "prefix-replay: {replayed_events} events replayed, {refires} refires{}",
            if incomplete { ", drive incomplete" } else { "" }
        ),
    ));
    let _ = std::fs::remove_file(store_path);
    Ok(observation)
}

/// Per-evaluation coordination/items scratch: one shared file would let
/// coordination state (counters, breakers, claims) leak between scenarios
/// and between the baseline and candidate arms, breaking the pairing.
/// Scenario-evaluation concurrency: `WHIPPLESCRIPT_EVAL_CONCURRENCY`
/// overrides; the default stays modest (each evaluation drives a full
/// workflow with its own stores and possibly provider turns).
fn eval_concurrency() -> usize {
    if let Ok(value) = std::env::var("WHIPPLESCRIPT_EVAL_CONCURRENCY") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.max(1);
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .min(4)
}

/// Per-evaluation side-store paths, passed EXPLICITLY through the drive
/// (previously env-var redirection, which was process-global and made
/// parallel evaluation impossible). One shared file would let
/// coordination state (counters, breakers, claims) leak between
/// scenarios and between the baseline and candidate arms, breaking the
/// pairing. The content store stays process-level (redirected once by
/// `contain_side_stores`; content-addressed, so sharing is pairing-safe).
fn eval_side_stores(seq: usize) -> crate::SideStorePaths {
    crate::SideStorePaths {
        coordination: eval_scratch_dir().join(format!("coordination-{seq}.sqlite")),
        items: eval_scratch_dir().join(format!("items-{seq}.sqlite")),
    }
}

fn open_scratch_coord(
    seq: usize,
) -> Result<whipplescript_store::coordination::CoordinationStore, String> {
    whipplescript_store::coordination::CoordinationStore::open(
        eval_scratch_dir().join(format!("coordination-{seq}.sqlite")),
    )
    .map_err(|error| format!("failed to open scratch coordination store: {error:?}"))
}

fn open_scratch_items(seq: usize) -> Result<whipplescript_store::items::WorkItemStore, String> {
    whipplescript_store::items::WorkItemStore::open(
        eval_scratch_dir().join(format!("items-{seq}.sqlite")),
    )
    .map_err(|error| format!("failed to open scratch items store: {error:?}"))
}

// ---------------------------------------------------------------------------
// Aggregation, bands, dominance
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct GaugeAggregate {
    scores: Vec<f64>,
    passes: Vec<bool>,
}

impl GaugeAggregate {
    fn n(&self) -> usize {
        self.scores.len()
    }
    fn mean(&self) -> Option<f64> {
        (!self.scores.is_empty())
            .then(|| self.scores.iter().sum::<f64>() / self.scores.len() as f64)
    }
    fn pass_rate(&self) -> Option<f64> {
        (!self.passes.is_empty())
            .then(|| self.passes.iter().filter(|p| **p).count() as f64 / self.passes.len() as f64)
    }
    fn quantile(&self, q: f64) -> Option<f64> {
        if self.scores.is_empty() {
            return None;
        }
        let mut sorted = self.scores.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let index = ((sorted.len() - 1) as f64 * q).round() as usize;
        Some(sorted[index.min(sorted.len() - 1)])
    }
    /// The operating point compared by the dominance check: pass rate when
    /// the gauge is chance-shaped, mean score otherwise.
    fn operating_point(&self) -> Option<f64> {
        self.pass_rate().or_else(|| self.mean())
    }
}

fn aggregate(observations: &[RunObservation], gauge: &str) -> GaugeAggregate {
    let mut aggregate = GaugeAggregate::default();
    for observation in observations {
        if let Some(reading) = observation.readings.get(gauge) {
            aggregate.scores.push(reading.score);
            if let Some(passed) = reading.passed {
                aggregate.passes.push(passed);
            }
        }
    }
    aggregate
}

fn bar_stat(aggregate: &GaugeAggregate, bar: &BarSpec) -> Option<f64> {
    if bar.chance_field.is_some() {
        return aggregate.pass_rate();
    }
    match bar.stat.as_deref() {
        Some("mean") | None => aggregate.mean(),
        Some(stat) => {
            let quantile = stat.strip_prefix('p')?.parse::<f64>().ok()? / 100.0;
            aggregate.quantile(quantile)
        }
    }
}

fn bar_met(aggregate: &GaugeAggregate, bar: &BarSpec) -> Option<bool> {
    let value = bar_stat(aggregate, bar)?;
    Some(if bar.ge {
        value >= bar.threshold
    } else {
        value <= bar.threshold
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delta {
    Better,
    InBand,
    Worse,
    Unmeasured,
}

/// The indifference band around the baseline operating point: the gauge's
/// noise floor by default (a pooled-SE minimal detectable effect), relative
/// bands for resource gauges (their noise floor degenerates toward zero),
/// `--within` / campaign `guard` overrides in percent of baseline.
fn indifference_band(
    spec: &GaugeSpec,
    base: &GaugeAggregate,
    cand: &GaugeAggregate,
    within_percent: Option<f64>,
    baseline_point: f64,
) -> f64 {
    if let Some(percent) = within_percent {
        return (baseline_point.abs() * percent / 100.0).max(f64::EPSILON);
    }
    if spec.builtin {
        return (baseline_point.abs() * RESOURCE_BAND_PERCENT / 100.0).max(f64::EPSILON);
    }
    // Noise floor: 1.96 * pooled standard error over the compared samples.
    let se = |aggregate: &GaugeAggregate| -> f64 {
        let n = aggregate.n().max(1) as f64;
        if let Some(rate) = aggregate.pass_rate() {
            (rate * (1.0 - rate) / n).sqrt()
        } else if let Some(mean) = aggregate.mean() {
            let variance = aggregate
                .scores
                .iter()
                .map(|score| (score - mean).powi(2))
                .sum::<f64>()
                / n;
            (variance / n).sqrt()
        } else {
            0.0
        }
    };
    let pooled = (se(base).powi(2) + se(cand).powi(2)).sqrt();
    (1.96 * pooled).max(QUALITY_BAND_FLOOR)
}

fn delta_verdict(
    spec: &GaugeSpec,
    base: &GaugeAggregate,
    cand: &GaugeAggregate,
    within_percent: Option<f64>,
) -> (Delta, f64, f64) {
    let (Some(base_point), Some(cand_point)) = (base.operating_point(), cand.operating_point())
    else {
        return (Delta::Unmeasured, 0.0, 0.0);
    };
    let band = indifference_band(spec, base, cand, within_percent, base_point);
    let signed = if spec.direction_up {
        cand_point - base_point
    } else {
        base_point - cand_point
    };
    let verdict = if signed > band {
        Delta::Better
    } else if signed < -band {
        Delta::Worse
    } else {
        Delta::InBand
    };
    (verdict, cand_point - base_point, band)
}

#[derive(Clone, Debug)]
struct GaugeVerdictLine {
    gauge: String,
    role: &'static str,
    delta: Delta,
    baseline: Option<f64>,
    candidate: Option<f64>,
    band: f64,
    bar_met: Option<bool>,
    reach_met: Option<bool>,
    /// The gauge's better-direction, carried onto the card so answered
    /// tradeoffs are self-contained precedents.
    direction_up: bool,
    /// The belief-update readout (DR-0041) over the comparable pairs:
    /// paired sign test when every pair carries bar verdicts, Student-t
    /// on paired deltas otherwise. None below the family's floor.
    p_better: Option<f64>,
}

#[derive(Clone, Debug)]
struct CandidateVerdict {
    lines: Vec<GaugeVerdictLine>,
    proposable: bool,
    tradeoff: bool,
    reasons: Vec<String>,
}

/// A baseline/candidate observation pair is comparable only when both
/// arms measured the same estimand: same regeneration mode (a prefix
/// replay against a whole-run fallback compares different quantities),
/// and neither arm poisoned by a refire or an unsettled drive. Dropping
/// the pair keeps the verdict honest; the card says how many were
/// dropped.
fn observation_pair_comparable(a: &RunObservation, b: &RunObservation) -> bool {
    fn flags(observation: &RunObservation) -> (bool, bool, bool, bool) {
        let mut prefix = false;
        let mut fallback = false;
        let mut refire = false;
        let mut incomplete = false;
        for reading in observation.readings.values() {
            for tag in &reading.tags {
                match tag.as_str() {
                    "prefix-replay" => prefix = true,
                    "replay-fallback" => fallback = true,
                    "replay-refire" => refire = true,
                    "drive-incomplete" => incomplete = true,
                    _ => {}
                }
            }
        }
        (prefix, fallback, refire, incomplete)
    }
    let (a_prefix, a_fallback, a_refire, a_incomplete) = flags(a);
    let (b_prefix, b_fallback, b_refire, b_incomplete) = flags(b);
    a_prefix == b_prefix
        && a_fallback == b_fallback
        && !a_refire
        && !b_refire
        && !a_incomplete
        && !b_incomplete
}

/// Retain only comparable pairs (index-aligned by scenario order),
/// returning the filtered arms and the number of dropped pairs.
fn comparable_pairs(
    base: &[RunObservation],
    cand: &[RunObservation],
) -> (Vec<RunObservation>, Vec<RunObservation>, usize) {
    let mut base_kept = Vec::new();
    let mut cand_kept = Vec::new();
    let mut dropped = 0usize;
    for (a, b) in base.iter().zip(cand.iter()) {
        if observation_pair_comparable(a, b) {
            base_kept.push(a.clone());
            cand_kept.push(b.clone());
        } else {
            dropped += 1;
        }
    }
    (base_kept, cand_kept, dropped)
}

/// The dominance invariant, exactly as modeled: accept only if at least one
/// ascend gauge improved, no ascend gauge regressed, every guarded gauge
/// held within its band, every declared bar is met, and sacrificed gauges
/// move freely (the evidence card says so). Reach targets ratchet: a target
/// the BASELINE already met is a hard bound the candidate may not drop
/// below; an unmet target never blocks genuine progress toward it. Repair
/// mode proposes only a candidate that RESTORES a bar the baseline
/// violated, without moving anything else beyond band.
fn dominance_verdict(
    specs: &[GaugeSpec],
    campaign: &CampaignSpec,
    base: &[RunObservation],
    cand: &[RunObservation],
) -> CandidateVerdict {
    let ascend_names: BTreeMap<&str, Option<&ReachTarget>> = campaign
        .ascend
        .iter()
        .map(|(name, reach)| (name.as_str(), reach.as_ref()))
        .collect();
    let sacrificed: BTreeSet<&str> = campaign.sacrifice.iter().map(String::as_str).collect();
    let mut lines = Vec::new();
    let mut reasons = Vec::new();
    let mut focus_up = false;
    let mut focus_down = false;
    let mut guard_broken = false;
    let mut bar_violated = false;
    let mut bar_restored = false;
    for spec in specs {
        let base_aggregate = aggregate(base, &spec.name);
        let cand_aggregate = aggregate(cand, &spec.name);
        if base_aggregate.n() == 0 && cand_aggregate.n() == 0 {
            continue;
        }
        let within = campaign.within_percent.get(&spec.name).copied();
        let (delta, _, band) = delta_verdict(spec, &base_aggregate, &cand_aggregate, within);
        let bar_status = spec
            .bar
            .as_ref()
            .and_then(|bar| bar_met(&cand_aggregate, bar));
        let baseline_bar_status = spec
            .bar
            .as_ref()
            .and_then(|bar| bar_met(&base_aggregate, bar));
        if bar_status == Some(false) {
            bar_violated = true;
            reasons.push(format!("`{}` violates its declared bar", spec.name));
        }
        if baseline_bar_status == Some(false) && bar_status == Some(true) {
            bar_restored = true;
        }
        let reach = ascend_names.get(spec.name.as_str()).copied().flatten();
        let reach_met = reach.and_then(|reach| {
            cand_aggregate.operating_point().map(|point| {
                if reach.ge {
                    point >= reach.threshold
                } else {
                    point <= reach.threshold
                }
            })
        });
        let role;
        if ascend_names.contains_key(spec.name.as_str()) {
            role = "ascend";
            match delta {
                Delta::Better => focus_up = true,
                Delta::Worse => {
                    focus_down = true;
                    reasons.push(format!("`{}` regressed (its own focus)", spec.name));
                }
                _ => {}
            }
            // Ratchet: a reach target the baseline had already achieved is
            // a hard bound; dropping back below it is a refusal even if the
            // movement sits inside the band.
            if let Some(reach) = reach {
                let baseline_met = base_aggregate.operating_point().map(|point| {
                    if reach.ge {
                        point >= reach.threshold
                    } else {
                        point <= reach.threshold
                    }
                });
                if baseline_met == Some(true) && reach_met == Some(false) {
                    bar_violated = true;
                    reasons.push(format!(
                        "`{}` dropped below its achieved reach target (ratchet)",
                        spec.name
                    ));
                }
            }
        } else if sacrificed.contains(spec.name.as_str()) {
            role = "sacrifice";
        } else {
            role = "guard";
            // Stage-ratchet floor (improve note §3): a completed earlier
            // stage's achieved level is a hard bound for later stages —
            // regression past it refuses even inside the band.
            if let Some((ge, floor)) = campaign.floors.get(&spec.name) {
                if let Some(point) = cand_aggregate.operating_point() {
                    let held = if *ge {
                        point >= *floor
                    } else {
                        point <= *floor
                    };
                    if !held {
                        bar_violated = true;
                        reasons.push(format!(
                            "`{}` fell past its stage-ratchet floor (achieved by a completed `then` stage)",
                            spec.name
                        ));
                    }
                }
            }
            if delta == Delta::Worse {
                guard_broken = true;
                reasons.push(format!(
                    "`{}` regressed beyond its indifference band and was not sacrificed",
                    spec.name
                ));
            }
            // Fail closed: a guarded gauge that was measured at baseline but
            // became unmeasurable on the candidate cannot certify
            // non-regression — refuse rather than silently pass.
            if delta == Delta::Unmeasured && base_aggregate.n() > 0 && cand_aggregate.n() == 0 {
                guard_broken = true;
                reasons.push(format!(
                    "`{}` became unmeasurable on the candidate (guarded gauges fail closed)",
                    spec.name
                ));
            }
        }
        // The belief-update readout over the comparable pairs: family A
        // (paired sign test) when every pair carries bar verdicts,
        // family B (Student-t on paired deltas) otherwise.
        let verdict_pairs: Vec<(bool, bool)> = base
            .iter()
            .zip(cand.iter())
            .filter_map(|(b, c)| {
                let control = b.readings.get(&spec.name)?.passed?;
                let treatment = c.readings.get(&spec.name)?.passed?;
                Some((control, treatment))
            })
            .collect();
        let score_deltas: Vec<f64> = base
            .iter()
            .zip(cand.iter())
            .filter_map(|(b, c)| {
                Some(c.readings.get(&spec.name)?.score - b.readings.get(&spec.name)?.score)
            })
            .collect();
        let p_better = if !verdict_pairs.is_empty() && verdict_pairs.len() == score_deltas.len() {
            p_better_sign(&verdict_pairs)
        } else {
            p_better_t(&score_deltas, spec.direction_up)
        };
        lines.push(GaugeVerdictLine {
            gauge: spec.name.clone(),
            role,
            delta,
            baseline: base_aggregate.operating_point(),
            candidate: cand_aggregate.operating_point(),
            band,
            bar_met: bar_status,
            reach_met,
            direction_up: spec.direction_up,
            p_better,
        });
    }
    // Repair mode: proposable iff a bar the BASELINE violated is restored
    // and nothing moved beyond band — a no-op on a healthy program repairs
    // nothing and is refused.
    let proposable = if campaign.repair {
        bar_restored && !bar_violated && !guard_broken
    } else {
        focus_up && !focus_down && !guard_broken && !bar_violated
    };
    let tradeoff = focus_up && guard_broken && !bar_violated && !focus_down;
    CandidateVerdict {
        lines,
        proposable,
        tradeoff,
        reasons,
    }
}

// ---------------------------------------------------------------------------
// Tradeoff precedents (the local utility model, settled 2026-07-11)
// ---------------------------------------------------------------------------

/// One gauge's record inside an answered-tradeoff precedent.
#[derive(Clone, Debug)]
struct PrecedentGauge {
    baseline: f64,
    candidate: f64,
    band: f64,
    direction_up: bool,
}

impl PrecedentGauge {
    fn adjusted_delta(&self) -> f64 {
        if self.direction_up {
            self.candidate - self.baseline
        } else {
            self.baseline - self.candidate
        }
    }
}

/// An answered tradeoff: a human speech act carried in the campaign
/// record, the only source of auto-resolution authority
/// (`improve-precedent.maude`).
#[derive(Clone, Debug)]
struct Precedent {
    campaign: String,
    candidate: String,
    accepted: bool,
    answered_at: String,
    gauges: BTreeMap<String, PrecedentGauge>,
}

impl Precedent {
    fn citation(&self) -> String {
        format!(
            "{}:{} ({} {})",
            self.campaign,
            self.candidate,
            if self.accepted {
                "accepted"
            } else {
                "rejected"
            },
            self.answered_at
        )
    }
}

/// Workspace-wide precedent fold: latest answer per (campaign, candidate)
/// wins; a revocation removes it entirely.
fn load_precedents(store: &ImproveStore) -> Result<Vec<Precedent>, String> {
    let answered = store
        .list_events_of_type("preference.answered")
        .map_err(|error| format!("failed to load precedents: {error:?}"))?;
    let revoked = store
        .list_events_of_type("preference.revoked")
        .map_err(|error| format!("failed to load revocations: {error:?}"))?;
    let mut by_key: BTreeMap<(String, String), Precedent> = BTreeMap::new();
    for event in answered {
        let Some(candidate) = event.payload["candidate"].as_str() else {
            continue;
        };
        let mut gauges = BTreeMap::new();
        for line in event.payload["gauges"].as_array().into_iter().flatten() {
            let (Some(gauge), Some(baseline), Some(cand), Some(band)) = (
                line["gauge"].as_str(),
                line["baseline"].as_f64(),
                line["candidate"].as_f64(),
                line["band"].as_f64(),
            ) else {
                continue;
            };
            gauges.insert(
                gauge.to_owned(),
                PrecedentGauge {
                    baseline,
                    candidate: cand,
                    band,
                    direction_up: line["direction"].as_str() != Some("down"),
                },
            );
        }
        by_key.insert(
            (event.campaign_id.clone(), candidate.to_owned()),
            Precedent {
                campaign: event.campaign_id.clone(),
                candidate: candidate.to_owned(),
                accepted: event.payload["verdict"].as_str() == Some("accepted"),
                answered_at: event.created_at.clone(),
                gauges,
            },
        );
    }
    for event in revoked {
        if let Some(candidate) = event.payload["candidate"].as_str() {
            by_key.remove(&(event.campaign_id.clone(), candidate.to_owned()));
        }
    }
    Ok(by_key.into_values().collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PrecedentResolution {
    AutoAccept(String),
    AutoReject(String),
}

/// A precedent applies only while the current baseline sits within its
/// answer-time band neighborhood on EVERY shared gauge, and only when the
/// gauge sets line up exactly — a tradeoff over gauges the precedent never
/// covered is a new decision. Fail closed on anything unmeasured.
fn precedent_applies(precedent: &Precedent, lines: &[GaugeVerdictLine]) -> bool {
    let comparable: Vec<&GaugeVerdictLine> = lines
        .iter()
        .filter(|line| line.role != "sacrifice")
        .collect();
    if comparable.len() != precedent.gauges.len() {
        return false;
    }
    comparable.iter().all(|line| {
        let Some(prec) = precedent.gauges.get(&line.gauge) else {
            return false;
        };
        let Some(baseline) = line.baseline else {
            return false;
        };
        line.candidate.is_some()
            && line.direction_up == prec.direction_up
            && (baseline - prec.baseline).abs() <= prec.band
    })
}

fn line_adjusted_delta(line: &GaugeVerdictLine) -> Option<f64> {
    let (baseline, candidate) = (line.baseline?, line.candidate?);
    Some(if line.direction_up {
        candidate - baseline
    } else {
        baseline - candidate
    })
}

/// Monotone precedent dominance — the ONLY auto-resolution authority
/// (default-on): auto-accept iff the candidate is at least an accepted
/// precedent's adjusted delta on every gauge; auto-reject iff at most a
/// rejected precedent's on every gauge; a conflict (both apply) asks.
fn precedent_resolution(
    precedents: &[Precedent],
    lines: &[GaugeVerdictLine],
) -> Option<PrecedentResolution> {
    const EPS: f64 = 1e-9;
    let dominance = |precedent: &Precedent, accept_side: bool| -> bool {
        lines
            .iter()
            .filter(|line| line.role != "sacrifice")
            .all(|line| {
                let (Some(delta), Some(prec)) =
                    (line_adjusted_delta(line), precedent.gauges.get(&line.gauge))
                else {
                    return false;
                };
                if accept_side {
                    delta >= prec.adjusted_delta() - EPS
                } else {
                    delta <= prec.adjusted_delta() + EPS
                }
            })
    };
    let accept = precedents
        .iter()
        .filter(|precedent| precedent.accepted && precedent_applies(precedent, lines))
        .find(|precedent| dominance(precedent, true));
    let reject = precedents
        .iter()
        .filter(|precedent| !precedent.accepted && precedent_applies(precedent, lines))
        .find(|precedent| dominance(precedent, false));
    match (accept, reject) {
        // Inconsistent precedents: no authority, ask.
        (Some(_), Some(_)) => None,
        (Some(precedent), None) => Some(PrecedentResolution::AutoAccept(precedent.citation())),
        (None, Some(precedent)) => Some(PrecedentResolution::AutoReject(precedent.citation())),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Holdout sealing
// ---------------------------------------------------------------------------

fn seal_scenarios<'a>(
    campaign_id: &str,
    scenarios: &'a [ScenarioRow],
) -> (Vec<&'a ScenarioRow>, Vec<&'a ScenarioRow>, bool) {
    let eligible: Vec<&ScenarioRow> = scenarios.iter().filter(|s| !s.retired).collect();
    if eligible.len() < MIN_SCENARIOS_FOR_SEALING {
        return (eligible, Vec::new(), false);
    }
    let sealed_count = ((eligible.len() as f64 * SEALED_FRACTION).ceil() as usize)
        .max(SEALED_FLOOR)
        .min(eligible.len().saturating_sub(2));
    let mut ranked: Vec<(&ScenarioRow, String)> = eligible
        .iter()
        .map(|scenario| {
            // Sorting on this hex decides which scenarios are held out, so the
            // encoding is part of the selection: a different one reshuffles the
            // sealed set of every existing campaign. `sha256_hex` owns it, and
            // pins it to a published vector.
            (
                *scenario,
                sha256_hex(&format!("{campaign_id}|{}", scenario.name)),
            )
        })
        .collect();
    ranked.sort_by(|a, b| a.1.cmp(&b.1));
    let sealed: Vec<&ScenarioRow> = ranked
        .iter()
        .take(sealed_count)
        .map(|(scenario, _)| *scenario)
        .collect();
    let sealed_names: BTreeSet<&str> = sealed.iter().map(|s| s.name.as_str()).collect();
    let open: Vec<&ScenarioRow> = eligible
        .into_iter()
        .filter(|scenario| !sealed_names.contains(scenario.name.as_str()))
        .collect();
    (open, sealed, true)
}

// ---------------------------------------------------------------------------
// The proposer
// ---------------------------------------------------------------------------

trait Proposer {
    fn propose(&mut self, reflection: &str) -> Result<Option<Proposal>, String>;
    fn name(&self) -> &'static str;
}

struct Proposal {
    source: String,
    rationale: String,
    /// Provider token usage of the proposing turn (0 for fixture), recorded
    /// as a `campaign.spend` event.
    tokens: i64,
    /// The turn's provider/model/split, when the proposer knows it: what
    /// record-time pricing consumes. `None` prices as `unpriced`.
    usage: Option<TurnUsage>,
}

/// Deterministic test/dev proposer: colon-separated candidate source paths
/// in WHIPPLESCRIPT_IMPROVE_PROPOSALS, consumed one per round.
struct FixtureProposer {
    remaining: Vec<String>,
}

impl FixtureProposer {
    fn from_env() -> Self {
        let remaining = std::env::var("WHIPPLESCRIPT_IMPROVE_PROPOSALS")
            .unwrap_or_default()
            .split(':')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect();
        Self { remaining }
    }
}

impl Proposer for FixtureProposer {
    fn propose(&mut self, _reflection: &str) -> Result<Option<Proposal>, String> {
        if self.remaining.is_empty() {
            return Ok(None);
        }
        let path = self.remaining.remove(0);
        let source = std::fs::read_to_string(&path)
            .map_err(|error| format!("fixture proposal `{path}`: {error}"))?;
        // Test lever mirroring WHIPPLESCRIPT_IMPROVE_PROPOSALS: a synthetic
        // `provider/model/input/output` usage so priced-spend paths (cap,
        // park, resume) are exercisable without a live provider.
        let usage = std::env::var("WHIPPLESCRIPT_IMPROVE_PROPOSAL_USAGE")
            .ok()
            .and_then(|raw| {
                let parts: Vec<&str> = raw.split('/').collect();
                match parts.as_slice() {
                    [provider, model, input, output] => Some(TurnUsage {
                        provider: (*provider).to_owned(),
                        model: (*model).to_owned(),
                        input_tokens: input.parse().ok()?,
                        output_tokens: output.parse().ok()?,
                        cache_read_tokens: None,
                        cache_write_tokens: None,
                        total_tokens: input.parse::<i64>().ok()? + output.parse::<i64>().ok()?,
                    }),
                    _ => None,
                }
            });
        Ok(Some(Proposal {
            source,
            rationale: format!("fixture proposal from {path}"),
            tokens: usage.as_ref().map_or(0, |usage| usage.total_tokens),
            usage,
        }))
    }
    fn name(&self) -> &'static str {
        "fixture"
    }
}

/// The reflective proposer: one structured native-coerce turn fed the
/// reflection material (never sealed traces — the caller builds the
/// reflection holdout-blind). Propose-don't-apply: its output is a
/// candidate, never a write.
struct NativeProposer;

impl Proposer for NativeProposer {
    fn propose(&mut self, reflection: &str) -> Result<Option<Proposal>, String> {
        let schema = json!({
            "type": "object",
            "properties": {
                "rationale": {"type": "string"},
                "source": {"type": "string"},
            },
            "required": ["rationale", "source"],
            "additionalProperties": false,
        });
        let (value, usage) = native_coerce_turn(
            "the native proposer",
            reflection.to_owned(),
            schema,
            "ImproveProposal",
            "improve-proposer",
            false,
        )
        .map_err(|error| format!("{error}, or use --proposer fixture"))?;
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .ok_or("proposer returned no source")?
            .to_owned();
        let rationale = value
            .get("rationale")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        Ok(Some(Proposal {
            source,
            rationale,
            tokens: usage.total_tokens,
            usage: Some(usage),
        }))
    }
    fn name(&self) -> &'static str {
        "native"
    }
}

/// The reflection material: program source, the campaign partition, and
/// open-scenario evidence. Sealed scenarios appear as AGGREGATE pass rates
/// only — never traces, contents, or judge rationales
/// (`improve-holdout.maude`).
#[allow(clippy::too_many_arguments)]
fn build_reflection(
    source: &str,
    campaign: &CampaignSpec,
    specs: &[GaugeSpec],
    baseline_open: &[RunObservation],
    baseline_sealed: &[RunObservation],
    open_scenarios: &[&ScenarioRow],
    prior_failures: &[String],
    sealed_engaged: bool,
) -> String {
    let mut reflection = String::new();
    reflection.push_str(
        "You are the improve proposer for a WhippleScript workflow. Propose ONE \
         targeted revision of the program below. Return the COMPLETE revised \
         program source. Improve the ascend gauges without regressing any \
         guarded gauge; declared bars are hard constraints.\n\n",
    );
    reflection.push_str(&format!("## Campaign\n{}\n\n", campaign.to_json()));
    reflection.push_str("## Gauge evidence (open scenarios)\n");
    for spec in specs {
        let aggregate = aggregate(baseline_open, &spec.name);
        if aggregate.n() == 0 {
            continue;
        }
        reflection.push_str(&format!(
            "- {}: operating point {:.4} over N={}\n",
            spec.name,
            aggregate.operating_point().unwrap_or(0.0),
            aggregate.n()
        ));
    }
    if sealed_engaged {
        let mut sealed_line =
            String::from("\n## Sealed holdout (aggregates only; traces withheld)\n");
        for spec in specs {
            let aggregate = aggregate(baseline_sealed, &spec.name);
            if let Some(rate) = aggregate.pass_rate() {
                sealed_line.push_str(&format!(
                    "- {}: pass rate {:.4} over N={}\n",
                    spec.name,
                    rate,
                    aggregate.n()
                ));
            }
        }
        reflection.push_str(&sealed_line);
    }
    if campaign.redacted_view {
        // Campaign-attached stratified reflection: aggregates only. No
        // scenario names, no inputs, no traces — the proposer works from
        // counts (`proposer:redacted-view` rides the campaign's evidence).
        reflection.push_str("\n## Failing open scenarios (redacted view: aggregates only)\n");
        for (index, observation) in baseline_open.iter().enumerate() {
            let failing: Vec<&str> = observation
                .readings
                .iter()
                .filter(|(_, reading)| reading.passed == Some(false))
                .map(|(gauge, _)| gauge.as_str())
                .collect();
            if !failing.is_empty() {
                reflection.push_str(&format!(
                    "- scenario #{} fails: {}\n",
                    index + 1,
                    failing.join(", ")
                ));
            }
        }
    } else {
        reflection.push_str("\n## Worst open scenarios\n");
        for observation in baseline_open {
            let failing: Vec<&str> = observation
                .readings
                .iter()
                .filter(|(_, reading)| reading.passed == Some(false))
                .map(|(gauge, _)| gauge.as_str())
                .collect();
            if let (Some(scenario), false) = (&observation.scenario, failing.is_empty()) {
                reflection.push_str(&format!(
                    "- scenario `{scenario}` fails: {}\n",
                    failing.join(", ")
                ));
                if let Some(row) = open_scenarios
                    .iter()
                    .find(|row| Some(&row.name) == observation.scenario.as_ref())
                {
                    reflection.push_str(&format!("  input: {}\n", row.input_json));
                }
            }
        }
    }
    if !prior_failures.is_empty() {
        reflection.push_str("\n## Prior candidates that were refused\n");
        for failure in prior_failures {
            reflection.push_str(&format!("- {failure}\n"));
        }
    }
    reflection.push_str(&format!("\n## Program\n```whip\n{source}\n```\n"));
    reflection
}

// ---------------------------------------------------------------------------
// Evidence recording
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn record_observations(
    store: &mut ImproveStore,
    observations: &[RunObservation],
    specs: &[GaugeSpec],
    execution_mode: &str,
    hash: &str,
    campaign_id: Option<&str>,
    candidate_id: Option<&str>,
    extra_tags: &[String],
) {
    for observation in observations {
        for (gauge, reading) in &observation.readings {
            let scorer = specs
                .iter()
                .find(|spec| &spec.name == gauge)
                .map(|spec| scorer_label(&spec.judge))
                .unwrap_or_else(|| "unknown".to_owned());
            let mut tags = reading.tags.clone();
            tags.extend(extra_tags.iter().cloned());
            let _ = store.record_evidence(NewEvidence {
                gauge,
                score: reading.score,
                passed: reading.passed,
                instance_id: None,
                program_hash: Some(hash),
                branch_ref: None,
                execution_mode,
                scorer: &scorer,
                scenario: observation.scenario.as_deref(),
                campaign_id,
                candidate_id,
                cost_micros: 0,
                tags,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// whip improve
// ---------------------------------------------------------------------------

fn resolve_program_path(explicit: Option<String>) -> Result<String, String> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(".")
        .map_err(|error| format!("failed to scan for a program: {error}"))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "whip"))
        .collect();
    candidates.sort();
    match candidates.len() {
        0 => Err("no .whip program found; pass --program <path>".to_owned()),
        1 => Ok(candidates.remove(0).to_string_lossy().into_owned()),
        _ => Err(format!(
            "multiple .whip programs found ({}); pass --program <path>",
            candidates
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(crate) fn improve_command(options: &CliOptions) -> ExitCode {
    let _scratch = EvalScratchGuard;
    match run_improve(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// Look up a campaign the operator asked to resume: it must exist and be
/// parked. Returns the folded summary and the campaign.opened payload.
fn resumable_campaign(
    store: &ImproveStore,
    campaign_id: &str,
) -> Result<(CampaignSummary, Value), String> {
    let summary = store
        .list_campaigns()
        .map_err(|error| format!("failed to read campaigns: {error:?}"))?
        .into_iter()
        .find(|campaign| campaign.campaign_id == campaign_id)
        .ok_or_else(|| format!("unknown campaign `{campaign_id}`"))?;
    if summary.status != "parked" {
        return Err(format!(
            "campaign `{campaign_id}` is not parked (status: {}); --resume continues parked \
             campaigns only",
            summary.status
        ));
    }
    let payload = summary.spec.clone();
    Ok((summary, payload))
}

fn run_improve(options: &CliOptions) -> Result<ExitCode, String> {
    // Compile first (gauge declarations live in the program).
    let (probe_path, probe_root) = {
        // Peek --program/--root/--resume before full arg parsing so
        // declared campaigns can inform positional-arg interpretation, a
        // multi-workflow program compiles under its root, and a resumed
        // campaign resolves its own recorded program.
        let mut path = None;
        let mut probe_root = None;
        let mut resume_probe = None;
        let mut iter = options.args.iter();
        while let Some(arg) = iter.next() {
            if arg == "--program" {
                path = iter.next().cloned();
            } else if arg == "--root" {
                probe_root = iter.next().cloned();
            } else if arg == "--resume" {
                resume_probe = iter.next().cloned();
            }
        }
        if path.is_none() {
            if let Some(campaign_id) = &resume_probe {
                path = Some(
                    resumable_campaign(&open_improve_store()?, campaign_id)?
                        .1
                        .get("program")
                        .and_then(Value::as_str)
                        .ok_or("malformed campaign record: no program path")?
                        .to_owned(),
                );
            }
        }
        (resolve_program_path(path)?, probe_root)
    };
    let (source, ir) = crate::compile_source_path_with_root(&probe_path, probe_root.as_deref())
        .map_err(|error| {
            format!(
                "`{probe_path}` does not compile: {}",
                compile_failure_summary(&error)
            )
        })?;
    let declared = declared_campaign_specs(&ir)?;
    let args = parse_improve_args(&options.args, &declared)?;
    let program_path = probe_path;
    let specs = collect_gauge_specs(&ir);
    if specs.iter().all(|spec| spec.builtin) && !args.spec.repair {
        return Err(
            "no gauges declared; declare `gauge <name> { judge via ... }` before improving"
                .to_owned(),
        );
    }
    let baseline_hash = program_hash(&source);
    let mut store = open_improve_store()?;
    let scenarios = store
        .list_scenarios()
        .map_err(|error| format!("failed to list scenarios: {error:?}"))?;
    if scenarios.is_empty() {
        return Err(
            "no pinned scenarios; pin at least one run first (`whip pin <instance> --as <name>`)"
                .to_owned(),
        );
    }
    let prices = PriceTable::load(&args.provider_config_paths)?;
    let (campaign_id, candidate_seq_start, campaign_spec, proposer_name) =
        if let Some(resume_id) = &args.resume {
            let (summary, payload) = resumable_campaign(&store, resume_id)?;
            let recorded_hash = payload
                .get("baseline_hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // The same guard adoption uses: a campaign's verdicts are
            // paired against ITS baseline; a drifted program needs a new
            // campaign, not a silently re-based old one.
            if recorded_hash != baseline_hash {
                return Err(format!(
                    "the program changed since campaign `{resume_id}` parked (recorded baseline \
                     {}…, current {}…); open a new campaign",
                    &recorded_hash[..12.min(recorded_hash.len())],
                    &baseline_hash[..12]
                ));
            }
            let mut spec = campaign_spec_from_json(payload.get("spec").unwrap_or(&Value::Null))?;
            // The allowance is per invocation (decision 2026-07-14): an
            // unchanged cap buys a fresh round of proposals; --spend-cap
            // refines it.
            spec.spend_cap_micros = args.spec.spend_cap_micros.or(spec.spend_cap_micros);
            let proposer_name = if options.args.iter().any(|arg| arg == "--proposer") {
                args.proposer.clone()
            } else {
                payload
                    .get("proposer")
                    .and_then(Value::as_str)
                    .unwrap_or(&args.proposer)
                    .to_owned()
            };
            store
                .append_campaign_event(
                    resume_id,
                    "campaign.resumed",
                    &json!({"cumulative_spent_micros": summary.spent_micros}),
                )
                .map_err(|error| format!("failed to record resume: {error:?}"))?;
            (
                resume_id.clone(),
                summary.candidates.max(0) as usize,
                spec,
                proposer_name,
            )
        } else {
            let campaign_id = store
                .open_campaign(&json!({
                    "spec": args.spec.to_json(),
                    "program": program_path,
                    "baseline_hash": baseline_hash,
                    "proposer": args.proposer,
                }))
                .map_err(|error| format!("failed to open campaign: {error:?}"))?;
            (campaign_id, 0, args.spec.clone(), args.proposer.clone())
        };
    for (name, _) in &campaign_spec.ascend {
        if !specs.iter().any(|spec| &spec.name == name) {
            return Err(format!(
                "unknown gauge `{name}` (declared gauges: {})",
                specs
                    .iter()
                    .map(|spec| spec.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let (open, sealed, sealing_engaged) = seal_scenarios(&campaign_id, &scenarios);
    let unheld_out = !sealing_engaged;
    contain_side_stores();
    let mut campaign_tags: Vec<String> = Vec::new();
    if unheld_out {
        campaign_tags.push("unheld-out".to_owned());
    }
    if args.provider == "fixture" {
        // Fixture-evaluated evidence must never pass for model behavior.
        campaign_tags.push("fixture-provider".to_owned());
    }
    if args.spec.redacted_view {
        campaign_tags.push("proposer:redacted-view".to_owned());
    }
    let outcome =
        (|store: &mut ImproveStore| -> Result<(Vec<Value>, bool, usize, usize, bool), String> {
            store
                .append_campaign_event(
                    &campaign_id,
                    "campaign.sealed",
                    &json!({
                        "sealed": sealed.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                        "open": open.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                        "unheld_out": unheld_out,
                    }),
                )
                .map_err(|error| format!("failed to record sealing: {error:?}"))?;

            // Baseline evaluation (paired regeneration: same scenarios,
            // both arms). Evaluations run concurrently over a bounded
            // pool: each is fully contained (its own run store + explicit
            // side stores), the only shared state is read-only refs and
            // the mutexed compile cache, and results keep input order
            // (the pairing).
            let mut seq = 0usize;
            let evaluate_all = |path: &str,
                                ir: &IrProgram,
                                rows: &[&ScenarioRow],
                                seq: &mut usize|
             -> Result<Vec<RunObservation>, String> {
                let base = *seq;
                *seq += rows.len();
                let limit = eval_concurrency().min(rows.len().max(1));
                if limit <= 1 {
                    return rows
                        .iter()
                        .enumerate()
                        .map(|(index, scenario)| {
                            evaluate_scenario(
                                path,
                                args.root.as_deref(),
                                &args.provider,
                                &args.provider_config_paths,
                                scenario,
                                &specs,
                                ir,
                                base + index + 1,
                                &prices,
                            )
                        })
                        .collect();
                }
                let mut results: Vec<Result<RunObservation, String>> =
                    Vec::with_capacity(rows.len());
                std::thread::scope(|scope| {
                    for chunk_start in (0..rows.len()).step_by(limit) {
                        let chunk_end = (chunk_start + limit).min(rows.len());
                        let handles: Vec<_> = (chunk_start..chunk_end)
                            .map(|index| {
                                let scenario = rows[index];
                                let root = args.root.as_deref();
                                let provider = args.provider.as_str();
                                let provider_config_paths = &args.provider_config_paths;
                                let specs = &specs;
                                let prices = &prices;
                                scope.spawn(move || {
                                    evaluate_scenario(
                                        path,
                                        root,
                                        provider,
                                        provider_config_paths,
                                        scenario,
                                        specs,
                                        ir,
                                        base + index + 1,
                                        prices,
                                    )
                                })
                            })
                            .collect();
                        for handle in handles {
                            results.push(handle.join().expect("evaluation thread panicked"));
                        }
                    }
                });
                results.into_iter().collect()
            };
            // Judge turns are provider spend like proposer turns: recorded
            // per evaluation batch at record-time prices, counting toward
            // the cap.
            let judge_spend = |store: &mut ImproveStore,
                               observations: &[RunObservation],
                               what: &str,
                               spent: &mut i64|
             -> Result<(), String> {
                let turns: Vec<&TurnUsage> = observations
                    .iter()
                    .flat_map(|observation| observation.judge_usage.iter())
                    .collect();
                if turns.is_empty() {
                    return Ok(());
                }
                let mut tokens = 0i64;
                let mut cost = 0i64;
                let mut unpriced = 0usize;
                for turn in &turns {
                    tokens += turn.total_tokens;
                    match prices.cost_micros(turn) {
                        Some(micros) => cost += micros,
                        None => unpriced += 1,
                    }
                }
                store
                    .append_campaign_event(
                        &campaign_id,
                        "campaign.spend",
                        &json!({
                            "cost_micros": cost,
                            "priced": unpriced == 0,
                            "tokens": tokens,
                            "turns": turns.len(),
                            "unpriced_turns": unpriced,
                            "what": what,
                        }),
                    )
                    .map_err(|error| format!("failed to record judge spend: {error:?}"))?;
                *spent += cost;
                Ok(())
            };
            // The candidate/baseline programs' OWN provider effects (agent turns,
            // coerce/decide) executed by drive_to_idle are the dominant campaign
            // cost — and, unlike judge turns, count toward the spend cap only if
            // folded here. `std.spend` already prices them per observation (the
            // same reading run_settle folds into its own cap); mirror that so the
            // `--spend-cap` guardrail actually bounds the whole run, not just the
            // judge + proposer turns.
            let workflow_spend = |store: &mut ImproveStore,
                                  observations: &[RunObservation],
                                  what: &str,
                                  spent: &mut i64|
             -> Result<(), String> {
                let cost: i64 = observations
                    .iter()
                    .filter_map(|observation| observation.readings.get("std.spend"))
                    .map(|reading| (reading.score * 1_000_000.0).round() as i64)
                    .sum();
                // Workflow turns whose model has no `prices` entry make `std.spend`
                // error `unpriced` -> a SKIPPED gauge, not a priced reading, so
                // their real cost is invisible to the cap (the most silent case:
                // no spend event at all). Record an honest unpriced spend event
                // (tokens from std.tokens when scored) so it is never silent and
                // the end-of-campaign cap check can flag it.
                let is_unpriced = |observation: &&RunObservation| {
                    observation
                        .skipped
                        .iter()
                        .any(|(gauge, reason)| gauge == "std.spend" && reason.contains("unpriced"))
                };
                let unpriced_turns = observations.iter().filter(is_unpriced).count();
                if cost == 0 && unpriced_turns == 0 {
                    return Ok(());
                }
                if cost > 0 {
                    store
                        .append_campaign_event(
                            &campaign_id,
                            "campaign.spend",
                            &json!({
                                "cost_micros": cost,
                                "priced": true,
                                "what": what,
                            }),
                        )
                        .map_err(|error| format!("failed to record workflow spend: {error:?}"))?;
                    *spent += cost;
                }
                if unpriced_turns > 0 {
                    let unpriced_tokens: i64 = observations
                        .iter()
                        .filter(is_unpriced)
                        .filter_map(|observation| observation.readings.get("std.tokens"))
                        .map(|reading| reading.score.round() as i64)
                        .sum();
                    store
                        .append_campaign_event(
                            &campaign_id,
                            "campaign.spend",
                            &json!({
                                "cost_micros": 0,
                                "priced": false,
                                "tokens": unpriced_tokens,
                                "unpriced_turns": unpriced_turns,
                                "what": what,
                            }),
                        )
                        .map_err(|error| format!("failed to record workflow spend: {error:?}"))?;
                }
                Ok(())
            };
            let mut spent_micros: i64 = 0;
            let baseline_open = evaluate_all(&program_path, &ir, &open, &mut seq)?;
            let baseline_sealed = evaluate_all(&program_path, &ir, &sealed, &mut seq)?;
            judge_spend(
                store,
                &baseline_open,
                "judge turns (baseline)",
                &mut spent_micros,
            )?;
            judge_spend(
                store,
                &baseline_sealed,
                "judge turns (baseline, sealed)",
                &mut spent_micros,
            )?;
            workflow_spend(
                store,
                &baseline_open,
                "workflow turns (baseline)",
                &mut spent_micros,
            )?;
            workflow_spend(
                store,
                &baseline_sealed,
                "workflow turns (baseline, sealed)",
                &mut spent_micros,
            )?;
            let mut baseline_tags = campaign_tags.clone();
            baseline_tags.push("baseline".to_owned());
            record_observations(
                store,
                &baseline_open,
                &specs,
                "regen",
                &baseline_hash,
                Some(&campaign_id),
                Some("baseline"),
                &baseline_tags,
            );
            record_observations(
                store,
                &baseline_sealed,
                &specs,
                "regen",
                &baseline_hash,
                Some(&campaign_id),
                Some("baseline"),
                &baseline_tags,
            );
            let unscored: BTreeSet<String> = baseline_open
                .iter()
                .flat_map(|observation| observation.skipped.iter().cloned())
                .map(|(gauge, reason)| format!("{gauge}: {reason}"))
                .collect();
            if !unscored.is_empty() && !options.json {
                for line in &unscored {
                    eprintln!("gauge unscored — {line}");
                }
            }

            // Ratchet execution of later `then` stages (improve note §3): a
            // stage is complete when EVERY ascend gauge in it carries a reach
            // target the baseline already meets — a target-less gauge is
            // open-ended maximization, so its stage never auto-advances, and
            // the final stage always executes. Advancing turns the completed
            // stage's ACHIEVED levels into hard guard floors and activates the
            // next recorded stage; each advance is a campaign event.
            let mut spec_active = campaign_spec.clone();
            let mut stages_advanced = 0usize;
            while !spec_active.ascend.is_empty() && !spec_active.later_stages.is_empty() {
                let complete = spec_active.ascend.iter().all(|(name, reach)| {
                    reach.as_ref().is_some_and(|reach| {
                        aggregate(&baseline_open, name)
                            .operating_point()
                            .is_some_and(|point| {
                                if reach.ge {
                                    point >= reach.threshold
                                } else {
                                    point <= reach.threshold
                                }
                            })
                    })
                });
                if !complete {
                    break;
                }
                let mut floors = Vec::new();
                for (name, _) in &spec_active.ascend {
                    if let Some(point) = aggregate(&baseline_open, name).operating_point() {
                        let ge = specs
                            .iter()
                            .find(|spec| &spec.name == name)
                            .map(|spec| spec.direction_up)
                            .unwrap_or(true);
                        spec_active.floors.insert(name.clone(), (ge, point));
                        floors.push(json!({"gauge": name, "ge": ge, "floor": point}));
                    }
                }
                let mut next_stage = Vec::new();
                for token in &spec_active.later_stages.remove(0) {
                    let (name, reach) = parse_target(token)?;
                    if !specs.iter().any(|spec| spec.name == name) {
                        return Err(format!("unknown gauge `{name}` in a `then` stage"));
                    }
                    next_stage.push((name, reach));
                }
                stages_advanced += 1;
                store
                    .append_campaign_event(
                        &campaign_id,
                        "stage.advanced",
                        &json!({
                            "completed": spec_active
                                .ascend
                                .iter()
                                .map(|(name, _)| name.clone())
                                .collect::<Vec<_>>(),
                            "floors": floors,
                            "next": next_stage
                                .iter()
                                .map(|(name, _)| name.clone())
                                .collect::<Vec<_>>(),
                        }),
                    )
                    .map_err(|error| format!("failed to record stage advance: {error:?}"))?;
                spec_active.ascend = next_stage;
            }

            let mut proposer: Box<dyn Proposer> = match proposer_name.as_str() {
                "fixture" => Box::new(FixtureProposer::from_env()),
                "native" => Box::new(NativeProposer),
                other => return Err(format!("unknown proposer `{other}` (fixture|native)")),
            };
            // Answered tradeoffs from every prior campaign: the only source of
            // auto-resolution authority (default-on, locality-bounded).
            let precedents = load_precedents(store)?;
            let mut prior_failures: Vec<String> = Vec::new();
            let mut cards: Vec<Value> = Vec::new();
            let mut proposed_any = false;
            // Resume continues the record's numbering: K-ids stay unique
            // across invocations of one campaign.
            let mut candidate_seq = candidate_seq_start;
            let mut parked = false;
            for _round in 0..MAX_PROPOSAL_ROUNDS {
                // The spend cap is a hard ceiling over RECORDED cost. Provider
                // price tables are a follow-on: token-only usage records cost 0,
                // so today the cap binds only where priced costs exist — stated in
                // DR-0037, never silent (the spend events carry the tokens).
                if let Some(cap) = spec_active.spend_cap_micros {
                    if spent_micros >= cap {
                        store
                            .append_campaign_event(
                                &campaign_id,
                                "campaign.parked",
                                &json!({"reason": "spend-cap", "spent_micros": spent_micros}),
                            )
                            .map_err(|error| format!("failed to park campaign: {error:?}"))?;
                        parked = true;
                        break;
                    }
                }
                let reflection = build_reflection(
                    &source,
                    &spec_active,
                    &specs,
                    &baseline_open,
                    &baseline_sealed,
                    &open,
                    &prior_failures,
                    sealing_engaged,
                );
                let Some(proposal) = proposer.propose(&reflection)? else {
                    break;
                };
                if proposal.tokens > 0 {
                    // Record-time pricing: the event stores the computed cost
                    // and history is never repriced. No table entry (or no
                    // split) is an honest `priced: false` with cost 0 — the
                    // tokens are still the record.
                    let cost_micros = proposal
                        .usage
                        .as_ref()
                        .and_then(|usage| prices.cost_micros(usage));
                    store
                    .append_campaign_event(
                        &campaign_id,
                        "campaign.spend",
                        &json!({
                            "cost_micros": cost_micros.unwrap_or(0),
                            "priced": cost_micros.is_some(),
                            "tokens": proposal.tokens,
                            "input_tokens": proposal.usage.as_ref().map(|usage| usage.input_tokens),
                            "output_tokens": proposal.usage.as_ref().map(|usage| usage.output_tokens),
                            "provider": proposal.usage.as_ref().map(|usage| usage.provider.clone()),
                            "model": proposal.usage.as_ref().map(|usage| usage.model.clone()),
                            "what": "proposer turn",
                        }),
                    )
                    .map_err(|error| format!("failed to record spend: {error:?}"))?;
                    spent_micros += cost_micros.unwrap_or(0);
                }
                candidate_seq += 1;
                let candidate_id = format!("K-{candidate_seq}");
                let candidate_path =
                    eval_scratch_dir().join(format!("candidate-{candidate_seq}.whip"));
                std::fs::write(&candidate_path, &proposal.source)
                    .map_err(|error| format!("failed to stage candidate: {error}"))?;
                let candidate_path_str = candidate_path.to_string_lossy().into_owned();
                // The static gate battery is a free feasibility oracle: candidates
                // that break invariants die before a sample is spent.
                let candidate_ir = match crate::compile_source_path_with_root(
                    &candidate_path_str,
                    args.root.as_deref(),
                ) {
                    Ok((_, candidate_ir)) => candidate_ir,
                    Err(error) => {
                        store
                    .append_campaign_event(
                        &campaign_id,
                        "candidate.rejected",
                        &json!({
                            "candidate": candidate_id,
                            "reason": format!("does not compile: {}", compile_failure_summary(&error)),
                            "rationale": proposal.rationale,
                        }),
                    )
                    .map_err(|error| format!("failed to record rejection: {error:?}"))?;
                        prior_failures.push(format!("{candidate_id}: does not compile"));
                        continue;
                    }
                };
                let candidate_open =
                    evaluate_all(&candidate_path_str, &candidate_ir, &open, &mut seq)?;
                judge_spend(
                    store,
                    &candidate_open,
                    &format!("judge turns ({candidate_id})"),
                    &mut spent_micros,
                )?;
                workflow_spend(
                    store,
                    &candidate_open,
                    &format!("workflow turns ({candidate_id})"),
                    &mut spent_micros,
                )?;
                let candidate_hash = program_hash(&proposal.source);
                record_observations(
                    store,
                    &candidate_open,
                    &specs,
                    "regen",
                    &candidate_hash,
                    Some(&campaign_id),
                    Some(&candidate_id),
                    &campaign_tags,
                );
                store
                    .append_campaign_event(
                        &campaign_id,
                        "candidate.recorded",
                        &json!({
                            "candidate": candidate_id,
                            "hash": candidate_hash,
                            "rationale": proposal.rationale,
                            "source": proposal.source,
                            "baseline_hash": baseline_hash,
                            "proposer": proposer.name(),
                        }),
                    )
                    .map_err(|error| format!("failed to record candidate: {error:?}"))?;
                let (paired_base, paired_cand, dropped_pairs) =
                    comparable_pairs(&baseline_open, &candidate_open);
                if paired_base.is_empty() {
                    store
                    .append_campaign_event(
                        &campaign_id,
                        "candidate.rejected",
                        &json!({
                            "candidate": candidate_id,
                            "reason": "no comparable scenario pairs (mode mismatch, refires, or incomplete drives)",
                            "rationale": proposal.rationale,
                        }),
                    )
                    .map_err(|error| format!("failed to record rejection: {error:?}"))?;
                    prior_failures.push(format!("{candidate_id}: no comparable scenario pairs"));
                    continue;
                }
                let open_verdict =
                    dominance_verdict(&specs, &spec_active, &paired_base, &paired_cand);
                let mut verdict = open_verdict.clone();
                let mut gate_tags = campaign_tags.clone();
                if dropped_pairs > 0 {
                    gate_tags.push(format!("pairs-dropped:{dropped_pairs}"));
                }
                // A tradeoff a precedent would AUTO-ACCEPT on the OPEN evidence
                // must still clear the holdout gate before the precedent is
                // honored: otherwise an open-only tradeoff is promoted without
                // ever evaluating the sealed scenarios, bypassing the seal.
                // Evaluate sealed and re-derive the verdict over combined
                // evidence here too, so the precedent decision below (computed
                // from verdict.lines) is judged on holdout-inclusive data.
                let open_precedent_auto_accepts = verdict.tradeoff
                    && matches!(
                        precedent_resolution(&precedents, &verdict.lines),
                        Some(PrecedentResolution::AutoAccept(_))
                    );
                if (verdict.proposable || open_precedent_auto_accepts) && sealing_engaged {
                    // Promotion gate: score the sealed holdout on BOTH arms and
                    // re-check dominance over the combined evidence. Every gate
                    // exposure wears the seal (cumulative, k=3).
                    let candidate_sealed =
                        evaluate_all(&candidate_path_str, &candidate_ir, &sealed, &mut seq)?;
                    judge_spend(
                        store,
                        &candidate_sealed,
                        &format!("judge turns ({candidate_id}, sealed)"),
                        &mut spent_micros,
                    )?;
                    workflow_spend(
                        store,
                        &candidate_sealed,
                        &format!("workflow turns ({candidate_id}, sealed)"),
                        &mut spent_micros,
                    )?;
                    record_observations(
                        store,
                        &candidate_sealed,
                        &specs,
                        "regen",
                        &candidate_hash,
                        Some(&campaign_id),
                        Some(&candidate_id),
                        &campaign_tags,
                    );
                    for scenario in &sealed {
                        let _ = store.bump_scenario_wear(&scenario.name, WEAR_OUT_AT);
                    }
                    let (sealed_base, sealed_cand, sealed_dropped) =
                        comparable_pairs(&baseline_sealed, &candidate_sealed);
                    if sealed_dropped > 0 {
                        gate_tags.push(format!("sealed-pairs-dropped:{sealed_dropped}"));
                    }
                    let combined_base: Vec<RunObservation> = paired_base
                        .iter()
                        .chain(sealed_base.iter())
                        .cloned()
                        .collect();
                    let combined_cand: Vec<RunObservation> = paired_cand
                        .iter()
                        .chain(sealed_cand.iter())
                        .cloned()
                        .collect();
                    verdict =
                        dominance_verdict(&specs, &spec_active, &combined_base, &combined_cand);
                    // A candidate that was DOMINANT on the open evidence but is
                    // no longer proposable on the combined evidence failed the
                    // gate. A tradeoff (never proposable) evaluated here only to
                    // judge the precedent on holdout-inclusive data is not
                    // "refused" — the precedent decision below stands on the
                    // combined verdict.
                    if open_verdict.proposable && !verdict.proposable {
                        verdict
                            .reasons
                            .push("failed the sealed promotion gate".to_owned());
                        gate_tags.push("holdout-refused".to_owned());
                    }
                }
                // The v1 MI lower bound: verbatim scenario-payload fragments
                // newly present in the candidate. Flag, never block.
                let all_scenarios: Vec<&ScenarioRow> =
                    open.iter().chain(sealed.iter()).copied().collect();
                let overlap = leakage_overlap(&proposal.source, &source, &all_scenarios);
                if !overlap.is_empty() {
                    gate_tags.push("leakage-overlap".to_owned());
                }
                let mut card = evidence_card(
                    &campaign_id,
                    &candidate_id,
                    &proposal.rationale,
                    &verdict,
                    &gate_tags,
                    unheld_out,
                );
                if !overlap.is_empty() {
                    card["overlap"] = json!(overlap
                        .iter()
                        .map(|fragment| fragment.chars().take(48).collect::<String>())
                        .collect::<Vec<_>>());
                }
                // A tradeoff first consults the precedent set: the Pareto-safe
                // closure of the human's actual answers may resolve it
                // (`improve-precedent.maude`); anything else asks as before.
                let resolution = if verdict.tradeoff {
                    precedent_resolution(&precedents, &verdict.lines)
                } else {
                    None
                };
                if let Some(resolution) = &resolution {
                    let (tag, citation) = match resolution {
                        PrecedentResolution::AutoAccept(citation) => {
                            ("auto-resolved:precedent", citation)
                        }
                        PrecedentResolution::AutoReject(citation) => {
                            ("auto-rejected:precedent", citation)
                        }
                    };
                    card["precedent"] = json!(citation);
                    card["tags"]
                        .as_array_mut()
                        .expect("cards always carry a tags array")
                        .push(json!(tag));
                }
                if verdict.proposable
                    || matches!(resolution, Some(PrecedentResolution::AutoAccept(_)))
                {
                    proposed_any = true;
                    store
                        .append_campaign_event(&campaign_id, "candidate.proposed", &card)
                        .map_err(|error| format!("failed to record proposal: {error:?}"))?;
                    cards.push(card);
                    // Propose-don't-apply: first undominated candidate ends the
                    // stage; adoption is the human's move (`whip adopt`).
                    break;
                } else if matches!(resolution, Some(PrecedentResolution::AutoReject(_))) {
                    store
                        .append_campaign_event(&campaign_id, "candidate.rejected", &card)
                        .map_err(|error| format!("failed to record rejection: {error:?}"))?;
                    prior_failures.push(format!(
                        "{candidate_id}: auto-rejected by precedent ({})",
                        verdict.reasons.join("; ")
                    ));
                    cards.push(card);
                } else if verdict.tradeoff {
                    store
                        .append_campaign_event(&campaign_id, "candidate.tradeoff", &card)
                        .map_err(|error| format!("failed to record tradeoff: {error:?}"))?;
                    prior_failures.push(format!(
                        "{candidate_id}: genuine tradeoff ({}) — escalated, not accepted",
                        verdict.reasons.join("; ")
                    ));
                    cards.push(card);
                } else {
                    store
                        .append_campaign_event(&campaign_id, "candidate.rejected", &card)
                        .map_err(|error| format!("failed to record rejection: {error:?}"))?;
                    prior_failures.push(format!("{candidate_id}: {}", verdict.reasons.join("; ")));
                    cards.push(card);
                }
            }
            // A parked campaign's invocation ends on the park event so the
            // record folds to `parked` and `--resume` can continue it; every
            // other outcome closes as before (never linger open).
            if !parked {
                store
                    .append_campaign_event(
                        &campaign_id,
                        "campaign.closed",
                        &json!({"proposed": proposed_any}),
                    )
                    .map_err(|error| format!("failed to close campaign: {error:?}"))?;
            }
            // The cap only binds priced cost; if any spend went unpriced under a
            // set cap, surface it (loud, non-blocking) rather than let the cap
            // silently under-count.
            warn_on_unpriced_spend_under_cap(store, &campaign_id, spec_active.spend_cap_micros);
            Ok((cards, proposed_any, candidate_seq, stages_advanced, parked))
        })(&mut store);
    let (cards, proposed_any, candidate_seq, stages_advanced, parked) = match outcome {
        Ok(parts) => parts,
        Err(message) => {
            // A campaign must never linger "open" after a crash: the record
            // says what happened.
            let _ = store.append_campaign_event(
                &campaign_id,
                "campaign.failed",
                &json!({"reason": message}),
            );
            return Err(message);
        }
    };
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.improve.v0",
            "campaign": campaign_id,
            "program": program_path,
            "baseline_hash": baseline_hash,
            "unheld_out": unheld_out,
            "cards": cards,
            "proposed": proposed_any,
            "stages_advanced": stages_advanced,
            "parked": parked,
        })));
    }
    println!("campaign {campaign_id} on `{program_path}`");
    if stages_advanced > 0 {
        println!(
            "  ratchet: {stages_advanced} completed `then` stage{} — achieved levels held as guard floors",
            if stages_advanced == 1 { "" } else { "s" }
        );
    }
    if unheld_out {
        println!("  tags: unheld-out (fewer than {MIN_SCENARIOS_FOR_SEALING} pinned scenarios)");
    }
    if cards.is_empty() {
        println!("  no candidates produced (proposer exhausted)");
    }
    for card in &cards {
        print_card(card);
    }
    if parked {
        println!("  parked: spend cap reached — resume with: whip improve --resume {campaign_id}");
    }
    if proposed_any {
        println!("adopt with: whip adopt {campaign_id}:K-{candidate_seq} --program {program_path}");
    }
    Ok(ExitCode::SUCCESS)
}

fn evidence_card(
    campaign_id: &str,
    candidate_id: &str,
    rationale: &str,
    verdict: &CandidateVerdict,
    tags: &[String],
    unheld_out: bool,
) -> Value {
    let mut all_tags = tags.to_vec();
    if unheld_out && !all_tags.iter().any(|tag| tag == "unheld-out") {
        all_tags.push("unheld-out".to_owned());
    }
    json!({
        "candidate": candidate_id,
        "campaign": campaign_id,
        "rationale": rationale,
        "proposable": verdict.proposable,
        "tradeoff": verdict.tradeoff,
        "reasons": verdict.reasons,
        "tags": all_tags,
        "gauges": verdict.lines.iter().map(|line| json!({
            "gauge": line.gauge,
            "role": line.role,
            "delta": match line.delta {
                Delta::Better => "better",
                Delta::InBand => "in-band",
                Delta::Worse => "worse",
                Delta::Unmeasured => "unmeasured",
            },
            "baseline": line.baseline,
            "candidate": line.candidate,
            "band": line.band,
            "bar_met": line.bar_met,
            "reach_met": line.reach_met,
            "p_better": line.p_better,
            "direction": if line.direction_up { "up" } else { "down" },
        })).collect::<Vec<_>>(),
    })
}

fn print_card(card: &Value) {
    let candidate = card["candidate"].as_str().unwrap_or("?");
    let status = if card["proposable"].as_bool().unwrap_or(false) {
        "PROPOSED"
    } else if card["tradeoff"].as_bool().unwrap_or(false) {
        "TRADEOFF — your call"
    } else {
        "refused"
    };
    println!("candidate {candidate}: {status}");
    if let Some(rationale) = card["rationale"].as_str() {
        if !rationale.is_empty() {
            println!("  rationale: {rationale}");
        }
    }
    if let Some(gauges) = card["gauges"].as_array() {
        for line in gauges {
            let base = line["baseline"].as_f64().unwrap_or(f64::NAN);
            let cand = line["candidate"].as_f64().unwrap_or(f64::NAN);
            let mut suffix = String::new();
            if let Some(met) = line["bar_met"].as_bool() {
                suffix.push_str(if met { " bar✓" } else { " bar✗" });
            }
            println!(
                "  {} [{}] {:.4} -> {:.4} ({}){}",
                line["gauge"].as_str().unwrap_or("?"),
                line["role"].as_str().unwrap_or("?"),
                base,
                cand,
                line["delta"].as_str().unwrap_or("?"),
                suffix
            );
        }
    }
    if let Some(citation) = card["precedent"].as_str() {
        println!("  precedent: {citation}");
    }
    if let Some(reasons) = card["reasons"].as_array() {
        for reason in reasons {
            if let Some(reason) = reason.as_str() {
                println!("  · {reason}");
            }
        }
    }
    if let Some(tags) = card["tags"].as_array() {
        if !tags.is_empty() {
            let rendered: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
            println!("  tags: {}", rendered.join(", "));
        }
    }
}

// ---------------------------------------------------------------------------
// whip campaigns / whip campaign <id> / whip adopt
// ---------------------------------------------------------------------------

pub(crate) fn campaigns_command(options: &CliOptions) -> ExitCode {
    let store = match open_improve_store() {
        Ok(store) => store,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let campaigns = match store.list_campaigns() {
        Ok(campaigns) => campaigns,
        Err(error) => {
            eprintln!("failed to list campaigns: {error:?}");
            return ExitCode::from(2);
        }
    };
    if options.json {
        return emit_json(json!({
            "schema": "whipplescript.campaigns.v0",
            "campaigns": campaigns.iter().map(campaign_summary_json).collect::<Vec<_>>(),
        }));
    }
    if campaigns.is_empty() {
        println!("no campaigns");
        return ExitCode::SUCCESS;
    }
    for campaign in &campaigns {
        println!(
            "{} {} candidates={} proposed={} opened={}",
            campaign.campaign_id,
            campaign.status,
            campaign.candidates,
            campaign.proposed,
            campaign.opened_at
        );
    }
    ExitCode::SUCCESS
}

fn campaign_summary_json(campaign: &CampaignSummary) -> Value {
    json!({
        "campaign": campaign.campaign_id,
        "status": campaign.status,
        "spec": campaign.spec,
        "opened_at": campaign.opened_at,
        "last_event_at": campaign.last_event_at,
        "candidates": campaign.candidates,
        "proposed": campaign.proposed,
        "spent_micros": campaign.spent_micros,
    })
}

pub(crate) fn campaign_detail_command(options: &CliOptions) -> ExitCode {
    let Some(campaign_id) = options.args.first() else {
        eprintln!("usage: whip campaign <id>");
        return ExitCode::from(2);
    };
    let store = match open_improve_store() {
        Ok(store) => store,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let events = match store.list_campaign_events(campaign_id) {
        Ok(events) => events,
        Err(error) => {
            eprintln!("failed to read campaign: {error:?}");
            return ExitCode::from(2);
        }
    };
    if events.is_empty() {
        eprintln!("unknown campaign `{campaign_id}`");
        return ExitCode::from(2);
    }
    if options.json {
        return emit_json(json!({
            "schema": "whipplescript.campaign.v0",
            "campaign": campaign_id,
            "events": events.iter().map(|event| json!({
                "seq": event.seq,
                "type": event.event_type,
                "payload": event.payload,
                "at": event.created_at,
            })).collect::<Vec<_>>(),
        }));
    }
    let mut summary = CampaignSummary {
        campaign_id: campaign_id.clone(),
        status: "open".to_owned(),
        spec: Value::Null,
        opened_at: String::new(),
        last_event_at: String::new(),
        candidates: 0,
        proposed: 0,
        spent_micros: 0,
    };
    for event in &events {
        fold_campaign_event(&mut summary, event);
    }
    println!(
        "campaign {} {} candidates={} proposed={}",
        summary.campaign_id, summary.status, summary.candidates, summary.proposed
    );
    for event in &events {
        match event.event_type.as_str() {
            "candidate.proposed" | "candidate.tradeoff" | "candidate.rejected" => {
                print_card(&event.payload);
            }
            "campaign.sealed" => {
                let sealed = event.payload["sealed"]
                    .as_array()
                    .map(|names| names.len())
                    .unwrap_or(0);
                let open = event.payload["open"]
                    .as_array()
                    .map(|names| names.len())
                    .unwrap_or(0);
                println!("  sealed {sealed} scenario(s), {open} open");
            }
            _ => {}
        }
    }
    ExitCode::SUCCESS
}

pub(crate) fn adopt_command(options: &CliOptions) -> ExitCode {
    match run_adopt(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn run_adopt(options: &CliOptions) -> Result<ExitCode, String> {
    let mut target = None;
    let mut program = None;
    let mut index = 0;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--program" => {
                index += 1;
                program = options.args.get(index).cloned();
            }
            other if target.is_none() => target = Some(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        index += 1;
    }
    let target = target.ok_or("usage: whip adopt <campaign>:<candidate> --program <path>")?;
    let (campaign_id, candidate_id) = target
        .split_once(':')
        .ok_or("adopt target must be <campaign>:<candidate> (e.g. C-1:K-2)")?;
    let program_path = resolve_program_path(program)?;
    let mut store = open_improve_store()?;
    let events = store
        .list_campaign_events(campaign_id)
        .map_err(|error| format!("failed to read campaign: {error:?}"))?;
    if events.is_empty() {
        return Err(format!("unknown campaign `{campaign_id}`"));
    }
    let recorded = events
        .iter()
        .find(|event| {
            event.event_type == "candidate.recorded"
                && event.payload["candidate"].as_str() == Some(candidate_id)
        })
        .ok_or_else(|| format!("campaign `{campaign_id}` has no candidate `{candidate_id}`"))?;
    // Adoption is offered for candidates the dominance invariant surfaced
    // as proposed, OR tradeoffs the human explicitly ACCEPTED via
    // `whip answer` (an un-revoked accepting answer IS the decision).
    let proposed = events.iter().any(|event| {
        event.event_type == "candidate.proposed"
            && event.payload["candidate"].as_str() == Some(candidate_id)
    }) || events
        .iter()
        .rev()
        .find_map(|event| {
            if event.payload["candidate"].as_str() != Some(candidate_id) {
                return None;
            }
            match event.event_type.as_str() {
                "preference.answered" => {
                    Some(event.payload["verdict"].as_str() == Some("accepted"))
                }
                "preference.revoked" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(false);
    if !proposed {
        return Err(format!(
            "candidate `{candidate_id}` was not proposed by campaign `{campaign_id}`              (it was refused or escalated as a tradeoff); adoption is reserved for              proposed candidates"
        ));
    }
    let source = recorded.payload["source"]
        .as_str()
        .ok_or("candidate record carries no source")?;
    let baseline_hash = recorded.payload["baseline_hash"]
        .as_str()
        .ok_or("candidate record carries no baseline hash")?;
    let current = std::fs::read_to_string(&program_path)
        .map_err(|error| format!("failed to read `{program_path}`: {error}"))?;
    // Adoption always merges into CURRENT mainline: if the program moved
    // under the campaign, refuse honestly rather than silently undo a human
    // edit (the certified-merge rebase is the principled upgrade).
    if program_hash(&current) != baseline_hash {
        return Err(format!(
            "`{program_path}` changed since campaign {campaign_id} evaluated its baseline; \
             re-run the campaign against the current program"
        ));
    }
    std::fs::write(&program_path, source)
        .map_err(|error| format!("failed to write `{program_path}`: {error}"))?;
    store
        .append_campaign_event(
            campaign_id,
            "candidate.adopted",
            &json!({
                "candidate": candidate_id,
                "program": program_path,
                "hash": program_hash(source),
            }),
        )
        .map_err(|error| format!("failed to record adoption: {error:?}"))?;
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.adopt.v0",
            "campaign": campaign_id,
            "candidate": candidate_id,
            "program": program_path,
        })));
    }
    println!("adopted {campaign_id}:{candidate_id} into `{program_path}`");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn answer_command(options: &CliOptions) -> ExitCode {
    match run_answer(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// `whip answer <campaign>:<candidate> --accept|--reject|--revoke`: answer
/// a surfaced tradeoff. The answer is a PRECEDENT — a speech act recorded
/// in the campaign record that (a) makes an accepted candidate adoptable
/// and (b) auto-resolves future tradeoffs it Pareto-dominates
/// (`improve-precedent.maude`). `--revoke` withdraws a prior answer.
fn run_answer(options: &CliOptions) -> Result<ExitCode, String> {
    let mut target = None;
    let mut verdict: Option<&str> = None;
    let mut answered_by = None;
    let mut index = 0;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--accept" => verdict = Some("accepted"),
            "--reject" => verdict = Some("rejected"),
            "--revoke" => verdict = Some("revoked"),
            "--by" => {
                index += 1;
                answered_by = options.args.get(index).cloned();
            }
            other if target.is_none() => target = Some(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        index += 1;
    }
    let usage = "usage: whip answer <campaign>:<candidate> --accept|--reject|--revoke [--by <who>]";
    let target = target.ok_or(usage)?;
    let verdict = verdict.ok_or(usage)?;
    let (campaign_id, candidate_id) = target
        .split_once(':')
        .ok_or("answer target must be <campaign>:<candidate> (e.g. C-1:K-2)")?;
    let mut store = open_improve_store()?;
    let events = store
        .list_campaign_events(campaign_id)
        .map_err(|error| format!("failed to read campaign: {error:?}"))?;
    if events.is_empty() {
        return Err(format!("unknown campaign `{campaign_id}`"));
    }
    let already_answered = events.iter().rev().find_map(|event| {
        if event.payload["candidate"].as_str() != Some(candidate_id) {
            return None;
        }
        match event.event_type.as_str() {
            "preference.answered" => Some(true),
            "preference.revoked" => Some(false),
            _ => None,
        }
    });
    if verdict == "revoked" {
        if already_answered != Some(true) {
            return Err(format!(
                "candidate `{candidate_id}` has no standing answer to revoke"
            ));
        }
        store
            .append_campaign_event(
                campaign_id,
                "preference.revoked",
                &json!({"candidate": candidate_id, "by": answered_by}),
            )
            .map_err(|error| format!("failed to record revocation: {error:?}"))?;
        if options.json {
            return Ok(emit_json(json!({
                "schema": "whipplescript.answer.v0",
                "campaign": campaign_id,
                "candidate": candidate_id,
                "verdict": "revoked",
            })));
        }
        println!("revoked the answer on {campaign_id}:{candidate_id}");
        return Ok(ExitCode::SUCCESS);
    }
    if already_answered == Some(true) {
        return Err(format!(
            "candidate `{candidate_id}` is already answered; revoke first              (`whip answer {campaign_id}:{candidate_id} --revoke`)"
        ));
    }
    // Only surfaced tradeoffs are answerable: proposed candidates are
    // adoptable already, refused candidates carry the model's verdict.
    let tradeoff = events
        .iter()
        .find(|event| {
            event.event_type == "candidate.tradeoff"
                && event.payload["candidate"].as_str() == Some(candidate_id)
        })
        .ok_or_else(|| {
            format!(
                "candidate `{candidate_id}` was not surfaced as a tradeoff;                  only tradeoff decisions are answerable"
            )
        })?;
    let gauges = tradeoff.payload["gauges"].clone();
    if !gauges
        .as_array()
        .is_some_and(|lines| lines.iter().all(|line| line["direction"].is_string()))
    {
        return Err(
            "this tradeoff card predates precedent support (no gauge directions recorded)"
                .to_owned(),
        );
    }
    store
        .append_campaign_event(
            campaign_id,
            "preference.answered",
            &json!({
                "candidate": candidate_id,
                "verdict": verdict,
                "by": answered_by,
                "gauges": gauges,
            }),
        )
        .map_err(|error| format!("failed to record answer: {error:?}"))?;
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.answer.v0",
            "campaign": campaign_id,
            "candidate": candidate_id,
            "verdict": verdict,
            "adoptable": verdict == "accepted",
        })));
    }
    println!(
        "{verdict} {campaign_id}:{candidate_id} — recorded as a precedent{}",
        if verdict == "accepted" {
            "; the candidate is now adoptable"
        } else {
            ""
        }
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// whip pin / whip gauges / ambient scoring
// ---------------------------------------------------------------------------

pub(crate) fn pin_command(options: &CliOptions) -> ExitCode {
    match run_pin(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn run_pin(options: &CliOptions) -> Result<ExitCode, String> {
    let usage = "usage: whip pin <instance> [at <mark>] --as <name>";
    let mut instance_id = None;
    let mut name = None;
    let mut mark = None;
    let mut index = 0;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--as" => {
                index += 1;
                name = options.args.get(index).cloned();
            }
            "at" => {
                index += 1;
                mark = Some(options.args.get(index).ok_or(usage)?.clone());
            }
            other if instance_id.is_none() => instance_id = Some(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        index += 1;
    }
    let instance_id = instance_id.ok_or(usage)?;
    let name = name.ok_or(usage)?;
    let store = SqliteStore::open(&options.store_path)
        .map_err(|error| format!("failed to open store: {error:?}"))?;
    let instance = store
        .get_instance(&instance_id)
        .map_err(|error| format!("failed to read instance: {error:?}"))?
        .ok_or_else(|| format!("unknown instance `{instance_id}`"))?;
    // A mark pin freezes the prefix at the FIRST time the run reached the
    // mark; the mark.reached event's own sequence is the cut coordinate.
    let mut mark_occurrences = 0usize;
    let cut_sequence = if let Some(mark) = &mark {
        let events = store
            .list_events(&instance_id)
            .map_err(|error| format!("failed to read events: {error:?}"))?;
        let matches: Vec<i64> = events
            .iter()
            .filter(|event| {
                event.event_type == "mark.reached"
                    && serde_json::from_str::<Value>(&event.payload_json)
                        .ok()
                        .and_then(|payload| payload["mark"].as_str().map(str::to_owned))
                        .as_deref()
                        == Some(mark.as_str())
            })
            .map(|event| event.sequence)
            .collect();
        mark_occurrences = matches.len();
        let cut = matches.first().copied();
        let Some(cut) = cut else {
            let stamped: BTreeSet<String> = events
                .iter()
                .filter(|event| event.event_type == "mark.reached")
                .filter_map(|event| {
                    serde_json::from_str::<Value>(&event.payload_json)
                        .ok()
                        .and_then(|payload| payload["mark"].as_str().map(str::to_owned))
                })
                .collect();
            return Err(format!(
                "instance {instance_id} never reached mark `{mark}` (marks stamped: {})",
                if stamped.is_empty() {
                    "none".to_owned()
                } else {
                    stamped.into_iter().collect::<Vec<_>>().join(", ")
                }
            ));
        };
        Some(cut)
    } else {
        None
    };
    let store_path = std::fs::canonicalize(&options.store_path)
        .unwrap_or_else(|_| options.store_path.clone())
        .to_string_lossy()
        .into_owned();
    let mut improve_store = open_improve_store()?;
    improve_store
        .pin_scenario(
            &name,
            &instance_id,
            None,
            &instance.input_json,
            None,
            mark.as_deref(),
            cut_sequence,
            cut_sequence.is_some().then_some(store_path.as_str()),
        )
        .map_err(|error| format!("failed to pin: {error:?}"))?;
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.pin.v0",
            "scenario": name,
            "instance": instance_id,
            "mark": mark,
            "cut_sequence": cut_sequence,
            "mark_occurrences": (mark_occurrences > 0).then_some(mark_occurrences),
        })));
    }
    match &mark {
        Some(mark) => {
            println!(
                "pinned `{name}` from instance {instance_id} at mark `{mark}` (cut seq {})",
                cut_sequence.unwrap_or(0)
            );
            if mark_occurrences > 1 {
                println!(
                    "  note: the mark fired {mark_occurrences} times; pinned the FIRST \
                     occurrence (occurrence selection is a follow-on)"
                );
            }
        }
        None => println!("pinned `{name}` from instance {instance_id}"),
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn suppose_command(options: &CliOptions) -> ExitCode {
    let _scratch = EvalScratchGuard;
    match run_suppose(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// `whip suppose <scenario> [--program <p>]`: ONE what-if regeneration of
/// the pinned scenario under the current program — the everyday debugging
/// what-if, and the do-operator as a verb. Mark-pinned scenarios replay
/// the frozen prefix and re-execute only the suffix (paired at the cut);
/// input pins re-run the whole workflow. The recorded run is the paired
/// control; the regenerated readings land in the evidence ledger.
fn run_suppose(options: &CliOptions) -> Result<ExitCode, String> {
    let usage = "usage: whip suppose <scenario> [--program <workflow.whip>] [--root <workflow>] [--provider <name>] [--provider-config <path>]";
    let mut scenario_name = None;
    let mut program = None;
    let mut root = None;
    let mut provider = "fixture".to_owned();
    let mut provider_config_paths: Vec<PathBuf> = Vec::new();
    let mut index = 0;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--program" => {
                index += 1;
                program = options.args.get(index).cloned();
            }
            "--root" => {
                index += 1;
                root = options.args.get(index).cloned();
            }
            "--provider" => {
                index += 1;
                provider = options.args.get(index).ok_or(usage)?.clone();
            }
            "--provider-config" => {
                index += 1;
                provider_config_paths.push(PathBuf::from(options.args.get(index).ok_or(usage)?));
            }
            other if scenario_name.is_none() => scenario_name = Some(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        index += 1;
    }
    let scenario_name = scenario_name.ok_or(usage)?;
    let program_path = resolve_program_path(program)?;
    let (_, ir) =
        crate::compile_source_path_with_root(&program_path, root.as_deref()).map_err(|error| {
            format!(
                "`{program_path}` does not compile: {}",
                compile_failure_summary(&error)
            )
        })?;
    let specs = collect_gauge_specs(&ir);
    let mut improve_store = open_improve_store()?;
    let scenario = improve_store
        .get_scenario(&scenario_name)
        .map_err(|error| format!("failed to read scenario: {error:?}"))?
        .ok_or_else(|| format!("unknown scenario `{scenario_name}`"))?;
    contain_side_stores();
    // The recorded run is the paired control: score it in place (read-only
    // against the source store).
    let source_store_path = scenario
        .store_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| options.store_path.clone());
    // Never create a store while looking for the control: an unresolvable
    // path yields an honest "no recorded control", not judge scores over a
    // blank record.
    let prices = PriceTable::load(&provider_config_paths)?;
    let recorded = source_store_path
        .exists()
        .then(|| SqliteStore::open(&source_store_path).ok())
        .flatten()
        .map(|store| {
            score_instance(
                &store,
                &scenario.instance_id,
                &specs,
                Some(&scenario.name),
                false,
                &ir,
                &prices,
            )
        });
    let regenerated = evaluate_scenario(
        &program_path,
        root.as_deref(),
        &provider,
        &provider_config_paths,
        &scenario,
        &specs,
        &ir,
        1,
        &prices,
    )?;
    let mode = if regenerated
        .readings
        .values()
        .any(|reading| reading.tags.iter().any(|tag| tag == "prefix-replay"))
    {
        "prefix-replay"
    } else {
        "input-replay"
    };
    // The observation lands in the ledger: every suppose is evidence.
    let source = std::fs::read_to_string(&program_path).unwrap_or_default();
    let hash = program_hash(&source);
    record_observations(
        &mut improve_store,
        std::slice::from_ref(&regenerated),
        &specs,
        "regen",
        &hash,
        None,
        None,
        &["suppose".to_owned()],
    );
    let gauges: Vec<Value> = specs
        .iter()
        .filter_map(|spec| {
            let after = regenerated.readings.get(&spec.name)?;
            let before = recorded
                .as_ref()
                .and_then(|observation| observation.readings.get(&spec.name));
            // The belief-update readout (DR-0041): the paired sign test
            // over the (recorded, regenerated) pair when both carry bar
            // verdicts. A single continuous delta has no scale, so
            // family B stays honestly silent at N=1.
            let p_better = match (before.and_then(|reading| reading.passed), after.passed) {
                (Some(control), Some(treatment)) => p_better_sign(&[(control, treatment)]),
                _ => None,
            };
            Some(json!({
                "gauge": spec.name,
                "recorded": before.map(|reading| reading.score),
                "regenerated": after.score,
                "recorded_passed": before.and_then(|reading| reading.passed),
                "regenerated_passed": after.passed,
                "p_better": p_better,
                "tags": after.tags,
            }))
        })
        .collect();
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.suppose.v0",
            "scenario": scenario_name,
            "mode": mode,
            "gauges": gauges,
            "skipped": regenerated
                .skipped
                .iter()
                .map(|(gauge, reason)| json!({"gauge": gauge, "reason": reason}))
                .collect::<Vec<_>>(),
        })));
    }
    println!("suppose `{scenario_name}` ({mode})");
    for line in &gauges {
        let recorded = line["recorded"]
            .as_f64()
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "—".to_owned());
        println!(
            "  {}: {} -> {:.4}{}{}",
            line["gauge"].as_str().unwrap_or("?"),
            recorded,
            line["regenerated"].as_f64().unwrap_or(f64::NAN),
            match line["regenerated_passed"].as_bool() {
                Some(true) => " ✓",
                Some(false) => " ✗",
                None => "",
            },
            line["p_better"]
                .as_f64()
                .map(|p| format!(" · P(better)={:.0}% · N=1 pair", p * 100.0))
                .unwrap_or_default()
        );
    }
    for (gauge, reason) in &regenerated.skipped {
        println!("  · {gauge}: {reason}");
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// whip settle — racing + stopping (models/maude/settle-stopping.maude)
// ---------------------------------------------------------------------------

/// The sound certifier from `settle-stopping.maude`: a strong (bar-passing)
/// observation raises the evidence level, a contrary one lowers it (floored
/// at zero), and the decision closes exactly at the threshold crossing —
/// anytime-valid, so crossing once suffices. Exhaustion below the threshold
/// is an honest `undetermined`, never a certificate.
struct SettleWalk {
    level: u32,
    threshold: u32,
    /// All-time high-water mark: the racing loop declares evidence
    /// exhausted when a full pass over the pinned pool fails to raise it.
    high_water: u32,
    /// Informative observations folded (the N the system chose).
    n: usize,
}

impl SettleWalk {
    fn new(threshold: u32) -> Self {
        Self {
            level: 0,
            threshold,
            high_water: 0,
            n: 0,
        }
    }

    /// Fold one observation; `true` exactly when this observation crosses
    /// the threshold.
    fn observe(&mut self, strong: bool) -> bool {
        self.n += 1;
        if strong {
            self.level += 1;
        } else {
            self.level = self.level.saturating_sub(1);
        }
        self.high_water = self.high_water.max(self.level);
        self.level >= self.threshold
    }
}

pub(crate) fn settle_command(options: &CliOptions) -> ExitCode {
    let _scratch = EvalScratchGuard;
    match run_settle(options) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// `whip settle <gauge>`: name the decision (the gauge's bar) and let the
/// system stop itself — racing regenerations over the pinned scenario pool
/// until the evidence level crosses the threshold (bar cleared) or a full
/// pass adds no net evidence (an honest `undetermined`). Never an
/// operator-chosen N. `--certify` records the crossing as a certificate on
/// the crossing observation's evidence row.
fn run_settle(options: &CliOptions) -> Result<ExitCode, String> {
    let usage = "usage: whip [--json] settle <gauge> [--certify] [--threshold <k>] [--program <workflow.whip>] [--root <workflow>] [--provider <name>] [--provider-config <path>]";
    let mut gauge_name = None;
    let mut certify = false;
    let mut spend_cap_micros: Option<i64> = None;
    let mut threshold = 3u32;
    let mut program = None;
    let mut root = None;
    let mut provider = "fixture".to_owned();
    let mut provider_config_paths: Vec<PathBuf> = Vec::new();
    let mut index = 0;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--certify" => certify = true,
            "--spend-cap" => {
                index += 1;
                spend_cap_micros = Some(parse_spend_cap(
                    options
                        .args
                        .get(index)
                        .ok_or("--spend-cap requires an amount")?,
                )?);
            }
            "--threshold" => {
                index += 1;
                threshold = options
                    .args
                    .get(index)
                    .ok_or(usage)?
                    .parse::<u32>()
                    .ok()
                    .filter(|k| *k >= 1)
                    .ok_or("invalid --threshold (use a positive integer)")?;
            }
            "--program" => {
                index += 1;
                program = options.args.get(index).cloned();
            }
            "--root" => {
                index += 1;
                root = options.args.get(index).cloned();
            }
            "--provider" => {
                index += 1;
                provider = options.args.get(index).ok_or(usage)?.clone();
            }
            "--provider-config" => {
                index += 1;
                provider_config_paths.push(PathBuf::from(options.args.get(index).ok_or(usage)?));
            }
            other if gauge_name.is_none() => gauge_name = Some(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        index += 1;
    }
    let gauge_name = gauge_name.ok_or(usage)?;
    let program_path = resolve_program_path(program)?;
    let (_, ir) =
        crate::compile_source_path_with_root(&program_path, root.as_deref()).map_err(|error| {
            format!(
                "`{program_path}` does not compile: {}",
                compile_failure_summary(&error)
            )
        })?;
    let specs = collect_gauge_specs(&ir);
    let spec = specs
        .iter()
        .find(|spec| spec.name == gauge_name)
        .ok_or_else(|| format!("unknown gauge `{gauge_name}` (declare it in the program)"))?;
    if spec.bar.is_none() {
        return Err(format!(
            "gauge `{gauge_name}` has no bar — settle needs a decision; declare an `expect` bar on the gauge"
        ));
    }
    let mut improve_store = open_improve_store()?;
    let scenarios: Vec<_> = improve_store
        .list_scenarios()
        .map_err(|error| format!("failed to read scenarios: {error:?}"))?
        .into_iter()
        .filter(|scenario| !scenario.retired)
        .collect();
    if scenarios.is_empty() {
        return Err(
            "no pinned scenarios to regenerate — pin one with `whip pin <instance> --as <name>`"
                .to_owned(),
        );
    }
    contain_side_stores();
    let source = std::fs::read_to_string(&program_path).unwrap_or_default();
    let hash = program_hash(&source);
    let prices = PriceTable::load(&provider_config_paths)?;

    // The belief-update readout alongside the certification walk
    // (DR-0041): θ = per-regeneration bar-pass probability under a
    // Jeffreys Beta posterior; the reference is the chance bar's own
    // rate, or majority (1/2) for stat-shaped bars.
    let bar_reference = spec
        .bar
        .as_ref()
        .map(|bar| {
            if bar.chance_field.is_some() {
                (bar.threshold, bar.ge)
            } else {
                (0.5, true)
            }
        })
        .unwrap_or((0.5, true));
    let mut strongs = 0usize;
    let mut contraries = 0usize;
    let mut walk = SettleWalk::new(threshold);
    let mut trail: Vec<Value> = Vec::new();
    let mut seq = 0usize;
    let mut crossed = false;
    let mut any_informative = false;
    let mut spent_micros: i64 = 0;
    let mut capped = false;
    'rounds: loop {
        let high_before_round = walk.high_water;
        let mut round_informative = false;
        for scenario in &scenarios {
            // The guardrail is currency, never a sample size (research
            // note §4.3): it binds only on PRICED regeneration cost —
            // unpriced usage keeps the honest posture (cost 0, no bite).
            if let Some(cap) = spend_cap_micros {
                if spent_micros >= cap {
                    capped = true;
                    break 'rounds;
                }
            }
            seq += 1;
            let observation = evaluate_scenario(
                &program_path,
                root.as_deref(),
                &provider,
                &provider_config_paths,
                scenario,
                &specs,
                &ir,
                seq,
                &prices,
            )?;
            spent_micros += observation
                .readings
                .get("std.spend")
                .map_or(0, |reading| (reading.score * 1_000_000.0).round() as i64);
            spent_micros += observation
                .judge_usage
                .iter()
                .filter_map(|turn| prices.cost_micros(turn))
                .sum::<i64>();
            let verdict = observation
                .readings
                .get(&gauge_name)
                .and_then(|reading| reading.passed.map(|passed| (reading.score, passed)));
            let mut tags = vec!["settle".to_owned()];
            if let Some((score, strong)) = verdict {
                round_informative = true;
                any_informative = true;
                if strong {
                    strongs += 1;
                } else {
                    contraries += 1;
                }
                crossed = walk.observe(strong);
                if crossed && certify {
                    tags.push("certificate".to_owned());
                }
                trail.push(json!({
                    "scenario": scenario.name,
                    "score": score,
                    "strong": strong,
                    "level": walk.level,
                }));
            } else {
                let reason = observation
                    .skipped
                    .iter()
                    .find(|(gauge, _)| gauge == &gauge_name)
                    .map(|(_, reason)| reason.clone())
                    .unwrap_or_else(|| "no reading".to_owned());
                trail.push(json!({
                    "scenario": scenario.name,
                    "uninformative": reason,
                }));
            }
            // Every settle regeneration is evidence, crossing or not.
            record_observations(
                &mut improve_store,
                std::slice::from_ref(&observation),
                &specs,
                "regen",
                &hash,
                None,
                None,
                &tags,
            );
            if crossed {
                break 'rounds;
            }
        }
        // Stopping is the system's: a full pass over the pool that set no
        // new high-water mark cannot be expected to add net evidence.
        if !round_informative || walk.high_water <= high_before_round {
            break;
        }
    }

    let (outcome, reason) = if crossed {
        (
            if certify { "certified" } else { "bar-cleared" },
            "threshold-crossed",
        )
    } else if capped {
        ("undetermined", "spend-cap-reached")
    } else if any_informative {
        ("undetermined", "evidence-exhausted")
    } else {
        ("undetermined", "no-informative-readings")
    };
    let certificate = (crossed && certify).then(|| {
        format!(
            "ct-{}",
            &program_hash(&format!("{gauge_name}:{hash}:{}:{}", walk.n, walk.level))[..8]
        )
    });
    let p_bar_met = (walk.n > 0).then(|| {
        let below = betainc(
            0.5 + strongs as f64,
            0.5 + contraries as f64,
            bar_reference.0,
        );
        if bar_reference.1 {
            1.0 - below
        } else {
            below
        }
    });
    if options.json {
        return Ok(emit_json(json!({
            "schema": "whipplescript.settle.v0",
            "gauge": gauge_name,
            "outcome": outcome,
            "reason": reason,
            "n": walk.n,
            "level": walk.level,
            "threshold": walk.threshold,
            "scenarios": scenarios.len(),
            "certificate": certificate,
            "p_bar_met": p_bar_met,
            "spent_micros": spent_micros,
            "trail": trail,
        })));
    }
    match outcome {
        "certified" => println!(
            "settle {gauge_name}: certified at N={} · level {}/{}{} · certificate {}",
            walk.n,
            walk.level,
            walk.threshold,
            p_bar_met
                .map(|p| format!(" · P(bar met)={:.0}%", p * 100.0))
                .unwrap_or_default(),
            certificate.as_deref().unwrap_or("?"),
        ),
        "bar-cleared" => println!(
            "settle {gauge_name}: bar cleared at N={} · level {}/{}{}",
            walk.n,
            walk.level,
            walk.threshold,
            p_bar_met
                .map(|p| format!(" · P(bar met)={:.0}%", p * 100.0))
                .unwrap_or_default()
        ),
        _ => {
            println!(
                "settle {gauge_name}: undetermined ({} at N={} · level {}/{})",
                reason.replace('-', " "),
                walk.n,
                walk.level,
                walk.threshold
            );
            if capped {
                println!(
                    "  · spent ${:.2} against the cap — raise --spend-cap to keep racing",
                    spent_micros as f64 / 1_000_000.0
                );
            } else {
                println!(
                    "  · a full pass over {} pinned scenario{} added no net evidence — pin more scenarios (whip pin) or revisit the bar",
                    scenarios.len(),
                    if scenarios.len() == 1 { "" } else { "s" }
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One standing-contradiction flag: evidence recorded under the accepted
/// candidate's own program hash contradicting what the answer accepted.
struct ContradictionFlag {
    gauge: String,
    citation: String,
    p_worse: f64,
    n: usize,
    reference: f64,
}

/// The standing-contradiction reopener (`contradiction-reopener.maude`,
/// design pass 2026-07-14): for every ACCEPTED precedent, fold the
/// evidence recorded under the accepted candidate's program hash since
/// the answer into a per-gauge contradiction posterior against the
/// answer-time operating point. The trigger is SUSTAINED — the posterior
/// must sit at ≥ 0.8 AND be non-decreasing over the last three
/// informative observations, so a single noisy day never nags — and the
/// flag is ADVISORY ONLY: it cites the precedent; revocation stays
/// `whip answer --revoke`. Rows are matched by the candidate's hash, so
/// a program that has since moved on quiesces the flag naturally.
fn standing_contradictions(
    store: &ImproveStore,
    gauge_filter: Option<&str>,
) -> Result<Vec<ContradictionFlag>, String> {
    const THRESHOLD: f64 = 0.8;
    const SUSTAIN: usize = 3;
    let precedents = load_precedents(store)?;
    let recorded = store
        .list_events_of_type("candidate.recorded")
        .map_err(|error| format!("failed to read candidate records: {error:?}"))?;
    let mut flags = Vec::new();
    for precedent in precedents.iter().filter(|precedent| precedent.accepted) {
        let Some(hash) = recorded
            .iter()
            .find(|event| {
                event.campaign_id == precedent.campaign
                    && event.payload.get("candidate").and_then(Value::as_str)
                        == Some(precedent.candidate.as_str())
            })
            .and_then(|event| event.payload.get("hash").and_then(Value::as_str))
        else {
            continue;
        };
        for (gauge, line) in &precedent.gauges {
            if gauge_filter.is_some_and(|filter| filter != gauge) {
                continue;
            }
            let mut rows = store
                .list_evidence(Some(gauge), None, None, Some(hash))
                .map_err(|error| format!("failed to read evidence: {error:?}"))?;
            // The reopener reads the AMBIENT stream: live rows accrued
            // after the answer. The campaign's own regen rows were the
            // evidence the answer already weighed — they reopen nothing.
            rows.retain(|row| {
                row.execution_mode == "live" && row.created_at > precedent.answered_at
            });
            rows.sort_by_key(|row| row.evidence_id);
            // Family A when the rows carry bar verdicts and the answer-time
            // operating point is rate-shaped (a chance gauge); family B
            // over raw scores otherwise. Both build the posterior
            // trajectory one informative observation at a time.
            let verdict_shaped = rows.iter().all(|row| row.passed.is_some())
                && (0.0..=1.0).contains(&line.candidate)
                && !rows.is_empty();
            let trajectory: Vec<f64> = if verdict_shaped {
                let mut passes = 0usize;
                let mut fails = 0usize;
                rows.iter()
                    .map(|row| {
                        if row.passed == Some(true) {
                            passes += 1;
                        } else {
                            fails += 1;
                        }
                        p_rate_below(passes, fails, line.candidate)
                    })
                    .collect()
            } else {
                let scores: Vec<f64> = rows.iter().map(|row| row.score).collect();
                (2..=scores.len())
                    .filter_map(|prefix| {
                        p_mean_worse(&scores[..prefix], line.candidate, line.direction_up)
                    })
                    .collect()
            };
            if trajectory.len() < SUSTAIN {
                continue;
            }
            let tail = &trajectory[trajectory.len() - SUSTAIN..];
            let sustained =
                tail.windows(2).all(|pair| pair[1] >= pair[0]) && tail[SUSTAIN - 1] >= THRESHOLD;
            if sustained {
                flags.push(ContradictionFlag {
                    gauge: gauge.clone(),
                    citation: precedent.citation(),
                    p_worse: tail[SUSTAIN - 1],
                    n: rows.len(),
                    reference: line.candidate,
                });
            }
        }
    }
    Ok(flags)
}

pub(crate) fn gauges_command(options: &CliOptions) -> ExitCode {
    let store = match open_improve_store() {
        Ok(store) => store,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let filter = options.args.first().map(String::as_str);
    let summaries = match store.evidence_summary(filter) {
        Ok(summaries) => summaries,
        Err(error) => {
            eprintln!("failed to read evidence: {error:?}");
            return ExitCode::from(2);
        }
    };
    // The ledger reopening earlier calls on its own as evidence
    // accumulates (research note §4.3) — advisory, precedent-citing.
    let contradictions = match standing_contradictions(&store, filter) {
        Ok(flags) => flags,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    if options.json {
        return emit_json(json!({
            "schema": "whipplescript.gauges.v0",
            "gauges": summaries.iter().map(|row| json!({
                "gauge": row.gauge,
                "n": row.n,
                "live": row.live,
                "regen": row.regen,
                "mean": if row.n > 0 { row.score_sum / row.n as f64 } else { 0.0 },
                "passes": row.passes,
            })).collect::<Vec<_>>(),
            "contradictions": contradictions.iter().map(|flag| json!({
                "gauge": flag.gauge,
                "precedent": flag.citation,
                "p_worse": flag.p_worse,
                "n": flag.n,
                "reference": flag.reference,
            })).collect::<Vec<_>>(),
        }));
    }
    if summaries.is_empty() {
        println!("no gauge evidence yet (runs score ambiently once gauges are declared)");
        return ExitCode::SUCCESS;
    }
    for row in &summaries {
        println!(
            "{}: mean {:.4} · N={} ({} regen · {} live) · passes={}",
            row.gauge,
            row.score_sum / (row.n.max(1)) as f64,
            row.n,
            row.regen,
            row.live,
            row.passes
        );
        for flag in contradictions.iter().filter(|flag| flag.gauge == row.gauge) {
            println!(
                "  ⚠ contradicts answered call {}: P(worse than {:.4})={:.0}% and tightening · N={} since the answer — reopen, or revoke with `whip answer`",
                flag.citation,
                flag.reference,
                flag.p_worse * 100.0,
                flag.n
            );
        }
    }
    ExitCode::SUCCESS
}

/// Ambient scoring hook, called from `whip dev` after a drive loop settles:
/// every run is an observation (research note §4.1). v1 scores the free,
/// deterministic judges (exec + builtins; labels need a scenario); prompt
/// judges are campaign-time. Failures are silent-skip by design here — the
/// ambient stream must never break a dev loop.
pub(crate) fn ambient_score_after_dev(
    store_path: &Path,
    instance_id: &str,
    ir: &IrProgram,
    json: bool,
    provider_config_paths: &[PathBuf],
    program_hash: &str,
) {
    if ir.gauges.is_empty() {
        return;
    }
    let Ok(store) = SqliteStore::open(store_path) else {
        return;
    };
    let specs = collect_gauge_specs(ir);
    // A malformed price table must not break the dev loop (ambient is
    // silent-skip by design), but it should not be silent either.
    let prices = PriceTable::load(provider_config_paths).unwrap_or_else(|error| {
        if !json {
            eprintln!("{error} (std.spend scores unpriced this run)");
        }
        PriceTable::default()
    });
    let observation = score_instance(&store, instance_id, &specs, None, true, ir, &prices);
    if observation.readings.is_empty() {
        return;
    }
    let Ok(mut improve_store) = open_improve_store() else {
        return;
    };
    for (gauge, reading) in &observation.readings {
        let scorer = specs
            .iter()
            .find(|spec| &spec.name == gauge)
            .map(|spec| scorer_label(&spec.judge))
            .unwrap_or_else(|| "unknown".to_owned());
        let _ = improve_store.record_evidence(NewEvidence {
            gauge,
            score: reading.score,
            passed: reading.passed,
            instance_id: Some(instance_id),
            // Hash-attributed so same-hash consumers (the reopener, the
            // warm scope) can fold ambient rows.
            program_hash: Some(program_hash),
            branch_ref: None,
            execution_mode: "live",
            scorer: &scorer,
            scenario: None,
            campaign_id: None,
            candidate_id: None,
            cost_micros: 0,
            tags: reading.tags.clone(),
        });
    }
    if !json {
        let rendered: Vec<String> = observation
            .readings
            .iter()
            .map(|(gauge, reading)| format!("{gauge} {:.4}", reading.score))
            .collect();
        println!("gauges scored (ambient): {}", rendered.join(" · "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_quality_no_bar(name: &str) -> GaugeSpec {
        GaugeSpec {
            name: name.to_owned(),
            judge: JudgeSpec::Exec("./judge".to_owned()),
            bar: None,
            inputs: Vec::new(),
            direction_up: true,
            builtin: false,
        }
    }

    fn spec_quality(name: &str) -> GaugeSpec {
        GaugeSpec {
            name: name.to_owned(),
            judge: JudgeSpec::Exec("./judge".to_owned()),
            bar: Some(BarSpec {
                chance_field: Some("ok".to_owned()),
                stat: None,
                ge: true,
                threshold: 0.5,
            }),
            inputs: Vec::new(),
            direction_up: true,
            builtin: false,
        }
    }

    fn observations(gauge: &str, passes: &[bool]) -> Vec<RunObservation> {
        passes
            .iter()
            .enumerate()
            .map(|(index, passed)| RunObservation {
                scenario: Some(format!("s{index}")),
                readings: BTreeMap::from([(
                    gauge.to_owned(),
                    GaugeReading {
                        score: if *passed { 1.0 } else { 0.0 },
                        passed: Some(*passed),
                        tags: Vec::new(),
                    },
                )]),
                skipped: Vec::new(),
                judge_usage: Vec::new(),
            })
            .collect()
    }

    fn merge(a: Vec<RunObservation>, b: Vec<RunObservation>) -> Vec<RunObservation> {
        a.into_iter()
            .zip(b)
            .map(|(mut left, right)| {
                left.readings.extend(right.readings);
                left
            })
            .collect()
    }

    #[test]
    fn parse_targets_and_stages() {
        let args: Vec<String> = [
            "extract_quality>=0.9",
            "then",
            "std.spend",
            "--sacrifice",
            "verbosity",
            "--within",
            "tone=2%",
            "--spend-cap",
            "$4",
            "--proposer",
            "fixture",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_improve_args(&args, &[]).expect("parses");
        assert_eq!(parsed.spec.ascend.len(), 1);
        assert_eq!(parsed.spec.ascend[0].0, "extract_quality");
        let reach = parsed.spec.ascend[0].1.as_ref().expect("reach target");
        assert!(reach.ge);
        assert!((reach.threshold - 0.9).abs() < 1e-9);
        assert_eq!(parsed.spec.later_stages.len(), 1);
        assert_eq!(parsed.spec.later_stages[0][0], "std.spend");
        assert_eq!(parsed.spec.sacrifice, vec!["verbosity"]);
        assert_eq!(parsed.spec.within_percent.get("tone"), Some(&2.0));
        assert_eq!(parsed.spec.spend_cap_micros, Some(4_000_000));
        assert!(!parsed.spec.repair);
    }

    #[test]
    fn bare_improve_is_repair_mode() {
        let parsed = parse_improve_args(&[], &[]).expect("parses");
        assert!(parsed.spec.repair);
    }

    #[test]
    fn dominance_accepts_undominated_candidate() {
        let specs = vec![spec_quality("focus"), spec_quality("guarded")];
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            ..Default::default()
        };
        let base = merge(
            observations("focus", &[false, false, false, true]),
            observations("guarded", &[true, true, true, true]),
        );
        let cand = merge(
            observations("focus", &[true, true, true, true]),
            observations("guarded", &[true, true, true, true]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(verdict.proposable, "reasons: {:?}", verdict.reasons);
        assert!(!verdict.tradeoff);
    }

    #[test]
    fn dominance_refuses_guard_regression() {
        let specs = vec![spec_quality("focus"), spec_quality_no_bar("guarded")];
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            ..Default::default()
        };
        let base = merge(
            observations("focus", &[false, false, false, false]),
            observations("guarded", &[true, true, true, true]),
        );
        let cand = merge(
            observations("focus", &[true, true, true, true]),
            observations("guarded", &[false, false, false, false]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(!verdict.proposable);
        assert!(verdict.tradeoff, "focus up + guard broken is a tradeoff");
        assert!(verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("guarded")));
    }

    #[test]
    fn dominance_sacrifice_releases_guard() {
        let specs = vec![spec_quality("focus"), spec_quality_no_bar("guarded")];
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            sacrifice: vec!["guarded".to_owned()],
            ..Default::default()
        };
        let base = merge(
            observations("focus", &[false, false, false, false]),
            observations("guarded", &[true, true, true, true]),
        );
        let cand = merge(
            observations("focus", &[true, true, true, true]),
            observations("guarded", &[false, false, false, false]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(
            verdict.proposable,
            "sacrificed regression is released: {:?}",
            verdict.reasons
        );
    }

    #[test]
    fn dominance_refuses_bar_violation() {
        let specs = vec![spec_quality("focus")];
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            ..Default::default()
        };
        // Improves from 0/4 to 1/4 — better than baseline but the declared
        // bar (>= 0.5) is still violated.
        let base = observations("focus", &[false, false, false, false]);
        let cand = observations("focus", &[true, false, false, false]);
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(!verdict.proposable, "bars are hard constraints");
    }

    #[test]
    fn resource_gauge_uses_relative_band_and_descends() {
        let spec = GaugeSpec {
            name: "std.latency".to_owned(),
            judge: JudgeSpec::Builtin,
            bar: None,
            inputs: Vec::new(),
            direction_up: false,
            builtin: true,
        };
        let base = GaugeAggregate {
            scores: vec![1000.0, 1000.0],
            passes: Vec::new(),
        };
        let better = GaugeAggregate {
            scores: vec![800.0, 800.0],
            passes: Vec::new(),
        };
        let noise = GaugeAggregate {
            scores: vec![1020.0, 1020.0],
            passes: Vec::new(),
        };
        let (verdict, _, _) = delta_verdict(&spec, &base, &better, None);
        assert_eq!(verdict, Delta::Better, "lower latency is better");
        let (verdict, _, _) = delta_verdict(&spec, &base, &noise, None);
        assert_eq!(verdict, Delta::InBand, "+2% sits inside the 5% band");
    }

    #[test]
    fn sealing_respects_floor_and_degeneracy() {
        let scenario = |name: &str| ScenarioRow {
            name: name.to_owned(),
            instance_id: "i".to_owned(),
            workflow: None,
            input_json: "{}".to_owned(),
            program_hash: None,
            mark: None,
            cut_sequence: None,
            store_path: None,
            pinned_at: String::new(),
            retired: false,
            wear: 0,
        };
        let few = vec![scenario("a"), scenario("b"), scenario("c")];
        let (open, sealed, engaged) = seal_scenarios("C-1", &few);
        assert!(!engaged, "below the floor the campaign runs unheld-out");
        assert_eq!(open.len(), 3);
        assert!(sealed.is_empty());
        let many: Vec<ScenarioRow> = (0..10)
            .map(|index| scenario(&format!("s{index}")))
            .collect();
        let (open, sealed, engaged) = seal_scenarios("C-1", &many);
        assert!(engaged);
        assert_eq!(sealed.len(), 2, "20% of 10, floor 2");
        assert_eq!(open.len(), 8);
        // Deterministic per campaign id.
        let (_, sealed_again, _) = seal_scenarios("C-1", &many);
        assert_eq!(
            sealed.iter().map(|s| &s.name).collect::<Vec<_>>(),
            sealed_again.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        // A different campaign seals a (generally) different subset — rotation.
        let (_, sealed_other, _) = seal_scenarios("C-2", &many);
        assert_ne!(
            sealed.iter().map(|s| &s.name).collect::<Vec<_>>(),
            sealed_other.iter().map(|s| &s.name).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn reflection_is_holdout_blind() {
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            ..Default::default()
        };
        let specs = vec![spec_quality("focus")];
        let open_observations = observations("focus", &[false]);
        let sealed_observations = vec![RunObservation {
            scenario: Some("sealed-secret".to_owned()),
            readings: BTreeMap::from([(
                "focus".to_owned(),
                GaugeReading {
                    score: 0.0,
                    passed: Some(false),
                    tags: Vec::new(),
                },
            )]),
            skipped: Vec::new(),
            judge_usage: Vec::new(),
        }];
        let reflection = build_reflection(
            "workflow X",
            &campaign,
            &specs,
            &open_observations,
            &sealed_observations,
            &[],
            &[],
            true,
        );
        assert!(
            !reflection.contains("sealed-secret"),
            "sealed scenario names/traces must never reach the proposer"
        );
        assert!(
            reflection.contains("Sealed holdout"),
            "aggregates over sealed scenarios are allowed"
        );
    }

    #[test]
    fn repair_mode_refuses_a_no_op_and_proposes_a_restore() {
        let specs = vec![spec_quality("focus")];
        let campaign = CampaignSpec {
            repair: true,
            ..Default::default()
        };
        // Healthy baseline, healthy candidate: nothing to repair, refuse.
        let healthy = observations("focus", &[true, true, true, true]);
        let verdict = dominance_verdict(&specs, &campaign, &healthy, &healthy);
        assert!(
            !verdict.proposable,
            "a no-op on a healthy program repairs nothing"
        );
        // Violated baseline restored by the candidate: proposable.
        let broken = observations("focus", &[false, false, false, false]);
        let restored = observations("focus", &[true, true, true, true]);
        let verdict = dominance_verdict(&specs, &campaign, &broken, &restored);
        assert!(verdict.proposable, "reasons: {:?}", verdict.reasons);
    }

    #[test]
    fn reach_target_ratchets_once_achieved() {
        let specs = vec![spec_quality("focus"), spec_quality_no_bar("helper")];
        let campaign = CampaignSpec {
            ascend: vec![
                (
                    "focus".to_owned(),
                    Some(ReachTarget {
                        ge: true,
                        threshold: 0.75,
                        raw: "0.75".to_owned(),
                    }),
                ),
                ("helper".to_owned(), None),
            ],
            ..Default::default()
        };
        // Baseline met the target (1.0 >= 0.75); the candidate improves the
        // other ascend gauge but drops focus back below the target — the
        // achieved level is a hard bound, refuse.
        let base = merge(
            observations("focus", &[true, true, true, true]),
            observations("helper", &[false, false, false, false]),
        );
        let cand = merge(
            observations("focus", &[true, true, false, false]),
            observations("helper", &[true, true, true, true]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(!verdict.proposable, "ratchet must hold the achieved reach");
        assert!(verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("ratchet")));
    }

    #[test]
    fn redacted_view_reflection_carries_no_scenario_content() {
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            redacted_view: true,
            ..Default::default()
        };
        let specs = vec![spec_quality("focus")];
        let failing = vec![RunObservation {
            scenario: Some("acme-outage-email".to_owned()),
            readings: BTreeMap::from([(
                "focus".to_owned(),
                GaugeReading {
                    score: 0.0,
                    passed: Some(false),
                    tags: Vec::new(),
                },
            )]),
            skipped: Vec::new(),
            judge_usage: Vec::new(),
        }];
        let row = ScenarioRow {
            name: "acme-outage-email".to_owned(),
            instance_id: "i".to_owned(),
            workflow: None,
            input_json: r#"{"ticket":{"body":"the acme production database is down"}}"#.to_owned(),
            program_hash: None,
            mark: None,
            cut_sequence: None,
            store_path: None,
            pinned_at: String::new(),
            retired: false,
            wear: 0,
        };
        let reflection = build_reflection(
            "workflow X",
            &campaign,
            &specs,
            &failing,
            &[],
            &[&row],
            &[],
            false,
        );
        assert!(
            !reflection.contains("acme"),
            "redacted view must carry neither scenario names nor inputs"
        );
        assert!(reflection.contains("scenario #1 fails: focus"));
        assert!(reflection.contains("redacted view"));
    }

    #[test]
    fn leakage_overlap_flags_new_verbatim_fragments_only() {
        let row = ScenarioRow {
            name: "s".to_owned(),
            instance_id: "i".to_owned(),
            workflow: None,
            input_json: r#"{"ticket":{"body":"the acme production database is down","signature":"already in the baseline prompt"}}"#
                .to_owned(),
            program_hash: None,
            mark: None,
            cut_sequence: None,
            store_path: None,
            pinned_at: String::new(),
            retired: false,
            wear: 0,
        };
        let baseline = "workflow X\n# already in the baseline prompt\n";
        let candidate =
            "workflow X\n# already in the baseline prompt\n# handle: the acme production database is down\n";
        let overlap = leakage_overlap(candidate, baseline, &[&row]);
        assert_eq!(overlap.len(), 1, "only the NEW fragment is flagged");
        assert!(overlap[0].contains("acme production database"));
        let clean = leakage_overlap(baseline, baseline, &[&row]);
        assert!(clean.is_empty());
    }

    #[test]
    fn redacted_view_flag_parses_and_tightens() {
        let args: Vec<String> = ["focus", "--redacted-view"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_improve_args(&args, &[]).expect("parses");
        assert!(parsed.spec.redacted_view);
        // A declared campaign without the clause is tightened by the flag.
        let declared = vec![(
            "release_tuning".to_owned(),
            CampaignSpec {
                ascend: vec![("focus".to_owned(), None)],
                ..Default::default()
            },
        )];
        let args: Vec<String> = ["release_tuning", "--redacted-view"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_improve_args(&args, &declared).expect("parses");
        assert!(parsed.spec.redacted_view);
        assert_eq!(parsed.spec.declared.as_deref(), Some("release_tuning"));
    }

    fn verdict_line(
        gauge: &str,
        role: &'static str,
        baseline: f64,
        candidate: f64,
        band: f64,
    ) -> GaugeVerdictLine {
        GaugeVerdictLine {
            gauge: gauge.to_owned(),
            role,
            delta: Delta::InBand,
            baseline: Some(baseline),
            candidate: Some(candidate),
            band,
            bar_met: None,
            reach_met: None,
            direction_up: true,
            p_better: None,
        }
    }

    fn precedent_from(accepted: bool, gauges: &[(&str, f64, f64, f64)]) -> Precedent {
        Precedent {
            campaign: "C-9".to_owned(),
            candidate: "K-9".to_owned(),
            accepted,
            answered_at: "2026-07-12 00:00:00".to_owned(),
            gauges: gauges
                .iter()
                .map(|(gauge, baseline, candidate, band)| {
                    (
                        (*gauge).to_owned(),
                        PrecedentGauge {
                            baseline: *baseline,
                            candidate: *candidate,
                            band: *band,
                            direction_up: true,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn precedent_dominance_grants_and_refuses() {
        // The human accepted: focus +0.3, guard -0.05 (both direction-up).
        let precedent = precedent_from(
            true,
            &[("focus", 0.5, 0.8, 0.05), ("guarded", 0.9, 0.85, 0.05)],
        );
        // A new tradeoff at least as good everywhere auto-accepts.
        let dominant = vec![
            verdict_line("focus", "ascend", 0.5, 0.85, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.86, 0.02),
        ];
        match precedent_resolution(std::slice::from_ref(&precedent), &dominant) {
            Some(PrecedentResolution::AutoAccept(citation)) => {
                assert!(citation.contains("C-9:K-9"));
            }
            other => panic!("expected auto-accept, got {other:?}"),
        }
        // Falling short of the precedent anywhere asks.
        let short = vec![
            verdict_line("focus", "ascend", 0.5, 0.85, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.80, 0.02),
        ];
        assert_eq!(
            precedent_resolution(std::slice::from_ref(&precedent), &short),
            None
        );
        // Locality: the operating point moved beyond the answer-time band.
        let moved = vec![
            verdict_line("focus", "ascend", 0.7, 0.99, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.86, 0.02),
        ];
        assert_eq!(
            precedent_resolution(std::slice::from_ref(&precedent), &moved),
            None
        );
        // Gauge-set mismatch fails closed: the precedent never covered the
        // extra gauge, so it carries no authority over it.
        let extra = vec![
            verdict_line("focus", "ascend", 0.5, 0.85, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.86, 0.02),
            verdict_line("tone", "guard", 0.9, 0.7, 0.02),
        ];
        assert_eq!(precedent_resolution(&[precedent], &extra), None);
    }

    #[test]
    fn rejected_precedent_auto_rejects_dominated_candidates_only() {
        // The human rejected: focus +0.2, guard -0.1.
        let precedent = precedent_from(
            false,
            &[("focus", 0.5, 0.7, 0.05), ("guarded", 0.9, 0.8, 0.05)],
        );
        // Strictly worse everywhere: auto-reject.
        let worse = vec![
            verdict_line("focus", "ascend", 0.5, 0.65, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.75, 0.02),
        ];
        match precedent_resolution(std::slice::from_ref(&precedent), &worse) {
            Some(PrecedentResolution::AutoReject(citation)) => {
                assert!(citation.contains("C-9:K-9"));
            }
            other => panic!("expected auto-reject, got {other:?}"),
        }
        // Better than the rejection anywhere: ask (it might be the
        // improvement the human was waiting for).
        let better = vec![
            verdict_line("focus", "ascend", 0.5, 0.9, 0.02),
            verdict_line("guarded", "guard", 0.9, 0.75, 0.02),
        ];
        assert_eq!(precedent_resolution(&[precedent], &better), None);
    }

    #[test]
    fn conflicting_precedents_carry_no_authority() {
        // An accepted and a rejected precedent that both apply and both
        // dominate: inconsistent — ask.
        let accepted = precedent_from(true, &[("focus", 0.5, 0.7, 0.05)]);
        let rejected = precedent_from(false, &[("focus", 0.5, 0.9, 0.05)]);
        let lines = vec![verdict_line("focus", "ascend", 0.5, 0.8, 0.02)];
        assert_eq!(
            precedent_resolution(&[accepted, rejected], &lines),
            None,
            "conflicting precedents must fall back to the ask"
        );
    }

    #[test]
    fn judge_arguments_resolve_against_the_record() {
        let record = json!({
            "input": {"ticket": {"id": "T-1", "title": "Fix login"}},
            "facts": [
                {"name": "Assessment", "key": "a1", "value": {"priority": "low"}},
                {"name": "Assessment", "key": "a2", "value": {"priority": "high"}},
                {"name": "Other", "key": "o1", "value": {"priority": "wrong"}},
            ],
        });
        assert_eq!(
            resolve_judge_argument("input.ticket.title", &record),
            Some(json!("Fix login"))
        );
        // The LAST recorded fact of the class wins: the run's final state.
        assert_eq!(
            resolve_judge_argument("facts.Assessment.priority", &record),
            Some(json!("high"))
        );
        assert_eq!(
            resolve_judge_argument("record", &record),
            Some(record.clone())
        );
        assert_eq!(
            resolve_judge_argument("input.ticket.missing", &record),
            None
        );
        assert_eq!(
            resolve_judge_argument("facts.Missing.priority", &record),
            None
        );
    }

    // The estimator numerics (DR-0041): checked against independently
    // computed reference values.

    #[test]
    fn incomplete_beta_and_t_cdf_match_reference_values() {
        assert!((betainc(0.5, 0.5, 0.5) - 0.5).abs() < 1e-9);
        assert!((betainc(1.0, 1.0, 0.25) - 0.25).abs() < 1e-9, "uniform CDF");
        // Symmetry: I_x(a,b) = 1 - I_{1-x}(b,a).
        let lhs = betainc(2.5, 1.5, 0.3);
        let rhs = 1.0 - betainc(1.5, 2.5, 0.7);
        assert!((lhs - rhs).abs() < 1e-9);
        assert!((student_t_cdf(0.0, 5.0) - 0.5).abs() < 1e-9);
        assert!((student_t_cdf(1.0, 10.0) - 0.829_553_4).abs() < 1e-6);
        assert!(student_t_cdf(50.0, 3.0) > 0.999);
    }

    #[test]
    fn sign_test_posterior_is_jeffreys_and_pairing_aware() {
        assert_eq!(p_better_sign(&[]), None, "no pairs, no posterior");
        // Concordant pairs are uninformative about the sign: dead even.
        let even = p_better_sign(&[(true, true), (false, false)]).expect("posterior");
        assert!((even - 0.5).abs() < 1e-9);
        // One discordant win under Jeffreys.
        let one_win = p_better_sign(&[(false, true)]).expect("posterior");
        assert!((one_win - 0.818_309_9).abs() < 1e-6);
        // Symmetric wins and losses cancel.
        let split = p_better_sign(&[(false, true), (true, false)]).expect("posterior");
        assert!((split - 0.5).abs() < 1e-9);
    }

    #[test]
    fn t_posterior_needs_scale_and_respects_direction() {
        assert_eq!(p_better_t(&[1.0], true), None, "one delta has no scale");
        // Deterministic improvement: certainty (up to float residue in
        // the mean, which can leave a ~1e-34 variance on the t path).
        assert!(p_better_t(&[0.2, 0.2, 0.2], true).expect("posterior") > 1.0 - 1e-9);
        assert!(p_better_t(&[0.2, 0.2, 0.2], false).expect("posterior") < 1e-9);
        let up = p_better_t(&[1.0, 1.2, 0.9, 1.1], true).expect("posterior");
        assert!(up > 0.99, "consistent positive deltas: {up}");
        let down = p_better_t(&[1.0, 1.2, 0.9, 1.1], false).expect("posterior");
        assert!((up + down - 1.0).abs() < 1e-9, "direction flips the tail");
    }

    #[test]
    fn contradiction_posterior_tightens_monotonically_on_sustained_failures() {
        // The reopener's family-A trajectory: each failure against a 0.9
        // answer-time operating point tightens the contradiction — the
        // sound trigger's `up` movements (contradiction-reopener.maude).
        let trajectory: Vec<f64> = (1..=3).map(|fails| p_rate_below(0, fails, 0.9)).collect();
        assert!(
            trajectory.windows(2).all(|pair| pair[1] > pair[0]),
            "monotone: {trajectory:?}"
        );
        assert!(trajectory[2] > 0.99);
        // A pass RECEDES the posterior — the streak reset.
        assert!(p_rate_below(1, 3, 0.9) < p_rate_below(0, 3, 0.9));
        // Degenerate references stay expressible (clamped off 1.0).
        assert!(p_rate_below(0, 3, 1.0) < 1.0);
    }

    #[test]
    fn price_table_prices_at_record_time_and_refuses_malformed_entries() {
        let dir = std::env::temp_dir().join(format!("whip-prices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("providers.json");
        std::fs::write(
            &path,
            r#"{"providers": [], "prices": [
                {"provider": "anthropic", "model": "claude-sonnet-5",
                 "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0}
            ]}"#,
        )
        .expect("write config");
        let table = PriceTable::load(std::slice::from_ref(&path)).expect("loads");
        let usage = TurnUsage {
            provider: "anthropic".to_owned(),
            model: "claude-sonnet-5".to_owned(),
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            cache_read_tokens: None,
            cache_write_tokens: None,
            total_tokens: 1_100_000,
        };
        // 1 Mtok in at $3 + 0.1 Mtok out at $15 = $4.50 = 4_500_000 micros.
        assert_eq!(table.cost_micros(&usage), Some(4_500_000));
        // No table entry (or no split) is unpriced, never zero-priced.
        let unknown = TurnUsage {
            model: "other".to_owned(),
            ..usage.clone()
        };
        assert_eq!(table.cost_micros(&unknown), None);
        let unsplit = TurnUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 500,
            ..usage
        };
        assert_eq!(table.cost_micros(&unsplit), None);
        // A malformed entry is an error — the user wrote a table and
        // deserves to know it is not being used.
        std::fs::write(
            &path,
            r#"{"prices": [{"provider": "anthropic", "model": "m", "input_per_mtok_usd": 3.0}]}"#,
        )
        .expect("write config");
        assert!(PriceTable::load(&[path]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_normalizes_cache_fields_by_wire_shape_not_provider_name() {
        // Anthropic shape: `input_tokens` EXCLUDES cache traffic; cache fields
        // are separate and disjoint. No `total_tokens` on the wire.
        let anthropic = TurnUsage::from_usage_json(
            "anthropic",
            "claude-sonnet-5",
            &json!({
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 900,
                "cache_creation_input_tokens": 200,
            }),
        );
        assert_eq!(anthropic.input_tokens, 100);
        assert_eq!(anthropic.cache_read_tokens, Some(900));
        assert_eq!(anthropic.cache_write_tokens, Some(200));
        assert_eq!(anthropic.total_tokens, 1250, "disjoint sum incl. cache");
        assert_eq!(anthropic.input_side_tokens(), 1200);

        // OpenAI chat shape: `prompt_tokens` INCLUDES the cached subset —
        // normalize by subtraction so the buckets stay disjoint.
        let openai_chat = TurnUsage::from_usage_json(
            "openai-generic",
            "gpt-4o-mini",
            &json!({
                "prompt_tokens": 1000,
                "completion_tokens": 50,
                "total_tokens": 1050,
                "prompt_tokens_details": { "cached_tokens": 900 },
            }),
        );
        assert_eq!(openai_chat.input_tokens, 100, "uncached = prompt - cached");
        assert_eq!(openai_chat.cache_read_tokens, Some(900));
        assert_eq!(
            openai_chat.cache_write_tokens, None,
            "OpenAI has no write bill"
        );
        assert_eq!(openai_chat.total_tokens, 1050, "provider total kept");

        // OpenAI Responses shape: `input_tokens` + `input_tokens_details`.
        let openai_responses = TurnUsage::from_usage_json(
            "openai",
            "gpt-4o",
            &json!({
                "input_tokens": 1000,
                "output_tokens": 20,
                "input_tokens_details": { "cached_tokens": 600 },
            }),
        );
        assert_eq!(openai_responses.input_tokens, 400);
        assert_eq!(openai_responses.cache_read_tokens, Some(600));

        // No cache fields at all: an honest None, not a fake zero — and the
        // legacy plain shape parses exactly as before.
        let plain = TurnUsage::from_usage_json(
            "fixture",
            "",
            &json!({ "input_tokens": 10, "output_tokens": 5 }),
        );
        assert_eq!(plain.cache_read_tokens, None);
        assert_eq!(plain.cache_write_tokens, None);
        assert_eq!(plain.total_tokens, 15);
    }

    #[test]
    fn cache_rates_price_cache_traffic_and_default_to_the_input_rate() {
        let dir = std::env::temp_dir().join(format!("whip-cache-prices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("providers.json");
        // Entry WITH explicit cache rates (the Anthropic-style discount).
        std::fs::write(
            &path,
            r#"{"prices": [
                {"provider": "anthropic", "model": "m",
                 "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0,
                 "cache_read_per_mtok_usd": 0.3, "cache_write_per_mtok_usd": 3.75}
            ]}"#,
        )
        .expect("write config");
        let table = PriceTable::load(std::slice::from_ref(&path)).expect("loads");
        let usage = TurnUsage {
            provider: "anthropic".to_owned(),
            model: "m".to_owned(),
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_read_tokens: Some(1_000_000),
            cache_write_tokens: Some(1_000_000),
            total_tokens: 3_000_000,
        };
        // 1M in at $3 + 1M cache-read at $0.30 + 1M cache-write at $3.75.
        assert_eq!(table.cost_micros(&usage), Some(7_050_000));

        // Entry WITHOUT cache rates: cache traffic prices at the input rate —
        // a conservative overestimate (providers discount reads), never $0.
        std::fs::write(
            &path,
            r#"{"prices": [
                {"provider": "anthropic", "model": "m",
                 "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0}
            ]}"#,
        )
        .expect("write config");
        let table = PriceTable::load(std::slice::from_ref(&path)).expect("loads");
        assert_eq!(table.cost_micros(&usage), Some(9_000_000));

        // Cache-only usage (fully cached prompt) is priceable, not unpriced.
        let cache_only = TurnUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: Some(500_000),
            cache_write_tokens: None,
            ..usage
        };
        assert_eq!(table.cost_micros(&cache_only), Some(1_500_000));

        // A malformed cache rate is a hard error like any malformed entry.
        std::fs::write(
            &path,
            r#"{"prices": [
                {"provider": "anthropic", "model": "m",
                 "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0,
                 "cache_read_per_mtok_usd": -1.0}
            ]}"#,
        )
        .expect("write config");
        assert!(PriceTable::load(&[path]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_rate_reads_out_only_when_a_provider_reports_caching() {
        let run = |provider: &str, metadata: Value| whipplescript_store::RunView {
            run_id: "r".to_owned(),
            effect_id: "e".to_owned(),
            provider: provider.to_owned(),
            worker_id: "w".to_owned(),
            status: "succeeded".to_owned(),
            started_at: String::new(),
            completed_at: None,
            metadata_json: metadata.to_string(),
            cancel_requested: false,
        };
        // 900 cache-read of 1200 input-side across the cached run; the
        // cache-blind run adds 300 uncached input-side tokens.
        let cached = run(
            "anthropic",
            json!({"usage": {"input_tokens": 100, "output_tokens": 10,
                              "cache_read_input_tokens": 900,
                              "cache_creation_input_tokens": 200}}),
        );
        let blind = run(
            "fixture",
            json!({"usage": {"input_tokens": 300, "output_tokens": 10}}),
        );
        let rate = total_cache_hit_rate(&[cached, blind.clone()]).expect("cache reported");
        assert!((rate - 900.0 / 1500.0).abs() < 1e-9, "rate {rate}");
        // No run reports cache fields -> honest absence, not a fake 0%.
        assert_eq!(total_cache_hit_rate(&[blind]), None);
    }

    #[test]
    fn spend_reading_is_strict_about_unpriced_usage() {
        let run = |provider: &str, metadata: Value| whipplescript_store::RunView {
            run_id: "r".to_owned(),
            effect_id: "e".to_owned(),
            provider: provider.to_owned(),
            worker_id: "w".to_owned(),
            status: "succeeded".to_owned(),
            started_at: String::new(),
            completed_at: None,
            metadata_json: metadata.to_string(),
            cancel_requested: false,
        };
        let mut table = PriceTable::default();
        table.rates.insert(
            ("anthropic".to_owned(), "claude-sonnet-5".to_owned()),
            PriceRate {
                input: 3.0,
                output: 15.0,
                cache_read: None,
                cache_write: None,
            },
        );
        let priced = run(
            "anthropic",
            json!({"model": "claude-sonnet-5",
                   "usage": {"input_tokens": 1_000_000, "output_tokens": 0}}),
        );
        let no_usage = run("fixture", json!({"note": "no tokens"}));
        assert_eq!(
            total_spend_usd(&[priced.clone(), no_usage.clone()], &table).expect("prices"),
            Some(3.0),
            "usage-free runs do not block pricing"
        );
        assert_eq!(
            total_spend_usd(&[no_usage], &table).expect("no usage at all"),
            None,
            "no usage anywhere = absent, never fabricated"
        );
        // One unpriceable usage-bearing run poisons the total: a partial
        // sum must not wear a full one.
        let unpriceable = run(
            "anthropic",
            json!({"usage": {"input_tokens": 5, "output_tokens": 5}}),
        );
        assert!(total_spend_usd(&[priced, unpriceable], &table).is_err());
    }

    #[test]
    fn campaign_spec_roundtrips_through_the_record() {
        let mut spec = CampaignSpec {
            ascend: vec![
                ("quality".to_owned(), None),
                (
                    "speed".to_owned(),
                    Some(ReachTarget {
                        ge: false,
                        threshold: 800.0,
                        raw: "800ms".to_owned(),
                    }),
                ),
            ],
            later_stages: vec![vec!["std.spend<=0.10".to_owned()]],
            sacrifice: vec!["verbosity".to_owned()],
            spend_cap_micros: Some(4_000_000),
            redacted_view: true,
            ..Default::default()
        };
        spec.floors.insert("held".to_owned(), (true, 0.9));
        spec.within_percent.insert("tone".to_owned(), 2.0);
        let roundtripped = campaign_spec_from_json(&spec.to_json()).expect("roundtrips");
        assert_eq!(roundtripped.ascend.len(), 2);
        assert_eq!(roundtripped.ascend[1].0, "speed");
        let reach = roundtripped.ascend[1].1.as_ref().expect("reach");
        assert!(!reach.ge);
        assert!((reach.threshold - 800.0).abs() < 1e-9);
        assert_eq!(roundtripped.later_stages, spec.later_stages);
        assert_eq!(roundtripped.floors.get("held"), Some(&(true, 0.9)));
        assert_eq!(roundtripped.within_percent.get("tone"), Some(&2.0));
        assert_eq!(roundtripped.spend_cap_micros, Some(4_000_000));
        assert!(roundtripped.redacted_view);
        assert_eq!(roundtripped.sacrifice, spec.sacrifice);
    }

    #[test]
    fn stage_ratchet_floor_refuses_regression_inside_the_band() {
        // A completed `then` stage's achieved level is a HARD floor for
        // later stages: a candidate slipping past it refuses even when the
        // movement sits inside a generous indifference band.
        let specs = vec![spec_quality_no_bar("focus"), spec_quality_no_bar("held")];
        let campaign = CampaignSpec {
            ascend: vec![("focus".to_owned(), None)],
            floors: BTreeMap::from([("held".to_owned(), (true, 1.0))]),
            within_percent: BTreeMap::from([("held".to_owned(), 50.0)]),
            ..Default::default()
        };
        let base = merge(
            observations("focus", &[false, false, false, false]),
            observations("held", &[true, true, true, true]),
        );
        let cand = merge(
            observations("focus", &[true, true, true, true]),
            observations("held", &[true, true, true, false]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &cand);
        assert!(
            !verdict.proposable,
            "the floor refuses in-band regression: {:?}",
            verdict.reasons
        );
        assert!(
            verdict
                .reasons
                .iter()
                .any(|reason| reason.contains("stage-ratchet floor")),
            "the refusal names the floor: {:?}",
            verdict.reasons
        );

        // Holding the floor exactly is not a violation.
        let holding = merge(
            observations("focus", &[true, true, true, true]),
            observations("held", &[true, true, true, true]),
        );
        let verdict = dominance_verdict(&specs, &campaign, &base, &holding);
        assert!(
            verdict.proposable,
            "holding the floor passes: {:?}",
            verdict.reasons
        );
    }

    #[test]
    fn later_stage_tokens_keep_their_targets() {
        let args: Vec<String> = ["extract_quality>=0.9", "then", "std.latency<=800ms"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_improve_args(&args, &[]).expect("parses");
        assert_eq!(parsed.spec.later_stages, vec![vec!["std.latency<=800ms"]]);
        let (name, reach) = parse_target(&parsed.spec.later_stages[0][0]).expect("re-parses");
        assert_eq!(name, "std.latency");
        let reach = reach.expect("target survives to stage activation");
        assert!(!reach.ge);
        assert!((reach.threshold - 800.0).abs() < 1e-9);
    }

    // The SettleWalk tests mirror models/maude/settle-stopping.maude: the
    // sound certifier never mints a certificate below the threshold, and
    // exhaustion below it is an honest undetermined.

    #[test]
    fn settle_walk_contrary_bound_never_crosses() {
        // strong;contrary;strong;contrary with K=3 — the model's bite
        // stream: the level never reaches the threshold.
        let mut walk = SettleWalk::new(3);
        for strong in [true, false, true, false] {
            assert!(!walk.observe(strong), "below-threshold stream certified");
        }
        assert_eq!(walk.level, 0);
        assert_eq!(walk.high_water, 1);
        assert_eq!(walk.n, 4);
    }

    #[test]
    fn settle_walk_sustained_evidence_crosses_at_threshold() {
        // The crossing is anytime-valid: it happens exactly at K, needing
        // no exhaustion of the remaining stream.
        let mut walk = SettleWalk::new(3);
        assert!(!walk.observe(true));
        assert!(!walk.observe(true));
        assert!(walk.observe(true), "third strong observation crosses K=3");
        assert_eq!(walk.n, 3);
    }

    #[test]
    fn settle_walk_floors_contrary_evidence_at_zero() {
        let mut walk = SettleWalk::new(2);
        walk.observe(false);
        walk.observe(false);
        assert_eq!(walk.level, 0, "contrary evidence floors at zero");
        walk.observe(true);
        assert!(walk.observe(true), "the floor does not owe a debt");
    }

    #[test]
    fn bar_stat_quantiles() {
        let aggregate = GaugeAggregate {
            scores: (1..=100).map(|value| value as f64).collect(),
            passes: Vec::new(),
        };
        let bar = BarSpec {
            chance_field: None,
            stat: Some("p90".to_owned()),
            ge: false,
            threshold: 95.0,
        };
        let value = bar_stat(&aggregate, &bar).expect("p90 computes");
        assert!((value - 90.0).abs() <= 1.0);
        assert_eq!(bar_met(&aggregate, &bar), Some(true));
    }

    #[test]
    fn unpriced_spend_under_a_cap_is_surfaced_not_silent() {
        // A `--spend-cap` binds only priced cost; with arbitrary OpenAI-compatible
        // models now easy to wire, a paid-but-unpriced model records $0 and the cap
        // silently never binds. The campaign must flag that in the record.
        let mut store = ImproveStore::open_in_memory().expect("open");
        let flagged = |store: &ImproveStore, campaign: &str| {
            store
                .list_campaign_events(campaign)
                .expect("events")
                .iter()
                .any(|event| event.event_type == "campaign.spend_cap_unpriced")
        };

        // A priced proposer turn + an UNPRICED workflow turn, under a cap.
        let with_unpriced = store
            .open_campaign(&json!({ "goal": "cap-unpriced" }))
            .expect("open campaign");
        store
            .append_campaign_event(
                &with_unpriced,
                "campaign.spend",
                &json!({ "cost_micros": 1000, "priced": true, "what": "proposer turn" }),
            )
            .expect("priced event");
        store
            .append_campaign_event(
                &with_unpriced,
                "campaign.spend",
                &json!({ "cost_micros": 0, "priced": false, "tokens": 5000,
                         "unpriced_turns": 1, "what": "workflow turns (baseline)" }),
            )
            .expect("unpriced event");
        warn_on_unpriced_spend_under_cap(&mut store, &with_unpriced, Some(5_000_000));
        assert!(
            flagged(&store, &with_unpriced),
            "unpriced spend under a cap must record a spend_cap_unpriced event"
        );

        // No cap -> nothing to enforce, no flag even with unpriced usage.
        let no_cap = store
            .open_campaign(&json!({ "goal": "no-cap" }))
            .expect("open");
        store
            .append_campaign_event(
                &no_cap,
                "campaign.spend",
                &json!({ "cost_micros": 0, "priced": false, "what": "workflow turns" }),
            )
            .expect("event");
        warn_on_unpriced_spend_under_cap(&mut store, &no_cap, None);
        assert!(!flagged(&store, &no_cap), "no cap -> no unpriced flag");

        // All priced under a cap -> no flag.
        let all_priced = store
            .open_campaign(&json!({ "goal": "priced" }))
            .expect("open");
        store
            .append_campaign_event(
                &all_priced,
                "campaign.spend",
                &json!({ "cost_micros": 42, "priced": true, "what": "proposer turn" }),
            )
            .expect("event");
        warn_on_unpriced_spend_under_cap(&mut store, &all_priced, Some(1_000_000));
        assert!(
            !flagged(&store, &all_priced),
            "all priced -> no unpriced flag"
        );
    }
}
