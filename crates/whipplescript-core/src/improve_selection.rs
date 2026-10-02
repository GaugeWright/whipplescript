//! Pure, host-neutral regularization for a paired improve comparison.
//! A host supplies gauge readings from its own governed harness; neither
//! package execution nor adoption authority lives in this module.

use std::collections::{BTreeMap, BTreeSet};

const RESOURCE_BAND_PERCENT: f64 = 5.0;
const QUALITY_BAND_FLOOR: f64 = 0.02;

#[derive(Clone, Debug)]
pub struct Reading {
    pub score: f64,
    pub passed: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct Bar {
    pub chance: bool,
    pub stat: Option<String>,
    pub ge: bool,
    pub threshold: f64,
}

#[derive(Clone, Debug)]
pub struct GaugeEvidence {
    pub name: String,
    pub direction_up: bool,
    pub resource: bool,
    pub bar: Option<Bar>,
    pub baseline: Vec<Reading>,
    pub candidate: Vec<Reading>,
    /// The host proved that the candidate has no denominator for this metric.
    /// It stays unmeasured on the card, but an unnamed guard does not fail
    /// closed merely because a ratio stopped applying.
    pub candidate_not_applicable: bool,
}

#[derive(Clone, Debug)]
pub struct Reach {
    pub ge: bool,
    pub threshold: f64,
}

#[derive(Clone, Debug, Default)]
pub struct Campaign {
    pub ascend: BTreeMap<String, Option<Reach>>,
    pub sacrifice: BTreeSet<String>,
    pub within_percent: BTreeMap<String, f64>,
    pub floors: BTreeMap<String, (bool, f64)>,
    pub repair: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delta {
    Better,
    InBand,
    Worse,
    Unmeasured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Ascend,
    Sacrifice,
    Guard,
}

#[derive(Clone, Debug)]
pub struct GaugeVerdict {
    pub gauge: String,
    pub role: Role,
    pub delta: Delta,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub band: f64,
    pub bar_met: Option<bool>,
    pub reach_met: Option<bool>,
    pub direction_up: bool,
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub lines: Vec<GaugeVerdict>,
    pub proposable: bool,
    pub tradeoff: bool,
    pub reasons: Vec<String>,
}

#[derive(Default)]
struct Aggregate {
    scores: Vec<f64>,
    passes: Vec<bool>,
}

impl Aggregate {
    fn from(readings: &[Reading]) -> Self {
        Self {
            scores: readings.iter().map(|reading| reading.score).collect(),
            passes: readings
                .iter()
                .filter_map(|reading| reading.passed)
                .collect(),
        }
    }

    fn n(&self) -> usize {
        self.scores.len()
    }

    fn mean(&self) -> Option<f64> {
        (!self.scores.is_empty())
            .then(|| self.scores.iter().sum::<f64>() / self.scores.len() as f64)
    }

    fn pass_rate(&self) -> Option<f64> {
        (!self.passes.is_empty()).then(|| {
            self.passes.iter().filter(|pass| **pass).count() as f64 / self.passes.len() as f64
        })
    }

    fn operating_point(&self) -> Option<f64> {
        self.pass_rate().or_else(|| self.mean())
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

    fn bar_stat(&self, bar: &Bar) -> Option<f64> {
        if bar.chance {
            return self.pass_rate();
        }
        match bar.stat.as_deref() {
            Some("mean") | None => self.mean(),
            Some(stat) => self.quantile(stat.strip_prefix('p')?.parse::<f64>().ok()? / 100.0),
        }
    }

    fn bar_met(&self, bar: &Bar) -> Option<bool> {
        let value = self.bar_stat(bar)?;
        Some(if bar.ge {
            value >= bar.threshold
        } else {
            value <= bar.threshold
        })
    }
}

fn band(
    gauge: &GaugeEvidence,
    baseline: &Aggregate,
    candidate: &Aggregate,
    override_percent: Option<f64>,
    baseline_point: f64,
) -> f64 {
    if let Some(percent) = override_percent {
        return (baseline_point.abs() * percent / 100.0).max(f64::EPSILON);
    }
    if gauge.resource {
        return (baseline_point.abs() * RESOURCE_BAND_PERCENT / 100.0).max(f64::EPSILON);
    }
    let se = |aggregate: &Aggregate| -> f64 {
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
    let pooled = (se(baseline).powi(2) + se(candidate).powi(2)).sqrt();
    (1.96 * pooled).max(QUALITY_BAND_FLOOR)
}

fn delta(
    gauge: &GaugeEvidence,
    baseline: &Aggregate,
    candidate: &Aggregate,
    override_percent: Option<f64>,
) -> (Delta, f64) {
    let (Some(before), Some(after)) = (baseline.operating_point(), candidate.operating_point())
    else {
        return (Delta::Unmeasured, 0.0);
    };
    let band = band(gauge, baseline, candidate, override_percent, before);
    let signed = if gauge.direction_up {
        after - before
    } else {
        before - after
    };
    let verdict = if signed > band {
        Delta::Better
    } else if signed < -band {
        Delta::Worse
    } else {
        Delta::InBand
    };
    (verdict, band)
}

/// Apply the same dominance and bar rule regardless of which harness produced
/// the readings. Inputs must already be paired by comparable scenario and
/// governed execution; a host must not pass an incomparable arm here.
pub fn select(gauges: &[GaugeEvidence], campaign: &Campaign) -> Verdict {
    let mut lines = Vec::new();
    let mut reasons = Vec::new();
    let mut focus_up = false;
    let mut focus_down = false;
    let mut guard_broken = false;
    let mut bar_violated = false;
    let mut bar_restored = false;
    for gauge in gauges {
        let baseline = Aggregate::from(&gauge.baseline);
        let candidate = Aggregate::from(&gauge.candidate);
        if baseline.n() == 0 && candidate.n() == 0 {
            continue;
        }
        let (movement, band) = delta(
            gauge,
            &baseline,
            &candidate,
            campaign.within_percent.get(&gauge.name).copied(),
        );
        let bar_met = gauge.bar.as_ref().and_then(|bar| candidate.bar_met(bar));
        let baseline_bar = gauge.bar.as_ref().and_then(|bar| baseline.bar_met(bar));
        if bar_met == Some(false) {
            bar_violated = true;
            reasons.push(format!("`{}` violates its declared bar", gauge.name));
        }
        if baseline_bar == Some(false) && bar_met == Some(true) {
            bar_restored = true;
        }
        let reach = campaign.ascend.get(&gauge.name).and_then(Option::as_ref);
        let reach_met = reach.and_then(|reach| {
            candidate.operating_point().map(|point| {
                if reach.ge {
                    point >= reach.threshold
                } else {
                    point <= reach.threshold
                }
            })
        });
        let role = if campaign.ascend.contains_key(&gauge.name) {
            match movement {
                Delta::Better => focus_up = true,
                Delta::Worse => {
                    focus_down = true;
                    reasons.push(format!("`{}` regressed (its own focus)", gauge.name));
                }
                _ => {}
            }
            if let Some(reach) = reach {
                let baseline_met = baseline.operating_point().map(|point| {
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
                        gauge.name
                    ));
                }
            }
            Role::Ascend
        } else if campaign.sacrifice.contains(&gauge.name) {
            Role::Sacrifice
        } else {
            if let Some((ge, floor)) = campaign.floors.get(&gauge.name) {
                if let Some(point) = candidate.operating_point() {
                    let held = if *ge {
                        point >= *floor
                    } else {
                        point <= *floor
                    };
                    if !held {
                        bar_violated = true;
                        reasons.push(format!(
                            "`{}` fell past its stage-ratchet floor (achieved by a completed `then` stage)",
                            gauge.name
                        ));
                    }
                }
            }
            if movement == Delta::Worse {
                guard_broken = true;
                reasons.push(format!(
                    "`{}` regressed beyond its indifference band and was not sacrificed",
                    gauge.name
                ));
            }
            if movement == Delta::Unmeasured
                && baseline.n() > 0
                && candidate.n() == 0
                && !gauge.candidate_not_applicable
            {
                guard_broken = true;
                reasons.push(format!(
                    "`{}` became unmeasurable on the candidate (guarded gauges fail closed)",
                    gauge.name
                ));
            }
            Role::Guard
        };
        lines.push(GaugeVerdict {
            gauge: gauge.name.clone(),
            role,
            delta: movement,
            baseline: baseline.operating_point(),
            candidate: candidate.operating_point(),
            band,
            bar_met,
            reach_met,
            direction_up: gauge.direction_up,
        });
    }
    let proposable = if campaign.repair {
        bar_restored && !bar_violated && !guard_broken
    } else {
        focus_up && !focus_down && !guard_broken && !bar_violated
    };
    Verdict {
        lines,
        proposable,
        tradeoff: focus_up && guard_broken && !bar_violated && !focus_down,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauge(name: &str, before: &[f64], after: &[f64]) -> GaugeEvidence {
        let readings = |values: &[f64]| {
            values
                .iter()
                .map(|score| Reading {
                    score: *score,
                    passed: None,
                })
                .collect()
        };
        GaugeEvidence {
            name: name.to_owned(),
            direction_up: true,
            resource: false,
            bar: None,
            baseline: readings(before),
            candidate: readings(after),
            candidate_not_applicable: false,
        }
    }

    #[test]
    fn resource_gauge_descends_outside_its_relative_band() {
        let mut latency = gauge("std.latency", &[1000.0, 1000.0], &[800.0, 800.0]);
        latency.direction_up = false;
        latency.resource = true;
        let campaign = Campaign {
            ascend: BTreeMap::from([("std.latency".to_owned(), None)]),
            ..Default::default()
        };
        let better = select(&[latency.clone()], &campaign);
        assert!(better.proposable);
        assert_eq!(better.lines[0].delta, Delta::Better);
        assert_eq!(better.lines[0].band, 50.0);
        latency.candidate = vec![
            Reading {
                score: 1020.0,
                passed: None
            };
            2
        ];
        let noise = select(&[latency], &campaign);
        assert!(!noise.proposable);
        assert_eq!(noise.lines[0].delta, Delta::InBand);
    }

    #[test]
    fn quantile_bar_and_guarded_regression_refuse_focus_gain() {
        let mut focus = gauge("quality", &[1.0, 1.0], &[2.0, 2.0]);
        focus.bar = Some(Bar {
            chance: false,
            stat: Some("p90".to_owned()),
            ge: true,
            threshold: 1.5,
        });
        let guard = gauge("tone", &[1.0, 1.0], &[0.0, 0.0]);
        let campaign = Campaign {
            ascend: BTreeMap::from([("quality".to_owned(), None)]),
            ..Default::default()
        };
        let result = select(&[focus, guard], &campaign);
        assert!(!result.proposable);
        assert!(result.tradeoff);
        assert_eq!(result.lines[0].bar_met, Some(true));
        assert_eq!(result.lines[1].role, Role::Guard);
        assert_eq!(result.lines[1].delta, Delta::Worse);
    }

    #[test]
    fn percentile_bar_uses_the_declared_operating_statistic() {
        let mut distribution = gauge(
            "latency",
            &(1..=100).map(|value| value as f64).collect::<Vec<_>>(),
            &(1..=100).map(|value| value as f64).collect::<Vec<_>>(),
        );
        distribution.bar = Some(Bar {
            chance: false,
            stat: Some("p90".to_owned()),
            ge: true,
            threshold: 75.0,
        });
        let result = select(&[distribution], &Campaign::default());
        assert_eq!(result.lines[0].bar_met, Some(true));
        assert!((result.lines[0].baseline.unwrap() - 50.5).abs() < 1e-9);
    }

    #[test]
    fn chance_bar_uses_pass_rate_even_when_scores_move() {
        let mut quality = gauge("quality", &[0.0, 0.0], &[100.0, 100.0]);
        quality
            .baseline
            .iter_mut()
            .for_each(|reading| reading.passed = Some(false));
        quality
            .candidate
            .iter_mut()
            .for_each(|reading| reading.passed = Some(false));
        quality.bar = Some(Bar {
            chance: true,
            stat: None,
            ge: true,
            threshold: 0.5,
        });
        let campaign = Campaign {
            ascend: BTreeMap::from([("quality".to_owned(), None)]),
            ..Default::default()
        };
        let result = select(&[quality], &campaign);
        assert_eq!(result.lines[0].bar_met, Some(false));
        assert!(!result.proposable);
    }

    #[test]
    fn repair_requires_restored_bar_without_guard_regression() {
        let mut quality = gauge("quality", &[0.0, 0.0], &[1.0, 1.0]);
        quality.bar = Some(Bar {
            chance: false,
            stat: Some("mean".to_owned()),
            ge: true,
            threshold: 0.9,
        });
        let campaign = Campaign {
            repair: true,
            ..Default::default()
        };
        assert!(select(&[quality.clone()], &campaign).proposable);
        quality.candidate = quality.baseline.clone();
        assert!(!select(&[quality], &campaign).proposable);
    }

    #[test]
    fn baseline_measured_guard_becoming_unmeasurable_fails_closed() {
        let guard = gauge("guard", &[1.0, 1.0], &[]);
        let result = select(&[guard], &Campaign::default());
        assert!(!result.proposable);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.contains("unmeasurable")));
    }

    #[test]
    fn proven_zero_denominator_does_not_block_an_independent_resource_gain() {
        let mut tokens = gauge("std.tokens", &[200.0, 200.0], &[0.0, 0.0]);
        tokens.direction_up = false;
        tokens.resource = true;
        let mut cache = gauge("std.cache_hit", &[0.5, 0.5], &[]);
        cache.resource = true;
        cache.candidate_not_applicable = true;
        let campaign = Campaign {
            ascend: BTreeMap::from([("std.tokens".to_owned(), None)]),
            ..Default::default()
        };
        let result = select(&[tokens, cache], &campaign);
        assert!(result.proposable, "{:?}", result.reasons);
        assert_eq!(result.lines[1].delta, Delta::Unmeasured);
        assert_eq!(result.lines[1].candidate, None);
    }
}
