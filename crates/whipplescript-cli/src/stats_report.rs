//! `whip stats` — the read-side aggregate over the durable log.
//!
//! DR-0114 decides that an aggregate is a pure fold over records already kept
//! durably; the fold itself lives in `whipplescript_kernel::stats` so the CLI,
//! the hosted host and a fixture assertion can run the same code. This module
//! is the surface: argument parsing, the store read, and the two renderings.
//!
//! `use super::*` keeps the imports and sibling helpers this resolves against,
//! matching the other extracted command modules.

use super::*;
use whipplescript_kernel::stats::{
    self, Dimension, EffectInput, InstanceInput, Measure, Measures, Query, Row, RunInput,
};

const USAGE: &str = "usage: whip [--store path] [--json] stats [<instance>]\n  \
    [--program <program-id>] [--since <rfc3339>] [--until <rfc3339>] [--by <dim>[,<dim>...]]\n  \
    a fold over the durable log: token, call and retry measures grouped by structural\n  \
    identifiers only — never a fact value, an effect target, or effect input (DR-0117).\n  \
    `grain` is always in the group key, so a row never mixes a population where a\n  \
    measure is recorded with one where it is not (DR-0116)";

#[derive(Debug)]
struct StatsOptions {
    instance_id: Option<String>,
    program_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    by: Vec<Dimension>,
}

impl StatsOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut instance_id = None;
        let mut program_id = None;
        let mut since = None;
        let mut until = None;
        let mut by: Vec<Dimension> = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--program" => {
                    let Some(value) = iter.next() else {
                        return Err("expected a program id after `--program`".to_owned());
                    };
                    program_id = Some(value.clone());
                }
                "--since" => {
                    let Some(value) = iter.next() else {
                        return Err("expected a timestamp after `--since`".to_owned());
                    };
                    since = Some(value.clone());
                }
                "--until" => {
                    let Some(value) = iter.next() else {
                        return Err("expected a timestamp after `--until`".to_owned());
                    };
                    until = Some(value.clone());
                }
                "--by" => {
                    let Some(value) = iter.next() else {
                        return Err("expected a dimension list after `--by`".to_owned());
                    };
                    for name in value.split(',') {
                        let name = name.trim();
                        if name.is_empty() {
                            continue;
                        }
                        // The DR-0117 refusal. One membership check, in the
                        // kernel, so the vocabulary is stated once and the
                        // refusal is one site the sweep can reach.
                        let dimension = Dimension::parse(name)?;
                        if !by.contains(&dimension) {
                            by.push(dimension);
                        }
                    }
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown stats option `{other}`"));
                }
                value if instance_id.is_none() => instance_id = Some(value.to_owned()),
                extra => {
                    // Its own message rather than the shared usage constant: a
                    // refusal that returns a value some other refusal also
                    // returns cannot be mutated into a distinct failure, so the
                    // sweep reports it UNMEASURED, which fails like unexercised.
                    return Err(format!(
                        "stats takes at most one instance id; got `{extra}` after `{}`",
                        instance_id.as_deref().unwrap_or("")
                    ));
                }
            }
        }
        Ok(Self {
            instance_id,
            program_id,
            since,
            until,
            by,
        })
    }
}

pub(crate) fn stats(options: &CliOptions) -> ExitCode {
    let parsed = match StatsOptions::parse(&options.args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let store = match open_observation_store_or_exit(options) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let instances = match store.list_instances() {
        Ok(instances) => instances,
        Err(error) => return report_store_error("failed to list instances", error),
    };

    let mut instance_inputs = Vec::new();
    let mut effect_inputs = Vec::new();
    let mut run_inputs = Vec::new();
    for instance in &instances {
        if parsed
            .instance_id
            .as_deref()
            .is_some_and(|wanted| wanted != instance.instance_id)
        {
            continue;
        }
        instance_inputs.push(InstanceInput {
            instance_id: instance.instance_id.clone(),
            program_id: instance.program_id.clone(),
            program_version_id: instance.version_id.clone(),
        });
        let effects = match store.list_effects(&instance.instance_id) {
            Ok(effects) => effects,
            Err(error) => return report_store_error("failed to list effects", error),
        };
        for effect in effects {
            effect_inputs.push(EffectInput {
                effect_id: effect.effect_id,
                instance_id: instance.instance_id.clone(),
                kind: effect.kind,
                status: effect.status,
                created_by_rule: effect.created_by_rule,
                program_version_id: effect.program_version_id,
                revision_epoch: effect.revision_epoch,
                profile: effect.profile,
                policy_block_category: effect.policy_block_category,
            });
        }
        let runs = match store.list_runs(&instance.instance_id) {
            Ok(runs) => runs,
            Err(error) => return report_store_error("failed to list runs", error),
        };
        for run in runs {
            run_inputs.push(RunInput {
                run_id: run.run_id,
                effect_id: run.effect_id,
                provider: run.provider,
                status: run.status,
                started_at: run.started_at,
                completed_at: run.completed_at,
                metadata_json: run.metadata_json,
            });
        }
    }

    let query = Query {
        by: parsed.by,
        instance_id: parsed.instance_id,
        program_id: parsed.program_id,
        since: parsed.since,
        until: parsed.until,
    };
    let rows = stats::fold(&instance_inputs, &effect_inputs, &run_inputs).rows(&query);

    if options.json {
        emit_json(json!({
            "schema": "whipplescript.stats_report.v0",
            "rows": rows.iter().map(row_to_json).collect::<Vec<_>>(),
        }))
    } else {
        render_text(&rows);
        ExitCode::SUCCESS
    }
}

/// A measure renders as its number, or as JSON `null` when the log does not
/// carry it. Null is never rewritten to `0` on the way out — that substitution
/// at the edge would undo the whole of DR-0116.
fn measure_to_json(measure: Measure) -> Value {
    measure.value().map_or(Value::Null, |value| json!(value))
}

fn measures_to_json(measures: &Measures) -> Value {
    json!({
        "effects": measure_to_json(measures.effects),
        "runs": measure_to_json(measures.runs),
        "retries": measure_to_json(measures.retries),
        "turns": measure_to_json(measures.turns),
        "calls": measure_to_json(measures.calls),
        "steps": measure_to_json(measures.steps),
        "input_uncached": measure_to_json(measures.input_uncached),
        "input_cache_read": measure_to_json(measures.input_cache_read),
        "input_cache_write": measure_to_json(measures.input_cache_write),
        "output": measure_to_json(measures.output),
        "completed": measure_to_json(measures.completed),
        "failed": measure_to_json(measures.failed),
        "timed_out": measure_to_json(measures.timed_out),
        "cancelled": measure_to_json(measures.cancelled),
        "blocked": measure_to_json(measures.blocked),
        "last_input_tokens": measure_to_json(measures.last_input_tokens),
    })
}

fn row_to_json(row: &Row) -> Value {
    let key: serde_json::Map<String, Value> = row
        .key
        .iter()
        .map(|(dimension, value)| {
            (
                dimension.name().to_owned(),
                value.clone().map_or(Value::Null, Value::String),
            )
        })
        .collect();
    json!({ "key": key, "measures": measures_to_json(&row.measures) })
}

fn render_text(rows: &[Row]) {
    if rows.is_empty() {
        println!("no rows");
        return;
    }
    let cell = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_owned());
    let number = |measure: Measure| {
        measure
            .value()
            .map_or_else(|| "-".to_owned(), |value| value.to_string())
    };
    for row in rows {
        let key: Vec<String> = row
            .key
            .iter()
            .map(|(dimension, value)| format!("{}={}", dimension.name(), cell(value)))
            .collect();
        println!(
            "{} effects={} runs={} retries={} calls={} steps={} in={} cache_read={} out={} failed={}",
            key.join(" "),
            number(row.measures.effects),
            number(row.measures.runs),
            number(row.measures.retries),
            number(row.measures.calls),
            number(row.measures.steps),
            number(row.measures.input_uncached),
            number(row.measures.input_cache_read),
            number(row.measures.output),
            number(row.measures.failed),
        );
    }
    // A dash is not a zero, and a reader who does not know that will read the
    // table wrong in exactly the direction DR-0116 is about.
    println!("(`-` is unrecorded, which is not zero)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_by_dimension_is_refused_rather_than_dropped() {
        // Dropping it would turn a breakdown into a total without saying so.
        let args = vec!["--by".to_owned(), "rule,fact_key".to_owned()];
        let error = StatsOptions::parse(&args).expect_err("fact_key is not a dimension");
        assert!(error.contains("unknown stats dimension `fact_key`"));
        assert!(error.contains("DR-0117"));
    }

    #[test]
    fn an_unknown_flag_is_refused() {
        let args = vec!["--sql".to_owned()];
        let error = StatsOptions::parse(&args).expect_err("there is no SQL door");
        assert!(error.contains("unknown stats option `--sql`"));
    }

    #[test]
    fn a_value_flag_missing_its_value_is_refused() {
        let error = StatsOptions::parse(&["--since".to_owned()]).expect_err("no value");
        assert!(error.contains("expected a timestamp after `--since`"));
    }

    #[test]
    fn every_value_flag_refuses_a_missing_value_by_name() {
        // One test per site, because the sweep measures sites: a single test
        // covering one of them leaves the others free to stop refusing.
        for (flag, expected) in [
            ("--program", "expected a program id after `--program`"),
            ("--since", "expected a timestamp after `--since`"),
            ("--until", "expected a timestamp after `--until`"),
            ("--by", "expected a dimension list after `--by`"),
        ] {
            let error = StatsOptions::parse(&[flag.to_owned()])
                .expect_err("a value flag with no value is refused");
            assert_eq!(error, expected, "{flag} did not refuse a missing value");
        }
    }

    #[test]
    fn a_second_positional_argument_is_refused() {
        let args = vec!["instance-one".to_owned(), "instance-two".to_owned()];
        let error = StatsOptions::parse(&args).expect_err("stats folds one instance or all");
        assert_eq!(
            error,
            "stats takes at most one instance id; got `instance-two` after `instance-one`"
        );
    }

    #[test]
    fn dimensions_parse_and_deduplicate_in_order() {
        let args = vec!["--by".to_owned(), "rule, model ,rule".to_owned()];
        let parsed = StatsOptions::parse(&args).expect("legal dimensions");
        assert_eq!(parsed.by, vec![Dimension::Rule, Dimension::Model]);
    }

    #[test]
    fn an_unrecorded_measure_serialises_as_null_and_never_as_zero() {
        let measures = Measures {
            output: Measure::unrecorded(),
            ..Measures::zero()
        };
        let rendered = measures_to_json(&measures);
        assert_eq!(rendered["output"], Value::Null);
        assert_eq!(rendered["runs"], json!(0));
    }
}
