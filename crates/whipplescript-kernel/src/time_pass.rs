//! The due-time pass, lifted from the native `dev` loop so the DO host can run
//! it too (DR-0033 Phase 6): complete due `timer.wait` effects and expire
//! deadline-passed effects, all through the threaded `RuntimeStore` handle.
//! `now` is injected (ISO-8601 UTC) — the pass never reads wall time itself, so
//! it honors both the native virtual clock and the DO's host-supplied instant.

use serde_json::json;
use whipplescript_store::{EffectCancellationRequest, EffectCompletion, RunStart, StoreResult};

use crate::{idempotency_key, RuntimeKernel};
use whipplescript_store::RuntimeStore;

/// What one due-time pass did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TimePassReport {
    pub timers_fired: usize,
    pub deadlines_expired: usize,
    pub terminal_events: Vec<String>,
}

/// Complete due timers and expire deadline-passed effects for one instance.
/// Mirrors the native `dev` loop's time pass byte-for-byte; the CLI delegates
/// here.
pub fn resolve_due_time_effects<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    now: &str,
) -> StoreResult<TimePassReport> {
    let mut report = TimePassReport::default();
    let due = kernel.store().due_time_effects(instance_id, now)?;
    for effect in due {
        // A `lease.acquire … wait <duration>` carries a creation-anchored
        // `timeout_seconds` purely to bound its contention retry, so it surfaces
        // here once the wait elapses. Its terminal is `contended` (give up), not a
        // timeout/expiry — the coordination handler on the effect pass owns that
        // completion, so leave it for the handler rather than expiring it here.
        if effect.kind == "lease.acquire" {
            continue;
        }
        if effect.kind == "timer.wait" {
            let run_id = idempotency_key(&[instance_id, &effect.effect_id, "timer-run"]);
            let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "timer-lease"]);
            kernel.start_run(RunStart {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "timer",
                worker_id: "whip-timer",
                lease_id: &lease_id,
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: &json!({
                    "duration_seconds": effect.timeout_seconds,
                })
                .to_string(),
            })?;
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "timer",
                worker_id: "whip-timer",
                status: "completed",
                exit_code: Some(0),
                summary: Some("timer fired"),
                metadata_json: &json!({
                    "duration_seconds": effect.timeout_seconds,
                })
                .to_string(),
                idempotency_key: Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "timer-terminal",
                ])),
            })?;
            let value_json = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "status": "completed",
                "fired": true,
                "duration_seconds": effect.timeout_seconds,
            })
            .to_string();
            kernel.derive_fact(
                instance_id,
                "timer.fired",
                &effect.effect_id,
                &value_json,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "timer.fired",
                ])),
            )?;
            report.timers_fired += 1;
            report.terminal_events.push(terminal.event_id);
            continue;
        }
        // Deadline expiry: running effects time out at the run level and get
        // a cancellation request; never-run effects expire directly.
        let running_run = kernel
            .store()
            .running_run_for_effect(instance_id, &effect.effect_id)?;
        let expired_run_id = running_run.as_ref().map(|run| run.run_id.clone());
        let terminal_event_id = match running_run {
            Some(run) => {
                let terminal = kernel.timeout_run(EffectCompletion {
                    instance_id,
                    effect_id: &effect.effect_id,
                    run_id: &run.run_id,
                    provider: &run.provider,
                    worker_id: &run.worker_id,
                    status: "timed_out",
                    exit_code: None,
                    summary: Some("deadline exceeded"),
                    metadata_json: &json!({
                        "timeout_seconds": effect.timeout_seconds,
                        "reason": "deadline exceeded",
                        // Under `failure` so the terminal carries a diagnostic:
                        // a deadline expiry is the effect's own failure kind,
                        // and the operator plane could not see it before.
                        "failure": {
                            "error_kind": "deadline_exceeded",
                            "message": "deadline exceeded",
                        },
                    })
                    .to_string(),
                    idempotency_key: Some(&idempotency_key(&[
                        instance_id,
                        &effect.effect_id,
                        "deadline-terminal",
                    ])),
                })?;
                let _ = kernel
                    .store_mut()
                    .request_effect_cancellation(EffectCancellationRequest {
                        instance_id,
                        effect_id: &effect.effect_id,
                        revision_id: None,
                        reason: Some("deadline exceeded"),
                        requested_by: "deadline",
                        causation_event_id: Some(&terminal.event_id),
                        idempotency_key: Some(&idempotency_key(&[
                            instance_id,
                            &effect.effect_id,
                            "deadline-cancel-request",
                        ])),
                    });
                terminal.event_id
            }
            None => {
                let terminal = kernel.store_mut().expire_effect(
                    instance_id,
                    &effect.effect_id,
                    Some(&idempotency_key(&[
                        instance_id,
                        &effect.effect_id,
                        "deadline-terminal",
                    ])),
                )?;
                terminal.event_id
            }
        };
        // `run_id`/`summary` are part of the TerminalTimedOut binding contract
        // (`after x times out as t` reads t.summary/t.run_id); run_id is null
        // for an effect that expired while still queued (it never ran).
        let value_json = json!({
            "effect_id": effect.effect_id,
            "run_id": expired_run_id,
            "status": "timed_out",
            "reason": "deadline exceeded",
            "summary": "deadline exceeded",
            "timeout_seconds": effect.timeout_seconds,
        })
        .to_string();
        kernel.derive_fact(
            instance_id,
            "effect.timed_out",
            &effect.effect_id,
            &value_json,
            Some(&terminal_event_id),
            Some(&idempotency_key(&[
                instance_id,
                &effect.effect_id,
                "effect.timed_out",
            ])),
        )?;
        report.deadlines_expired += 1;
        report.terminal_events.push(terminal_event_id);
    }
    Ok(report)
}

use serde_json::Value;
use whipplescript_parser::{
    CalendarPattern, IrProgram, IrSource, MissedPolicy, Recurrence, SourceValue, TimeOfDay, Weekday,
};

pub fn parse_clock_instant(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map(|naive| Utc.from_utc_datetime(&naive))
}

fn calendar_weekday(day: Weekday) -> chrono::Weekday {
    match day {
        Weekday::Monday => chrono::Weekday::Mon,
        Weekday::Tuesday => chrono::Weekday::Tue,
        Weekday::Wednesday => chrono::Weekday::Wed,
        Weekday::Thursday => chrono::Weekday::Thu,
        Weekday::Friday => chrono::Weekday::Fri,
        Weekday::Saturday => chrono::Weekday::Sat,
        Weekday::Sunday => chrono::Weekday::Sun,
    }
}

pub fn calendar_date_matches(date: chrono::NaiveDate, pattern: CalendarPattern) -> bool {
    use chrono::Datelike;
    match pattern {
        CalendarPattern::Day => true,
        CalendarPattern::Weekday => {
            !matches!(date.weekday(), chrono::Weekday::Sat | chrono::Weekday::Sun)
        }
        CalendarPattern::Weekly(day) => date.weekday() == calendar_weekday(day),
    }
}

/// The UTC instant of `time` on `date` in `tz`, handling DST: a nonexistent local
/// time (spring-forward gap) yields `None` (the occurrence is skipped); an
/// ambiguous local time (fall-back) resolves to the earliest instant.
pub fn local_occurrence_instant(
    tz: chrono_tz::Tz,
    date: chrono::NaiveDate,
    time: TimeOfDay,
) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    let naive = date.and_hms_opt(u32::from(time.hour), u32::from(time.minute), 0)?;
    match tz.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Some(dt.with_timezone(&chrono::Utc)),
        chrono::LocalResult::Ambiguous(earliest, _) => Some(earliest.with_timezone(&chrono::Utc)),
        chrono::LocalResult::None => None,
    }
}

/// Calendar occurrences in the half-open window `(cursor, now]`, evaluated in
/// `tz_name` (DST-correct), returned as canonical ISO-8601 UTC strings — the
/// calendar analogue of `due_interval_occurrences`. An unparseable instant or
/// timezone yields no occurrences (the source simply does not fire).
pub fn due_calendar_occurrences(
    cursor: &str,
    now: &str,
    tz_name: &str,
    pattern: CalendarPattern,
    time: TimeOfDay,
) -> Vec<String> {
    let (Some(cursor_utc), Some(now_utc)) = (parse_clock_instant(cursor), parse_clock_instant(now))
    else {
        return Vec::new();
    };
    let Ok(tz) = tz_name.parse::<chrono_tz::Tz>() else {
        return Vec::new();
    };
    if now_utc <= cursor_utc {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut date = cursor_utc.with_timezone(&tz).date_naive();
    let end_date = now_utc.with_timezone(&tz).date_naive();
    // Bound the day scan so a long-idle source can't loop unboundedly; missed
    // occurrences beyond the bound are coalesced by the missed policy anyway.
    let mut guard = 0u32;
    while date <= end_date && guard < 4000 {
        guard += 1;
        if calendar_date_matches(date, pattern) {
            if let Some(occurrence) = local_occurrence_instant(tz, date, time) {
                if occurrence > cursor_utc && occurrence <= now_utc {
                    out.push(occurrence.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                }
            }
        }
        let Some(next) = date.succ_opt() else { break };
        date = next;
    }
    out
}

pub fn select_clock_occurrences(
    due: &[String],
    missed: Option<&MissedPolicy>,
) -> Vec<(String, i64)> {
    if due.is_empty() {
        return Vec::new();
    }
    let last = due.last().expect("non-empty").clone();
    match missed {
        // catch_up: admit one fact per occurrence, newest `limit` of them.
        Some(MissedPolicy::CatchUp { limit }) => {
            let keep = (*limit as usize).max(1);
            let start = due.len().saturating_sub(keep);
            due[start..].iter().map(|at| (at.clone(), 0)).collect()
        }
        // skip: emit only the next observed occurrence; missed ones are dropped.
        Some(MissedPolicy::Skip) => vec![(last, 0)],
        // coalesce: emit one occurrence representing all missed ticks. Also the
        // flood-safe default when no policy is declared (a long-idle source must
        // not admit one fact per elapsed interval at once).
        _ => vec![(last, (due.len() as i64) - 1)],
    }
}

/// Builds a clock signal payload by resolving the source's `emit <signal> { … }`
/// field mapping against the observation (`scheduled_at`/`observed_at`/
/// `occurrence_id`/`missed_count`/`schedule_name`). Paths off the `observe`
/// binding read the observation; literals pass through.
pub fn clock_emit_payload(
    source: &IrSource,
    observation: &serde_json::Map<String, Value>,
) -> Value {
    let mut payload = serde_json::Map::new();
    for field in &source.emit_fields {
        let value = match &field.value {
            SourceValue::Path {
                binding, segments, ..
            } => {
                if binding.name == source.observe_binding && segments.len() == 1 {
                    observation
                        .get(&segments[0].name)
                        .cloned()
                        .unwrap_or(Value::Null)
                } else {
                    Value::Null
                }
            }
            SourceValue::String(literal) => Value::String(literal.value.clone()),
            SourceValue::Number(number, _) => serde_json::from_str(number).unwrap_or(Value::Null),
        };
        payload.insert(field.name.clone(), value);
    }
    Value::Object(payload)
}

/// Fires due occurrences of clock sources (spec/std-time.md) — all three
/// recurrence forms: `every <duration>` (interval), `every <calendar> at
/// <hh:mm>` (tz-aware calendar), and one-shot `at <hh:mm>` (fire-once). For
/// each clock source, enumerate occurrences due since the cursor (the last
/// admitted occurrence, else the instance start) up to `now`, apply the missed
/// policy, and admit each as a durable signal fact keyed by
/// `occurrence_id = H(source, scheduled_instant)` so re-evaluation and replay
/// are idempotent.
pub fn resolve_due_clock_sources<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    now: &str,
    ir: &IrProgram,
) -> StoreResult<u64> {
    let mut admitted = 0u64;
    for source in &ir.sources {
        if !source.is_clock {
            continue;
        }
        let Some(recurrence) = source.recurrence.as_ref() else {
            continue;
        };
        let Some(instance) = kernel.store().get_instance(instance_id)? else {
            continue;
        };
        let last = kernel
            .store()
            .last_clock_occurrence(instance_id, &source.emit_signal)?;
        let cursor = last.clone().unwrap_or_else(|| instance.created_at.clone());
        // Calendar/`at` recurrence resolves in the source timezone (required by the
        // checker for those forms); interval recurrence ignores it.
        let timezone = source.timezone.as_deref().unwrap_or("UTC");
        let due =
            match recurrence {
                Recurrence::EveryDuration { seconds, .. } => kernel
                    .store()
                    .due_interval_occurrences(&cursor, *seconds as i64, now)?,
                Recurrence::EveryCalendar { pattern, time, .. } => {
                    due_calendar_occurrences(&cursor, now, timezone, *pattern, *time)
                }
                // `at <time>` is a single scheduled occurrence (spec/std-time.md): the
                // first daily occurrence of the time after the source start, fired once.
                // Once any occurrence has been admitted, it never fires again.
                Recurrence::At { time, .. } => {
                    if last.is_some() {
                        Vec::new()
                    } else {
                        due_calendar_occurrences(
                            &instance.created_at,
                            now,
                            timezone,
                            CalendarPattern::Day,
                            *time,
                        )
                        .into_iter()
                        .take(1)
                        .collect()
                    }
                }
            };
        let observed_at = kernel.store().resolve_clock(now)?;
        for (scheduled_at, missed_count) in select_clock_occurrences(&due, source.missed.as_ref()) {
            let occurrence_id = idempotency_key(&[&source.name, &scheduled_at]);
            let mut observation = serde_json::Map::new();
            observation.insert("scheduled_at".to_owned(), Value::String(scheduled_at));
            observation.insert("observed_at".to_owned(), Value::String(observed_at.clone()));
            observation.insert(
                "occurrence_id".to_owned(),
                Value::String(occurrence_id.clone()),
            );
            observation.insert("missed_count".to_owned(), json!(missed_count));
            // `schedule_name` completes the declared `ClockObservation` schema
            // (spec/std-time.md T2): the source's declared name.
            observation.insert(
                "schedule_name".to_owned(),
                Value::String(source.name.clone()),
            );
            let payload_json = clock_emit_payload(source, &observation).to_string();
            // Record the occurrence event, then derive its durable signal fact
            // (mirroring `whip signal`): the unique index on `occurrence_id` makes
            // both steps idempotent across re-evaluation and replay.
            let received = kernel.ingest_external_event(
                instance_id,
                &source.emit_signal,
                &payload_json,
                Some(&occurrence_id),
            )?;
            kernel.derive_fact(
                instance_id,
                &source.emit_signal,
                &received.event_id,
                &payload_json,
                Some(&received.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    "clock-fact",
                    &received.event_id,
                ])),
            )?;
            admitted += 1;
        }
    }
    Ok(admitted)
}

/// The earliest FUTURE clock-source occurrence (unix milliseconds) strictly
/// after `now`, across the program's clock sources — the clock half of the
/// DO's single wake-up alarm (DR-0033 Phase 6). Runs after the due pass, so
/// anything at or before `now` has already fired; this looks forward only.
pub fn next_clock_due_unix_ms<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    now: &str,
    ir: &IrProgram,
) -> StoreResult<Option<i64>> {
    let Some(now_utc) = parse_clock_instant(now) else {
        return Ok(None);
    };
    let mut earliest: Option<i64> = None;
    let mut consider = |instant: chrono::DateTime<chrono::Utc>| {
        let ms = instant.timestamp_millis();
        if earliest.is_none_or(|current| ms < current) {
            earliest = Some(ms);
        }
    };
    for source in &ir.sources {
        if !source.is_clock {
            continue;
        }
        let Some(recurrence) = source.recurrence.as_ref() else {
            continue;
        };
        let Some(instance) = kernel.store().get_instance(instance_id)? else {
            continue;
        };
        let last = kernel
            .store()
            .last_clock_occurrence(instance_id, &source.emit_signal)?;
        let cursor = last.clone().unwrap_or_else(|| instance.created_at.clone());
        let Some(cursor_utc) = parse_clock_instant(&cursor) else {
            continue;
        };
        let timezone = source.timezone.as_deref().unwrap_or("UTC");
        match recurrence {
            Recurrence::EveryDuration { seconds, .. } => {
                let step = *seconds as i64;
                if step <= 0 {
                    continue;
                }
                // First cursor + k*step strictly after now.
                let base = cursor_utc.timestamp();
                let now_s = now_utc.timestamp();
                let k = if now_s < base {
                    1
                } else {
                    ((now_s - base) / step) + 1
                };
                if let Some(instant) =
                    chrono::DateTime::<chrono::Utc>::from_timestamp(base + k * step, 0)
                {
                    consider(instant);
                }
            }
            Recurrence::EveryCalendar { pattern, time, .. } => {
                if let Some(instant) = next_calendar_occurrence(now_utc, timezone, *pattern, *time)
                {
                    consider(instant);
                }
            }
            Recurrence::At { time, .. } => {
                // Fires once; nothing to schedule after it has fired.
                if last.is_none() {
                    if let Some(instant) =
                        next_calendar_occurrence(now_utc, timezone, CalendarPattern::Day, *time)
                    {
                        consider(instant);
                    }
                }
            }
        }
    }
    Ok(earliest)
}

/// The first calendar occurrence of `time` strictly after `after`, evaluated in
/// `tz_name` (DST-correct, forward-scanning with the same bound as the due
/// enumeration).
fn next_calendar_occurrence(
    after: chrono::DateTime<chrono::Utc>,
    tz_name: &str,
    pattern: CalendarPattern,
    time: TimeOfDay,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let tz: chrono_tz::Tz = tz_name.parse().ok()?;
    let mut date = after.with_timezone(&tz).date_naive();
    for _ in 0..4000 {
        if calendar_date_matches(date, pattern) {
            if let Some(occurrence) = local_occurrence_instant(tz, date, time) {
                if occurrence > after {
                    return Some(occurrence);
                }
            }
        }
        date = date.succ_opt()?;
    }
    None
}
