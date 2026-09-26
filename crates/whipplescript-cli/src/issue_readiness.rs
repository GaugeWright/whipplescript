//! `whip issue` verbs over the one readiness (DR-0126): the guarded `claim`,
//! the explanation (`why`), deferral (`defer`, `undefer`, `waits`, `review`),
//! and ordering (`order`, `rank`). Every question is asked at the CLI's own
//! boundary instant — the store's clock, read once per command — and the
//! answer names that instant.

use std::process::ExitCode;

use serde_json::{json, Value};
use whipplescript_store::items::readiness::{canonical_instant, Unready, WaitCondition};
use whipplescript_store::items::{ClaimOutcome, WorkItemStore};

use super::{
    emit_issue_row, emit_json, flag_value, issue_actor, issue_ttl_expires, report_store_error,
    work_item_to_json, CliOptions,
};

/// The boundary instant for this command: the store's clock, once.
fn boundary_instant(store: &WorkItemStore) -> Result<String, ExitCode> {
    store
        .store_now()
        .map_err(|error| report_store_error("failed to read the store clock", error))
}

/// An instant given on the command line: an ISO-8601 instant, a date (midnight
/// UTC), or a duration from `at` (`30m`, `7d`).
fn instant_arg(value: &str, at: &str) -> Option<String> {
    if let Some(instant) = canonical_instant(value) {
        return Some(instant);
    }
    let seconds = whipplescript_parser::body::parse_short_duration_seconds(value)?;
    let base = chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%d %H:%M:%S").ok()?;
    let shifted = base.checked_add_signed(chrono::Duration::seconds(seconds as i64))?;
    Some(shifted.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn reasons_json(reasons: &[Unready]) -> Value {
    serde_json::to_value(reasons).unwrap_or(Value::Null)
}

fn print_reasons(reasons: &[Unready]) {
    for reason in reasons {
        println!("  - {}", reason.describe());
    }
}

/// `claim <id> [--actor A] [--ttl D] [--override <reason>]`: the claim guard.
/// A non-open issue is refused. An open one that is not ready is refused with
/// every reason, unless a person overrides it and says why — which the claim
/// records.
pub(super) fn claim(store: &mut WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let args = &options.args;
    let Some(id) = args.get(1).filter(|id| !id.starts_with("--")) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let actor = issue_actor(flag_value(args, "--actor"));
    // `--ttl <duration>` records a timed claim (`expires_at = now + ttl`);
    // omitting it is the untimed backstop lease.
    let expires = issue_ttl_expires(args);
    let override_reason = flag_value(args, "--override");
    if args.iter().any(|arg| arg == "--override") && override_reason.is_none() {
        eprintln!("--override needs a reason: the claim records why it skipped readiness");
        return ExitCode::from(2);
    }
    let at = match boundary_instant(store) {
        Ok(at) => at,
        Err(code) => return code,
    };
    match store.claim_item_at(
        id,
        &actor,
        expires.as_deref(),
        &at,
        override_reason.as_deref(),
    ) {
        Ok(ClaimOutcome::Claimed) => {
            let note = if override_reason.is_some() {
                "claimed (readiness overridden)"
            } else {
                "claimed"
            };
            emit_issue_row(store, id, note, options.json)
        }
        Ok(ClaimOutcome::AlreadyClaimed { holder }) => {
            eprintln!("issue `{id}` is already claimed by {holder}");
            ExitCode::FAILURE
        }
        Ok(ClaimOutcome::NotFound) => {
            eprintln!("issue `{id}` was not found");
            ExitCode::FAILURE
        }
        Ok(ClaimOutcome::NotOpen { status }) => {
            if options.json {
                let _ = emit_json(json!({"id": id, "outcome": "not_open", "status": status}));
            }
            eprintln!("issue `{id}` is {status}, not open work; reopen it to claim it");
            ExitCode::FAILURE
        }
        Ok(ClaimOutcome::NotReady { reasons }) => {
            if options.json {
                let _ = emit_json(json!({
                    "id": id, "outcome": "not_ready", "at": at, "reasons": reasons_json(&reasons),
                }));
            }
            eprintln!("issue `{id}` is not ready at {at}:");
            for reason in &reasons {
                eprintln!("  - {}", reason.describe());
            }
            eprintln!("claim something ready (`whip issue ready`), or pass --override \"<why>\"");
            ExitCode::FAILURE
        }
        Err(error) => report_store_error("failed to claim issue", error),
    }
}

/// `why <id>`: every reason the issue is not ready, at this instant.
fn why(store: &WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let Some(id) = options.args.get(1) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let at = match boundary_instant(store) {
        Ok(at) => at,
        Err(code) => return code,
    };
    let reasons = match store.unready_reasons_at(id, &at) {
        Ok(reasons) => reasons,
        Err(error) => return report_store_error("failed to read readiness", error),
    };
    if reasons.contains(&Unready::NotFound) {
        eprintln!("issue `{id}` was not found");
        return ExitCode::FAILURE;
    }
    let ordering_conflict = store
        .ordering_conflicts()
        .is_ok_and(|conflicted| conflicted.contains(id.as_str()));
    if options.json {
        return emit_json(json!({
            "id": id,
            "at": at,
            "ready": reasons.is_empty(),
            "reasons": reasons_json(&reasons),
            "ordering_conflict": ordering_conflict,
        }));
    }
    if reasons.is_empty() {
        println!("{id} is ready at {at}");
    } else {
        println!("{id} is not ready at {at}:");
        print_reasons(&reasons);
    }
    if ordering_conflict {
        println!("{id}'s ordering statements contradict each other (see `whip issue conflicts`)");
    }
    ExitCode::SUCCESS
}

/// Parse the one condition flag `defer` was given.
fn condition_arg(
    store: &WorkItemStore,
    args: &[String],
    at: &str,
) -> Result<(WaitCondition, Option<String>), String> {
    let given: Vec<&str> = ["--until", "--after", "--reached", "--demand"]
        .into_iter()
        .filter(|flag| args.iter().any(|arg| arg == flag))
        .collect();
    if given.len() != 1 {
        return Err("give exactly one of --until, --after, --reached, --demand".to_owned());
    }
    let flag = given[0];
    let value = flag_value(args, flag).ok_or_else(|| format!("{flag} needs a value"))?;
    Ok(match flag {
        "--until" => {
            let instant =
                instant_arg(&value, at).ok_or_else(|| format!("`{value}` is not an instant"))?;
            // A deferral to an instant is reviewed at that instant, unless told
            // otherwise: by then it has either lifted or something is wrong.
            (
                WaitCondition::At {
                    instant: instant.clone(),
                },
                Some(instant),
            )
        }
        "--after" => {
            let issue = store
                .subject_content_id(&value)
                .map_err(|error| format!("{error:?}"))?
                .ok_or_else(|| format!("issue `{value}` was not found"))?;
            (WaitCondition::Settled { issue }, None)
        }
        "--reached" => {
            let (record, status) = value
                .rsplit_once(':')
                .ok_or("--reached takes <record>:<status>, e.g. N-3:accepted")?;
            let record = store
                .resolve_norm_record(record)
                .map_err(|error| format!("{error:?}"))?
                .ok_or_else(|| format!("norm record `{record}` was not found"))?;
            (
                WaitCondition::Reached {
                    record,
                    status: status.to_owned(),
                },
                None,
            )
        }
        _ => {
            let (label, at_least) = value
                .rsplit_once(':')
                .ok_or("--demand takes <label>:<count>, e.g. provider-request:2")?;
            let at_least = at_least
                .parse::<i64>()
                .map_err(|_| format!("`{at_least}` is not a count"))?;
            (
                WaitCondition::Count {
                    label: label.to_owned(),
                    at_least,
                },
                None,
            )
        }
    })
}

/// `defer <id> --until <when> | --after <issue> | --reached <record>:<status>
/// | --demand <label>:<n> [--review <when>] [--actor A]`.
fn defer(store: &mut WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let args = &options.args;
    let Some(id) = args.get(1).filter(|id| !id.starts_with("--")) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let at = match boundary_instant(store) {
        Ok(at) => at,
        Err(code) => return code,
    };
    let (condition, default_review) = match condition_arg(store, args, &at) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let review_at = match flag_value(args, "--review") {
        Some(value) => match instant_arg(&value, &at) {
            Some(instant) => instant,
            None => {
                eprintln!("`{value}` is not an instant");
                return ExitCode::from(2);
            }
        },
        None => match default_review {
            Some(instant) => instant,
            None => {
                eprintln!(
                    "a deferral needs --review <when>: the date its owner looks again if it has \
                     not lifted (a date, an instant, or a duration such as 30d)"
                );
                return ExitCode::from(2);
            }
        },
    };
    let actor = issue_actor(flag_value(args, "--actor"));
    match store.add_wait(id, &condition, &review_at, Some(&actor)) {
        Ok(wait) => {
            if options.json {
                let mut row = store
                    .get_item(id)
                    .ok()
                    .flatten()
                    .map(|item| work_item_to_json(&item))
                    .unwrap_or_else(|| json!({"id": id}));
                if let Some(map) = row.as_object_mut() {
                    map.insert("wait".to_owned(), json!(wait));
                    map.insert("review_at".to_owned(), json!(review_at));
                }
                emit_json(row)
            } else {
                println!("{id} deferred (wait {}), review {review_at}", short(&wait));
                ExitCode::SUCCESS
            }
        }
        Err(error) => report_store_error("failed to defer issue", error),
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// `undefer <id> <wait>|--all [--actor A]`: lift waits early, which is an act.
fn undefer(store: &mut WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let args = &options.args;
    let Some(id) = args.get(1).filter(|id| !id.starts_with("--")) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let all = args.iter().any(|arg| arg == "--all");
    let wait = args.get(2).filter(|arg| !arg.starts_with("--"));
    if all == wait.is_some() {
        eprintln!("name one wait (from `whip issue waits {id}`) or pass --all");
        return ExitCode::from(2);
    }
    let actor = issue_actor(flag_value(args, "--actor"));
    match store.remove_waits(id, wait.map(String::as_str), Some(&actor)) {
        Ok(0) => {
            eprintln!("issue `{id}` has no such wait");
            ExitCode::FAILURE
        }
        Ok(count) => emit_issue_row(store, id, &format!("lifted {count} wait(s)"), options.json),
        Err(error) => report_store_error("failed to lift waits", error),
    }
}

fn waits_json(store: &WorkItemStore, id: &str, at: &str) -> Value {
    let verdicts = store.wait_verdicts(id, at).unwrap_or_default();
    Value::Array(
        verdicts
            .into_iter()
            .map(|(wait, verdict, described)| {
                json!({
                    "id": wait.id,
                    "condition": wait.condition,
                    "description": described,
                    "review_at": wait.review_at,
                    "added_by": wait.added_by,
                    "created_at": wait.created_at,
                    "holds": verdict.holds,
                    "observed": verdict.observed,
                    "due_for_review": !verdict.holds && wait.review_at.as_str() <= at,
                })
            })
            .collect(),
    )
}

/// `waits <id>`: the issue's live waits, each with what it observed now.
fn waits(store: &WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let Some(id) = options.args.get(1) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let at = match boundary_instant(store) {
        Ok(at) => at,
        Err(code) => return code,
    };
    let rows = waits_json(store, id, &at);
    if options.json {
        return emit_json(rows);
    }
    let rows = rows.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("{id} has no waits");
    }
    for row in rows {
        println!(
            "{} {} — {} ({}), review {}{}",
            short(row["id"].as_str().unwrap_or_default()),
            row["description"].as_str().unwrap_or_default(),
            if row["holds"].as_bool() == Some(true) {
                "holds"
            } else {
                "unmet"
            },
            row["observed"].as_str().unwrap_or_default(),
            row["review_at"].as_str().unwrap_or_default(),
            if row["due_for_review"].as_bool() == Some(true) {
                " — DUE FOR REVIEW"
            } else {
                ""
            },
        );
    }
    ExitCode::SUCCESS
}

/// `review [--tracker TR] [--assignee A]`: deferrals past their review date and
/// still unmet — what an owner looks at again.
fn review(store: &WorkItemStore, options: &CliOptions) -> ExitCode {
    let args = &options.args;
    let at = match boundary_instant(store) {
        Ok(at) => at,
        Err(code) => return code,
    };
    let queue = flag_value(args, "--tracker");
    let assignee = flag_value(args, "--assignee");
    let due = match store.review_items_at(queue.as_deref(), assignee.as_deref(), &at) {
        Ok(due) => due,
        Err(error) => return report_store_error("failed to read the review view", error),
    };
    if options.json {
        return emit_json(Value::Array(
            due.iter()
                .map(|item| {
                    let mut row = work_item_to_json(item);
                    if let Some(map) = row.as_object_mut() {
                        map.insert("waits".to_owned(), waits_json(store, &item.id, &at));
                    }
                    row
                })
                .collect(),
        ));
    }
    if due.is_empty() {
        println!("no deferrals due for review at {at}");
    }
    for item in &due {
        println!(
            "{} [{}] tracker={} {}",
            item.id, item.status, item.queue, item.title
        );
        for row in waits_json(store, &item.id, &at)
            .as_array()
            .into_iter()
            .flatten()
        {
            if row["due_for_review"].as_bool() == Some(true) {
                println!(
                    "  {} — {}, review was due {}",
                    row["description"].as_str().unwrap_or_default(),
                    row["observed"].as_str().unwrap_or_default(),
                    row["review_at"].as_str().unwrap_or_default()
                );
            }
        }
    }
    ExitCode::SUCCESS
}

/// Why a statement "`before` before `after`" by `actor` will rank nothing, if
/// it will not (DR-0126 Decision 4): the two are not siblings, or their
/// parent has an owner who is not `actor` — which makes it a proposal.
fn statement_caveat(
    store: &WorkItemStore,
    before: &str,
    after: &str,
    actor: &str,
) -> Option<String> {
    let graph = store.ordering_graph().ok()?;
    let parents = |issue: &str| graph.parents.get(issue).cloned().unwrap_or_default();
    let (pb, pa) = (parents(before), parents(after));
    if pb != pa && pb.intersection(&pa).next().is_none() {
        return Some(format!(
            "{before} and {after} are not siblings, so this ranks nothing; order their parents instead"
        ));
    }
    let shared: Vec<&String> = pb.intersection(&pa).collect();
    let owners: Vec<&String> = shared
        .iter()
        .filter_map(|parent| graph.owners.get(*parent))
        .collect();
    if !shared.is_empty() && !owners.is_empty() && !owners.iter().any(|owner| *owner == actor) {
        return Some(format!(
            "recorded as a proposal: only {} (owner of {}) ranks these",
            owners
                .iter()
                .map(|owner| owner.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            shared
                .iter()
                .map(|parent| parent.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    None
}

/// `order <a> before <b> [--actor A]`: an ordering statement. It ranks only
/// between siblings, and only when its writer owns their parent (DR-0126).
fn order(store: &mut WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let args = &options.args;
    let (Some(first), Some(word), Some(then)) = (args.get(1), args.get(2), args.get(3)) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    if word != "before" {
        eprintln!("{usage}");
        return ExitCode::from(2);
    }
    let actor = issue_actor(flag_value(args, "--actor"));
    match store.add_relation_by(first, then, "blocks", Some("order"), Some(&actor)) {
        Ok(()) => {
            let caveat = statement_caveat(store, first, then, &actor);
            if let (Some(caveat), false) = (&caveat, options.json) {
                eprintln!("{caveat}");
            }
            emit_issue_row(
                store,
                first,
                &format!("ordered before {then}"),
                options.json,
            )
        }
        Err(error) => report_store_error("failed to order issues", error),
    }
}

/// `rank <parent> <first> <second> ... [--actor A]`: rank children of `parent`
/// in this order — a chain of ordering statements.
fn rank(store: &mut WorkItemStore, options: &CliOptions, usage: &str) -> ExitCode {
    let args = &options.args;
    let mut positional = Vec::new();
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--actor" {
            iter.next();
        } else {
            positional.push(arg.as_str());
        }
    }
    let Some((parent, children)) = positional.split_first() else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    if children.len() < 2 {
        eprintln!("rank needs at least two children of {parent}, in order");
        return ExitCode::from(2);
    }
    let actor = issue_actor(flag_value(args, "--actor"));
    let is_child = |child: &str| {
        store.relations(child).is_ok_and(|relations| {
            relations
                .iter()
                .any(|r| r.kind == "parent-of" && r.from == *parent && r.to == child)
        })
    };
    if let Some(stranger) = children.iter().find(|child| !is_child(child)) {
        eprintln!("{stranger} is not a child of {parent} (`whip issue link {parent} parent-of {stranger}`)");
        return ExitCode::FAILURE;
    }
    for pair in children.windows(2) {
        if let Err(error) =
            store.add_relation_by(pair[0], pair[1], "blocks", Some("order"), Some(&actor))
        {
            return report_store_error("failed to rank issues", error);
        }
    }
    let caveat = statement_caveat(store, children[0], children[1], &actor);
    if options.json {
        return emit_json(json!({
            "parent": parent, "ranked": children, "by": actor, "proposal": caveat.is_some(),
        }));
    }
    match caveat {
        Some(caveat) => println!("{parent}: {} — {caveat}", children.join(" > ")),
        None => println!("{parent}: ranked {}", children.join(" > ")),
    }
    ExitCode::SUCCESS
}

/// The readiness section of `show`, as JSON.
pub(super) fn readiness_json(store: &WorkItemStore, id: &str) -> Option<Value> {
    let at = store.store_now().ok()?;
    let reasons = store.unready_reasons_at(id, &at).ok()?;
    Some(json!({
        "at": at,
        "ready": reasons.is_empty(),
        "reasons": reasons_json(&reasons),
        "waits": waits_json(store, id, &at),
        "ordering_conflict": store
            .ordering_conflicts()
            .is_ok_and(|conflicted| conflicted.contains(id)),
    }))
}

/// The readiness section of `show`, as text.
pub(super) fn print_readiness(store: &WorkItemStore, id: &str) {
    let Some(value) = readiness_json(store, id) else {
        return;
    };
    let reasons: Vec<Unready> = store
        .unready_reasons_at(id, value["at"].as_str().unwrap_or_default())
        .unwrap_or_default();
    if reasons.is_empty() {
        println!("ready: yes");
    } else {
        println!("ready: no");
        print_reasons(&reasons);
    }
    for row in value["waits"].as_array().into_iter().flatten() {
        println!(
            "wait {}: {} ({}), review {}",
            short(row["id"].as_str().unwrap_or_default()),
            row["description"].as_str().unwrap_or_default(),
            row["observed"].as_str().unwrap_or_default(),
            row["review_at"].as_str().unwrap_or_default()
        );
    }
    if value["ordering_conflict"].as_bool() == Some(true) {
        println!("ordering: CONFLICTED (its ordering statements contradict each other)");
    }
}

/// The DR-0126 verbs `fn issue` hands over; `None` for any other command.
pub(super) fn verbs(
    store: &mut WorkItemStore,
    options: &CliOptions,
    command: &str,
    usage: &str,
) -> Option<ExitCode> {
    Some(match command {
        "why" => why(store, options, usage),
        "defer" => defer(store, options, usage),
        "undefer" => undefer(store, options, usage),
        "waits" => waits(store, options, usage),
        "review" => review(store, options),
        "order" => order(store, options, usage),
        "rank" => rank(store, options, usage),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn options(args: &[&str]) -> CliOptions {
        CliOptions {
            command: Some("issue".to_owned()),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            store_path: PathBuf::from("unused.sqlite"),
            json: false,
            input_json: None,
        }
    }

    fn store_with_issue() -> (WorkItemStore, String) {
        let mut store = WorkItemStore::open_in_memory().expect("opens");
        let id = store
            .file_item("q", "parked", "", &[], &json!({}), None, None)
            .expect("files")
            .id;
        (store, id)
    }

    /// `defer` takes exactly one condition: none is a usage error rather than
    /// a guess, and two is refused rather than silently taking the first.
    #[test]
    fn defer_takes_exactly_one_condition() {
        let (mut store, id) = store_with_issue();
        let none = verbs(
            &mut store,
            &options(&["defer", &id, "--review", "1d"]),
            "defer",
            "usage",
        );
        assert_eq!(none, Some(ExitCode::from(2)));
        let two = verbs(
            &mut store,
            &options(&[
                "defer",
                &id,
                "--until",
                "2031-01-01",
                "--demand",
                "ask:1",
                "--review",
                "1d",
            ]),
            "defer",
            "usage",
        );
        assert_eq!(two, Some(ExitCode::from(2)));
        assert!(
            store.waits(&id).expect("waits").is_empty(),
            "nothing recorded"
        );
        let one = verbs(
            &mut store,
            &options(&["defer", &id, "--until", "2031-01-01"]),
            "defer",
            "usage",
        );
        assert_eq!(one, Some(ExitCode::SUCCESS));
        assert_eq!(store.waits(&id).expect("waits").len(), 1);
    }

    /// An override must say why: the reason is what the claim records.
    #[test]
    fn an_override_without_a_reason_is_refused() {
        let (mut store, id) = store_with_issue();
        assert_eq!(
            claim(&mut store, &options(&["claim", &id, "--override"]), "usage"),
            ExitCode::from(2)
        );
        assert!(store
            .get_item(&id)
            .expect("get")
            .expect("row")
            .claimed_by
            .is_none());
    }
}
