//! DR-0295: description age is a causal observation, never a prose judgement.
//! Every final behavior assertion drives the actual CLI; fixture transport uses
//! existing public event admission, so this also compiles on the pre-feature CLI.
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use whipplescript_store::items::{event_content_id, TrackerEvent, WorkItemStore};

struct Fixture {
    root: tempfile::TempDir,
    store: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        assert!(Command::new("git")
            .args(["init", "--quiet"])
            .arg(root.path())
            .stdin(Stdio::null())
            .status()
            .expect("initialize fixture Git repository")
            .success());
        let store = root.path().join("items.sqlite");
        drop(WorkItemStore::open(&store).expect("initialize fixture item store"));
        Self { root, store }
    }
    fn cli(&self, args: &[&str]) -> Output {
        static CLI_IDENTITY: std::sync::Once = std::sync::Once::new();
        CLI_IDENTITY.call_once(|| println!("#ws1077 cli-image={}", env!("CARGO_BIN_EXE_whip")));
        let capture = tempfile::tempdir().expect("create CLI output capture");
        let mut child = Command::new(env!("CARGO_BIN_EXE_whip"))
            .current_dir(self.root.path())
            .env("WHIPPLESCRIPT_ITEMS_STORE", &self.store)
            .env("WHIPPLESCRIPT_MISUSE_LOG", "off")
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(capture.path().join("out")).expect("create CLI stdout capture"))
            .stderr(File::create(capture.path().join("err")).expect("create CLI stderr capture"))
            .spawn()
            .expect("spawn actual CLI");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().expect("poll actual CLI") {
                return Output {
                    status,
                    stdout: fs::read(capture.path().join("out")).expect("read CLI stdout"),
                    stderr: fs::read(capture.path().join("err")).expect("read CLI stderr"),
                };
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out CLI");
                child.wait().expect("reap timed-out CLI");
                panic!("owned CLI {args:?} exceeded deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn json(&self, args: &[&str]) -> Value {
        let mut argv = vec!["--json"];
        argv.extend(args);
        let out = self.cli(&argv);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("decode successful CLI JSON")
    }
    fn show(&self, id: &str) -> Value {
        self.json(&["issue", "show", id])
    }
    fn import(&self, events: &[TrackerEvent]) -> String {
        let mut store = WorkItemStore::open(&self.store).expect("open fixture for event import");
        let report = store.import_events(events).expect("import fixture events");
        assert_eq!(report.rejected, 0, "fixture content IDs must be admitted");
        store
            .list_items(Some("context-fixture"), None)
            .expect("list imported fixture issues")
            .into_iter()
            .find(|row| row.title == "Description fixture")
            .expect("find imported fixture issue")
            .id
    }
}
fn root_event() -> TrackerEvent {
    let payload =
        json!({"queue":"context-fixture", "title":"Description fixture", "body":"Original body",
        "labels":[], "metadata":{}, "filed_by":null, "assigned_to":null})
        .to_string();
    let at = "2026-10-09 12:00:00";
    let id = event_content_id("issue.created", None, &payload, None, &[], at);
    TrackerEvent {
        event_id: id.clone(),
        parents: vec![],
        issue_id: Some(id),
        kind: "issue.created".into(),
        payload_json: payload,
        actor: None,
        created_at: at.into(),
    }
}
fn child(
    root: &TrackerEvent,
    parents: &[&TrackerEvent],
    kind: &str,
    payload: Value,
    at: &str,
) -> TrackerEvent {
    let parents = parents
        .iter()
        .map(|e| e.event_id.clone())
        .collect::<Vec<_>>();
    let payload_json = payload.to_string();
    let event_id = event_content_id(
        kind,
        root.issue_id.as_deref(),
        &payload_json,
        Some("fixture"),
        &parents,
        at,
    );
    TrackerEvent {
        event_id,
        parents,
        issue_id: root.issue_id.clone(),
        kind: kind.into(),
        payload_json,
        actor: Some("fixture".into()),
        created_at: at.into(),
    }
}
fn comment(root: &TrackerEvent, parents: &[&TrackerEvent], at: &str) -> TrackerEvent {
    child(
        root,
        parents,
        "comment.added",
        json!({"author":"fixture","body":"Later observation"}),
        at,
    )
}
fn evidence(root: &TrackerEvent, parents: &[&TrackerEvent], at: &str) -> TrackerEvent {
    child(
        root,
        parents,
        "evidence.added",
        json!({"kind":"test","reference":"fixture:proof","note":"Observation","added_by":"fixture"}),
        at,
    )
}
fn body(root: &TrackerEvent, parents: &[&TrackerEvent], text: &str, at: &str) -> TrackerEvent {
    child(
        root,
        parents,
        "issue.field_set",
        json!({"field":"body","value":text}),
        at,
    )
}
fn context(show: &Value) -> &Value {
    assert!(
        show["description_context"].is_object(),
        "actual show must expose description_context"
    );
    &show["description_context"]
}
fn counts(
    c: &Value,
    later_comments: u64,
    later_evidence: u64,
    unordered_comments: u64,
    unordered_evidence: u64,
) {
    assert_eq!(
        c["later_comments"], later_comments,
        "causally later comment witness"
    );
    assert_eq!(c["later_evidence"], later_evidence);
    assert_eq!(c["unordered_comments"], unordered_comments);
    assert_eq!(c["unordered_evidence"], unordered_evidence);
}
fn events(f: &Fixture) -> Vec<TrackerEvent> {
    WorkItemStore::open_read_only(&f.store)
        .expect("open fixture read-only for export")
        .export_events()
        .expect("export fixture events")
}

#[test]
fn description_context_tracks_causal_comment_and_evidence_not_wall_clock() {
    let f = Fixture::new();
    // Real current writer establishes the same causal edges independently of
    // deterministic transported-clock vectors below; no timestamp sleeps/retries.
    let id = {
        let mut s = WorkItemStore::open(&f.store).unwrap();
        s.file_item(
            "actual-writer",
            "Writer",
            "Body",
            &[],
            &json!({}),
            None,
            None,
        )
        .unwrap()
        .id
    };
    let initial = f.show(&id);
    counts(context(&initial), 0, 0, 0, 0);
    assert_eq!(
        context(&initial)["body_revisions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(context(&initial)["body_provenance_ambiguous"], false);
    assert_eq!(
        context(&initial)["body_revisions"][0]["event_id"],
        events(&f)[0].event_id
    );
    {
        let mut s = WorkItemStore::open(&f.store).unwrap();
        s.add_comment(&id, Some("fixture"), "Written comment")
            .unwrap();
        s.add_evidence(
            &id,
            Some("test"),
            Some("fixture:actual"),
            None,
            Some("fixture"),
        )
        .unwrap();
    }
    counts(context(&f.show(&id)), 1, 1, 0, 0);
    for at in ["2026-10-09 12:00:00", "2020-01-01 00:00:00"] {
        let imported = Fixture::new();
        let root = root_event();
        let c = comment(&root, &[&root], at);
        let e = evidence(&root, &[&c], at);
        let id = imported.import(&[root.clone(), c, e]);
        let shown = imported.show(&id);
        let ctx = context(&shown);
        counts(ctx, 1, 1, 0, 0);
        assert_eq!(ctx["body_revisions"][0]["event_id"], root.event_id);
        assert_eq!(ctx["body_revisions"][0]["edited_at"], root.created_at);
    }
}

#[test]
fn description_revision_acknowledges_prior_discussion_including_identical_body() {
    let f = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let e = evidence(&root, &[&c], &root.created_at);
    let id = f.import(&[root, c, e]);
    let original_events = events(&f);
    let before = f.show(&id);
    counts(context(&before), 1, 1, 0, 0);
    f.json(&["issue", "set", &id, "body", "Original body"]);
    let reset = f.show(&id);
    counts(context(&reset), 0, 0, 0, 0);
    assert_ne!(
        context(&before)["body_revisions"],
        context(&reset)["body_revisions"]
    );
    let after = events(&f);
    assert!(original_events.iter().all(|old| after
        .iter()
        .any(|e| e.event_id == old.event_id && e.payload_json == old.payload_json)));
    f.json(&["issue", "set", &id, "body", "Changed nonempty body"]);
    let changed = f.show(&id);
    assert_eq!(changed["body"], "Changed nonempty body");
    counts(context(&changed), 0, 0, 0, 0);
    assert_ne!(
        context(&changed)["body_revisions"],
        context(&reset)["body_revisions"]
    );
    {
        let mut s = WorkItemStore::open(&f.store).unwrap();
        s.add_comment(&id, Some("fixture"), "After changed body")
            .unwrap();
        s.add_evidence(
            &id,
            Some("test"),
            Some("fixture:changed"),
            None,
            Some("fixture"),
        )
        .unwrap();
    }
    counts(context(&f.show(&id)), 1, 1, 0, 0);
    f.json(&["issue", "set", &id, "body", "Changed nonempty body"]);
    let identical = f.show(&id);
    assert_eq!(identical["body"], "Changed nonempty body");
    counts(context(&identical), 0, 0, 0, 0);
    assert_ne!(
        context(&identical)["body_revisions"],
        context(&changed)["body_revisions"]
    );
    f.json(&["issue", "set", &id, "body", ""]);
    let empty = f.show(&id);
    assert_eq!(empty["body"], "");
    counts(context(&empty), 0, 0, 0, 0);
    assert!(context(&empty)["body_revisions"][0]["edited_at"].is_string());
}

#[test]
fn title_status_and_assignment_do_not_reset_description_age() {
    let f = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let id = f.import(&[root, c]);
    let before = f.show(&id)["description_context"].clone();
    f.json(&["issue", "assign", &id, "--to", "fixture-agent"]);
    let shown = f.show(&id);
    assert_eq!(
        shown["assigned_to"], "fixture-agent",
        "actual requested assignment must be visible"
    );
    assert_eq!(context(&shown), &before);
    counts(context(&shown), 1, 0, 0, 0);
    for (field, value) in [("title", "Revised title"), ("status", "closed")] {
        f.json(&["issue", "set", &id, field, value]);
        let shown = f.show(&id);
        assert_eq!(
            shown[field], value,
            "actual requested field mutation must be visible"
        );
        assert_eq!(context(&shown), &before);
        counts(context(&shown), 1, 0, 0, 0);
    }
}

#[test]
fn concurrent_body_and_discussion_report_partial_order_honestly() {
    for same in [false, true] {
        let f = Fixture::new();
        let root = root_event();
        let a = body(&root, &[&root], "Branch body", "2026-10-09 12:01:00");
        let b = body(
            &root,
            &[&root],
            if same { "Branch body" } else { "Other body" },
            "2026-10-09 12:02:00",
        );
        let c = comment(&root, &[&a], "2026-10-09 12:03:00");
        let id = f.import(&[root.clone(), a.clone(), b.clone(), c.clone()]);
        let shown = f.show(&id);
        counts(context(&shown), 0, 0, 1, 0);
        assert_eq!(
            context(&shown)["body_revisions"].as_array().unwrap().len(),
            2
        );
        assert_eq!(shown["conflicted"], !same);
        assert_eq!(context(&shown)["body_provenance_ambiguous"], true);
        let e = evidence(&root, &[&b], "2026-10-09 12:04:00");
        f.import(std::slice::from_ref(&e));
        counts(context(&f.show(&id)), 0, 0, 1, 1);
        let both = comment(&root, &[&c, &e], "2026-10-09 12:05:00");
        f.import(&[both]);
        counts(context(&f.show(&id)), 1, 0, 1, 1);
    }
}

#[test]
fn description_context_survives_alias_transport_and_rebuild() {
    let source = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let id = source.import(&[root.clone(), c]);
    let wanted = source.show(&id)["description_context"].clone();
    let destination = Fixture::new();
    {
        let mut s = WorkItemStore::open(&destination.store).unwrap();
        s.file_item(
            "other",
            "Earlier local alias",
            "",
            &[],
            &json!({}),
            None,
            None,
        )
        .unwrap();
    }
    let exported = events(&source);
    let moved = destination.import(&exported);
    assert_ne!(id, moved);
    assert_eq!(context(&destination.show(&moved)), &wanted);
    destination.import(&exported);
    WorkItemStore::open(&destination.store)
        .unwrap()
        .rebuild_projection()
        .unwrap();
    assert_eq!(context(&destination.show(&moved)), &wanted);
    let reordered = Fixture::new();
    let reverse = exported.into_iter().rev().collect::<Vec<_>>();
    let other = reordered.import(&reverse);
    assert_eq!(context(&reordered.show(&other)), &wanted);
}

#[test]
fn description_show_json_and_text_share_context_and_edit_path() {
    let f = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let id = f.import(&[root.clone(), c]);
    let shown = f.show(&id);
    counts(context(&shown), 1, 0, 0, 0);
    let out = f.cli(&["issue", "show", &id]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains(&root.created_at),
        "body-specific edit time must be visible"
    );
    assert!(
        text.to_ascii_lowercase().contains("later discussion") && text.contains("comment"),
        "newer discussion indicator must be explicit: {text}"
    );
    assert!(
        text.contains("issue edit")
            && text.contains("title")
            && text.contains("body")
            && text.contains("--expect-state-token"),
        "direct guarded revision path: {text}"
    );
}

// Isolated corruption targets existing event rows while projection/body remains
// readable. No hash-valid transport is mislabeled malformed or admitted as such.
fn damage(f: &Fixture, kind: &str, column: &str, value: &str) {
    f.json(&["issue", "bootstrap"]);
    let lock = File::options()
        .read(true)
        .write(true)
        .open(f.store.with_extension("discovery.lock"))
        .expect("open discovery publication lock");
    lock.lock().expect("hold discovery publication lock");
    let db = Connection::open(&f.store).expect("open owned corruption fixture");
    db.create_scalar_function(
        "whip_tracker_discovery_writer_v1",
        0,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
        |_| Ok(1_i64),
    )
    .expect("register fixture writer permit");
    db.execute(
        &format!("UPDATE tracker_events SET {column}=?1 WHERE kind=?2"),
        [value, kind],
    )
    .expect("write owned malformed event");
}
#[test]
fn description_context_refuses_malformed_or_unavailable_history() {
    for fault in [
        "parents-json",
        "payload-json",
        "payload-null",
        "dangling",
        "self-cycle",
        "timestamp",
        "evidence-field",
    ] {
        let f = Fixture::new();
        let root = root_event();
        let c = comment(&root, &[&root], &root.created_at);
        let e = evidence(&root, &[&c], &root.created_at);
        let id = f.import(&[root, c.clone(), e]);
        let (kind, column, value) = match fault {
            "parents-json" => ("comment.added", "parents_json", "not-json".to_owned()),
            "payload-json" => ("comment.added", "payload_json", "not-json".to_owned()),
            "payload-null" => ("comment.added", "payload_json", "null".to_owned()),
            "dangling" => (
                "comment.added",
                "parents_json",
                json!(["absent-event"]).to_string(),
            ),
            "self-cycle" => (
                "comment.added",
                "parents_json",
                json!([c.event_id]).to_string(),
            ),
            "timestamp" => ("comment.added", "created_at", "not-a-date".to_owned()),
            "evidence-field" => (
                "evidence.added",
                "payload_json",
                json!({"kind":"test"}).to_string(),
            ),
            _ => unreachable!(),
        };
        damage(&f, kind, column, &value);
        // Opening and projection still work; the actual strict provenance reader
        // must refuse rather than a fixture-open or generic process failure.
        assert!(WorkItemStore::open_read_only(&f.store)
            .unwrap()
            .get_item(&id)
            .unwrap()
            .is_some());
        let before = logical_state(&f.store);
        for args in [
            vec!["issue", "show", &id],
            vec!["--json", "issue", "show", &id],
        ] {
            let out = f.cli(&args);
            assert!(
                !out.status.success(),
                "damaged event must not produce a false clear: {fault}"
            );
            let diagnostic = String::from_utf8_lossy(&out.stderr);
            assert!(
                diagnostic.contains("issue description context")
                    && diagnostic
                        .contains("recorded description provenance is invalid or incomplete"),
                "strict reader diagnostic for {fault}: {diagnostic}"
            );
            assert!(!String::from_utf8_lossy(&out.stdout).contains("description_context"));
        }
        assert_eq!(logical_state(&f.store), before);
    }
    // Existing supported CLI custody-opening guard, not an encrypted per-event
    // key-unavailable decoder fixture. No host authority is invented here.
    let f = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let id = f.import(&[root, c]);
    Connection::open(&f.store)
        .unwrap()
        .execute_batch("UPDATE tracker_payload_protection SET domain='host-owned-private-domain'")
        .unwrap();
    let before = logical_state(&f.store);
    let discovery_before = discovery_files(f.root.path());
    for args in [
        vec!["issue", "show", &id],
        vec!["--json", "issue", "show", &id],
    ] {
        let out = f.cli(&args);
        assert!(
            !out.status.success(),
            "plain show cannot bypass protected custody"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("Original body") && !stdout.contains("description_context"));
    }
    assert_eq!(logical_state(&f.store), before);
    assert_eq!(discovery_files(f.root.path()), discovery_before);
}
fn logical_state(path: &Path) -> Vec<String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open logical snapshot read-only");
    let mut names = db
        .prepare("SELECT name,coalesce(sql,'') FROM sqlite_schema ORDER BY name")
        .expect("prepare schema snapshot");
    let schema = names
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .expect("query schema snapshot")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect schema snapshot");
    let mut result = vec![db
        .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
        .expect("read snapshot journal mode")];
    for (name, sql) in schema {
        result.push(format!("{name}:{sql}"));
        if sql.starts_with("CREATE TABLE") {
            let mut rows = db
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .expect("prepare table snapshot");
            let count = rows.column_count();
            let mut data = rows
                .query_map([], |r| {
                    Ok((0..count)
                        .map(|i| format!("{:?}", r.get_ref(i).expect("read snapshot column")))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .expect("query table snapshot")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect table snapshot");
            data.sort();
            result.extend(data);
        }
    }
    result
}
// Main database/WAL bytes and permissions are durable store inputs. SQLite's
// read-only WAL reader may update SHM bookkeeping; that is not schema/event
// mutation and is deliberately not claimed to be universally byte immutable.
fn durable_files(path: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
    let mut files = BTreeMap::new();
    for path in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
    ] {
        if path.exists() {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&path)
                    .expect("read durable file permissions")
                    .permissions()
                    .mode()
            };
            #[cfg(not(unix))]
            let mode = u32::from(
                fs::metadata(&path)
                    .expect("read durable file permissions")
                    .permissions()
                    .readonly(),
            );
            files.insert(
                path.clone(),
                (fs::read(&path).expect("read durable file bytes"), mode),
            );
        }
    }
    files
}
fn discovery_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, path: &Path, all: &mut BTreeMap<PathBuf, Vec<u8>>) {
        if !path.exists() {
            return;
        }
        for e in fs::read_dir(path).expect("enumerate discovery files") {
            let p = e.expect("read discovery directory entry").path();
            if p.is_dir() {
                walk(root, &p, all)
            } else {
                all.insert(
                    p.strip_prefix(root)
                        .expect("relativize discovery path")
                        .into(),
                    fs::read(p).expect("read discovery file bytes"),
                );
            }
        }
    }
    let mut all = BTreeMap::new();
    walk(root, &root.join("tracker"), &mut all);
    all
}
#[test]
fn description_show_is_read_only_under_locks_and_guarded_edit_is_cas() {
    let f = Fixture::new();
    let root = root_event();
    let c = comment(&root, &[&root], &root.created_at);
    let id = f.import(&[root, c]);
    f.json(&["issue", "bootstrap"]);
    let before = logical_state(&f.store);
    let files = discovery_files(f.root.path());
    assert!(!files.is_empty());
    let expected = f.show(&id);
    let token = expected["state_token"].as_str().unwrap().to_owned();
    let publication = File::options()
        .read(true)
        .write(true)
        .open(f.store.with_extension("discovery.lock"))
        .unwrap();
    publication.lock().unwrap();
    let writer = Connection::open(&f.store).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer
        .create_scalar_function(
            "whip_tracker_discovery_writer_v1",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(1_i64),
        )
        .unwrap();
    writer
        .execute(
            "UPDATE tracker_issues SET title='Uncommitted hidden title' WHERE issue_id=?1",
            [&id],
        )
        .unwrap();
    let durable_before = durable_files(&f.store);
    assert_eq!(f.show(&id), expected);
    assert!(f.cli(&["issue", "show", &id]).status.success());
    assert_eq!(durable_files(&f.store), durable_before);
    assert_eq!(logical_state(&f.store), before);
    assert_eq!(discovery_files(f.root.path()), files);
    writer.execute_batch("ROLLBACK").unwrap();
    drop(writer);
    drop(publication);
    assert_eq!(
        f.json(&[
            "issue",
            "set",
            &id,
            "title",
            "After first view",
            "--expect-state-token",
            &token
        ])["outcome"],
        "applied"
    );
    let prior = f.show(&id);
    let prior_events = events(&f);
    assert_eq!(
        f.json(&[
            "issue",
            "set",
            &id,
            "body",
            "Must not overwrite",
            "--expect-state-token",
            &token
        ])["outcome"],
        "state-changed"
    );
    let refused = f.cli(&[
        "issue",
        "set",
        &id,
        "body",
        "Must not overwrite",
        "--expect-state-token",
        &token,
    ]);
    assert!(!refused.status.success());
    assert_eq!(f.show(&id), prior);
    assert_eq!(
        serde_json::to_value(events(&f)).unwrap(),
        serde_json::to_value(prior_events).unwrap()
    );
    let current = prior["state_token"].as_str().unwrap();
    assert_eq!(
        f.json(&[
            "issue",
            "set",
            &id,
            "body",
            "Reviewed body",
            "--expect-state-token",
            current
        ])["outcome"],
        "applied"
    );
    counts(context(&f.show(&id)), 0, 0, 0, 0);
}
