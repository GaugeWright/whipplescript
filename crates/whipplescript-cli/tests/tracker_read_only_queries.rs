//! DR-0188: a query observes committed work without entering discovery's writer path.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

fn command(cwd: &Path, store: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
    command
        .current_dir(cwd)
        .env("WHIPPLESCRIPT_ITEMS_STORE", store)
        .env("WHIPPLESCRIPT_MISUSE_LOG", "off")
        .args(args)
        .stdin(Stdio::null());
    command
}

// A regression must fail promptly while the scratch locks are STILL held,
// rather than pass because a timer let the writer go. Kill only this test's child.
fn run(cwd: &Path, store: &Path, args: &[&str]) -> Output {
    // The newly linked macOS binary's first launch can spend several seconds
    // in the loader. Warm it once before fixture setup or any held-lock probe;
    // every tracker operation still has the strict five-second deadline below.
    static PREFLIGHT: std::sync::Once = std::sync::Once::new();
    PREFLIGHT.call_once(|| {
        let version = run_bounded(cwd, store, &["--version"], Duration::from_secs(30));
        assert!(version.status.success(), "CLI startup preflight");
    });
    run_bounded(cwd, store, args, Duration::from_secs(5))
}

fn run_bounded(cwd: &Path, store: &Path, args: &[&str], timeout: Duration) -> Output {
    let capture = tempfile::tempdir().expect("capture");
    let stdout = File::create(capture.path().join("stdout")).expect("create stdout capture file");
    let stderr = File::create(capture.path().join("stderr")).expect("create stderr capture file");
    let mut child = command(cwd, store, args)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn scratch CLI child");
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("check scratch child status") {
            return Output {
                status,
                stdout: fs::read(capture.path().join("stdout")).expect("read scratch child stdout"),
                stderr: fs::read(capture.path().join("stderr")).expect("read scratch file bytes"),
            };
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill our scratch child");
            child.wait().expect("reap scratch child");
            panic!("whip {args:?} exceeded its {timeout:?} process deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn good(cwd: &Path, store: &Path, args: &[&str]) -> Value {
    let out = run(cwd, store, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("JSON result")
}

fn checkout(path: &Path) {
    fs::create_dir_all(path).expect("create scratch fixture directory");
    assert!(Command::new("git")
        .args(["init", "--quiet"])
        .arg(path)
        .stdin(Stdio::null())
        .status()
        .expect("initialize scratch Git checkout")
        .success());
}

fn seed(cwd: &Path, store: &Path) -> String {
    good(
        cwd,
        store,
        &[
            "--json",
            "issue",
            "new",
            "--tracker",
            "t",
            "--title",
            "committed-title",
        ],
    )["id"]
        .as_str()
        .expect("JSON result carries a string identity")
        .to_owned()
}

// Observe every logical table, not only events: accidental enrollment, schema
// setup, counters or a projection repair must be visible to this assertion.
fn logical_state(store: &Path) -> Vec<String> {
    let connection = Connection::open_with_flags(store, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open scratch tracker connection");
    let mut statement = connection
        .prepare("SELECT name, coalesce(sql,'') FROM sqlite_schema ORDER BY name")
        .expect("prepare scratch schema inspection");
    let schema = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("collect scratch store rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect scratch store rows");
    let mut state = vec![connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .expect("read scratch store metadata")];
    for (name, sql) in schema {
        state.push(format!("{name}: {sql}"));
        if sql.starts_with("CREATE TABLE") {
            let quoted = name.replace('"', "\"\"");
            let mut statement = connection
                .prepare(&format!("SELECT * FROM \"{quoted}\""))
                .expect("prepare scratch store query");
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|index| {
                            format!("{:?}", row.get_ref(index).expect("read scratch row value"))
                        })
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .expect("query scratch table rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect scratch store rows");
            rows.sort();
            state.extend(rows);
        }
    }
    state
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        if !path.exists() {
            return;
        }
        for entry in fs::read_dir(path).expect("enumerate scratch discovery files") {
            let path = entry
                .expect("read scratch discovery directory entry")
                .path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root)
                        .expect("file belongs to scratch discovery root")
                        .to_owned(),
                    fs::read(path).expect("read scratch file bytes"),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, &root.join("tracker"), &mut result);
    result
}

#[test]
fn query_matrix_answers_committed_data_while_both_writer_locks_remain_held() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let publisher = fixture.path().join("publisher");
    let query_checkout = fixture.path().join("query-checkout");
    checkout(&publisher);
    checkout(&query_checkout);
    let store = fixture.path().join("items.sqlite");
    let id = seed(&publisher, &store);
    let assertion = good(
        &publisher,
        &store,
        &["--json", "assert", "new", "--title", "committed-assertion"],
    );
    let assertion_id = assertion["id"]
        .as_str()
        .expect("JSON result carries a string identity");
    let before = logical_state(&store);
    let generated = files(&publisher);
    assert!(
        !generated.is_empty(),
        "seed publishes a real discovery view"
    );
    let abandoned = publisher.join(".tracker-stage-read-query-must-not-clean");
    fs::create_dir(&abandoned).expect("create scratch fixture directory");
    let owner = fs::read(publisher.join("tracker/.whipplescript-discovery-owner"))
        .expect("read scratch file bytes");
    fs::write(abandoned.join(".whipplescript-discovery-owner"), owner)
        .expect("write scratch discovery owner marker");
    fs::write(abandoned.join("sentinel"), "still present").expect("write abandoned-stage sentinel");
    let transport = fixture.path().join("transport-export");
    let transport_str = transport.to_str().expect("scratch transport path is UTF-8");
    let git_exclude =
        fs::read(query_checkout.join(".git/info/exclude")).expect("read scratch file bytes");
    let publication_lock = File::options()
        .read(true)
        .write(true)
        .open(store.with_extension("discovery.lock"))
        .expect("open scratch publication lock file");
    publication_lock
        .lock()
        .expect("hold scratch publication lock");
    let writer = Connection::open(&store).expect("open scratch tracker connection");
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .expect("apply scratch SQL setup");
    // This scratch writer genuinely holds the publication lock above. Retain
    // the durable trigger guard and provide its connection-local permit solely
    // to stage an uncommitted title that a query must never observe.
    writer
        .create_scalar_function(
            "whip_tracker_discovery_writer_v1",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(1_i64),
        )
        .expect("register scratch writer permit");
    writer
        .execute(
            "UPDATE tracker_issues SET title='uncommitted-private-title' WHERE issue_id=?1",
            [&id],
        )
        .expect("stage uncommitted scratch title");

    let commands: Vec<Vec<&str>> = vec![
        vec!["issue"],
        vec!["issue", "list", "--tracker", "t"],
        vec!["issue", "show", &id],
        vec!["issue", "ready", "t"],
        vec!["issue", "why", &id],
        vec!["issue", "waits", &id],
        vec!["issue", "review"],
        vec!["issue", "conflicts", &id],
        vec!["issue", "conflicts", "--tracker", "t"],
        vec!["issue", "comments", &id],
        vec!["issue", "anchors", &id],
        vec!["issue", "evidence", &id],
        vec!["issue", "evidence", &id, "--kind"],
        vec!["issue", "export"],
        vec!["issue", "export", "--to", transport_str],
        vec!["assert"],
        vec!["assert", "list"],
        vec!["assert", "show", assertion_id],
        vec!["assert", "anchors", assertion_id],
    ];
    for args in commands {
        let mut json_args = vec!["--json"];
        json_args.extend(args);
        let result = good(&query_checkout, &store, &json_args);
        assert!(
            !result.to_string().contains("uncommitted-private-title"),
            "{json_args:?}: {result}"
        );
        if json_args.contains(&"show") && json_args.contains(&id.as_str()) {
            assert_eq!(result["title"], "committed-title");
        }
    }
    // Both locks remain held through every process result and invariant check.
    assert_eq!(logical_state(&store), before);
    assert_eq!(files(&publisher), generated);
    assert_eq!(
        fs::read_to_string(abandoned.join("sentinel")).expect("read generated discovery record"),
        "still present"
    );
    assert!(
        transport.is_dir(),
        "explicit export transport output is still permitted"
    );
    assert!(!query_checkout.join("tracker").exists());
    assert!(!query_checkout.join(".whipplescript").exists());
    assert_eq!(
        fs::read(query_checkout.join(".git/info/exclude")).expect("read scratch file bytes"),
        git_exclude
    );
    writer
        .execute_batch("ROLLBACK")
        .expect("apply scratch SQL setup");
    drop(publication_lock);
}

#[test]
fn queries_refuse_missing_and_incompatible_authority_without_initializing_it() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path();
    let missing = root.join("missing-parent/items.sqlite");
    for args in [
        &["issue"][..],
        &["issue", "list"][..],
        &["assert"][..],
        &["assert", "list"][..],
        &["issue", "bootstrap", "unexpected"][..],
    ] {
        let refusal = run(root, &missing, args);
        assert!(!refusal.status.success());
        if args.len() == 1 || args.get(1) == Some(&"list") {
            let message = String::from_utf8_lossy(&refusal.stderr);
            assert!(!message.contains("whip bug"), "{message}");
            assert!(message.contains("existing readable store"), "{message}");
            assert!(message.contains("WHIPPLESCRIPT_ITEMS_STORE"), "{message}");
            assert!(message.contains("whip issue bootstrap"), "{message}");
        }
        assert!(!missing
            .parent()
            .expect("scratch store path has a parent")
            .exists());
    }
    let empty = root.join("empty.sqlite");
    drop(Connection::open(&empty).expect("open scratch tracker connection"));
    let before = logical_state(&empty);
    assert!(!run(root, &empty, &["issue", "list"]).status.success());
    assert_eq!(logical_state(&empty), before);

    let store = root.join("items.sqlite");
    seed(root, &store);
    for sql in [
        "UPDATE schema_migrations SET name='foreign'",
        "UPDATE schema_migrations SET name='work-item', version=version+1",
    ] {
        let db = Connection::open(&store).expect("open scratch tracker connection");
        db.execute_batch(sql).expect("apply scratch SQL setup");
        let before = logical_state(&store);
        assert!(!run(root, &store, &["issue", "list"]).status.success());
        assert_eq!(logical_state(&store), before);
    }
}

#[test]
fn reads_support_future_write_protocol_and_evidence_attachment_still_writes() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path();
    checkout(root);
    let store = root.join("items.sqlite");
    let id = seed(root, &store);
    good(
        root,
        &store,
        &[
            "--json",
            "issue",
            "evidence",
            &id,
            "--note",
            "synchronous-note",
        ],
    );
    let evidence = good(root, &store, &["--json", "issue", "evidence", &id]);
    assert_eq!(evidence[0]["note"], "synchronous-note");
    assert!(
        fs::read_to_string(root.join(format!("tracker/tasks/{id}.hjson")))
            .expect("read generated discovery record")
            .contains("synchronous-note")
    );
    let db = Connection::open(&store).expect("open scratch tracker connection");
    db.execute_batch("UPDATE tracker_write_protocol SET version=7, raised_by='9.9.9'")
        .expect("apply scratch SQL setup");
    let before = logical_state(&store);
    assert_eq!(
        good(root, &store, &["--json", "issue", "show", &id])["title"],
        "committed-title"
    );
    good(root, &store, &["--json", "issue", "evidence", &id]);
    let refused = run(
        root,
        &store,
        &["issue", "evidence", &id, "--note", "forbidden"],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("upgrade whip"));
    let bootstrap = run(root, &store, &["issue", "bootstrap"]);
    assert!(
        !bootstrap.status.success(),
        "future write protocol refuses writable bootstrap even in an enrolled checkout"
    );
    assert!(String::from_utf8_lossy(&bootstrap.stderr).contains("upgrade whip"));
    assert_eq!(logical_state(&store), before);
}

#[test]
fn bootstrap_explicitly_enrolls_and_repairs_but_show_leaves_a_missing_view_missing() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path().join("checkout");
    checkout(&root);
    let store = fixture.path().join("items.sqlite");
    let bootstrap = run(&root, &store, &["issue", "bootstrap"]);
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let id = seed(&root, &store);
    let record = root.join(format!("tracker/tasks/{id}.hjson"));
    let published = fs::read(&record).expect("read scratch file bytes");
    fs::remove_file(&record).expect("remove scratch generated record");
    let before = logical_state(&store);
    good(&root, &store, &["--json", "issue", "show", &id]);
    assert!(!record.exists(), "query does not repair a derived view");
    assert_eq!(logical_state(&store), before);
    let bootstrap = run(&root, &store, &["issue", "bootstrap"]);
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    assert_eq!(
        fs::read(&record).expect("read scratch file bytes"),
        published
    );
    assert_eq!(
        logical_state(&store),
        before,
        "bootstrap repairs publication without changing tracker work"
    );
}

#[test]
fn plain_cli_queries_do_not_bypass_protected_custody() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path();
    let store = root.join("items.sqlite");
    seed(root, &store);
    Connection::open(&store)
        .expect("open scratch tracker connection")
        .execute_batch("UPDATE tracker_payload_protection SET domain='host-owned-private-domain'")
        .expect("apply scratch SQL setup");
    let before = logical_state(&store);
    for args in [&["issue", "list"][..], &["assert", "list"][..]] {
        let refusal = run(root, &store, args);
        assert!(!refusal.status.success());
        assert!(!String::from_utf8_lossy(&refusal.stdout).contains("committed-title"));
    }
    assert_eq!(logical_state(&store), before);
}

#[test]
fn a_query_does_not_convert_a_restored_rollback_journal_store_to_wal() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path();
    let store = root.join("items.sqlite");
    let id = seed(root, &store);
    let db = Connection::open(&store).expect("open scratch tracker connection");
    let mode: String = db
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .expect("set scratch restored store to rollback journal");
    assert_eq!(mode, "delete");
    drop(db);
    let before = logical_state(&store);
    assert_eq!(
        good(root, &store, &["--json", "issue", "show", &id])["title"],
        "committed-title"
    );
    assert_eq!(logical_state(&store), before);
    assert!(!store.with_extension("sqlite-wal").exists());
}

#[test]
fn bootstrap_refuses_to_report_enrollment_without_a_git_checkout() {
    let fixture = tempfile::tempdir().expect("create isolated test directory");
    let root = fixture.path();
    let store = root.join("items.sqlite");
    seed(root, &store);
    let before = logical_state(&store);
    let bootstrap = run(root, &store, &["issue", "bootstrap"]);
    assert!(!bootstrap.status.success());
    assert!(!root.join("tracker").exists());
    assert_eq!(logical_state(&store), before);
}
