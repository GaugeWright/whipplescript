//! Inspection must not initialize or alter the runtime it explains.
use super::*;

type InspectionCommand = (&'static str, fn(&CliOptions) -> ExitCode);
const COMMANDS: &[InspectionCommand] = &[
    ("instances", instances),
    ("status", status),
    ("log", log),
    ("facts", facts),
    ("view", view),
    ("effects", effects),
    ("progressions", progressions),
    ("runs", runs),
    ("artifacts", artifacts),
    ("evidence", evidence),
    ("diagnostics", diagnostics),
    ("trace", trace),
];

struct ObservationFixture(TempPath);
impl ObservationFixture {
    fn new() -> Self {
        let root = unique_test_path("read-only-observation", "dir");
        fs::create_dir(&root).expect("isolated fixture");
        Self(root)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.sqlite")
    }
}
impl Drop for ObservationFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("closed fixture cleanup");
    }
}

fn options(name: &str, path: &Path, instance: &str, json: bool) -> CliOptions {
    let mut args = if name == "instances" {
        vec![]
    } else {
        vec![instance.to_owned()]
    };
    if name == "trace" {
        args.push("--check".to_owned());
    }
    CliOptions {
        command: Some(name.to_owned()),
        args,
        store_path: path.to_owned(),
        json,
        input_json: None,
    }
}

#[test]
fn read_only_observation_commands_do_not_create_missing_stores() {
    let fixture = ObservationFixture::new();
    let missing_parent = fixture.0.join("absent");
    for (name, command) in COMMANDS {
        for path in [
            fixture.database(),
            missing_parent.join("runtime.sqlite"),
            PathBuf::from(":memory:"),
        ] {
            for json in [false, true] {
                assert_eq!(
                    command(&options(name, &path, "absent", json)),
                    ExitCode::FAILURE,
                    "{name}, json={json}, path={path:?}"
                );
                assert!(!fixture.database().exists(), "{name} created a database");
                assert!(!missing_parent.exists(), "{name} created a directory");
            }
        }
    }
}

#[test]
fn read_only_observation_commands_do_not_migrate_incompatible_stores() {
    let fixture = ObservationFixture::new();
    let path = fixture.database();
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE unrelated (value TEXT);")
            .unwrap();
    }
    let before = fs::read(&path).unwrap();
    for (name, command) in COMMANDS {
        for json in [false, true] {
            assert_eq!(
                command(&options(name, &path, "absent", json)),
                ExitCode::FAILURE,
                "{name}, json={json}"
            );
            assert_eq!(fs::read(&path).unwrap(), before, "{name} altered schema");
            assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1, "{name}");
        }
    }
}

#[test]
fn read_only_observation_commands_read_real_workflow_without_changing_evidence() {
    let fixture = ObservationFixture::new();
    let path = fixture.database();
    let source_path = fixture.0.join("observation.whip");
    fs::write(
        &source_path,
        "workflow Observe(ticket: Ticket) -> float ! string\n\n\
         class Ticket {\n  id string\n}\n\n\
         rule score\n  when Ticket as ticket\n=> {\n  complete result 0.9\n}\n",
    )
    .unwrap();
    let started = start_workflow_instance(
        source_path.to_str().unwrap(),
        None,
        None,
        Some(r#"{"ticket":{"id":"t1"}}"#),
        &options("dev", &path, "", false),
    )
    .unwrap_or_else(|_| panic!("real workflow starts"));
    // A readable store need not carry the mutation path's private modes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o750)).unwrap();
    }
    let before = fs::read(&path).unwrap();
    let before_events = SqliteStore::open_read_only(&path)
        .unwrap()
        .list_events(&started.instance_id)
        .unwrap();
    assert!(!before_events.is_empty());
    for (name, command) in COMMANDS {
        for json in [false, true] {
            assert_eq!(
                command(&options(name, &path, &started.instance_id, json)),
                ExitCode::SUCCESS,
                "{name}, json={json}"
            );
            assert_eq!(fs::read(&path).unwrap(), before, "{name} altered database");
            assert_eq!(
                SqliteStore::open_read_only(&path)
                    .unwrap()
                    .list_events(&started.instance_id)
                    .unwrap(),
                before_events,
                "{name} changed history"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o640,
                    "{name}"
                );
                assert_eq!(
                    fs::metadata(&fixture.0).unwrap().permissions().mode() & 0o777,
                    0o750,
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn worker_input_read_connects_without_a_migration_lock_or_database_creation() {
    let fixture = ObservationFixture::new();
    let path = fixture.database();
    let effect = ClaimableEffect {
        effect_id: "following".into(), kind: "agent.tell".into(), target: Some("worker".into()), profile: None,
        input_json: json!({"after": {"binding": "prior", "predicate": "succeeds", "upstream_effect_id": "prior"}}).to_string(),
        required_capabilities_json: "[]".into(), declared_profiles_json: "[]".into(),
    };
    assert!(resolve_effect_input_after_bindings(&path, "instance", &effect).is_err());
    assert!(!path.exists());
    drop(SqliteStore::open(&path).unwrap());
    let mut writer = rusqlite::Connection::open(&path).unwrap();
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(
        resolve_effect_input_after_bindings(&path, "instance", &effect).unwrap(),
        effect.input_json
    );
    tx.commit().unwrap();
}
