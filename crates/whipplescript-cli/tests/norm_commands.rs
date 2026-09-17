#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};
use whipplescript_custodian::{store::SealedStore, Custodian, DeniedEgress};
use whipplescript_custody::{CredentialKind, CredentialName, CustodyCall};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    trust: Value,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-norm-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("norm CLI fixture");
        let socket = root.join("custody.sock");
        let listener = UnixListener::bind(socket).expect("norm CLI fixture");
        listener.set_nonblocking(true).expect("norm CLI fixture");
        let mut sealed =
            SealedStore::create(None, "synthetic-norm-fixture").expect("norm CLI fixture");
        for (name, byte) in [("owner", 1), ("worker", 2), ("successor", 3)] {
            sealed
                .register(
                    CredentialName::new(&format!("norm/{name}")).expect("norm CLI fixture"),
                    CredentialKind::Ed25519,
                    vec![byte; 32].into(),
                    None,
                    None,
                )
                .expect("norm CLI fixture");
        }
        let custodian = Custodian::new(sealed, Box::new(DeniedEgress));
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                // Blocking reads inside the handler, the way
                // `credential_proxy`'s accept loop already does it: the
                // listener above is non-blocking so the loop can watch `stop`,
                // and Linux hands back an accepted socket with O_NONBLOCK
                // cleared while BSD -- macOS -- hands back one that inherited
                // it. Without this the read below returned EAGAIN instantly on
                // macOS, the fixture thread panicked inside `expect`, and the
                // client read the resulting EOF as `malformed reply`, which
                // then panicked in a destructor and aborted the whole test
                // binary. A read timeout does not cover it; a non-blocking
                // socket does not wait to time out.
                let _ = stream.set_nonblocking(false);
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("norm CLI fixture");
                let mut line = String::new();
                BufReader::new(stream.try_clone().expect("norm CLI fixture"))
                    .read_line(&mut line)
                    .expect("norm CLI fixture");
                let call: CustodyCall = serde_json::from_str(&line).expect("norm CLI fixture");
                let reply = custodian.handle(&call);
                writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&reply).expect("norm CLI fixture")
                )
                .expect("norm CLI fixture");
            }
        });
        let trust = json!({
            "bindings": [
                {"name":"owner","principal":"owner","credential":"norm/owner","version":{"kind":"immutable_local"}},
                {"name":"worker","principal":"worker","credential":"norm/worker","version":{"kind":"immutable_local"}},
                {"name":"successor","principal":"owner","credential":"norm/successor","version":{"kind":"immutable_local"}}
            ],
            "creation_grants":[{"creator":"worker","owner":"owner"}]
        });
        Self {
            root,
            trust,
            stop,
            server: Some(server),
        }
    }
    fn seed_norm_artifacts(&self) -> Value {
        use std::collections::BTreeMap;
        use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
        use whipplescript_store::content::ContentStore;
        let mut branches =
            BranchStore::open(self.root.join("branches.sqlite")).expect("query branches");
        let content = ContentStore::open(self.root.join("content.sqlite")).expect("query content");
        branches.ensure_mainline("t0").expect("query mainline");
        let mut blobs = BTreeMap::new();
        let mut cuts = Vec::new();
        for (cut, files) in [
            (
                "before",
                vec![
                    ("src/auth.py", "authorization"),
                    ("src/parser.py", "old café"),
                ],
            ),
            (
                "after",
                vec![("src/parser.py", "changed"), ("src/new.py", "new")],
            ),
        ] {
            let mut manifest = BTreeMap::new();
            for (path, body) in files {
                let id = content.put(body.as_bytes()).expect("query file");
                blobs.insert(id.clone(), body.to_owned());
                manifest.insert(path, id);
            }
            let body = serde_json::to_string(&manifest).expect("flat manifest");
            let root = content.put(body.as_bytes()).expect("query manifest");
            blobs.insert(root.clone(), body);
            branches
                .record_cut(CutRecord {
                    cut_id: cut,
                    change_id: cut,
                    branch_id: MAINLINE_BRANCH_ID,
                    manifest_hash: &root,
                    parent_cut_id: None,
                    origin: None,
                    actor: None,
                    intent: None,
                    recorded_at: "t1",
                })
                .expect("query cut");
            cuts.push(json!({"cut_id":cut,"change_id":cut,"branch_id":MAINLINE_BRANCH_ID,"manifest_hash":root,"recorded_at":"t1"}));
        }
        json!({"cuts":cuts,"blobs":blobs.into_iter().map(|(id,body)|json!({"id":id,"byte_len":body.len(),"body":body})).collect::<Vec<_>>()})
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
        command
            .current_dir(&self.root)
            .env_clear()
            .env(
                "WHIPPLESCRIPT_CUSTODIAN_SOCKET",
                self.root.join("custody.sock"),
            )
            .env("WHIPPLESCRIPT_NORM_TRUST", self.trust.to_string())
            .env("WHIPPLESCRIPT_ITEMS_STORE", self.root.join("items.sqlite"))
            .env(
                "WHIPPLESCRIPT_BRANCH_STORE",
                self.root.join("branches.sqlite"),
            )
            .env(
                "WHIPPLESCRIPT_VCS_CONTENT_STORE",
                self.root.join("content.sqlite"),
            )
            .arg("--json")
            .arg("norm")
            .args(args);
        command
    }
    fn run(&self, args: &[&str]) -> Value {
        let output = self.command(args).output().expect("norm CLI fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("norm CLI fixture")
    }
    fn refuse(&self, args: &[&str]) -> Output {
        let output = self.command(args).output().expect("norm CLI fixture");
        assert!(
            !output.status.success(),
            "unexpected success: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        output
    }
    fn write(&self, name: &str, value: &Value) {
        std::fs::write(
            self.root.join(name),
            serde_json::to_vec(value).expect("norm CLI fixture"),
        )
        .expect("norm CLI fixture");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server
            .take()
            .expect("norm CLI fixture")
            .join()
            .expect("norm CLI fixture");
        std::fs::remove_dir_all(&self.root).expect("norm CLI fixture");
    }
}

#[test]
fn norm_cli_custody_lifecycle_rotation_and_trusted_restore() {
    let mut fixture = Fixture::new();
    fixture.run(&["bootstrap", "--as", "owner", "--creator", "worker"]);
    fixture.write("fields.json", &json!({"title":"First decision","intent":"Record the bounded contract","subjects":["src/auth.py"]}));
    let created = fixture.run(&[
        "create",
        "decision@1",
        "--as",
        "worker",
        "--fields",
        "fields.json",
    ]);
    let record = created["result"]["event_id"]
        .as_str()
        .expect("norm CLI fixture");
    fixture.refuse(&["transition", "N-1", "accepted", "--as", "worker"]);
    fixture.run(&["transition", "N-1", "accepted", "--as", "owner"]);
    fixture.write("fields.json", &json!({"title":"Revised decision","intent":"Record the bounded contract","subjects":["src/auth.py"]}));
    fixture.run(&["edit", "N-1", "--as", "worker", "--fields", "fields.json"]);
    let snapshot = fixture.run(&["snapshot"]);
    assert_eq!(
        snapshot["result"]["snapshot"]["records"][0]["record"]["id"],
        record
    );
    assert_eq!(
        snapshot["result"]["snapshot"]["records"][0]["record"]["status"],
        "proposed"
    );
    fixture.run(&["rotate", "--as", "owner", "--successor", "successor"]);
    fixture.refuse(&["transition", "N-1", "accepted", "--as", "owner"]);
    fixture.run(&["transition", "N-1", "accepted", "--as", "successor"]);
    let final_snapshot = fixture.run(&["snapshot"]);
    let exported = fixture.run(&["export"]);
    assert_eq!(
        exported["result"]["events"]
            .as_array()
            .expect("norm CLI fixture")
            .len(),
        6
    );
    fixture.write("history.json", &exported["result"]["events"]);
    assert_eq!(
        fixture.run(&["import", "--events", "history.json"])["result"]["inserted"],
        0
    );
    // A destination can only be pinned by the independent process host input.
    let destination = fixture.root.join("restored.sqlite");
    let denied = fixture
        .command(&["import", "--events", "history.json"])
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("norm CLI fixture");
    assert!(!denied.status.success());
    fixture.trust["checkpoint"] = exported["result"]["checkpoint"].clone();
    fixture.trust["creation_grants"] = json!([]);
    let provision = fixture
        .command(&["provision"])
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("norm CLI fixture");
    assert!(
        provision.status.success(),
        "{}",
        String::from_utf8_lossy(&provision.stderr)
    );
    let imported = fixture
        .command(&["import", "--events", "history.json"])
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("norm CLI fixture");
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let restored = fixture
        .command(&["snapshot"])
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("norm CLI fixture");
    assert!(restored.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&restored.stdout).expect("norm CLI fixture"),
        final_snapshot
    );
}

#[test]
fn norm_cli_sign_dispatch_preserves_exact_events_and_raw_refusals() {
    let fixture = Fixture::new();
    let statement = json!({
        "protocol":"whipplescript.norm/v1",
        "actor":{"principal":"owner","algorithm":"ed25519-custodian","key_id":"credential:norm/owner#local"},
        "nonce":"prepared-genesis","created_at":"2026-09-06T00:00:00Z",
        "action":{"act":"bootstrap","creator":"worker","charter":{"vocabularies":[],"owner_scopes":[]}}
    });
    fixture.write("statement.json", &statement);
    fixture.refuse(&["sign", "--as", "worker", "--statement", "statement.json"]);
    let signed = fixture.run(&["sign", "--as", "owner", "--statement", "statement.json"]);
    assert!(
        !fixture.root.join("items.sqlite").exists(),
        "signing does not open a ledger"
    );
    let request = json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"append","event":signed}});
    fixture.write("request.json", &request);
    let invalid = request.to_string().replacen("{", "{\"bindings\":[],", 1);
    std::fs::write(fixture.root.join("invalid.json"), invalid).expect("norm CLI fixture");
    fixture.refuse(&["dispatch", "--request", "invalid.json"]);
    fixture.refuse(&["snapshot"]);
    fixture.write("event.json", &signed);
    fixture.refuse(&["cosign", "--as", "successor", "--event", "event.json"]);
    let first = fixture.run(&["dispatch", "--request", "request.json"]);
    assert_eq!(
        fixture.run(&["dispatch", "--request", "request.json"]),
        first
    );
    assert_eq!(
        fixture.run(&["export"])["result"]["events"]
            .as_array()
            .expect("norm CLI fixture")
            .len(),
        1
    );
    let ledger = first["result"]["event_id"]
        .as_str()
        .expect("norm CLI fixture");
    let rotation = json!({
        "protocol":"whipplescript.norm/v1",
        "actor":statement["actor"], "nonce":"rotation", "created_at":"2026-09-06T00:00:01Z",
        "action":{"act":"rotate","ledger":ledger,"previous":ledger,"successor":{
            "principal":"owner","algorithm":"ed25519-custodian","key_id":"credential:norm/successor#local"
        },"frontier":[ledger]}
    });
    fixture.write("rotation.json", &rotation);
    let primary = fixture.run(&["sign", "--as", "owner", "--statement", "rotation.json"]);
    fixture.write("primary.json", &primary);
    fixture.refuse(&["cosign", "--as", "worker", "--event", "primary.json"]);
    let mut forged = primary.clone();
    forged["signature"] = json!("invalid");
    fixture.write("forged.json", &forged);
    fixture.refuse(&["cosign", "--as", "successor", "--event", "forged.json"]);
    let dual = fixture.run(&["cosign", "--as", "successor", "--event", "primary.json"]);
    fixture.write("rotate-request.json", &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"append","event":dual}}));
    fixture.run(&["dispatch", "--request", "rotate-request.json"]);
    assert_eq!(
        fixture.run(&["snapshot"])["result"]["snapshot"]["owner"]["key_id"],
        "credential:norm/successor#local"
    );
}

#[test]
fn norm_cli_refuses_missing_or_ambiguous_host_configuration() {
    let mut fixture = Fixture::new();
    let args = ["bootstrap", "--as", "owner", "--creator", "worker"];
    for variable in ["WHIPPLESCRIPT_NORM_TRUST", "WHIPPLESCRIPT_CUSTODIAN_SOCKET"] {
        assert!(!fixture
            .command(&args)
            .env_remove(variable)
            .output()
            .expect("norm CLI fixture")
            .status
            .success());
    }
    assert!(!fixture
        .command(&args)
        .env(
            "WHIPPLESCRIPT_CUSTODIAN_SOCKET",
            fixture.root.join("missing.sock")
        )
        .output()
        .expect("norm CLI fixture")
        .status
        .success());
    fixture.trust["creation_grants"] = json!([]);
    fixture.refuse(&args);
    fixture.trust["creation_grants"] = json!([{"creator":"worker","owner":"owner"}]);
    let original = fixture.trust.clone();
    fixture.trust["bindings"][0]["version"] = json!({"kind":"version","version":1});
    fixture.refuse(&args); // local backend returned None, not pinned version 1
    fixture.trust = original.clone();
    fixture.trust["bindings"][0]["version"] = json!({"kind":"version","version":0});
    fixture.refuse(&args);
    fixture.trust = original.clone();
    fixture.trust["bindings"][2]["name"] = json!("owner");
    fixture.refuse(&args);
    fixture.trust = original.clone();
    fixture.trust["bindings"][0]["name"] = json!("");
    fixture.refuse(&["bootstrap", "--as", "", "--creator", "worker"]);
    fixture.trust = original;
    fixture.refuse(&[
        "bootstrap",
        "--as",
        "worker",
        "--as",
        "owner",
        "--creator",
        "worker",
    ]);
    fixture.refuse(&[
        "bootstrap",
        "--as",
        "owner",
        "--creator",
        "worker",
        "--bindings",
        "request.json",
    ]);
    fixture.refuse(&["provision"]);
    for malformed in [
        vec!["unknown"],
        vec!["snapshot", "extra"],
        vec!["bootstrap", "--as"],
        vec!["bootstrap", "--as", "owner"],
        vec!["bootstrap", "--as", "unknown", "--creator", "worker"],
    ] {
        fixture.refuse(&malformed);
    }
    fixture.run(&args);
    fixture.refuse(&["unknown"]);
    fixture.refuse(&["snapshot", "extra"]);
    fixture.write("fields.json", &json!({"title":"Uninstalled"}));
    fixture.refuse(&[
        "create",
        "missing@1",
        "--as",
        "worker",
        "--fields",
        "fields.json",
    ]);
    fixture.refuse(&["edit", "N-99", "--as", "worker", "--fields", "fields.json"]);
    assert_eq!(
        fixture.run(&["export"])["result"]["events"]
            .as_array()
            .expect("norm CLI fixture")
            .len(),
        1
    );
}

#[test]
fn norm_cli_custody_history_roundtrips_through_do_public_verification() {
    use ring::signature::KeyPair as _;
    use whipplescript_host_do::norm_commands::execute_hosted_norm_command;
    use whipplescript_store::norm::NormCheckpoint;

    let mut fixture = Fixture::new();
    fixture.run(&["bootstrap", "--as", "owner", "--creator", "worker"]);
    fixture.write("fields.json", &json!({"title":"Portable issue"}));
    fixture.run(&[
        "create",
        "issue@1",
        "--as",
        "worker",
        "--fields",
        "fields.json",
    ]);
    // The fresh vector carries an explicit retirement of an older acceptance
    // while preserving a newer draft, through real CLI/custody signatures.
    fixture.write("obligation.json", &json!({"name":"authorize","proposition":"deny unknown","domain":"workspace","subject":"src/auth.py"}));
    fixture.run(&[
        "create",
        "obligation@1",
        "--as",
        "worker",
        "--fields",
        "obligation.json",
    ]);
    fixture.refuse(&["retire", "N-2", "retired", "--as", "owner"]);
    fixture.run(&["transition", "N-2", "accepted", "--as", "owner"]);
    fixture.write("obligation.json", &json!({"name":"authorize","proposition":"deny anonymous too","domain":"workspace","subject":"src/auth.py"}));
    fixture.run(&[
        "edit",
        "N-2",
        "--as",
        "worker",
        "--fields",
        "obligation.json",
    ]);
    fixture.refuse(&["retire", "N-2", "retired", "--as", "worker"]);
    fixture.refuse(&["retire", "N-2", "accepted", "--as", "owner"]);
    fixture.run(&["retire", "N-2", "retired", "--as", "owner"]);
    fixture.refuse(&["retire", "N-2", "retired", "--as", "owner"]);
    let snapshot = fixture.run(&["snapshot"]);
    let obligation = snapshot["result"]["snapshot"]["records"]
        .as_array()
        .expect("records")
        .iter()
        .find(|named| named["alias"] == "N-2")
        .expect("obligation");
    let obligation_id = obligation["record"]["id"].clone();
    assert_eq!(obligation["effectiveness"]["kind"], "inactive");
    assert_eq!(obligation["record"]["status"], "proposed");
    assert_eq!(
        obligation["record"]["fields"]["proposition"],
        "deny anonymous too"
    );
    fixture.run(&["rotate", "--as", "owner", "--successor", "successor"]);
    let original = fixture.run(&["export"]);
    let public_bindings: Vec<_> = [("owner", "owner", 1), ("worker", "worker", 2), ("successor", "owner", 3)]
        .into_iter().map(|(name, principal, seed)| {
            let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("synthetic key");
            let public_key_hex: String = key.public_key().as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
            json!({"actor":{"principal":principal,"algorithm":"ed25519-custodian","key_id":format!("credential:norm/{name}#local")},"public_key_hex":public_key_hex})
        }).collect();
    let hosted_trust =
        json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]});
    let checkpoint: NormCheckpoint =
        serde_json::from_value(original["result"]["checkpoint"].clone()).expect("checkpoint");
    let mut hosted = whipplescript_host_do::do_store::test_support::store();
    hosted
        .pin_norm_checkpoint(&checkpoint)
        .expect("independent host pin");
    let run = |store: &mut _, command: Value| -> Value {
        serde_json::from_str(
            &execute_hosted_norm_command(
                store,
                &hosted_trust.to_string(),
                &json!({
                    "protocol":"whipplescript.norm.commands/v1", "command":command,
                })
                .to_string(),
            )
            .expect("DO authenticates custody-produced history"),
        )
        .expect("response")
    };
    assert_eq!(
        run(
            &mut hosted,
            json!({"kind":"import","events":original["result"]["events"]})
        )["result"]["inserted"],
        7
    );
    // Local names follow each clone's admission order; independent creations
    // can acquire different aliases on causal import. Compare signed identities
    // and the complete derived state after removing only this local label.
    let without_aliases = |mut snapshot: Value| {
        for named in snapshot["result"]["snapshot"]["records"]
            .as_array_mut()
            .expect("records")
        {
            named.as_object_mut().expect("named record").remove("alias");
        }
        snapshot
    };
    assert_eq!(
        without_aliases(run(&mut hosted, json!({"kind":"snapshot"}))),
        without_aliases(fixture.run(&["snapshot"]))
    );
    let charter = whipplescript_store::norm::NormCharter::bundled().expect("bundled charter");
    let definition = charter
        .vocabularies
        .into_iter()
        .find(|entry| entry.definition.name == "issue")
        .expect("issue")
        .definition;
    let vocabulary =
        whipplescript_core::vocabulary::Vocabulary::new(definition).expect("vocabulary");
    fixture.write("hosted-statement.json", &json!({
        "protocol":"whipplescript.norm/v1", "actor":public_bindings[2]["actor"],
        "nonce":"hosted-write","created_at":"2026-09-06T00:00:00Z",
        "action":{"act":"create","ledger":checkpoint.ledger,"authority":checkpoint.authority_head,
            "vocabulary":vocabulary.reference(),"fields_json":"{\"title\":\"Written at hosted door\"}"}
    }));
    let signed = fixture.run(&[
        "sign",
        "--as",
        "successor",
        "--statement",
        "hosted-statement.json",
    ]);
    run(&mut hosted, json!({"kind":"append","event":signed}));
    for (index, status) in [(0, "accepted"), (1, "retired")] {
        let snapshot = run(&mut hosted, json!({"kind":"snapshot"}));
        let named = snapshot["result"]["snapshot"]["records"]
            .as_array()
            .expect("records")
            .iter()
            .find(|named| named["record"]["id"] == obligation_id)
            .expect("obligation");
        let record = &named["record"];
        let mut action = json!({"act":if index == 0 { "transition" } else { "retire" },
            "ledger":checkpoint.ledger, "authority":checkpoint.authority_head,
            "vocabulary":record["vocabulary"], "record":record["id"],
            "previous":record["head"], "status":status});
        if index == 1 {
            action["revision"] = named["effectiveness"]["record"]["content_head"].clone();
            action["activation"] = named["effectiveness"]["record"]["head"].clone();
        }
        fixture.write("hosted-lifecycle.json", &json!({
            "protocol":"whipplescript.norm/v1", "actor":public_bindings[2]["actor"],
            "nonce":format!("hosted-lifecycle-{index}"), "created_at":"2026-09-06T00:00:00Z", "action":action,
        }));
        let signed = fixture.run(&[
            "sign",
            "--as",
            "successor",
            "--statement",
            "hosted-lifecycle.json",
        ]);
        run(&mut hosted, json!({"kind":"append", "event":signed}));
    }
    let snapshot = run(&mut hosted, json!({"kind":"snapshot"}));
    let named = snapshot["result"]["snapshot"]["records"]
        .as_array()
        .expect("records")
        .iter()
        .find(|named| named["record"]["id"] == obligation_id)
        .expect("obligation");
    assert_eq!(named["effectiveness"]["kind"], "inactive");
    assert_eq!(named["record"]["status"], "retired");
    // Keep an effective requirement in the exported vector so the actual
    // worker checks populated classification, not only empty/retired inventory.
    let charter = whipplescript_store::norm::NormCharter::bundled().expect("charter");
    let definition = charter
        .vocabularies
        .iter()
        .find(|entry| entry.definition.name == "obligation")
        .expect("obligation")
        .definition
        .clone();
    let vocabulary =
        whipplescript_core::vocabulary::Vocabulary::new(definition).expect("vocabulary");
    let mut active_record = Value::Null;
    for index in 0..2 {
        let action = if index == 0 {
            json!({"act":"create", "ledger":checkpoint.ledger, "authority":checkpoint.authority_head,
                "vocabulary":vocabulary.reference(), "fields_json":json!({"name":"active requirement","proposition":"deny unknown","domain":"workspace","subject":"src/auth.py"}).to_string()})
        } else {
            json!({"act":"transition", "ledger":checkpoint.ledger, "authority":checkpoint.authority_head,
                "vocabulary":vocabulary.reference(), "record":active_record, "previous":active_record, "status":"accepted"})
        };
        fixture.write("inventory-statement.json", &json!({
            "protocol":"whipplescript.norm/v1", "actor":public_bindings[2]["actor"],
            "nonce":format!("inventory-{index}"), "created_at":"2026-09-06T00:00:00Z", "action":action,
        }));
        let signed = fixture.run(&[
            "sign",
            "--as",
            "successor",
            "--statement",
            "inventory-statement.json",
        ]);
        let appended = run(&mut hosted, json!({"kind":"append", "event":signed}));
        if index == 0 {
            active_record = appended["result"]["event_id"].clone();
        }
    }
    let inventory = run(&mut hosted, json!({"kind":"inventory"}));
    assert_eq!(
        inventory["result"]["inventory"]["classification_complete"],
        true
    );
    assert_eq!(
        inventory["result"]["inventory"]["requirements"]
            .as_object()
            .expect("requirements")
            .len(),
        1
    );
    assert_eq!(
        inventory["result"]["inventory"]["requirements"][active_record.as_str().expect("id")]
            ["declaration"]["proposition"],
        "deny unknown"
    );
    assert_eq!(
        inventory["result"]["inventory"],
        run(&mut hosted, json!({"kind":"snapshot"}))["result"]["snapshot"]["inventory"]
    );
    let exported = run(&mut hosted, json!({"kind":"export"}));
    let expected_snapshot = run(&mut hosted, json!({"kind":"snapshot"}));
    fixture.write("history.json", &exported["result"]["events"]);
    fixture.trust = json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[],"checkpoint":exported["result"]["checkpoint"]});
    let destination = fixture.root.join("portable.sqlite");
    for args in [
        vec!["provision"],
        vec!["import", "--events", "history.json"],
    ] {
        let output = fixture
            .command(&args)
            .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
            .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
            .output()
            .expect("native command");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = fixture
        .command(&["snapshot"])
        .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("snapshot");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let restored_snapshot = serde_json::from_slice::<Value>(&output.stdout).expect("response");
    assert_eq!(
        without_aliases(restored_snapshot.clone()),
        without_aliases(expected_snapshot)
    );
    let inventory_output = fixture
        .command(&["inventory"])
        .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("inventory command");
    assert!(inventory_output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&inventory_output.stdout).expect("inventory response"),
        inventory
    );
    // Public verification does not install a signing handle.
    fixture.refuse(&[
        "sign",
        "--as",
        "successor",
        "--statement",
        "hosted-statement.json",
    ]);
    let artifacts = fixture.seed_norm_artifacts();
    let prior_retirement = exported["result"]["events"]
        .as_array()
        .expect("events")
        .iter()
        .find(|event| event["kind"] == "norm.record.retired")
        .expect("retirement");
    let retired_action: Value =
        serde_json::from_str(prior_retirement["payload_json"].as_str().expect("payload"))
            .expect("signed retirement");
    let frontier = json!([retired_action["statement"]["action"]["activation"]]);
    fixture.write("frontier.json", &frontier);
    let mut queries = Vec::new();
    for (args, command) in [
        (
            vec!["snapshot", "--frontier", "frontier.json"],
            json!({"kind":"snapshot_at","frontier":frontier}),
        ),
        (
            vec!["inventory", "--frontier", "frontier.json"],
            json!({"kind":"inventory_at","frontier":frontier}),
        ),
        (
            vec!["resources", "before", "--frontier", "frontier.json"],
            json!({"kind":"resources","point":{"cut":"before","frontier":frontier}}),
        ),
        (
            vec!["resources", "after"],
            json!({"kind":"resources","point":{"cut":"after"}}),
        ),
        (
            vec![
                "compare-resources",
                "before",
                "after",
                "--before-frontier",
                "frontier.json",
            ],
            json!({"kind":"compare_resources","before":{"cut":"before","frontier":frontier},"after":{"cut":"after"}}),
        ),
    ] {
        let output = fixture
            .command(&args)
            .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
            .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
            .output()
            .expect("native query");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).expect("query response");
        assert_eq!(
            response["result"]["captured"]["checkpoint"],
            exported["result"]["checkpoint"]
        );
        queries.push(json!({"command":command,"response":response}));
    }
    assert_eq!(
        queries[2]["response"]["result"]["resources"]["binding_complete"],
        true
    );
    assert_eq!(
        queries[3]["response"]["result"]["resources"]["binding_complete"],
        false
    );
    assert_eq!(
        queries[4]["response"]["result"]["comparison"]["requirements"]
            .as_array()
            .expect("union")
            .len(),
        2
    );
    assert_eq!(
        queries[4]["response"]["result"]["comparison"]["changes"]["src/auth.py"],
        "deleted"
    );
    assert_ne!(
        queries[0]["response"]["result"]["snapshot"]["checkpoint"],
        exported["result"]["checkpoint"]
    );
    for args in [
        vec!["snapshot", "--frontier", "missing.json"],
        vec!["resources", "missing-cut"],
        vec!["resources"],
        vec!["compare-resources", "before"],
        vec!["resources", "before", "--frontier"],
    ] {
        let output = fixture
            .command(&args)
            .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
            .output()
            .expect("invalid query");
        assert!(!output.status.success());
    }
    fixture.write("empty-frontier.json", &json!([]));
    assert!(!fixture
        .command(&["resources", "before", "--frontier", "empty-frontier.json"])
        .env("WHIPPLESCRIPT_ITEMS_STORE", &destination)
        .output()
        .expect("empty frontier")
        .status
        .success());
    if let Some(path) = std::env::var_os("WHIPPLESCRIPT_NORM_VECTOR_OUT") {
        std::fs::write(path, serde_json::to_vec(&json!({
            "protocol":"whipplescript.norm.test-vector/v1", "public_bindings":public_bindings,
            "checkpoint":exported["result"]["checkpoint"], "events":exported["result"]["events"],
            // Both native restoration and the WASM consumer begin empty, so
            // their causal-import aliases may be compared exactly.
            "snapshot":restored_snapshot, "artifacts":artifacts, "queries":queries,
        })).expect("public vector JSON")).expect("write synthetic native vector");
    }
}

#[test]
fn norm_cli_restores_hosted_p256_history_with_public_bindings_only() {
    use ring::signature::KeyPair as _;
    use whipplescript_host_do::norm_commands::execute_hosted_norm_command;
    use whipplescript_store::norm::{
        NormAct, NormActor, NormCharter, NormStatement, SignedNormEvent,
    };

    let mut fixture = Fixture::new();
    let rng = ring::rand::SystemRandom::new();
    let algorithm = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let encoded = ring::signature::EcdsaKeyPair::generate_pkcs8(algorithm, &rng)
        .expect("synthetic P-256 key");
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, encoded.as_ref(), &rng)
        .expect("key pair");
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let public_key_hex = hex(key.public_key().as_ref());
    let actor = NormActor {
        principal: "hosted-owner".into(),
        algorithm: "p256-sha256".into(),
        key_id: public_key_hex.clone(),
    };
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: actor.clone(),
        nonce: "hosted-genesis".into(),
        created_at: "2026-09-06T00:00:00Z".into(),
        action: NormAct::Bootstrap {
            creator: "worker".into(),
            charter: NormCharter {
                resource_domains: None,
                vocabularies: vec![],
                owner_scopes: vec![],
            },
        },
    };
    let signature = hex(key
        .sign(&rng, &statement.signing_bytes().expect("bytes"))
        .expect("signature")
        .as_ref());
    let event = SignedNormEvent {
        statement,
        signature,
        successor_signature: None,
    };
    let trust =
        json!({"bindings":[actor],"creation_grants":[{"creator":"worker","owner":"hosted-owner"}]});
    let mut hosted = whipplescript_host_do::do_store::test_support::store();
    let run = |store: &mut _, command: Value| -> Value {
        serde_json::from_str(
            &execute_hosted_norm_command(
                store,
                &trust.to_string(),
                &json!({
                    "protocol":"whipplescript.norm.commands/v1","command":command,
                })
                .to_string(),
            )
            .expect("hosted command"),
        )
        .expect("response")
    };
    run(&mut hosted, json!({"kind":"append","event":event}));
    let exported = run(&mut hosted, json!({"kind":"export"}));
    let expected = run(&mut hosted, json!({"kind":"snapshot"}));
    fixture.trust = json!({"bindings":[],"public_bindings":[{"actor":actor,"public_key_hex":public_key_hex}],"creation_grants":[],"checkpoint":exported["result"]["checkpoint"]});
    fixture.write("hosted-history.json", &exported["result"]["events"]);
    for args in [
        vec!["provision"],
        vec!["import", "--events", "hosted-history.json"],
    ] {
        let result = fixture
            .command(&args)
            .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
            .output()
            .expect("native command");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let snapshot = fixture
        .command(&["snapshot"])
        .env_remove("WHIPPLESCRIPT_CUSTODIAN_SOCKET")
        .output()
        .expect("snapshot");
    assert!(
        snapshot.status.success(),
        "{}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&snapshot.stdout).expect("response"),
        expected
    );
    fixture.trust["public_bindings"][0]["actor"]["principal"] = json!("unrelated-owner");
    fixture.refuse(&["snapshot"]); // a public key is not an implicit principal binding
}

#[test]
fn norm_artifact_capture_matches_native_and_do_stores() {
    use whipplescript_store::branches::{Branches, CutRecord, MAINLINE_BRANCH_ID};
    use whipplescript_store::content::ContentBlobs;
    use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits, CapturedArtifact};
    fn exercise(mut branches: impl Branches, content: impl ContentBlobs) -> CapturedArtifact {
        branches
            .ensure_mainline("t0")
            .expect("artifact capture fixture");
        let file = content
            .put("stored candidate".as_bytes())
            .expect("artifact capture fixture");
        let root = whipplescript_store::manifest_tree::build(
            &content,
            &std::collections::BTreeMap::from([("candidate.txt".into(), file.clone())]),
        )
        .expect("artifact capture fixture");
        for (id, manifest) in [("old", root.as_str()), ("new", "unavailable")] {
            branches
                .record_cut(CutRecord {
                    cut_id: id,
                    change_id: id,
                    branch_id: MAINLINE_BRANCH_ID,
                    manifest_hash: manifest,
                    parent_cut_id: None,
                    origin: None,
                    actor: None,
                    intent: None,
                    recorded_at: "t1",
                })
                .expect("artifact capture fixture");
        }
        let captured = capture_cut(&branches, &content, "old", ArtifactLimits::default())
            .expect("artifact capture fixture");
        assert_eq!(captured.files()["candidate.txt"], "stored candidate");
        assert!(capture_cut(&branches, &content, "new", ArtifactLimits::default()).is_err());
        content
            .erase(&file, "t2")
            .expect("artifact capture fixture");
        assert!(capture_cut(&branches, &content, "old", ArtifactLimits::default()).is_err());
        captured
    }
    let native = exercise(
        whipplescript_store::branches::BranchStore::open(":memory:")
            .expect("artifact capture fixture"),
        whipplescript_store::content::ContentStore::open(":memory:")
            .expect("artifact capture fixture"),
    );
    let sql = whipplescript_host_do::do_store::test_support::RusqliteDoSql::in_memory();
    let hosted = exercise(
        whipplescript_host_do::do_branches::DoBranches::new(sql.clone())
            .expect("artifact capture fixture"),
        whipplescript_host_do::do_branches::DoContentBlobs::new(sql)
            .expect("artifact capture fixture"),
    );
    assert_eq!(native, hosted);
}

/// What this host is missing to run the observer, or `None` when it can.
///
/// The PRESENCE of `python3` is all this needs, not a particular version. The
/// method's declared `python_version` is derived by running `python3` when the
/// observation is enqueued, and the observer reports the version of the
/// `python3` it actually runs, so the adapter header binds whenever those two
/// are the same interpreter. 3.9, 3.12 and 3.14 each pass on their own; this
/// test was verified under 3.9.6 and 3.14.7.
///
/// What broke it on macOS was therefore not a version but a DISAGREEMENT: the
/// worker's environment was cleared without PATH, so its observer resolved
/// `python3` through the OS default path while the enqueue side used the
/// caller's, and the two halves reported different interpreters. Forwarding
/// PATH is that repair. This covers only a host with no python3 at all, where
/// the enqueue fixture would otherwise panic inside `whip` with nothing
/// pointing at the cause.
fn norm_observer_python_prerequisite() -> Option<String> {
    let found = Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    (!found).then(|| {
        "the norm observer needs python3 on PATH, and there is none. Any version does: \
         the enqueue side and the observer must simply resolve the SAME one."
            .to_owned()
    })
}

#[test]
fn norm_cli_publication_recovers_verified_execution_with_real_custody() {
    if let Some(reason) = norm_observer_python_prerequisite() {
        // A skip here is available only when nobody is collecting this test's
        // OUTPUT. It is not just an assertion: it is the producer of the
        // publication vector that the hosted worker's authenticated suite
        // consumes, and `worker/scripts/generate-norm-vector.mjs` sets the
        // variable below and then reads the file it writes. Standing down with
        // that variable set hands the consumer a missing file and an ENOENT
        // three jobs away from the cause -- which is exactly what a first,
        // wrong guard on this test did to `hosted-runtime-contracts`. So when
        // the vector has been asked for, an unmet prerequisite is a failure
        // that names itself, here, where it can be read.
        assert!(
            std::env::var_os("WHIPPLESCRIPT_NORM_PUBLICATION_VECTOR_OUT").is_none(),
            "the publication vector was requested, but {reason}"
        );
        eprintln!("skipped: {reason}");
        return;
    }
    use whipplescript_custody::client::UnixSocketTransport;
    use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
    use whipplescript_kernel::norm_execution::{fixtures as execution, PreparedNormExecution};
    use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
    use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
    use whipplescript_store::content::ContentStore;
    use whipplescript_store::items::WorkItemStore;
    use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
    use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
    use whipplescript_store::{RuntimeStore, SqliteStore};

    let mut publication_vectors = Vec::new();
    for actual in [false, true] {
        let fixture = Fixture::new();
        let mut charter = whipplescript_store::norm::NormCharter::bundled().expect("charter");
        charter
            .vocabularies
            .push(execution::observation_vocabulary());
        charter.owner_scopes.push("observe.publish".into());
        fixture.write("charter.json", &json!(charter));
        fixture.run(&[
            "bootstrap",
            "--as",
            "owner",
            "--creator",
            "worker",
            "--charter",
            "charter.json",
        ]);
        let python = Command::new("python3")
            .args(["-c", "import sys; print(sys.version.split()[0])"])
            .output()
            .expect("fixture Python version");
        assert!(python.status.success());
        let mut support = execution::template();
        support["method"]["runtime"]["python_version"] = json!(String::from_utf8(python.stdout)
            .expect("Python version")
            .trim());
        fixture.write("fields.json", &json!({"name":"allow","proposition":"unknown denied","domain":"workspace","subject":"main.py","support_contract":support.to_string()}));
        let created = fixture.run(&[
            "create",
            "obligation@1",
            "--as",
            "owner",
            "--fields",
            "fields.json",
        ]);
        let record = created["result"]["event_id"]
            .as_str()
            .expect("requirement id");
        fixture.run(&["transition", "N-1", "accepted", "--as", "owner"]);

        let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
        let key = NormCustodyKey::new(
            "owner".into(),
            CredentialName::new("norm/owner").expect("credential"),
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .expect("custody key");
        let verifier = NormGovernanceVerifier::new(
            vec![NormPrincipalBinding {
                actor: key.actor().clone(),
                verifier: &key,
            }],
            [("worker".into(), "owner".into())].into(),
        )
        .expect("verifier");
        let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
        let view = ledger.norm_view(&verifier).expect("verified ledger");
        let history = CapturedNormHistory::capture(
            &view,
            &ledger.export_events().expect("events"),
            &verifier,
            NormHistoryLimits::default(),
        )
        .expect("history");
        let mut branches =
            BranchStore::open(fixture.root.join("branches.sqlite")).expect("branches");
        let content = ContentStore::open(fixture.root.join("content.sqlite")).expect("content");
        branches.ensure_mainline("t0").expect("mainline");
        let source = if actual {
            "def allow(user): return True"
        } else {
            "def allow(user): return False"
        };
        let file = content.put(source.as_bytes()).expect("source");
        let manifest = content
            .put(json!({"main.py":file}).to_string().as_bytes())
            .expect("manifest");
        branches
            .record_cut(CutRecord {
                cut_id: "cut",
                change_id: "cut",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("cut");
        let artifact =
            capture_cut(&branches, &content, "cut", ArtifactLimits::default()).expect("artifact");
        let prepared = PreparedNormExecution::prepare(
            &history,
            &verifier,
            &artifact,
            &execution::script(),
            execution::selection(&view.ledger, record),
        )
        .expect("prepare");
        norm_enqueue_command_fixture(&fixture, record, actual);
        // Exercise the hosted public-key-only door with the same independently
        // captured execution and real custody signatures as the native command.
        use ring::signature::KeyPair;
        use whipplescript_host_do::do_store::{DoSql, SqlValue};
        use whipplescript_host_do::norm_commands::execute_hosted_norm_publication;
        use whipplescript_store::norm_commands::NormCommandStore;
        let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32])
            .expect("synthetic public key");
        let public_key_hex: String = public
            .public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let public_bindings = json!([{"actor":key.actor(),"public_key_hex":public_key_hex}]);
        let trust = json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]})
            .to_string();
        let enqueue =
            norm_hosted_enqueue_fixture(&ledger, &verifier, &trust, &artifact, record, None);
        let mut advance: whipplescript_store::norm::SignedNormEvent = serde_json::from_str(
            &ledger
                .export_events()
                .expect("events")
                .into_iter()
                .find(|event| event.event_id == record)
                .expect("requirement event")
                .payload_json,
        )
        .expect("signed requirement");
        advance.statement.nonce = "enqueue-history-advance".into();
        advance.signature = key.sign(&advance.statement).expect("sign later event");
        let mut hosted = whipplescript_host_do::do_store::test_support::store();
        hosted
            .pin_norm_checkpoint(&ledger.norm_checkpoint().expect("checkpoint").expect("pin"))
            .expect("host pin");
        hosted
            .import_norm(&ledger.export_events().expect("history"), &verifier)
            .expect("hosted import");
        let mut hosted = execution::journal_execution(
            hosted,
            &prepared,
            &execution::receipt(&prepared, actual, false),
            actual,
        );
        let sql_json = |value: &SqlValue| match value {
            SqlValue::Null => Value::Null,
            SqlValue::Int(n) => json!(n),
            SqlValue::Text(s) => json!(s),
        };
        let mut runtime_rows = Vec::new();
        for table in hosted.store().sql.query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY CASE WHEN name = 'instances' THEN 0 ELSE 1 END, name", &[]).expect("tables") {
            let SqlValue::Text(table) = &table[0] else { panic!("table name") };
            let columns: Vec<String> = hosted.store().sql.query(&format!("PRAGMA table_info(\"{table}\")"), &[]).expect("columns").into_iter().map(|row| match &row[1] { SqlValue::Text(name) => name.clone(), _ => panic!("column name") }).collect();
            if !columns.iter().any(|name| name == "instance_id") { continue; }
            let rows: Vec<Value> = hosted.store().sql.query(&format!("SELECT * FROM \"{table}\" WHERE instance_id = ?"), &[SqlValue::Text("instance".into())]).expect("fixture rows").iter().map(|row| json!(row.iter().map(sql_json).collect::<Vec<_>>())).collect();
            if !rows.is_empty() { runtime_rows.push(json!({"table":table,"columns":columns,"rows":rows})); }
        }
        let draft_command = json!({"kind":"prepare","instance":"instance","run":"run","vocabulary":"local-observation@1","actor":key.actor(),"created_at":"2026-09-10T00:00:00Z"});
        let request = |command: Value| {
            json!({"protocol":"whipplescript.norm.publication/v1","command":command}).to_string()
        };
        let artifacts = |cut: &str| {
            assert_eq!(cut, "cut");
            Ok(artifact.clone())
        };
        let before_draft = hosted.store().list_events("instance").expect("journal");
        for malformed in [
            json!({"protocol":"untrusted","command":draft_command}).to_string(),
            json!({"protocol":"whipplescript.norm.publication/v1","command":draft_command,"public_bindings":public_bindings}).to_string(),
            request(json!({"kind":"prepare","instance":"instance","run":"run","vocabulary":"decision@1","actor":key.actor(),"created_at":"t1"})),
            request(json!({"kind":"prepare","instance":"instance","run":"run","vocabulary":"unknown@1","actor":key.actor(),"created_at":"t1"})),
        ] {
            assert!(execute_hosted_norm_publication(hosted.store_mut(), &trust, &malformed, &artifacts).is_err());
            assert_eq!(hosted.store().list_events("instance").expect("journal"), before_draft);
        }
        let draft: Value = serde_json::from_str(
            &execute_hosted_norm_publication(
                hosted.store_mut(),
                &trust,
                &request(draft_command.clone()),
                &artifacts,
            )
            .expect("host draft"),
        )
        .expect("draft JSON");
        assert_eq!(draft["result"]["kind"], "unsigned");
        let statement: whipplescript_store::norm::NormStatement =
            serde_json::from_value(draft["result"]["statement"].clone()).expect("statement");
        let event = whipplescript_store::norm::SignedNormEvent {
            signature: key.sign(&statement).expect("external custody signature"),
            statement,
            successor_signature: None,
        };
        let mut incompatible = event.clone();
        let whipplescript_store::norm::NormAct::Create { vocabulary, .. } =
            &mut incompatible.statement.action
        else {
            panic!("create")
        };
        *vocabulary = whipplescript_core::vocabulary::Vocabulary::new(
            view.charter
                .vocabularies
                .iter()
                .find(|entry| entry.definition.name == "decision")
                .expect("decision vocabulary")
                .definition
                .clone(),
        )
        .expect("vocabulary")
        .reference()
        .clone();
        incompatible.signature = key
            .sign(&incompatible.statement)
            .expect("signed incompatible vocabulary");
        let mut forged = event.clone();
        let whipplescript_store::norm::NormAct::Create { fields_json, .. } =
            &mut forged.statement.action
        else {
            panic!("create")
        };
        let mut changed: Value = serde_json::from_str(fields_json).expect("fields");
        changed["observation_json"] = json!("{}");
        *fields_json = changed.to_string();
        forged.signature = key
            .sign(&forged.statement)
            .expect("signed substituted report");
        let publish = |event: &whipplescript_store::norm::SignedNormEvent| {
            request(json!({"kind":"publish","instance":"instance","run":"run","event":event}))
        };
        for retained in [false, true] {
            let before = hosted.store().list_events("instance").expect("journal");
            assert!(execute_hosted_norm_publication(
                hosted.store_mut(),
                &trust,
                &publish(&forged),
                &artifacts
            )
            .expect_err("signed report substitution")
            .contains("differs"));
            assert_eq!(
                hosted.store().list_events("instance").expect("journal"),
                before
            );
            assert!(
                execute_hosted_norm_publication(
                    hosted.store_mut(),
                    &trust,
                    &publish(&incompatible),
                    &artifacts
                )
                .is_err(),
                "incompatible vocabulary must not occupy the slot"
            );
            assert_eq!(
                hosted.store().list_events("instance").expect("journal"),
                before
            );
            let response: Value = serde_json::from_str(
                &execute_hosted_norm_publication(
                    hosted.store_mut(),
                    &trust,
                    &publish(&event),
                    &artifacts,
                )
                .expect("host publish"),
            )
            .expect("publication JSON");
            let recovered: Value = serde_json::from_str(
                &execute_hosted_norm_publication(
                    hosted.store_mut(),
                    &trust,
                    &request(draft_command.clone()),
                    &artifacts,
                )
                .expect("host retained draft"),
            )
            .expect("retained JSON");
            assert_eq!(
                recovered["result"],
                json!({"kind":"retained","event":event})
            );
            if retained {
                assert_eq!(
                    hosted.store().list_events("instance").expect("journal"),
                    before
                );
            }
            if !retained {
                publication_vectors.push(json!({"enqueue":enqueue,"advance":advance,"public_bindings":public_bindings,"checkpoint":ledger.norm_checkpoint().expect("checkpoint").expect("pin"),"events":ledger.export_events().expect("history"),"runtime_rows":runtime_rows,"draft_command":draft_command,"draft":draft,"event":event,"forged":forged,"incompatible":incompatible,"response":response,"artifacts":{"blobs":[{"id":file,"body":source,"byte_len":source.len()},{"id":manifest,"body":json!({"main.py":file}).to_string(),"byte_len":json!({"main.py":file}).to_string().len()}],"cuts":[{"cut_id":"cut","change_id":"cut","branch_id":MAINLINE_BRANCH_ID,"manifest_hash":manifest,"recorded_at":"t1"}]}}));
            }
        }
        let runtime_path = fixture.root.join("runtime.sqlite");
        // Supplied authenticated executor response; this test exercises the real
        // command/custody/storage boundary, not a live Python process.
        drop(execution::journal_execution(
            SqliteStore::open(&runtime_path).expect("runtime"),
            &prepared,
            &execution::receipt(&prepared, actual, false),
            actual,
        ));
        let before_invalid = SqliteStore::open(&runtime_path)
            .expect("runtime")
            .list_events("instance")
            .expect("journal");
        let invalid = fixture
            .command(&[
                "publish-observation",
                "instance",
                "run",
                "decision@1",
                "--as",
                "owner",
            ])
            .env("WHIPPLESCRIPT_STORE", &runtime_path)
            .output()
            .expect("incompatible vocabulary command");
        assert!(!invalid.status.success());
        assert_eq!(
            SqliteStore::open(&runtime_path)
                .expect("runtime")
                .list_events("instance")
                .expect("journal"),
            before_invalid,
            "a refused vocabulary must leave the publication slot available"
        );
        let invoke = |publisher: &str| {
            fixture
                .command(&[
                    "publish-observation",
                    "instance",
                    "run",
                    "local-observation@1",
                    "--as",
                    publisher,
                ])
                .env("WHIPPLESCRIPT_STORE", &runtime_path)
                .output()
                .expect("publication command")
        };
        let missing = fixture
            .command(&[
                "publish-observation",
                "instance",
                "missing-run",
                "local-observation@1",
                "--as",
                "owner",
            ])
            .env("WHIPPLESCRIPT_STORE", &runtime_path)
            .output()
            .expect("missing run command");
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("run is missing"));
        let before = ledger.export_events().expect("events");
        let wrong = invoke("worker");
        assert!(!wrong.status.success());
        assert!(String::from_utf8_lossy(&wrong.stderr).contains("publisher"));
        assert_eq!(ledger.export_events().expect("events"), before);
        let published = invoke("owner");
        assert!(
            published.status.success(),
            "{}",
            String::from_utf8_lossy(&published.stderr)
        );
        let published: Value = serde_json::from_slice(&published.stdout).expect("publication JSON");
        let events = ledger.export_events().expect("events");
        assert_eq!(events.len(), before.len() + 1);
        let journal = SqliteStore::open(&runtime_path)
            .expect("runtime")
            .list_events("instance")
            .expect("journal");
        let wrong = invoke("worker");
        assert!(!wrong.status.success());
        assert!(String::from_utf8_lossy(&wrong.stderr).contains("publisher"));
        let recovered = invoke("owner");
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&recovered.stdout).expect("recovered JSON"),
            published
        );
        assert_eq!(ledger.export_events().expect("events"), events);
        assert_eq!(
            SqliteStore::open(&runtime_path)
                .expect("runtime")
                .list_events("instance")
                .expect("journal"),
            journal
        );
        // Retention cannot turn a missing original artifact into verified evidence.
        rusqlite::Connection::open(fixture.root.join("branches.sqlite"))
            .expect("artifact database")
            .execute("DELETE FROM cuts WHERE cut_id = 'cut'", [])
            .expect("remove captured cut");
        let missing_cut = invoke("owner");
        assert!(!missing_cut.status.success());
        assert_eq!(ledger.export_events().expect("events"), events);
        assert_eq!(
            SqliteStore::open(&runtime_path)
                .expect("runtime")
                .list_events("instance")
                .expect("journal"),
            journal
        );
    }
    if let Ok(path) = std::env::var("WHIPPLESCRIPT_NORM_PUBLICATION_VECTOR_OUT") {
        std::fs::write(path, serde_json::to_vec(&json!({"protocol":"whipplescript.norm.publication-test-vector/v1","cases":publication_vectors})).expect("publication vector JSON")).expect("publication vector");
    }
}

fn norm_enqueue_command_fixture(fixture: &Fixture, requirement: &str, actual: bool) {
    use whipplescript_kernel::{
        norm_execution::fixtures::script, ProgramVersionInput, RuntimeKernel,
    };
    use whipplescript_store::{ScriptCapabilityRegistration, SqliteStore};
    let path = fixture.root.join("enqueue.sqlite");
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&path).expect("norm enqueue fixture"));
    let version = kernel
        .create_program_version(ProgramVersionInput {
            program_name: "enqueue-command",
            source_hash: "fixture",
            ir_hash: "fixture",
            compiler_version: "fixture",
            ir_snapshot: None,
        })
        .expect("norm enqueue fixture");
    let instance = kernel
        .create_instance(&version, "{}")
        .expect("norm enqueue fixture");
    let invoke = |capability: &str, deadline: &str, epoch: &str| {
        fixture
            .command(&[
                "enqueue-observation",
                &instance,
                requirement,
                "cut",
                "--effect",
                "command-observe",
                "--capability",
                capability,
                "--as",
                "owner",
                "--deadline",
                deadline,
            ])
            .env("WHIPPLESCRIPT_STORE", &path)
            .env("WHIPPLESCRIPT_COMPUTE_ENV_HASH", epoch)
            .output()
            .expect("norm enqueue fixture")
    };
    let before = kernel
        .store()
        .list_events(&instance)
        .expect("norm enqueue fixture");
    assert!(!invoke("observer", "120", "epoch").status.success());
    let installed = script();
    kernel
        .store()
        .register_script_capability(ScriptCapabilityRegistration {
            name: &installed.name,
            argv_json: &installed.argv_json,
            sha256: &installed.sha256,
            env_json: &installed.env_json,
            hermetic: installed.hermetic,
            body: &installed.body,
        })
        .expect("norm enqueue fixture");
    for (deadline, epoch) in [
        ("0", "epoch"),
        ("-1", "epoch"),
        ("4294967296", "epoch"),
        ("120", "wrong"),
    ] {
        assert!(!invoke("observer", deadline, epoch).status.success());
        assert_eq!(
            kernel
                .store()
                .list_events(&instance)
                .expect("norm enqueue fixture"),
            before
        );
    }
    let first = invoke("observer", "120", "epoch");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).expect("norm enqueue fixture");
    assert_eq!(first["effect_id"], "command-observe");
    assert_eq!(first["artifact"]["cut"], "cut");
    assert!(first["acknowledgment"]["event_id"].is_string());
    assert_eq!(
        kernel
            .store()
            .list_effects(&instance)
            .expect("norm enqueue fixture")
            .len(),
        1
    );
    assert!(kernel
        .store()
        .list_runs(&instance)
        .expect("norm enqueue fixture")
        .is_empty());
    fixture.write(
        "enqueue-original-frontier.json",
        &first["anchor"]["frontier"],
    );
    fixture.write("enqueue-later-fields.json", &json!({"name":"later", "proposition":"later obligation", "domain":"workspace", "subject":"main.py"}));
    fixture.run(&[
        "create",
        "obligation@1",
        "--as",
        "owner",
        "--fields",
        "enqueue-later-fields.json",
    ]);
    let current = fixture.run(&["snapshot"]);
    let current_frontier = &current["result"]["snapshot"]["frontier"];
    assert!(current_frontier.is_array(), "{current}");
    assert_ne!(current_frontier, &first["anchor"]["frontier"]);
    fixture.write("enqueue-current-frontier.json", current_frontier);

    // A separately authorized instance traverses the ordinary CLI worker and
    // real observer process; the first invocation remains undispatched.
    let real_instance = kernel
        .create_instance(&version, "{}")
        .expect("real observer instance");
    kernel
        .store()
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: "script.observer",
            description: "fixture observer grant",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("observer schema");
    kernel
        .store()
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "real-observer",
            program_id: Some(&version.program_id),
            capability: "script.observer",
            provider: "builtin-script",
            config_json: "{}",
        })
        .expect("observer grant");
    // Configured deployment identity wins over the ambient legacy label, also
    // when this particular method uses the cooperative profile.
    fixture.write("native-host.json", &json!({
        "protocol":"whipplescript.exec.native-norm-host/v1", "endpoint":"unix:///fixture",
        "installed":{"protocol":"whipplescript.exec.native-runtime-image/v1", "daemon_id":"fixture",
            "base_image":format!("sha256:{}", "b".repeat(64)), "image_id":format!("sha256:{}", "c".repeat(64)),
            "runtime":{"engine":whipplescript_kernel::norm_runner::PythonEngine::Cpython3147Wasi { artifact_path:"/opt/norm/runtime.wasm".into(), artifact_sha256:"a".repeat(64) },
                "executable":"/opt/norm/observer", "python_version":"3.14.7", "environment":"epoch"}}
    }));
    let real_enqueue = fixture
        .command(&[
            "enqueue-observation",
            &real_instance,
            requirement,
            "cut",
            "--effect",
            "real-observe",
            "--capability",
            "observer",
            "--as",
            "owner",
            "--deadline",
            "120",
        ])
        .env("WHIPPLESCRIPT_STORE", &path)
        .env("WHIPPLESCRIPT_COMPUTE_ENV_HASH", "ignored-legacy-label")
        .env(
            "WHIPPLESCRIPT_NATIVE_NORM_RUNTIME",
            fixture.root.join("native-host.json"),
        )
        .output()
        .expect("real enqueue");
    assert!(
        real_enqueue.status.success(),
        "{}",
        String::from_utf8_lossy(&real_enqueue.stderr)
    );
    let worker = Command::new(env!("CARGO_BIN_EXE_whip"))
        .current_dir(&fixture.root)
        .env_clear()
        // PATH, because the observer this worker runs is a real subprocess and
        // the interpreter it finds decides the outcome. `exec_server` forwards
        // PATH to the script it spawns on purpose -- "only the declared values
        // plus PATH" -- so a worker with NO PATH is an environment production
        // never has. Without it the child resolved `python3` through the OS
        // default path instead -- the same interpreter as the enqueue half on
        // the Linux runner, and a different one on macOS, where /usr/bin/python3
        // is Apple's 3.9. That disagreement, not any particular version, is
        // what produced `no bound observer header` here and nothing there.
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("WHIPPLESCRIPT_STORE", &path)
        .env("WHIPPLESCRIPT_COMPUTE_ENV_HASH", "ignored-legacy-label")
        .env(
            "WHIPPLESCRIPT_NATIVE_NORM_RUNTIME",
            fixture.root.join("native-host.json"),
        )
        .args(["--json", "worker", &real_instance, "--once"])
        .output()
        .expect("ordinary worker");
    assert!(
        worker.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&worker.stdout),
        String::from_utf8_lossy(&worker.stderr)
    );
    let runs = kernel.store().list_runs(&real_instance).expect("real runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, if actual { "failed" } else { "completed" });
    let publish = || {
        fixture
            .command(&[
                "publish-observation",
                &real_instance,
                &runs[0].run_id,
                "local-observation@1",
                "--as",
                "owner",
            ])
            .env("WHIPPLESCRIPT_STORE", &path)
            .output()
            .expect("real publication")
    };
    let published = publish();
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let published: Value = serde_json::from_slice(&published.stdout).expect("real observation");
    assert_eq!(
        published["observation"]["judgment"]["outcome"],
        if actual { "fail" } else { "pass" }
    );
    assert_eq!(
        published["observation"]["observation_integrity"],
        json!({"kind":"cooperative"})
    );
    assert_eq!(
        published["observation"]["report"]["observations"][0]["actual"],
        json!(actual)
    );
    assert_eq!(
        published["observation"]["judgment"]["counterexamples"]
            .as_array()
            .expect("counterexamples")
            .len(),
        usize::from(actual)
    );
    let after_publish = kernel
        .store()
        .list_events(&real_instance)
        .expect("real journal");
    let retry = publish();
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&retry.stdout).expect("real retry"),
        published
    );
    assert_eq!(
        kernel
            .store()
            .list_events(&real_instance)
            .expect("real journal"),
        after_publish
    );
    assert_eq!(
        kernel
            .store()
            .list_runs(&real_instance)
            .expect("real runs")
            .len(),
        1
    );

    kernel
        .store_mut()
        .transition_instance(whipplescript_store::InstanceTransition {
            instance_id: &instance,
            status: "paused",
            reason: None,
            idempotency_key: Some("paused"),
        })
        .expect("norm enqueue fixture");
    rusqlite::Connection::open(&path)
        .expect("norm enqueue fixture")
        .execute(
            "DELETE FROM script_capabilities WHERE name = 'observer'",
            [],
        )
        .expect("norm enqueue fixture");
    let retained = kernel
        .store()
        .list_events(&instance)
        .expect("norm enqueue fixture");
    let replay = invoke("observer", "120", "changed");
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&replay.stdout).expect("norm enqueue fixture"),
        first
    );
    for (frontier, succeeds) in [
        ("enqueue-original-frontier.json", true),
        ("enqueue-current-frontier.json", false),
    ] {
        let explicit = fixture
            .command(&[
                "enqueue-observation",
                &instance,
                requirement,
                "cut",
                "--effect",
                "command-observe",
                "--capability",
                "observer",
                "--as",
                "owner",
                "--deadline",
                "120",
                "--frontier",
                frontier,
            ])
            .env("WHIPPLESCRIPT_STORE", &path)
            .env("WHIPPLESCRIPT_COMPUTE_ENV_HASH", "changed")
            .output()
            .expect("explicit frontier retry");
        assert_eq!(
            explicit.status.success(),
            succeeds,
            "{}",
            String::from_utf8_lossy(&explicit.stderr)
        );
        if succeeds {
            assert_eq!(
                serde_json::from_slice::<Value>(&explicit.stdout).expect("explicit retry"),
                first
            );
        }
    }
    assert!(!invoke("observer", "121", "changed").status.success());
    assert!(!invoke("different", "120", "changed").status.success());
    assert_eq!(
        kernel
            .store()
            .list_events(&instance)
            .expect("norm enqueue fixture"),
        retained
    );
    assert!(kernel
        .store()
        .list_runs(&instance)
        .expect("norm enqueue fixture")
        .is_empty());
}

fn norm_hosted_enqueue_fixture(
    ledger: &whipplescript_store::items::WorkItemStore,
    verifier: &dyn whipplescript_store::norm::NormVerifier,
    trust: &str,
    artifact: &whipplescript_store::norm_artifact::CapturedArtifact,
    requirement: &str,
    runtime: Option<&whipplescript_kernel::norm_runner::PythonRuntime>,
) -> Value {
    use whipplescript_host_do::do_store::{test_support, DoSql, SqlValue};
    use whipplescript_host_do::norm_commands::execute_hosted_norm_enqueue;
    use whipplescript_kernel::{
        norm_execution::fixtures::script, ProgramVersionInput, RuntimeKernel,
    };
    use whipplescript_store::norm_commands::NormCommandStore;
    use whipplescript_store::{RuntimeStore, ScriptCapabilityRegistration};
    let mut kernel = RuntimeKernel::new(test_support::store());
    let version = kernel
        .create_program_version(ProgramVersionInput {
            program_name: "hosted-enqueue",
            source_hash: "fixture",
            ir_hash: "fixture",
            compiler_version: "fixture",
            ir_snapshot: None,
        })
        .expect("enqueue version");
    let instance = kernel
        .create_instance(&version, "{}")
        .expect("enqueue instance");
    let mut installed = script();
    let runtime_json = runtime.map(|runtime| serde_json::to_string(runtime).expect("runtime JSON"));
    if let Some(runtime) = runtime {
        let mut method = whipplescript_kernel::norm_execution::fixtures::method();
        method.runtime = runtime.clone();
        installed.body = method.adapter().into();
        installed.sha256 = whipplescript_kernel::exec_http::sha256_hex(installed.body.as_bytes());
        installed.argv_json =
            json!([runtime.executable, "executor", "observe-norm", "{script}"]).to_string();
    }
    kernel
        .store()
        .register_script_capability(ScriptCapabilityRegistration {
            name: &installed.name,
            argv_json: &installed.argv_json,
            sha256: &installed.sha256,
            env_json: &installed.env_json,
            hermetic: installed.hermetic,
            body: &installed.body,
        })
        .expect("enqueue observer");
    let mut runtime_rows = Vec::new();
    for table in kernel.store().sql.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('schema_migrations', 'tracker_assertion_counter', 'tracker_counter') ORDER BY CASE name WHEN 'programs' THEN 0 WHEN 'program_versions' THEN 1 WHEN 'instances' THEN 2 ELSE 3 END, name", &[]).expect("tables") {
        let SqlValue::Text(table) = &table[0] else { panic!("table name") };
        let columns: Vec<String> = kernel.store().sql.query(&format!("PRAGMA table_info(\"{table}\")"), &[]).expect("columns").into_iter().map(|row| match &row[1] { SqlValue::Text(name) => name.clone(), _ => panic!("column name") }).collect();
        let rows: Vec<Value> = kernel.store().sql.query(&format!("SELECT * FROM \"{table}\""), &[]).expect("fixture rows").iter().map(|row| json!(row.iter().map(|value| match value {
            SqlValue::Null => Value::Null, SqlValue::Int(n) => json!(n), SqlValue::Text(s) => json!(s),
        }).collect::<Vec<_>>())).collect();
        if !rows.is_empty() { runtime_rows.push(json!({"table":table,"columns":columns,"rows":rows})); }
    }
    kernel
        .store_mut()
        .pin_norm_checkpoint(&ledger.norm_checkpoint().expect("checkpoint").expect("pin"))
        .expect("pin");
    kernel
        .store_mut()
        .import_norm(&ledger.export_events().expect("history"), verifier)
        .expect("history import");
    let command = json!({"instance":instance,"requirement":requirement,"cut":"cut","effect":"hosted-observe","capability":"observer","publisher":"owner","deadline_seconds":120});
    let request = |command: Value| {
        json!({"protocol":"whipplescript.norm.enqueue/v1","command":command}).to_string()
    };
    let artifacts = |cut: &str| {
        if cut == artifact.basis().cut {
            Ok(artifact.clone())
        } else {
            Err(whipplescript_store::StoreError::Conflict(
                "unknown cut".into(),
            ))
        }
    };
    let before = kernel.store().list_events(&instance).expect("journal");
    for field in ["publisher", "deadline_seconds", "executor_url", "files"] {
        let mut invalid = command.clone();
        invalid[field] = if field == "deadline_seconds" {
            json!(0)
        } else {
            json!("untrusted")
        };
        assert!(
            execute_hosted_norm_enqueue(
                &mut kernel,
                trust,
                &request(invalid),
                &artifacts,
                "https://executor",
                "epoch",
                runtime_json.as_deref(),
            )
            .is_err(),
            "{field}"
        );
        assert_eq!(
            kernel.store().list_events(&instance).expect("journal"),
            before
        );
    }
    for malformed in [
        json!({"protocol":"unknown","command":command}),
        json!({"protocol":"whipplescript.norm.enqueue/v1","command":command,"bindings":[]}),
    ] {
        assert!(execute_hosted_norm_enqueue(
            &mut kernel,
            trust,
            &malformed.to_string(),
            &artifacts,
            "https://executor",
            "epoch",
            runtime_json.as_deref(),
        )
        .is_err());
        assert_eq!(
            kernel.store().list_events(&instance).expect("journal"),
            before
        );
    }
    assert!(execute_hosted_norm_enqueue(
        &mut kernel,
        trust,
        &request(command.clone()),
        &artifacts,
        "https://executor",
        "wrong-epoch",
        None,
    )
    .is_err());
    assert_eq!(
        kernel.store().list_events(&instance).expect("journal"),
        before
    );
    if let Some(runtime) = runtime {
        let mut changed = runtime.clone();
        changed.executable = "/changed/observer".into();
        let changed = serde_json::to_string(&changed).expect("changed runtime JSON");
        for profile in [None, Some(changed.as_str())] {
            let result = execute_hosted_norm_enqueue(
                &mut kernel,
                trust,
                &request(command.clone()),
                &artifacts,
                "https://executor",
                "epoch",
                profile,
            );
            assert!(
                result.is_err(),
                "missing or changed protected profile admitted: {result:?}"
            );
            assert_eq!(
                kernel.store().list_events(&instance).expect("journal"),
                before
            );
        }
    }
    let response: Value = serde_json::from_str(
        &execute_hosted_norm_enqueue(
            &mut kernel,
            trust,
            &request(command.clone()),
            &artifacts,
            "https://executor",
            if runtime.is_some() {
                "cache-epoch"
            } else {
                "epoch"
            },
            runtime_json.as_deref(),
        )
        .expect("enqueue"),
    )
    .expect("response");
    let retained = kernel.store().list_events(&instance).expect("journal");
    assert_eq!(
        serde_json::from_str::<Value>(
            &execute_hosted_norm_enqueue(
                &mut kernel,
                trust,
                &request(command.clone()),
                &artifacts,
                "https://executor",
                "changed",
                None,
            )
            .expect("replay")
        )
        .expect("response"),
        response
    );
    assert_eq!(
        kernel.store().list_events(&instance).expect("journal"),
        retained
    );
    if let Some(runtime) = runtime {
        let mut changed = runtime.clone();
        changed.executable = "/changed/observer".into();
        let changed = serde_json::to_string(&changed).expect("changed runtime JSON");
        let acknowledgment = execute_hosted_norm_enqueue(
            &mut kernel,
            trust,
            &request(command.clone()),
            &artifacts,
            "https://executor",
            "changed",
            Some(&changed),
        )
        .expect("retained acknowledgment after configuration change");
        assert_eq!(
            serde_json::from_str::<Value>(&acknowledgment).expect("acknowledgment JSON"),
            response
        );
        assert_eq!(
            kernel.store().list_events(&instance).expect("journal"),
            retained
        );
    }
    let mut changed_deadline = command.clone();
    changed_deadline["deadline_seconds"] = json!(121);
    assert!(execute_hosted_norm_enqueue(
        &mut kernel,
        trust,
        &request(changed_deadline),
        &artifacts,
        "https://executor",
        "changed",
        None,
    )
    .is_err());
    assert_eq!(
        kernel.store().list_events(&instance).expect("journal"),
        retained
    );
    assert!(kernel
        .store()
        .list_runs(&instance)
        .expect("runs")
        .is_empty());
    json!({"command":command,"runtime_rows":runtime_rows,"response":response})
}

#[path = "norm_commands/protected.rs"]
mod protected;

#[path = "norm_commands/hosted_profile.rs"]
mod hosted_profile;

#[path = "norm_commands/hosted_protected.rs"]
mod hosted_protected;

#[path = "norm_commands/impact.rs"]
mod impact;
