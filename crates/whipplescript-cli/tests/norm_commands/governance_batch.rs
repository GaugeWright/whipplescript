//! Same-roster process/snapshot comparison, not Company adoption or a latency gate.
use super::*;
use std::time::Instant;
use whipplescript_store::norm::NormCheckpoint;
use whipplescript_store::norm_governance_import::{GovernanceImportRequest, GovernanceSource};

fn hosted_trust() -> Value {
    use ring::signature::KeyPair as _;
    let public_bindings: Vec<_> = [("owner", "owner", 1), ("worker", "worker", 2)]
        .into_iter()
        .map(|(name, principal, seed)| {
            let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                .expect("owned synthetic custody key");
            let public_key_hex: String = key
                .public_key()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            json!({"actor":{"principal":principal,"algorithm":"ed25519-custodian",
                "key_id":format!("credential:norm/{name}#local")},"public_key_hex":public_key_hex})
        })
        .collect();
    json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]})
}

fn stable_snapshot(mut snapshot: Value) -> Value {
    // Local N-* aliases follow insertion order, not portable signed identity.
    // Existing CLI/DO round-trip conformance applies this same normalization.
    for named in snapshot["result"]["snapshot"]["records"]
        .as_array_mut()
        .expect("complete snapshot records")
    {
        let alias = named.get_mut("alias").expect("local alias field");
        assert!(alias
            .as_str()
            .expect("local alias string")
            .strip_prefix("N-")
            .and_then(|number| number.parse::<u64>().ok())
            .is_some());
        *alias = Value::String("<host-local-alias>".into());
    }
    snapshot
}

#[test]
fn complete_governance_source_same_roster_native_and_do_batch_parity() {
    let supplied = std::env::var_os("WS828_COMPANY_LOG");
    let raw = match supplied.as_ref() {
        Some(path) => std::fs::read(path).expect("explicit complete Company source"),
        None => br#"// portable attributed chronology, not the Company dataset
{"schemaVersion":1,"events":[
 {"decisionId":"DR-0001","state":"proposed","class":"founder","title":"One"},
 {"decisionId":"DR-0001","state":"withdrawn","reason":"No adoption"},
 {"decisionId":"DR-0002","state":"folded","unknownSourceField":{"kept":true}}
]}"#
        .to_vec(),
    };
    let source = GovernanceSource::from_bytes(
        "GaugeWright".into(),
        "94ffc6a".into(),
        "decisions/log.hjson".into(),
        &raw,
    )
    .expect("independently parsed complete source");
    let baseline = Fixture::new();
    let batch = Fixture::new();
    for fixture in [&baseline, &batch] {
        fixture.run(&[
            "bootstrap",
            "--as",
            "owner",
            "--creator",
            "worker",
            "--nonce",
            "same-bootstrap",
            "--at",
            "2026-10-07T00:00:00Z",
        ]);
    }
    let initial = batch.run(&["export"]);
    assert_eq!(
        baseline.run(&["export"]),
        initial,
        "same exact initial signed basis"
    );
    std::fs::write(batch.root.join("source.hjson"), &raw).expect("owned source file");
    let started = Instant::now();
    let prepared = batch.run(&[
        "prepare-governance",
        "--source",
        "source.hjson",
        "--scope",
        "GaugeWright",
        "--revision",
        "94ffc6a",
        "--import-id",
        "same-roster",
        "--as",
        "owner",
        "--nonce",
        "same-roster",
        "--at",
        "2026-10-07T00:01:00Z",
    ]);
    let preparation_seconds = started.elapsed().as_secs_f64();
    let request: GovernanceImportRequest =
        serde_json::from_value(prepared.clone()).expect("actual custody-prepared request");
    assert_eq!(request.descriptor.source, source);
    assert_eq!(request.descriptor.chronology.len(), source.event_count);
    assert!(
        request.descriptor.adoptions.is_empty(),
        "no source lifecycle becomes approval"
    );
    let parsed = source.events().expect("exact source chronology");
    if let Some(path) = std::env::var_os("WS828_COMPANY_EVENTS") {
        let expected: Vec<Value> = serde_json::from_slice(
            &std::fs::read(path).expect("independent Company parser typed reference"),
        )
        .expect("reference JSON");
        assert_eq!(
            parsed, expected,
            "every source field matches independent Company HJSON reader"
        );
    }
    for (index, entry) in request.descriptor.chronology.iter().enumerate() {
        assert_eq!(entry.index, index);
        assert_eq!(entry.raw_parsed_event, parsed[index]);
        assert_eq!(entry.effective_event, None);
    }
    batch.write("batch.json", &prepared);
    let started = Instant::now();
    let imported = batch.run(&["import-governance", "--request", "batch.json"]);
    let native_batch_seconds = started.elapsed().as_secs_f64();
    assert_eq!(
        imported["result"]["import"]["admitted"],
        request.events.len()
    );
    assert_eq!(
        imported["result"]["import"]["mapping"],
        serde_json::to_value(&request.descriptor.mapping).expect("map serialization")
    );
    let started = Instant::now();
    for event in &request.events {
        let signed: Value = serde_json::from_str(&event.payload_json).expect("actual signed act");
        baseline.run(&["snapshot"]);
        baseline.write(
            "act.json",
            &json!({"protocol":"whipplescript.norm.commands/v1",
            "command":{"kind":"append","event":signed}}),
        );
        baseline.run(&["dispatch", "--request", "act.json"]);
    }
    let native_ordinary_seconds = started.elapsed().as_secs_f64();
    assert_eq!(
        baseline.run(&["export"]),
        batch.run(&["export"]),
        "all retained signed events and current checkpoint identical"
    );
    assert!(
        stable_snapshot(baseline.run(&["snapshot"])) == stable_snapshot(batch.run(&["snapshot"])),
        "every derived record/state identical after excluding local alias names"
    );
    let before_retry = batch.run(&["export"]);
    let before_retry_snapshot = batch.run(&["snapshot"]);
    assert_eq!(
        batch.run(&["import-governance", "--request", "batch.json"])["result"]["import"]
            ["replayed"],
        true
    );
    assert_eq!(batch.run(&["export"]), before_retry);
    assert!(
        batch.run(&["snapshot"]) == before_retry_snapshot,
        "same-host exact retry cannot change aliases or any state"
    );

    let trust = hosted_trust().to_string();
    let run = |store: &mut _, command: Value| -> Value {
        serde_json::from_str(
            &whipplescript_host_do::norm_commands::execute_hosted_norm_command(
                store,
                &trust,
                &json!({"protocol":"whipplescript.norm.commands/v1",
            "command":command})
                .to_string(),
            )
            .expect("real DO public verifier"),
        )
        .expect("actual hosted response")
    };
    let checkpoint: NormCheckpoint =
        serde_json::from_value(initial["result"]["checkpoint"].clone())
            .expect("same initial checkpoint");
    let mut do_batch = whipplescript_host_do::do_store::test_support::store();
    let mut do_ordinary = whipplescript_host_do::do_store::test_support::store();
    for store in [&mut do_batch, &mut do_ordinary] {
        store
            .pin_norm_checkpoint(&checkpoint)
            .expect("explicit initial hosted pin");
        run(
            store,
            json!({"kind":"import","events":initial["result"]["events"]}),
        );
    }
    let started = Instant::now();
    let do_result = run(
        &mut do_batch,
        json!({"kind":"governance_import","request":request}),
    );
    let do_batch_seconds = started.elapsed().as_secs_f64();
    let do_before_retry = run(&mut do_batch, json!({"kind":"export"}));
    let do_snapshot_before_retry = run(&mut do_batch, json!({"kind":"snapshot"}));
    assert_eq!(
        run(
            &mut do_batch,
            json!({"kind":"governance_import","request":request})
        )["result"]["import"]["replayed"],
        true
    );
    assert!(run(&mut do_batch, json!({"kind":"export"})) == do_before_retry);
    assert!(
        run(&mut do_batch, json!({"kind":"snapshot"})) == do_snapshot_before_retry,
        "same DO isolate retry preserves local aliases and complete state"
    );
    assert_eq!(
        do_result["result"]["import"]["mapping"],
        imported["result"]["import"]["mapping"]
    );
    let started = Instant::now();
    for event in &request.events {
        run(&mut do_ordinary, json!({"kind":"snapshot"}));
        let signed: Value = serde_json::from_str(&event.payload_json).expect("actual signed act");
        run(&mut do_ordinary, json!({"kind":"append","event":signed}));
    }
    let do_ordinary_seconds = started.elapsed().as_secs_f64();
    let do_export = run(&mut do_batch, json!({"kind":"export"}));
    assert_eq!(run(&mut do_ordinary, json!({"kind":"export"})), do_export);
    assert_eq!(do_export["result"], before_retry["result"]);
    assert!(
        stable_snapshot(run(&mut do_ordinary, json!({"kind":"snapshot"})))
            == stable_snapshot(run(&mut do_batch, json!({"kind":"snapshot"}))),
        "complete DO derived state is equal except local aliases"
    );
    let first = request
        .descriptor
        .mapping
        .first()
        .expect("at least one source number");
    assert_eq!(
        batch.run(&["resolve-governance", "GaugeWright", &first.number])["result"]["record"],
        first.record
    );
    assert_eq!(
        run(
            &mut do_batch,
            json!({"kind":"governance_reference","scope":"GaugeWright",
        "number":first.number})
        )["result"]["record"],
        first.record
    );
    println!(
        "WS828_SAME_ROSTER {}",
        json!({"dataset":if supplied.is_some(){"complete-company94"}else{"portable"},
        "raw_sha256":source.sha256,"source_events":source.event_count,
        "mapped_decisions":request.descriptor.mapping.len(),"signed_acts":request.events.len(),
        "preparation_processes":1,"preparation_snapshots":1,"preparation_seconds":preparation_seconds,
        "native_ordinary_processes":2*request.events.len(),"native_ordinary_snapshots":request.events.len(),
        "native_ordinary_seconds":native_ordinary_seconds,"native_batch_processes":1,"native_batch_seconds":native_batch_seconds,
        "do_ordinary_host_calls":2*request.events.len(),"do_ordinary_snapshots":request.events.len(),
        "do_ordinary_seconds":do_ordinary_seconds,"do_batch_host_calls":1,"do_batch_seconds":do_batch_seconds,
        "limits":"same signed roster; ordinary snapshots included; local aliases differ across admission order, same-host retry preserves them exactly; DO shared synchronous SQLite fixture not Workerd/prod; no production latency or Company adoption; preparation reparses/clones"})
    );
}
