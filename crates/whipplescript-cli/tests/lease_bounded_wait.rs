//! Bounded-wait lease acquisition (spec/coordination.md).
//!
//! `acquire <lease> for <key> [until ttl] wait <duration> as <b>` retries a
//! contended acquire on every worker pass until the slot frees (then `held`) or
//! the wait elapses (then `contended`). These tests pin the three behaviors:
//!   (a) a plain `acquire` on a busy slot routes to `contended` immediately;
//!   (b) `acquire … wait` on a busy slot stays pending (re-claimable) and, once
//!       the holder releases, acquires `held`;
//!   (c) once the wait deadline passes (advanced via the injected virtual clock),
//!       it gives up and completes `contended`.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use whipplescript_store::coordination::{AcquireOutcome, CoordinationStore};

fn temp_path(label: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "whipplescript-lease-wait-{label}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

/// A single-workflow program with a shared, 1-slot lease. `{ACQUIRE}` is
/// substituted with the acquire clause under test so a foreign holder seeded
/// under owner `shared` contends with the running instance.
const SOURCE_TEMPLATE: &str = r#"
workflow LeaseWaitDemo

output result Done
failure error Busy

class Ticket {
  id string
}

class Done {
  note string
}

class Busy {
  reason string
}

lease deploy_slot {
  shared
  key Ticket
  slots 1
  ttl 1h
}

rule seed
  when started
=> {
  record Ticket {
    id "prod"
  }
}

rule grab
  when Ticket as t
=> {
  {ACQUIRE}

  after slot held {
    release slot
    complete result {
      note "acquired the slot"
    }
  }
  after slot contended {
    fail error {
      reason "slot busy"
    }
  }
}
"#;

fn source_with(acquire: &str) -> String {
    SOURCE_TEMPLATE.replace("{ACQUIRE}", acquire)
}

fn seed_foreign_holder(coordination: &std::path::Path) {
    let mut seeded = CoordinationStore::open(coordination).expect("open coordination store");
    assert_eq!(
        seeded
            .try_acquire_for_owner("shared", "deploy_slot", "prod", 1, 600, "ins_other")
            .expect("seed holder"),
        AcquireOutcome::Held
    );
}

fn dev(bin: &str, store: &str, source: &str, coordination: &str) -> Value {
    let output = Command::new(bin)
        .args([
            "--store",
            store,
            "--json",
            "run",
            source,
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination)
        .output()
        .expect("dev runs");
    assert!(
        output.status.success(),
        "dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json")
}

/// One `step` (rule advance) + `worker` (effect pass) round over an existing
/// instance, mirroring the `dev`/scenario drive loop — but on the *same*
/// instance across calls (`dev` mints a fresh instance each invocation).
fn drive_round(bin: &str, store: &str, instance: &str, source: &str, coordination: &str) {
    for command in [
        vec!["--store", store, "step", instance, "--program", source],
        vec![
            "--store",
            store,
            "worker",
            instance,
            "--program",
            source,
            "--provider",
            "fixture",
        ],
    ] {
        let output = Command::new(bin)
            .args(&command)
            .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination)
            .output()
            .expect("command runs");
        assert!(
            output.status.success(),
            "{command:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn instance_status(bin: &str, store: &str, instance: &str) -> String {
    let output = Command::new(bin)
        .args(["--store", store, "--json", "status", instance])
        .output()
        .expect("status runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let status: Value =
        serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("status json");
    status
        .pointer("/instance/status")
        .and_then(Value::as_str)
        .expect("instance status")
        .to_owned()
}

/// (a) A plain `acquire` on a busy slot routes straight to `contended` — the
/// instance fails on the `contended` arm in a single worker pass.
#[test]
fn plain_acquire_contends_immediately() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("plain", "sqlite");
    let source = temp_path("plain", "whip");
    let coordination = temp_path("plain-coord", "sqlite");
    fs::write(&source, source_with("acquire deploy_slot for t.id as slot")).expect("write source");
    seed_foreign_holder(&coordination);

    let store_str = store.to_str().expect("utf-8");
    let dev = dev(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        coordination.to_str().expect("utf-8"),
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&source);
    let _ = fs::remove_file(&coordination);
}

/// (b) `acquire … wait` on a busy slot stays pending (re-claimable, instance
/// still running) rather than completing `contended`. Once the foreign holder
/// releases, a later worker pass acquires `held` and the instance completes.
#[test]
fn wait_defers_then_acquires_on_release() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("wait-defer", "sqlite");
    let source = temp_path("wait-defer", "whip");
    let coordination = temp_path("wait-defer-coord", "sqlite");
    // A generous wait so no plausible wall-clock test runtime crosses the deadline.
    fs::write(
        &source,
        source_with("acquire deploy_slot for t.id wait 10m as slot"),
    )
    .expect("write source");
    seed_foreign_holder(&coordination);

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let coordination_str = coordination.to_str().expect("utf-8");

    // First pass: the acquire contends but soft-defers, so the instance is still
    // running with no `contended`/`held` terminal yet.
    let started = dev(bin, store_str, source_str, coordination_str);
    let instance = started
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    assert_eq!(
        instance_status(bin, store_str, &instance),
        "running",
        "wait should soft-defer while the slot is busy, not complete contended"
    );

    // Free the slot.
    {
        let mut holder = CoordinationStore::open(&coordination).expect("open coordination");
        assert!(
            holder
                .release_for_owner("shared", "deploy_slot", "prod", "ins_other")
                .expect("release"),
            "seeded holder should be released"
        );
    }

    // Later passes over the *same* instance re-attempt the acquire, now free, and
    // drive the held arm (release + complete) to completion.
    let mut status = instance_status(bin, store_str, &instance);
    for _ in 0..8 {
        if status != "running" {
            break;
        }
        drive_round(bin, store_str, &instance, source_str, coordination_str);
        status = instance_status(bin, store_str, &instance);
    }
    assert_eq!(
        status, "completed",
        "the acquire should win the freed slot and complete on the held arm"
    );

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&source);
    let _ = fs::remove_file(&coordination);
}

/// (c) When the wait deadline elapses without the slot freeing, the acquire gives
/// up and completes `contended`. The injected virtual clock (`given clock at`)
/// advances past the creation-anchored deadline deterministically — no sleeping.
#[test]
fn wait_gives_up_after_deadline() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let source = temp_path("wait-giveup", "whip");
    let coordination = temp_path("wait-giveup-coord", "sqlite");
    seed_foreign_holder(&coordination);

    // Same program, plus a scenario that advances the clock far past the wait
    // deadline while the seeded holder still holds the slot.
    let program = format!(
        "{}\n{}",
        source_with("acquire deploy_slot for t.id wait 10m as slot"),
        r#"
test "wait elapses then gives up" {
  workflow LeaseWaitDemo
  given clock at "2035-01-01T00:00:00Z"
  run until idle
  expect rule grab fired
  expect workflow failed
}
"#
    );
    fs::write(&source, program).expect("write source");

    let output = Command::new(bin)
        .args(["--json", "test", source.to_str().expect("utf-8")])
        .env(
            "WHIPPLESCRIPT_COORDINATION_STORE",
            coordination.to_str().expect("utf-8"),
        )
        .output()
        .expect("whip test runs");
    let report: Value = serde_json::from_slice(&output.stdout).expect("test report JSON");
    let scenario = report
        .get("scenarios")
        .and_then(Value::as_array)
        .and_then(|scenarios| scenarios.first())
        .expect("one scenario");
    assert_eq!(
        scenario.get("status").and_then(Value::as_str),
        Some("passed"),
        "the give-up scenario should pass (workflow fails on the contended arm): {report}"
    );

    let _ = fs::remove_file(&source);
    let _ = fs::remove_file(&coordination);
}
