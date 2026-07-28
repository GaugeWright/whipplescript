//! Lease renew (spec/coordination.md): `renew <acquire-binding> [until <ttl>] as
//! <b>` extends a held lease's TTL before it expires, completing the lease
//! lifecycle (acquire / wait / renew / release).
//!
//! Two levels:
//!   (a) the store primitive `renew_lease_for_owner` — a still-live hold gets its
//!       expiry advanced (`Renewed`, returns the new `expires_at`); a lease this
//!       holder does not hold, or one already released, matches no row and yields
//!       `None` (`NotHeld`);
//!   (b) end-to-end through parse -> lowering -> handler: the shipped example
//!       acquires, renews out to 300s, then releases and completes, and the
//!       `lease.renew` effect reaches `completed` carrying the renewed TTL.

use std::{
    fs,
    path::{Path, PathBuf},
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
        "whipplescript-lease-renew-{label}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

/// (a) The store primitive: renewing a held lease advances its expiry and returns
/// the new `expires_at`; renewing a lease this holder does not hold — or one that
/// has been released — reports `NotHeld` (`None`).
#[test]
fn renew_advances_expiry_and_reports_not_held() {
    let coordination = temp_path("store", "sqlite");
    let mut store = CoordinationStore::open(&coordination).expect("open coordination store");

    // Hold the single shared slot.
    assert_eq!(
        store
            .try_acquire_for_owner("shared", "deploy_slot", "prod", 1, 60, "ins_a")
            .expect("acquire"),
        AcquireOutcome::Held
    );

    // Renew twice with increasing TTLs; each returns the new expiry, and the
    // longer TTL pushes it strictly further out (`Renewed`).
    let expiry_short = store
        .renew_lease_for_owner("shared", "deploy_slot", "prod", 120, "ins_a")
        .expect("renew held lease")
        .expect("renewing a held lease returns Some(expires_at)");
    let expiry_long = store
        .renew_lease_for_owner("shared", "deploy_slot", "prod", 300, "ins_a")
        .expect("renew held lease again")
        .expect("second renew still holds");
    assert!(
        expiry_long > expiry_short,
        "renewing to a longer TTL advances the expiry: {expiry_long} !> {expiry_short}"
    );

    // A holder that does not hold this lease cannot renew it (`NotHeld`).
    assert!(
        store
            .renew_lease_for_owner("shared", "deploy_slot", "prod", 300, "ins_other")
            .expect("renew by non-holder")
            .is_none(),
        "renewing a lease you do not hold reports NotHeld"
    );

    // After releasing, the original holder can no longer renew (`NotHeld`).
    assert!(
        store
            .release_for_owner("shared", "deploy_slot", "prod", "ins_a")
            .expect("release"),
        "the holder's lease is released"
    );
    assert!(
        store
            .renew_lease_for_owner("shared", "deploy_slot", "prod", 300, "ins_a")
            .expect("renew after release")
            .is_none(),
        "renewing after release reports NotHeld"
    );

    let _ = fs::remove_file(&coordination);
}

/// (b) End-to-end: the shipped `coord-lease-renew.whip` example acquires the slot,
/// renews it out to 300s, then releases and completes. The `lease.renew` effect
/// runs through the real parse/lowering/handler pipeline to `completed`, carrying
/// the renewed 300s TTL.
#[test]
fn renew_effect_completes_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/coord-lease-renew.whip")
        .canonicalize()
        .expect("example exists");
    let store = temp_path("e2e", "sqlite");
    let coordination = temp_path("e2e-coord", "sqlite");
    let store_str = store.to_str().expect("utf-8");

    let output = Command::new(bin)
        .args([
            "--store",
            store_str,
            "--json",
            "run",
            example.to_str().expect("utf-8"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .env(
            "WHIPPLESCRIPT_COORDINATION_STORE",
            coordination.to_str().expect("utf-8"),
        )
        .output()
        .expect("dev runs");
    assert!(
        output.status.success(),
        "dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let dev: Value =
        serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");

    let status_output = Command::new(bin)
        .args(["--store", store_str, "--json", "status", instance])
        .env(
            "WHIPPLESCRIPT_COORDINATION_STORE",
            coordination.to_str().expect("utf-8"),
        )
        .output()
        .expect("status runs");
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    let status: Value =
        serde_json::from_str(&status_stdout[status_stdout.find('{').expect("json")..])
            .expect("status json");

    assert_eq!(
        status.pointer("/instance/status").and_then(Value::as_str),
        Some("completed"),
        "the renew workflow completes: {status}"
    );

    let renew = status
        .get("effects")
        .and_then(Value::as_array)
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("lease.renew"))
        .expect("a lease.renew effect");
    assert_eq!(
        renew.get("status").and_then(Value::as_str),
        Some("completed"),
        "the lease.renew effect runs to completion: {renew}"
    );
    assert_eq!(
        renew.pointer("/input/ttl_seconds").and_then(Value::as_i64),
        Some(300),
        "the renew carries its `until 300s` TTL: {renew}"
    );

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&coordination);
}
