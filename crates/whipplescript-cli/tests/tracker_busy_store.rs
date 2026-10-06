//! A tracker command queues behind another whip's write instead of failing
//! (WS-771, DR-0187). whip used to wait 5 s for the store's write lock and
//! then report "internal store error (database is locked); this is a whip
//! bug", while one write could hold the lock for longer than that. How the
//! failure reads, when a wait does run out, is in the CLI's own tests.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn whip(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_whip"))
        .current_dir(root)
        .env("WHIPPLESCRIPT_ITEMS_STORE", root.join("items.sqlite"))
        .env("WHIPPLESCRIPT_MISUSE_LOG", "off")
        .arg("issue")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("whip runs")
}

#[test]
fn a_tracker_command_waits_out_a_write_longer_than_five_seconds() {
    let root = tempfile::tempdir().expect("temp directory");
    let root = root.path();
    let created = whip(root, &["new", "--tracker", "t", "--title", "before"]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );

    // Another writer holds the lock past the 5 s every store used to wait.
    let held = Duration::from_secs(7);
    let holder = rusqlite::Connection::open(root.join("items.sqlite")).expect("store");
    holder.execute_batch("BEGIN IMMEDIATE").expect("write lock");
    let release = std::thread::spawn(move || {
        std::thread::sleep(held);
        holder.execute_batch("ROLLBACK").expect("release");
    });
    let started = Instant::now();
    let out = whip(root, &["new", "--tracker", "t", "--title", "while busy"]);
    let waited = started.elapsed();
    release.join().expect("holder");

    assert!(
        out.status.success(),
        "a command must queue behind the write: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        waited >= Duration::from_secs(5),
        "it can only have succeeded by waiting for the lock, not around it ({waited:?})"
    );
    let listing = whip(root, &["list", "--tracker", "t"]);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("while busy"));
}
