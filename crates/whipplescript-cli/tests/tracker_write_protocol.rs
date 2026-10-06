//! A whip too old for a tracker store's write rules still reads it, and is
//! told plainly that writing needs an upgrade (DR-0186, WS-696). Before this,
//! whip 0.8.0 read the founder's store normally and then failed every write
//! with "internal store error (no such function: ...); this is a whip bug".

use std::path::Path;
use std::process::{Command, Output, Stdio};

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

fn good(root: &Path, args: &[&str]) -> String {
    let out = whip(root, args);
    assert!(
        out.status.success(),
        "whip issue {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn refused(root: &Path, args: &[&str]) -> String {
    let out = whip(root, args);
    assert!(!out.status.success(), "whip issue {args:?} should refuse");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn checkout() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temp directory");
    let git = Command::new("git")
        .arg("init")
        .arg(root.path())
        .stdin(Stdio::null())
        .output()
        .expect("git");
    assert!(git.status.success());
    root
}

fn sql(root: &Path, statement: &str) {
    rusqlite::Connection::open(root.join("items.sqlite"))
        .expect("store")
        .execute_batch(statement)
        .expect("statement");
}

fn first_id(listing: &str) -> String {
    listing
        .split_whitespace()
        .next()
        .expect("an issue")
        .to_owned()
}

#[test]
fn a_newer_write_protocol_keeps_reads_and_refuses_writes_plainly() {
    let root = checkout();
    let root = root.path();
    good(
        root,
        &["new", "--tracker", "t", "--title", "written before"],
    );
    sql(
        root,
        "UPDATE tracker_write_protocol SET version = 7, raised_by = '9.9.9'",
    );

    let listing = good(root, &["list", "--tracker", "t"]);
    assert!(listing.contains("written before"), "{listing}");
    let id = first_id(&listing);
    assert!(good(root, &["show", &id]).contains("written before"));
    good(root, &["ready", "t"]);

    let message = refused(root, &["new", "--tracker", "t", "--title", "written after"]);
    assert!(
        message.contains(
            "tracker store write protocol (raised by whip 9.9.9) is 7, but this whip writes \
             only up to 1"
        ),
        "{message}"
    );
    assert!(
        message.contains("reading the store still works; upgrade whip to write to it"),
        "{message}"
    );
    assert!(!message.contains("whip bug"), "{message}");
    let message = refused(root, &["note", &id, "a note"]);
    assert!(message.contains("upgrade whip to write to it"), "{message}");
    assert!(!good(root, &["list", "--tracker", "t"]).contains("written after"));
}

#[test]
fn a_write_rule_this_whip_lacks_is_not_reported_as_a_whip_bug() {
    let root = checkout();
    let root = root.path();
    good(
        root,
        &["new", "--tracker", "t", "--title", "written before"],
    );
    // A newer whip's rule installed without raising the protocol.
    sql(
        root,
        "CREATE TRIGGER future_writer BEFORE INSERT ON tracker_events \
         BEGIN SELECT whip_future_writer_v2(); END;",
    );
    let message = refused(root, &["new", "--tracker", "t", "--title", "written after"]);
    assert!(
        message.contains("this store has write rules that this whip does not provide"),
        "{message}"
    );
    assert!(message.contains("whip_future_writer_v2"), "{message}");
    assert!(!message.contains("whip bug"), "{message}");
    assert!(good(root, &["list", "--tracker", "t"]).contains("written before"));
}
