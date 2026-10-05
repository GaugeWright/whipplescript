//! `whip` commands whose workspace stores are the calling test's own.
//!
//! Unset, the binary resolves each workspace store -- coordination, work
//! items, content, branches and the rest -- as `.whipplescript/<name>.sqlite`
//! under the CURRENT WORKING DIRECTORY, and a step opens the coordination and
//! work-item stores every time, with a schema write under an immediate
//! transaction. So every `whip` a test spawned shared those write locks with
//! every other test running at the same moment. On a host whose disk was
//! saturated, one commit held a lock past the store's 5 s busy timeout, and a
//! `whip run` with no tracker or coordination work in it exited with
//! `database is locked`: four soft_middle exec tests at once on the Legion on
//! 2026-09-27 (WS-86). A workstation whose shell sets a store variable fared
//! worse, because a suite inherited it and opened the operator's live store --
//! even a test that ran `whip` in a directory of its own.
//!
//! The directory belongs to the calling thread, and libtest runs every test on
//! a thread of its own under `cargo test` and nextest alike, so each test gets
//! one directory for all its commands and loses it when it ends, panic
//! included. A test that pins a store itself still wins, since a later `.env`
//! for the same name replaces these. control_plane.rs isolates its commands the
//! same way, keyed on each test's store rather than its thread.

use std::{
    ffi::OsStr,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// A `whip` command with every workspace store redirected into the calling
/// test's directory.
pub fn whip_command(bin: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(bin);
    isolate_stores(&mut command);
    command
}

/// The same redirection for a command built another way -- after an
/// `env_clear`, say, which would otherwise take these with it.
#[allow(dead_code)] // Only the files that clear a command's environment use it.
pub fn isolate_stores(command: &mut Command) -> &mut Command {
    SIDE_STORES.with(|side| {
        for (name, file) in SIDE_STORE_FILES {
            command.env(name, side.dir.join(file));
        }
    });
    command
}

/// The calling thread's directory, for a test that inspects it.
#[allow(dead_code)] // Only the harness's own test asks.
pub fn side_store_dir() -> PathBuf {
    SIDE_STORES.with(|side| side.dir.clone())
}

/// Every store `whip` resolves relative to the workspace, and the file each
/// is redirected to. `--store` still wins where a command passes it; the run
/// store is here so a command that passes none writes into the test's
/// directory rather than its working directory.
const SIDE_STORE_FILES: [(&str, &str); 10] = [
    ("WHIPPLESCRIPT_STORE", "store.sqlite"),
    ("WHIPPLESCRIPT_COORDINATION_STORE", "coordination.sqlite"),
    ("WHIPPLESCRIPT_ITEMS_STORE", "items.sqlite"),
    ("WHIPPLESCRIPT_CONTENT_STORE", "harness-content.sqlite"),
    ("WHIPPLESCRIPT_IMPROVE_STORE", "improve.sqlite"),
    ("WHIPPLESCRIPT_INCIDENTS_STORE", "incidents.sqlite"),
    ("WHIPPLESCRIPT_WORKSTREAM_STORE", "workstreams.sqlite"),
    ("WHIPPLESCRIPT_BRANCH_STORE", "branches.sqlite"),
    ("WHIPPLESCRIPT_VCS_CONTENT_STORE", "vcs-content.sqlite"),
    ("WHIPPLESCRIPT_MEMORY_STORE", "memory.sqlite"),
];

/// A pid and a counter, not a clock: two threads can read the same instant,
/// and macOS reports microseconds, but `fetch_add` never hands one value out
/// twice. The pid is the test binary's, so two binaries never meet either.
static SIDE_STORE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct SideStores {
    dir: PathBuf,
}

impl SideStores {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-test-side-{}-{}",
            std::process::id(),
            SIDE_STORE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create side store directory");
        Self { dir }
    }
}

impl Drop for SideStores {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

thread_local! {
    static SIDE_STORES: SideStores = SideStores::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_overrides_poison_and_later_explicit_override_wins() {
        let mut command = Command::new("unused-fixture-binary");
        for (name, _) in SIDE_STORE_FILES {
            command.env(name, "/unusable-parent/poison.sqlite");
        }
        isolate_stores(&mut command);
        let dir = side_store_dir();
        assert!(dir.is_dir());
        let values: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for (name, file) in SIDE_STORE_FILES {
            assert_eq!(
                values.get(OsStr::new(name)).copied().flatten(),
                Some(dir.join(file).as_os_str())
            );
        }
        let next = whip_command("unused-fixture-binary");
        assert_eq!(
            next.get_envs().collect::<Vec<_>>(),
            command.get_envs().collect::<Vec<_>>()
        );
        let explicit = dir.join("explicit-items.sqlite");
        command.env("WHIPPLESCRIPT_ITEMS_STORE", &explicit);
        let values: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(
            values
                .get(OsStr::new("WHIPPLESCRIPT_ITEMS_STORE"))
                .copied()
                .flatten(),
            Some(explicit.as_os_str())
        );
    }

    #[test]
    fn panic_removes_owned_thread_directory() {
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let dir = side_store_dir();
            fs::write(dir.join("owned-fixture"), "synthetic").expect("write fixture");
            send.send(dir).expect("send owned path");
            panic!("intentional fixture cleanup control");
        });
        let dir = receive.recv().expect("receive owned path");
        assert!(thread.join().is_err());
        assert!(
            !dir.exists(),
            "{} outlived its panicking thread",
            dir.display()
        );
    }
}
