//! The pure-rule fixpoint is bounded, so a runaway rule cannot hang a pass.
//!
//! `spec/semantics.md` used to argue this loop needed no bound, on the ground
//! that "a fact with a given id can never be re-recorded, so the round loop
//! reaches quiescence". That argument is Datalog's, and it holds there because
//! Datalog has no function symbols. WhippleScript has arithmetic in a record
//! body, so a rule that records `n x.n + 1` off its own trigger mints a value
//! no earlier fact carried: dedup bounds re-recording, not production.
//!
//! Measured before the bound existed: this exact program committed 1197 times
//! inside ONE pass and was still going. `--max-iterations` does not help — it
//! bounds passes, and the run never leaves the first one.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The runaway: recursive through its own aggregate, and every firing mints a
/// value that has never been recorded before.
const RUNAWAY: &str = r#"workflow FixpointRunaway

output result Done

class Done {
  n int
}

class Item {
  n int
}

rule grow
  when Item as i where count(Item where n >= 0) > 0
=> {
  record Item {
    n i.n + 1
  }
}

rule seed
  when started
=> {
  record Item {
    n 0
  }
}

rule finish
  when Item as i where i.n > 99999
=> {
  complete result {
    n i.n
  }
}
"#;

fn temp_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "whip-fixpoint-{label}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Wait for the child, killing it past the deadline. Without the bound the run
/// never returns, and a test that merely asserted on output would hang CI
/// instead of failing; this turns that into a clean assertion.
fn run_with_deadline(mut child: std::process::Child, deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => return true,
            None if started.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[test]
fn a_runaway_rule_fixpoint_stops_the_pass_instead_of_hanging_it() {
    let dir = temp_dir("runaway");
    let program = dir.join("runaway.whip");
    fs::write(&program, RUNAWAY).expect("write program");

    // A low bound keeps the test quick; the shipped default is 10_000, and the
    // most any example in the repository needs is SIX.
    let child = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args([
            "run",
            program.to_str().expect("path"),
            "--max-iterations",
            "1",
        ])
        .env("WHIPPLESCRIPT_MAX_ROUNDS", "50")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn whip run");

    assert!(
        run_with_deadline(child, Duration::from_secs(60)),
        "`whip run` did not return: the pure-rule fixpoint is unbounded again"
    );

    let instances = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(["instances"])
        .current_dir(&dir)
        .output()
        .expect("list instances");
    let listing = String::from_utf8_lossy(&instances.stdout).into_owned();
    let instance = listing
        .split_whitespace()
        .find(|word| word.starts_with("ins_"))
        .unwrap_or_else(|| panic!("no instance in `whip instances` output:\n{listing}"))
        .to_owned();

    let diagnostics = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(["diagnostics", &instance])
        .current_dir(&dir)
        .output()
        .expect("read diagnostics");
    let text = String::from_utf8_lossy(&diagnostics.stdout).into_owned();

    assert!(
        text.contains("rule.fixpoint.unbounded"),
        "the bound stopped the pass without saying why:\n{text}"
    );
    // The diagnostic must name the rule that kept firing: "it looped" is not
    // actionable, "`grow` looped" is.
    assert!(
        text.contains("grow"),
        "the diagnostic does not name the looping rule:\n{text}"
    );

    fs::remove_dir_all(&dir).ok();
}
