//! The step budget parks an instance; it never truncates one (DR-0082).
//!
//! Static analysis proves that a CYCLE cannot turn forever (DR-0081) and says
//! nothing about how long a workflow runs, because length is data: a fan-out
//! over a stream, a ceiling read from an input, a loop that ends when a person
//! answers. The runtime answer is a window of world crossings after which the
//! instance parks with everything intact, on the precedent of `whip improve`'s
//! spend cap.
//!
//! What this pins is the difference between parking and stopping: a paused
//! instance, a diagnostic that says how to continue, facts still there, and a
//! `whip resume` that actually resumes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// The world-paced agent loop: legal, unbounded by design, and exactly the shape
/// no static analysis will ever bound. Each turn is one world crossing.
const FOREVER: &str = r#"@service
workflow StepBudgetForever

class Ping {
  n int
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

table seeds as Ping [
  { n 0 }
]

rule begin
  when Ping as p
=> {
  tell worker "{{ p.n }}" as turn

  after turn succeeds as x {
    done p -> record Ping {
      n p.n + 1
    }
  }
}
"#;

fn temp_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "whip-step-budget-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn whip(dir: &PathBuf, args: &[&str], budget: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(args)
        .env("WHIPPLESCRIPT_STEP_BUDGET", budget)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|error| panic!("run whip {args:?}: {error}"));
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_spent_step_budget_parks_the_instance_and_resume_continues_it() {
    let dir = temp_dir("parks");
    let program = dir.join("forever.whip");
    fs::write(&program, FOREVER).expect("write program");

    let path = program.to_str().expect("path").to_owned();
    whip(
        &dir,
        &["run", &path, "--max-iterations", "40", "--wait"],
        "2",
    );

    let listing = whip(&dir, &["instances"], "2");
    let instance = listing
        .split_whitespace()
        .find(|word| word.starts_with("ins_"))
        .unwrap_or_else(|| panic!("no instance in `whip instances`:\n{listing}"))
        .to_owned();

    // Parked, not terminal: `paused` is the state the lifecycle already had.
    let status = whip(&dir, &["status", &instance], "2");
    assert!(
        status.contains("paused"),
        "the instance did not park:\n{status}"
    );

    // And it says so, with the way out in the message.
    let diagnostics = whip(&dir, &["diagnostics", &instance], "2");
    assert!(
        diagnostics.contains("instance.step_budget.parked"),
        "the park was silent:\n{diagnostics}"
    );
    assert!(
        diagnostics.contains("whip resume") && diagnostics.contains("WHIPPLESCRIPT_STEP_BUDGET"),
        "the diagnostic must name both ways to continue:\n{diagnostics}"
    );

    // Nothing was truncated: the facts the run produced are still there.
    let facts = whip(&dir, &["facts", &instance], "2");
    assert!(
        facts.contains("Ping"),
        "parking must leave the instance's facts intact:\n{facts}"
    );

    // And resume means resume: the instance runs again rather than re-parking on
    // its next step, because the window is measured from the last resume.
    let resumed = whip(&dir, &["resume", &instance], "2");
    assert!(
        !resumed.contains("cannot transition"),
        "resume was refused:\n{resumed}"
    );
    let after = whip(&dir, &["status", &instance], "2");
    assert!(
        after.contains("running") || after.contains("paused"),
        "the instance is neither running nor parked after resume:\n{after}"
    );

    fs::remove_dir_all(&dir).ok();
}
