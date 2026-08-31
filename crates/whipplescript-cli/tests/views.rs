//! DR-0083 Decision 4: a view's derived fact supersedes its predecessor, keyed
//! by firing identity, while the commit log appends.
//!
//! The control matters as much as the assertion. The same program spelled
//! `rule` instead of `view` must keep every derivation live — that is what
//! makes this a test of supersede rather than a test that the program runs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A view whose count moves 1 -> 2 -> 3, driven by a rule that adds a `Ticket`
/// whenever the count is still low.
const PROGRAM: &str = r#"workflow ViewSupersede

output result Done

class Done {
  n int
}

class Queue {
  name string
}

class Ticket {
  n int
}

class QueueBacklog {
  queue string
  open int
}

rule seed
  when started
=> {
  record Queue {
    name "payments"
  }
  record Ticket {
    n 1
  }
}

view backlog
  when Queue as q
=> {
  record QueueBacklog {
    queue q.name
    open count(Ticket where n > 0)
  }
}

rule add_more
  when QueueBacklog as b where b.open < 3
=> {
  record Ticket {
    n b.open + 1
  }
}

rule finish
  when QueueBacklog as b where b.open >= 3
=> {
  complete result {
    n b.open
  }
}
"#;

fn temp_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("whip-views-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run a program and return its reported status with its live `QueueBacklog`
/// facts. The status is returned rather than asserted because the `rule`
/// controls below deliberately do NOT complete: under DR-0083 a rule evaluates
/// its body once, so a program that depended on re-derivation now goes idle,
/// and that is the behaviour being pinned.
fn run_and_read(dir: &Path, source: &str) -> (String, Vec<String>) {
    let program = dir.join("program.whip");
    fs::write(&program, source).expect("write program");

    let run = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(["run", program.to_str().expect("path")])
        .current_dir(dir)
        .output()
        .expect("spawn whip run");
    let status = String::from_utf8_lossy(&run.stdout).into_owned();

    let instances = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(["instances"])
        .current_dir(dir)
        .output()
        .expect("list instances");
    let listing = String::from_utf8_lossy(&instances.stdout).into_owned();
    let instance = listing
        .split_whitespace()
        .find(|word| word.starts_with("ins_"))
        .unwrap_or_else(|| panic!("no instance in:\n{listing}"))
        .to_owned();

    let facts = Command::new(env!("CARGO_BIN_EXE_whip"))
        .args(["facts", &instance])
        .current_dir(dir)
        .output()
        .expect("read facts");
    let live = String::from_utf8_lossy(&facts.stdout)
        .lines()
        .filter(|line| line.contains("QueueBacklog"))
        .map(str::to_owned)
        .collect();
    (status, live)
}

#[test]
fn a_view_supersedes_its_previous_derivation() {
    let dir = temp_dir("supersede");
    let (status, live) = run_and_read(&dir, PROGRAM);

    assert!(
        status.contains("status completed"),
        "the view tracks its set, so the program reaches its terminal:\n{status}"
    );

    assert_eq!(
        live.len(),
        1,
        "a view holds ONE current value per firing; found:\n{}",
        live.join("\n")
    );
    assert!(
        live[0].contains("\"open\":3"),
        "the surviving derivation must be the latest, not the first:\n{}",
        live[0]
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_same_program_as_a_rule_evaluates_once_and_does_not_track() {
    let dir = temp_dir("control");
    // The control that makes the test above mean something, and the semantic
    // flip stated as a test rather than left as a surprise. Only the keyword
    // differs. A rule evaluates its body ONCE and closes, so it derives from
    // the set as it stood and never tracks it again — which means this program,
    // written against the old re-deriving behaviour, no longer reaches its
    // terminal.
    let (status, live) = run_and_read(
        &dir,
        &PROGRAM.replace("\nview backlog\n", "\nrule backlog\n"),
    );

    assert_eq!(
        live.len(),
        1,
        "a rule evaluates once, so it holds exactly what it derived; found:\n{}",
        live.join("\n")
    );
    assert!(
        live[0].contains("\"open\":1"),
        "and it holds the value the set had when it fired:\n{}",
        live[0]
    );
    assert!(
        !status.contains("status completed"),
        "a program that depended on re-derivation no longer completes:\n{status}"
    );
    fs::remove_dir_all(&dir).ok();
}

/// DR-0083 Decision 5: a view whose trigger is retracted ends, and its
/// derivation goes with it.
///
/// DR-0043 pins a rule firing to its trigger's values precisely so a consumed
/// trigger cannot strand a continuation. A view has no continuations, so that
/// reason does not reach it: a view is a maintained statement about its
/// subject, and a subject that is gone leaves no statement behind.
const RETRACTION: &str = r#"workflow ViewRetract

output result Done

class Done {
  note string
}

class Queue {
  name string
}

class Ticket {
  n int
}

class QueueBacklog {
  queue string
  open int
}

class Decommissioned {
  queue string
}

rule seed
  when started
=> {
  record Queue {
    name "payments"
  }
  record Ticket {
    n 1
  }
}

view backlog
  when Queue as q
=> {
  record QueueBacklog {
    queue q.name
    open count(Ticket where n > 0)
  }
}

rule decommission
  when Queue as q
  when QueueBacklog as b
=> {
  done q
  record Decommissioned {
    queue q.name
  }
}

rule finish
  when Decommissioned as d
=> {
  complete result {
    note d.queue
  }
}
"#;

#[test]
fn a_view_withdraws_its_derivation_when_its_trigger_is_retracted() {
    let dir = temp_dir("retract");
    let (_status, live) = run_and_read(&dir, RETRACTION);

    assert!(
        live.is_empty(),
        "the view's subject was retracted, so its derivation must go too; found:\n{}",
        live.join("\n")
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_same_retraction_as_a_rule_leaves_the_derivation_standing() {
    let dir = temp_dir("retract-control");
    // The control, and it is the DR-0043 behaviour this decision deliberately
    // departs from: a rule firing is pinned to its trigger's values, so
    // consuming the trigger leaves what it recorded exactly where it was.
    let (_status, live) = run_and_read(
        &dir,
        &RETRACTION.replace("\nview backlog\n", "\nrule backlog\n"),
    );

    assert_eq!(
        live.len(),
        1,
        "a rule is pinned, so its record survives its trigger; found:\n{}",
        live.join("\n")
    );
    fs::remove_dir_all(&dir).ok();
}
