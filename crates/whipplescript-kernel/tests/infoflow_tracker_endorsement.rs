//! DR-0051: a tracker is a governed resource, and a claim may endorse.
//!
//! Two properties, and the second is only sound because of the first.
//!
//! A tracker is an inbound channel with a durable queue and an external filing
//! surface, so its issues are information-flow sources like any other input.
//! Before this they were invisible to the checker — issue text reached a
//! `from`-labelled sink with no grant and no diagnostic, and *still* did when
//! the tracker was explicitly labelled `from public`.
//!
//! And a person's decision can now cross the integrity axis. Before this the
//! only sanctioned raise was a source-marked `endorsed` coerce — a model call —
//! so a gate whose reviewer is a human could only refuse to admit or declare its
//! verdict unvouched.

use whipplescript_kernel::ifc::{check_with_envelope, VerifiedEnvelope};

fn admit(program: &str, envelope: &str) -> Result<(), String> {
    let verified = VerifiedEnvelope::verify_text(envelope).map_err(|e| format!("envelope: {e}"))?;
    let ir = whipplescript_parser::compile_program(program)
        .ir
        .ok_or_else(|| "does not compile".to_owned())?;
    let d = check_with_envelope(&ir, &verified);
    if d.is_empty() {
        Ok(())
    } else {
        Err(d
            .iter()
            .map(|x| x.message.clone())
            .collect::<Vec<_>>()
            .join("; "))
    }
}

const LAUNDER: &str = r#"use std.tracker

@service
workflow Probe

class Vouched { note string }

tracker inbox

rule take
  when inbox has ready issue as v
=> {
  claim v as hold
  after hold succeeds {
    record Vouched {
      note v.title
    }
  }
}
"#;

#[test]
fn a_tracker_issue_is_an_information_flow_source() {
    let refused = admit(
        LAUNDER,
        "grant fact vouched -> fact:Vouched from Operator\n",
    );
    println!("[ungranted]: {refused:?}");
    assert!(
        refused.is_err(),
        "an ungranted tracker must not shape a vouched fact"
    );

    let refused = admit(LAUNDER, "grant fact vouched -> fact:Vouched from Operator\ngrant tracker inbox -> tracker:/inbox from public\n");
    println!("[public]: {refused:?}");
    assert!(
        refused.is_err(),
        "a public tracker must not shape a vouched fact"
    );

    let ok = admit(LAUNDER, "grant fact vouched -> fact:Vouched from Operator\ngrant tracker inbox -> tracker:/inbox from Operator\n");
    println!("[operator]: {ok:?}");
    assert!(ok.is_ok(), "a vouched tracker may shape a vouched fact");

    let ok = admit(LAUNDER, "grant fact vouched -> fact:Vouched from public\n");
    println!("[public sink]: {ok:?}");
    assert!(ok.is_ok(), "public into public still admits");
}

/// The gate shape: a rule *guarded* by public facts records an Operator-vouched
/// verdict, and what raises it is a person's claim on a vouched queue.
const GATE: &str = r#"use std.files
use std.tracker

@service
workflow Gate

class Screening { disposition "keep" | "flag" }
class Pending { request string }

tracker verdicts

table pendings as Pending [ { request "x" } ]

rule settle
  when Pending as p
  when verdicts has ready issue as v where v.body == p.request
=> {
  claim v as hold endorsed
  after hold succeeds {
    record Screening {
      disposition v.title
    }
  }
}
"#;

const GRANTS: &str = "grant fact pending -> fact:Pending from public\n\
grant fact screening -> fact:Screening from Operator\n";

#[test]
fn a_claim_on_a_vouched_queue_is_an_endorsement_crossing() {
    // Unmarked: the guard influence denies, exactly as before this DR.
    let refused = admit(
        GATE.replace(" endorsed", "").as_str(),
        &format!("{GRANTS}grant tracker verdicts -> tracker:/verdicts from Operator\n"),
    );
    println!("[unmarked]: {refused:?}");
    assert!(
        refused.is_err(),
        "without a marked crossing the guard influence stands"
    );

    // Marked but the tracker is unvouched: the self-endorsement hole, refused.
    let refused = admit(
        GATE,
        &format!("{GRANTS}grant endorse pending to Operator\n"),
    );
    println!("[unvouched tracker]: {refused:?}");
    let message = refused.expect_err("an unvouched queue may not endorse");
    assert!(
        message.contains("which nobody vouches"),
        "refused for the right reason: {message}"
    );

    // Marked, vouched tracker, and the grant naming what is raised.
    let ok = admit(GATE, &format!("{GRANTS}grant tracker verdicts -> tracker:/verdicts from Operator\ngrant endorse pending to Operator\n"));
    println!("[vouched + grant]: {ok:?}");
    assert!(
        ok.is_ok(),
        "a person's claim on a vouched queue is the crossing"
    );

    // A grant alone never vouches a raw influence: drop the marker, keep both grants.
    let refused = admit(GATE.replace(" endorsed", "").as_str(), &format!("{GRANTS}grant tracker verdicts -> tracker:/verdicts from Operator\ngrant endorse pending to Operator\n"));
    println!("[grants, no marker]: {refused:?}");
    assert!(
        refused.is_err(),
        "a grant alone never vouches a raw influence"
    );
}

/// DR-0051 §4: only closed fields cross.
///
/// The narrowing constrains *what a decision may be*, not what the item may
/// contain. It binds a fully honest endorser: a reviewer who quotes a hostile
/// item into a free-text verdict has done their job and has also relayed
/// attacker text into a fact labelled Operator-vouched.
#[test]
fn an_endorsement_may_only_shape_a_field_that_cannot_hold_prose() {
    let gate = |verdict_field: &str| {
        format!(
            r#"use std.tracker

@service
workflow Gate

class Screening {{ {verdict_field} }}
class Pending {{ request string }}

tracker verdicts

table pendings as Pending [ {{ request "x" }} ]

rule settle
  when Pending as p
  when verdicts has ready issue as v where v.body == p.request
=> {{
  claim v as hold endorsed
  after hold succeeds {{
    record Screening {{
      disposition v.title
    }}
  }}
}}
"#
        )
    };
    let envelope = "grant fact pending -> fact:Pending from public\n\
grant fact screening -> fact:Screening from Operator\n\
grant tracker verdicts -> tracker:/verdicts from Operator\n\
grant endorse pending to Operator\n";

    // A closed union: the verdict is a decision.
    let ok = admit(&gate(r#"disposition "keep" | "flag""#), envelope);
    println!("[closed union]: {ok:?}");
    assert!(ok.is_ok(), "a closed union is a decision");

    // A bare string: unbounded, so whatever the endorser quoted crosses too.
    let refused = admit(&gate("disposition string"), envelope);
    println!("[bare string]: {refused:?}");
    let message = refused.expect_err("a free-text verdict may not be endorsed");
    assert!(
        message.contains("can carry prose"),
        "refused for the right reason: {message}"
    );

    // One bare arm reopens a union — the case a variant-count check would miss.
    let refused = admit(&gate(r#"disposition "keep" | string"#), envelope);
    println!("[reopened union]: {refused:?}");
    assert!(refused.is_err(), "one bare arm reopens the union");

    // A number cannot instruct a downstream reader, so it is not prose.
    let ok = admit(&gate("disposition int"), envelope);
    println!("[int]: {ok:?}");
    assert!(ok.is_ok(), "a bounded non-string value is not prose");
}
