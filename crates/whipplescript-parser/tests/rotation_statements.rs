//! `rotate` and `revoke` as workflow statements (DR-0053 §12 Amendment).
//!
//! The amendment is explicit that rotation STAYS a workflow — rule-matchable,
//! resumable, auditable, dry-runnable describes orchestration, not a verb — and
//! that only one indivisible step joins the protocol: a successor under the
//! same entry, both valid. These tests pin the surface that makes the
//! orchestration writable, and the two refusals that keep it honest.

use whipplescript_parser::compile_program;

fn program(body: &str) -> String {
    format!(
        "@service\nworkflow W\n\nuse std.custody\nuse std.ingress\n\ncredential deploy_key {{ kind ed25519  allow [sign] }}\n\nsignal s.x {{ a string }}\n\noutput result R\nclass R {{ v string }}\n\nrule r\n  when s.x as e\n=> {{\n{body}}}\n"
    )
}

fn errors(body: &str) -> Vec<String> {
    compile_program(&program(body))
        .diagnostics
        .into_iter()
        .map(|d| match d.suggestion {
            Some(help) => format!("{} | {help}", d.message),
            None => d.message,
        })
        .collect()
}

#[test]
fn a_rotation_and_its_revocation_compile_as_one_workflow() {
    // The shape §12 sketches: rotate, then end the overlap once the workflow's
    // own half is done. The `after … succeeds` arm is what makes the overlap a
    // window the author controls rather than a race.
    let found = errors(
        "  rotate deploy_key as successor\n  after successor succeeds {\n    revoke deploy_key\n    record R { v \"done\" }\n  }\n",
    );
    assert!(found.is_empty(), "the rotation shape compiles: {found:#?}");
}

#[test]
fn a_rotation_that_binds_nothing_is_refused() {
    // A rotation returns the version the successor took, and that number is how
    // the workflow's half knows which key it is cutting to. A rotation whose
    // result nobody names cannot be finished.
    let found = errors("  rotate deploy_key\n  record R { v \"done\" }\n");
    assert!(
        found.iter().any(|said| said.contains("names no binding")
            && said.contains("the version the successor took")),
        "{found:#?}"
    );
}

#[test]
fn a_revocation_that_binds_something_is_refused() {
    // Bare on purpose: ending a credential answers nothing a workflow branches
    // on, so a binding would promise a decision the statement cannot inform.
    let found = errors("  revoke deploy_key as ended\n  record R { v \"done\" }\n");
    assert!(
        found.iter().any(|said| said.contains("binds a result")
            && said.contains("nothing a workflow branches on")),
        "{found:#?}"
    );
}

#[test]
fn rotate_and_revoke_are_suggestible_misspellings() {
    // A statement the parser accepts but the keyword table omits can never be
    // suggested back to an author who typo'd it. The in-crate guard test pins
    // the table itself; this pins what an author actually sees.
    let found = errors("  rotat deploy_key as successor\n  record R { v \"done\" }\n");
    assert!(
        found.iter().any(|said| said.contains("rotate")),
        "a misspelled `rotate` is offered the real keyword: {found:#?}"
    );
}
