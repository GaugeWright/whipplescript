//! The inbound-source clauses std.ingress I4 deferred: `path` as an endpoint,
//! `auth <mode> secret <ident>`, and `correlate` (spec/std-ingress.md Surface).
//!
//! They deferred WITH the listener because grammar with nothing to consume it
//! is dead surface. These are the refusals that make the surface honest, and
//! each is checked by the message an author reads rather than by `is_err`.

use whipplescript_parser::compile_program;

fn program(source_block: &str) -> String {
    format!(
        "@service\nworkflow W\n\nuse std.ingress\n\nsignal s.x {{ a string }}\n\noutput result R\nclass R {{ v string }}\n\n{source_block}\n\nrule r\n  when s.x as e\n=> {{\n  complete result {{ v e.a }}\n}}\n"
    )
}

fn errors(source_block: &str) -> Vec<String> {
    compile_program(&program(source_block))
        .diagnostics
        .into_iter()
        // Message AND suggestion: the field list an author needs lives in the
        // suggestion, and a test that read only the message would pass while
        // the help went missing.
        .map(|d| match d.suggestion {
            Some(help) => format!("{} | {help}", d.message),
            None => d.message,
        })
        .collect()
}

fn only_error(source_block: &str) -> String {
    let errors = errors(source_block);
    assert_eq!(
        errors.len(),
        1,
        "expected exactly one diagnostic, got {errors:#?}"
    );
    errors.into_iter().next().expect("one")
}

const INBOUND: &str = r#"source http as inb {
  path "/hooks/github"
  auth hmac secret github_webhook
  correlate observation.body.instance
  dedup observation.delivery
  observe as observation
  emit s.x { a observation.path }
}"#;

#[test]
fn an_inbound_source_declares_an_endpoint_its_auth_and_its_correlation() {
    let found = errors(INBOUND);
    assert!(
        found.is_empty(),
        "the whole inbound clause set compiles: {found:#?}"
    );
}

#[test]
fn an_endpoint_without_auth_is_refused_at_the_declaration() {
    // Fail-closed by CONSTRUCTION: there is no unauthenticated mode to omit
    // `auth` into, so the refusal is here rather than at the first forged
    // delivery.
    let said = only_error(
        r#"source http as inb {
  path "/hooks/github"
  observe as observation
  emit s.x { a observation.path }
}"#,
    );
    assert!(said.contains("declares no `auth`"), "{said}");
    assert!(
        said.contains("could inject its signal"),
        "the refusal says what is at stake: {said}"
    );
}

#[test]
fn a_secret_literal_in_a_source_is_refused() {
    // event-ingress.md Non-Goals: no source-level secret literals. The parse is
    // the only place this refusal is cheap -- afterwards the secret is already
    // in the file, and in the repository.
    let said = only_error(
        r#"source http as inb {
  path "/hooks/github"
  auth hmac secret "sk-live-not-a-real-key"
  observe as observation
  emit s.x { a observation.path }
}"#,
    );
    assert!(said.contains("may not carry a secret literal"), "{said}");
}

#[test]
fn a_source_is_inbound_or_outbound_but_not_both() {
    let said = only_error(
        r#"source http as both {
  url "https://example.com/feed.json"
  path "/hooks/github"
  auth bearer secret tok
  observe as observation
  emit s.x { a observation.path }
}"#,
    );
    assert!(said.contains("both `url` and `path`"), "{said}");
    assert!(said.contains("polling and listening"), "{said}");
}

#[test]
fn auth_without_an_endpoint_has_no_delivery_to_authenticate() {
    let said = only_error(
        r#"source http as poll {
  url "https://example.com/feed.json"
  auth bearer secret tok
  observe as observation
  emit s.x { a observation.url }
}"#,
    );
    assert!(said.contains("serves no endpoint"), "{said}");
}

#[test]
fn correlate_without_an_endpoint_is_refused() {
    // A polling source already knows which instance it runs for, so a
    // correlation clause there names a question nobody asked.
    let said = only_error(
        r#"source http as poll {
  url "https://example.com/feed.json"
  correlate observation.item
  observe as observation
  emit s.x { a observation.url }
}"#,
    );
    assert!(said.contains("serves no endpoint"), "{said}");
    assert!(said.contains("already knows which instance"), "{said}");
}

#[test]
fn an_unknown_auth_mode_is_refused_by_name() {
    let said = only_error(
        r#"source http as inb {
  path "/hooks/github"
  auth basic secret tok
  observe as observation
  emit s.x { a observation.path }
}"#,
    );
    assert!(said.contains("unknown auth mode `basic`"), "{said}");
}

#[test]
fn an_http_source_that_neither_polls_nor_serves_is_refused() {
    let said = only_error(
        r#"source http as neither {
  observe as observation
  emit s.x { a observation.url }
}"#,
    );
    assert!(
        said.contains("neither `url` nor `path`"),
        "the refusal names both directions: {said}"
    );
}

#[test]
fn an_inbound_observation_is_the_delivery_rather_than_a_poll() {
    // `item`/`item_index` are the POLLING shape: there is no array for a
    // delivery to be an element of, so reading one is a typo the author wants
    // named rather than a null at runtime.
    let said = only_error(
        r#"source http as inb {
  path "/hooks/github"
  auth hmac secret tok
  observe as observation
  emit s.x { a observation.item }
}"#,
    );
    assert!(said.contains("no field `item`"), "{said}");
    assert!(
        said.contains("body") && said.contains("delivery"),
        "and lists what a delivery does carry: {said}"
    );
}

#[test]
fn correlate_is_anchored_at_an_observation_field() {
    // The body's interior is the SENDER's JSON and cannot be checked here, but
    // which observation field the path starts from can be -- and a typo in the
    // anchor is a correlation that silently never matches.
    let said = only_error(
        r#"source http as inb {
  path "/hooks/github"
  auth hmac secret tok
  correlate somethingelse.instance
  observe as observation
  emit s.x { a observation.path }
}"#,
    );
    assert!(
        said.contains("must name a path off the `observe` binding"),
        "{said}"
    );
}
