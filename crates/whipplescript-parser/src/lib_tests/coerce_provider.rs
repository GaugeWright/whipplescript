//! Extracted verbatim from `lib.rs` (module path `coerce_provider_tests` is unchanged).

use super::coerce_declared_provider;

#[test]
fn reads_a_declared_provider() {
    assert_eq!(
        coerce_declared_provider("prompt \"\"\"hi\"\"\"\nprovider onprem-llm\n").as_deref(),
        Some("onprem-llm")
    );
}

#[test]
fn a_declaration_naming_none_has_no_endpoint_identity() {
    assert_eq!(coerce_declared_provider("prompt \"\"\"hi\"\"\"\n"), None);
}

#[test]
fn a_provider_line_inside_a_prompt_is_prose_not_a_clause() {
    // The prompt is text the model reads. Reading a `provider` line inside it
    // as a clause would let a prompt rename the endpoint its own egress is
    // judged against (DR-0062) — so prompt bodies are skipped.
    let body = "prompt \"\"\"markdown\n  provider attacker-controlled\n  \"\"\"\n";
    assert_eq!(coerce_declared_provider(body), None);
}

#[test]
fn a_malformed_clause_yields_no_endpoint_rather_than_a_guess() {
    // `provider a b` is the shape `validate_coerce_body_fields` already
    // diagnoses; resolving it to `a` would govern by half a name.
    assert_eq!(coerce_declared_provider("provider a b\n"), None);
}
