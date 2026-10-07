//! The verified-source obligations (DR-0053 §6, amended 2026-09-03 onto the
//! ingress source): `require verified <source>` grounds the label of the
//! signal a source emits on the custodian's verification, and the endorse
//! hatch does not apply to a verified source.

use super::*;

/// The source whose `require verified` grounds signal `<name>`'s label, if the
/// governed envelope demands one (DR-0053 §6, amended 2026-09-03).
///
/// The admission core asks this of every door. A signal one of these sources
/// emits carries a label that attaches on EVIDENCE, so it may become a fact
/// only through a delivery the custodian verified: `whip signal`, the stdio
/// driver, a poller and an `auth` endpoint all assert where it came from and
/// prove nothing, and admitting through any of them would give an asserted
/// delivery the label the envelope reserved for a proven one. Ungoverned or a
/// rejected envelope → `None`, as for [`signal_is_internal_in`].
pub fn signal_requires_verification_in(
    status: &EnvelopeStatus,
    ir: &IrProgram,
    signal_name: &str,
) -> Option<String> {
    let EnvelopeStatus::Verified(verified) = status else {
        return None;
    };
    let demanded = verified.envelope().requires_verified();
    ir.sources
        .iter()
        .find(|source| source.emit_signal == signal_name && demanded.contains(&source.name))
        .map(|source| source.name.clone())
}

/// The verified-source obligations a program owes its envelope (DR-0053 §6).
///
/// Two refusals, both about GROUNDING rather than which way a label moves:
///
/// - **The endorse hatch does not apply to a verified source.** A signature
///   proves origin, not truthfulness: a verified Stripe delivery establishes
///   that Stripe sent it and nothing about whether its contents may drive an
///   `Auditor` sink. An endorse grant over the signal such a source emits, or
///   over the source by name, would assert authority the signature never
///   established — the DR-0051 §3 laundering fault one layer up — so it is a
///   check error rather than a silent no-op. The precedent is the internal
///   signal, which also takes its integrity from its mechanism and gets no hatch.
/// - **`require verified <source>` is demanded, never assumed.** The program
///   must declare that source `verified with`, and every OTHER source emitting
///   the same signal must be verified too: one asserted door into a signal is
///   enough to make every fact of it an assertion.
///
/// A demand naming a source the program does not declare binds nothing here —
/// a policy may govern several programs — and the admission core still refuses
/// the demanded source's signal through any unverified door of a program that
/// does declare it.
pub fn check_verified_sources(ir: &IrProgram, envelope: &Envelope) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let verified: Vec<&whipplescript_parser::IrSource> = ir
        .sources
        .iter()
        .filter(|source| source.verified_credential.is_some())
        .collect();
    for (resource, role) in &envelope.endorse {
        let target = envelope.resolve(resource);
        let Some(source) = verified.iter().find(|source| {
            source.name == *resource
                || source.name == target
                || target == format!("signal:{}", source.emit_signal)
                || *resource == source.emit_signal
        }) else {
            continue;
        };
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("security.endorse_over_verified_source"),
            severity: Severity::Error,
            span: source.span,
            message: format!(
                "the envelope grants `endorse {resource} to {role}`, but `{resource}` is what the \
                 verified source `{}` delivers: a signature proves who sent a delivery, not that \
                 its contents may be trusted, so the endorse hatch does not apply to a verified \
                 source (DR-0053 §6)",
                source.name
            ),
            suggestion: whipplescript_parser::suggest(format!(
                "remove the endorse grant, and give `signal:{}` its integrity with a `from <Role>` \
                 label on its grant — which `require verified {}` then grounds on the signature",
                source.emit_signal, source.name
            )),
            related: Vec::new(),
            fixits: Vec::new(),
        });
    }
    for demanded in envelope.requires_verified() {
        let Some(source) = ir.sources.iter().find(|source| source.name == *demanded) else {
            continue;
        };
        for door in ir
            .sources
            .iter()
            .filter(|door| door.emit_signal == source.emit_signal)
            .filter(|door| door.verified_credential.is_none())
        {
            let message = if door.name == source.name {
                format!(
                    "the envelope requires `{demanded}` to be verified, but it is not declared \
                     `verified with <credential>`: the label governance gives `signal:{}` is \
                     reserved for deliveries the custodian proves (DR-0053 §6)",
                    source.emit_signal
                )
            } else {
                format!(
                    "the envelope requires `{demanded}` to be verified, and source `{}` also \
                     emits `{}` without `verified with`: one asserted door into a signal makes \
                     every fact of it an assertion (DR-0053 §6)",
                    door.name, source.emit_signal
                )
            };
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("security.unverified_source"),
                severity: Severity::Error,
                span: door.span,
                message,
                suggestion: whipplescript_parser::suggest(format!(
                    "declare `verified with <credential>` on source `{}` in place of `auth`, \
                     naming a credential the custodian holds",
                    door.name
                )),
                related: Vec::new(),
                fixits: Vec::new(),
            });
        }
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    //! DR-0053 §6, amended 2026-09-03: `verified with <credential>` on an ingress
    //! source, and what it changes about the label of the signal it emits.
    //!
    //! The admission door was built first. These are the check-time halves of the
    //! open tail: the label is GROUNDED on the signature when the envelope demands
    //! it (`require verified <source>`), and the endorse hatch does not apply to a
    //! verified source, because a signature proves origin and not truthfulness.

    use super::super::{check_with_envelope, Envelope, VerifiedEnvelope};

    fn check(program: &str, envelope: &str) -> Vec<(String, String)> {
        let verified = VerifiedEnvelope::verify_text(envelope).expect("envelope verifies");
        let compiled = whipplescript_parser::compile_program(program);
        let ir = compiled.ir.unwrap_or_else(|| {
            panic!(
                "fixture compiles: {:#?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| &d.message)
                    .collect::<Vec<_>>()
            )
        });
        check_with_envelope(&ir, &verified)
            .into_iter()
            .map(|d| (d.code.as_str().to_owned(), d.message))
            .collect()
    }

    fn codes(found: &[(String, String)]) -> Vec<&str> {
        found.iter().map(|(code, _)| code.as_str()).collect()
    }

    const PROGRAM_HEAD: &str = "@service\nworkflow Hooks\n\nuse std.ingress\nuse std.custody\n\ncredential hook_key { kind hmac-sha256 }\n\nsignal github.push { repo string }\n\noutput result R\nclass R { v string }\n\n";

    const RULE: &str = "rule r\n  when github.push as p\n=> {\n  complete result { v p.repo }\n}\n";

    fn verified_source(name: &str, path: &str) -> String {
        format!(
            "source http as {name} {{\n  path \"{path}\"\n  verified with hook_key\n  observe as observation\n  emit github.push {{ repo observation.path }}\n}}\n\n"
        )
    }

    fn auth_source(name: &str, path: &str) -> String {
        format!(
            "source http as {name} {{\n  path \"{path}\"\n  auth hmac secret hook_secret\n  observe as observation\n  emit github.push {{ repo observation.path }}\n}}\n\n"
        )
    }

    fn program(sources: &[String]) -> String {
        format!("{PROGRAM_HEAD}{}{RULE}", sources.concat())
    }

    const LABEL: &str = "grant signal push -> signal:github.push from Operator\n";

    #[test]
    fn a_demanded_verification_is_met_by_a_verified_source() {
        let found = check(
            &program(&[verified_source("pushes", "/hooks/github")]),
            &format!("{LABEL}require verified pushes\n"),
        );
        assert!(
            !codes(&found).contains(&"security.unverified_source"),
            "{found:?}"
        );
    }

    #[test]
    fn a_demanded_verification_refuses_an_auth_source() {
        let found = check(
            &program(&[auth_source("pushes", "/hooks/github")]),
            &format!("{LABEL}require verified pushes\n"),
        );
        let (_, message) = found
            .iter()
            .find(|(code, _)| code == "security.unverified_source")
            .unwrap_or_else(|| panic!("an asserted source cannot meet the demand: {found:?}"));
        assert!(message.contains("`pushes`"), "{message}");
        assert!(message.contains("signal:github.push"), "{message}");
    }

    /// One asserted door into the signal is enough: every fact of it could then be
    /// an assertion, so the label is no longer grounded.
    #[test]
    fn a_second_unverified_door_into_the_same_signal_is_refused() {
        let found = check(
            &program(&[
                verified_source("pushes", "/hooks/github"),
                auth_source("legacy", "/hooks/legacy"),
            ]),
            &format!("{LABEL}require verified pushes\n"),
        );
        let refusals: Vec<&String> = found
            .iter()
            .filter(|(code, _)| code == "security.unverified_source")
            .map(|(_, message)| message)
            .collect();
        assert_eq!(refusals.len(), 1, "{found:?}");
        assert!(
            refusals[0].contains("source `legacy` also emits"),
            "{}",
            refusals[0]
        );
    }

    /// A policy may govern several programs, so a demand for a source this one
    /// does not declare binds nothing here.
    #[test]
    fn a_demand_for_an_undeclared_source_binds_nothing() {
        let found = check(
            &program(&[auth_source("pushes", "/hooks/github")]),
            &format!("{LABEL}require verified elsewhere\n"),
        );
        assert!(
            !codes(&found).contains(&"security.unverified_source"),
            "{found:?}"
        );
    }

    #[test]
    fn the_endorse_hatch_does_not_apply_to_a_verified_source() {
        // Over the signal's handle, which resolves to `signal:github.push` …
        let found = check(
            &program(&[verified_source("pushes", "/hooks/github")]),
            &format!("{LABEL}grant endorse push to Auditor\n"),
        );
        let (_, message) = found
            .iter()
            .find(|(code, _)| code == "security.endorse_over_verified_source")
            .unwrap_or_else(|| {
                panic!("an endorse grant over a verified source is refused: {found:?}")
            });
        assert!(
            message.contains("origin") || message.contains("who sent"),
            "{message}"
        );
        assert!(message.contains("`pushes`"), "{message}");

        // … and over the source by name.
        let found = check(
            &program(&[verified_source("pushes", "/hooks/github")]),
            &format!("{LABEL}grant endorse pushes to Auditor\n"),
        );
        assert!(
            codes(&found).contains(&"security.endorse_over_verified_source"),
            "{found:?}"
        );
    }

    /// The refusal is about grounding, so it does not reach an `auth` source: that
    /// label was only ever asserted, and the hatch over it is today's path.
    #[test]
    fn the_endorse_hatch_still_applies_to_an_auth_source() {
        let found = check(
            &program(&[auth_source("pushes", "/hooks/github")]),
            &format!("{LABEL}grant endorse push to Auditor\n"),
        );
        assert!(
            !codes(&found).contains(&"security.endorse_over_verified_source"),
            "{found:?}"
        );
    }

    #[test]
    fn require_verified_round_trips_and_refuses_a_malformed_line() {
        let envelope = Envelope::from_dsl("require verified pushes\n").expect("parses");
        assert!(envelope.requires_verified().contains("pushes"));
        let canonical = envelope.to_canonical_json();
        assert!(
            canonical.contains("\"require_verified\":[\"pushes\"]"),
            "{canonical}"
        );
        let reparsed = Envelope::from_json(&canonical).expect("canonical reparses");
        assert_eq!(reparsed.requires_verified(), envelope.requires_verified());

        let quiet = Envelope::from_dsl(LABEL).expect("parses");
        assert!(
            !quiet.to_canonical_json().contains("require_verified"),
            "an envelope that never asked keeps its signed hash"
        );

        let error = Envelope::from_dsl("require verified pushes legacy\n")
            .err()
            .expect("one source per line");
        assert!(error.contains("exactly one source"), "{error}");
        let error = Envelope::from_dsl("require verified push*\n")
            .err()
            .expect("a pattern is not a source");
        assert!(error.contains("line 1"), "{error}");
        let error = Envelope::from_json(r#"{"require_verified": "pushes"}"#)
            .err()
            .expect("not an array");
        assert!(
            error.contains("require_verified must be an array"),
            "{error}"
        );
    }
}
