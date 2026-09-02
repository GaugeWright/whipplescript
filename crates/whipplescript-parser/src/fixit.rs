//! Machine-applicable repairs — the `fixit` half of `spec/error-handling.md`
//! "Suggestions And Fixits".
//!
//! A suggestion is a sentence for a person; a fixit is a patch for a program. An
//! editor may apply one on a keystroke and a `--fix` mode may apply one
//! unattended, so the bar is not "this is probably what they meant" but "the
//! compiler knows the exact bytes to replace and the exact text to put there".
//! The spec's rule is the same one, stated as policy: emit a fixit only when the
//! edit is local and semantics-preserving enough to be safe.
//!
//! ## Why fixits are DERIVED here rather than attached at the emission site
//!
//! There are ninety-seven did-you-mean sites and they all reach the same three
//! helpers ([`crate::suggest_otherwise`], [`crate::suggest_then`],
//! [`crate::suggest_then_keyword`]). None of them holds the source text, and
//! none of them can see whether the diagnostic's primary span is actually ON the
//! misspelled token. Plenty of them are not: `examples/invalid/misspelled-name.whip`
//! draws three carets over whole statements (`record Resolutoin { note "done" }`)
//! while naming the class `Resolution` as the candidate, and a naive "replace
//! the primary span with the candidate" would turn that statement into the bare
//! word `Resolution`. Those wide carets are a span-quality defect the tracker
//! already owns (D2c); the answer here is to DECLINE them, not to guess.
//!
//! So the fixit is decided in ONE place, from the finished diagnostic and the
//! source it came from, and every condition below is a way of asking the text
//! whether the edit is real. A site that cannot satisfy them gets no fixit,
//! which is the safe direction: a fixit that does not fix is worse than none.
//!
//! ## The sentence is built and read back in one place
//!
//! [`did_you_mean`] is the only producer of the "did you mean `x`?" clause and
//! [`suggested_candidate`] is the only reader of it, so the pair is a round
//! trip rather than a scrape of prose that happened to look parseable —
//! `did_you_mean_round_trips_through_every_helper` pins that.

#[cfg(test)]
use crate::FixitEdit;
use crate::{closest_name, Applicability, CompileOutput, Diagnostic, Fixit, SourceSpan};

/// The one place the did-you-mean clause is WRITTEN for a candidate that stands
/// alone at its distance. Every helper that offers a candidate reaches this
/// through [`did_you_mean_of`], so [`suggested_candidate`] can read the
/// candidate back out of a finished diagnostic.
pub(crate) fn did_you_mean(name: &str) -> String {
    format!("did you mean `{name}`?")
}

/// The clause for a candidate a RIVAL matches exactly — a second name the
/// closeness policy ranks at the same distance ([`crate::closest_rivals`]).
///
/// Both are named, because that is the honest sentence: the compiler has two
/// answers and no way to choose between them, and printing the alphabetically
/// first alone would present a tie-break as a finding. The reader can tell them
/// apart; that is what the reader is for. A machine reading the same clause gets
/// [`Applicability::Likely`] out of it, which is the other half — see
/// [`fixits_for`].
fn did_you_mean_either(name: &str, rival: &str) -> String {
    format!("did you mean `{name}` or `{rival}`?")
}

/// The did-you-mean clause for whatever [`crate::closest_rivals`] returned — the
/// ONE entry point the three suggestion helpers use, so the clause and its
/// reader stay a round trip across both forms.
pub(crate) fn did_you_mean_of(name: &str, rival: Option<&str>) -> String {
    match rival {
        Some(rival) => did_you_mean_either(name, rival),
        None => did_you_mean(name),
    }
}

/// The candidate named by a suggestion that opens with the did-you-mean clause,
/// paired with the RIVAL when the clause names one; `None` for a suggestion that
/// offers no candidate at all.
///
/// Anchored at the start on purpose: every producer puts the clause first and
/// appends its fallback after it, so a backtick pair found anywhere else in the
/// sentence is prose (`` `whip package sync` ``, a field list, a code sample)
/// and must not be mistaken for a replacement. Anchored at the END too — the
/// clause must close with `?` immediately, or `` ` or ` `` and a second name —
/// so that a fallback which merely STARTS with a backticked name cannot be read
/// as one.
///
/// The sentence is what carries the rival from the closeness policy to the
/// fixit, and nothing in between has to know about it. That is deliberate: a
/// sentence that lost its rival would be a wrong sentence long before it was a
/// wrong applicability, so the reader and the machine fail together or not at
/// all.
pub(crate) fn suggested_candidate(suggestion: &str) -> Option<(&str, Option<&str>)> {
    let rest = suggestion.strip_prefix("did you mean `")?;
    let (name, rest) = rest.split_once('`')?;
    if let Some(rest) = rest.strip_prefix(" or `") {
        return rest.split_once("`?").map(|(rival, _)| (name, Some(rival)));
    }
    rest.starts_with('?').then_some((name, None))
}

/// A bare name: identifier characters, with at most one leading `@` for the tag
/// and annotation vocabularies.
///
/// Deliberately excludes `.`, whitespace and every other separator, which is
/// what keeps a dotted field path (`issue.prioirty`), a two-word clause head
/// (`partition by`) and a whole clause out of the fixit population — replacing
/// any of those wholesale with a bare candidate produces a different program.
fn bare_name(text: &str) -> Option<(bool, &str)> {
    let (annotated, body) = match text.strip_prefix('@') {
        Some(body) => (true, body),
        None => (false, text),
    };
    if body.is_empty() || !body.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some((annotated, body))
}

/// Whether `span` covers a WHOLE token rather than a slice of a longer one.
///
/// Without this, a span that happens to land on the tail of an identifier would
/// pass every other check and produce an edit that splices the candidate into
/// the middle of a name.
///
/// The caller has already read `source[span]`, which proves both offsets are in
/// bounds and on character boundaries, so the two neighbours are plain slices
/// rather than a second round of bounds checking: ONE guard answers "can the
/// source speak for this span at all", and it is the caller's.
fn span_is_a_whole_token(source: &str, span: SourceSpan) -> bool {
    let name_char = |c: char| c.is_alphanumeric() || c == '_' || c == '@';
    !source[..span.start]
        .chars()
        .next_back()
        .is_some_and(name_char)
        && !source[span.end..].chars().next().is_some_and(name_char)
}

/// Whether `code` sits in a namespace where an edit changes what the program is
/// PERMITTED to do rather than what it means.
///
/// `spec/error-handling.md` "Suggestions And Fixits": "do not suggest granting
/// broader authority unless the diagnostic is explicitly an operator-profile
/// problem" and "do not suggest disabling a safety check". A fixit is the
/// strongest form of suggesting: it is applied by an editor on a keystroke and
/// by a `--fix` with nobody watching, and the spec's one exception — an
/// operator-profile problem — is a judgement about intent that no derivation from
/// the text can make. So the whole of `capability.*` and `security.*` is out,
/// and the reader keeps the sentence, which is the surface where that judgement
/// belongs.
///
/// Written as a predicate over the code rather than as a list of sites, for the
/// same reason the rest of this module is: there are ninety-seven did-you-mean
/// helpers' worth of emission sites and no one of them can be trusted to
/// remember. Nothing in these namespaces reaches a fixit TODAY, which is exactly
/// when a guard is cheap: `capability.not_granted` and
/// `security.script_disabled` are already COVERED codes with suggestions, and a
/// D2c caret narrowing on either would mint an authority edit for free.
fn is_authority_namespace(code: &str) -> bool {
    code.starts_with("capability.") || code.starts_with("security.")
}

/// The fixits `diagnostic` earns against `source`, which is empty for all but
/// the did-you-mean population.
///
/// Every condition is a refusal, and each one has a program behind it:
///
/// 1. the diagnostic must not be an AUTHORITY diagnostic — see
///    [`is_authority_namespace`]; the spec forbids suggesting a grant or the
///    disabling of a safety check, and a fixit is a suggestion applied without
///    anyone reading it;
/// 2. the suggestion must open with the [`did_you_mean`] clause — a fallback
///    like "declare one with `memory pool p { … }`" names a repair the compiler
///    cannot place;
/// 3. the primary span must be readable as a bare name, and so must the
///    candidate — this is what excludes a caret over a whole statement, a dotted
///    field path, and a two-word clause head (`partition by`, whose caret covers
///    only the FIRST word, so replacing it would leave the second behind);
/// 4. both must be annotated (`@tag`) or neither, so `@bonded` is never
///    repaired to a bare `bounded`;
/// 5. the span must cover a whole token, never a slice of a longer name;
/// 6. and the token under the caret must itself be a near miss of the
///    candidate under the SAME closeness policy that produced the suggestion —
///    which is how a diagnostic whose caret is not on the misspelled name
///    (a binding, a clause head, a whole statement) declines the fixit without
///    anyone having to enumerate those sites.
///
/// Condition 6 uses the open ([`closest_name`]) budget rather than the closed
/// one. The suggestion's existence already proves the producing site's own
/// policy accepted the pair, so this is not re-deciding the suggestion; it is
/// asking whether the caret is on the token the suggestion is about, and the
/// open budget is the one that admits the case-only near miss (`Priority` for
/// `priority`) a closed budget refuses by design.
///
/// THE RUNG IS NOT A CONSTANT. `Applicability::Exact` is the compiler's claim
/// that it KNOWS the edit. When the clause names a rival — a second candidate
/// the closeness policy ranked at the same distance ([`crate::closest_rivals`])
/// — the compiler knows no such thing: it broke a tie alphabetically, which is
/// the right answer for a sentence a person judges and a coin flip for a patch a
/// `--fix` commits. `xode` is one edit from both `mode` and `node`. So a rival
/// makes the fixit `Likely`, and the fixit is still WORTH emitting: the rung is
/// exactly the vocabulary for "this is probably right", an editor offers it
/// without marking it preferred, and an unattended applier is told, in the one
/// field it reads, not to take it.
pub(crate) fn fixits_for(diagnostic: &Diagnostic, source: &str) -> Vec<Fixit> {
    if is_authority_namespace(diagnostic.code.as_str()) {
        return Vec::new();
    }
    let Some(suggestion) = diagnostic.suggestion.as_deref() else {
        return Vec::new();
    };
    let Some((candidate, rival)) = suggested_candidate(suggestion) else {
        return Vec::new();
    };
    let Some(written) = source.get(diagnostic.span.start..diagnostic.span.end) else {
        return Vec::new();
    };
    let (Some((written_at, _)), Some((candidate_at, _))) =
        (bare_name(written), bare_name(candidate))
    else {
        return Vec::new();
    };
    if written_at != candidate_at || !span_is_a_whole_token(source, diagnostic.span) {
        return Vec::new();
    }
    if closest_name(written, [candidate]).as_deref() != Some(candidate) {
        return Vec::new();
    }
    vec![Fixit::replace(
        format!("replace `{written}` with `{candidate}`"),
        diagnostic.span,
        candidate,
        // `Exact` says the compiler knows the whole edit: these bytes, that
        // name, nothing else moves.
        // `fixits_repair_the_program_over_the_example_corpus` and its CLI
        // counterpart are what keep it honest — they apply every one of these
        // and recompile.
        if rival.is_some() {
            Applicability::Likely
        } else {
            Applicability::Exact
        },
    )]
}

/// Fill in [`Diagnostic::fixits`] across both channels of a finished compile.
///
/// The single writer, called from `compile_program_with_root` where the source
/// is still in hand. Attaching here rather than at the emission sites means a
/// new did-you-mean site gets a fixit for free and cannot get a wrong one.
pub(crate) fn attach_fixits(output: &mut CompileOutput, source: &str) {
    for diagnostic in output.diagnostics.iter_mut().chain(&mut output.warnings) {
        diagnostic.fixits = fixits_for(diagnostic, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{diagnostic_code, suggest_then, DiagnosticCode};

    /// Build the diagnostic shape this module reads: a code, a caret and a
    /// suggestion.
    ///
    /// The code matters for exactly one condition — the authority namespaces,
    /// which are refused outright — and for nothing else: every other condition
    /// is earned by what the TEXT says, not by which check spoke.
    fn coded_diagnostic(
        code: DiagnosticCode,
        span: (usize, usize),
        suggestion: &str,
    ) -> Diagnostic {
        Diagnostic::error(
            code,
            SourceSpan {
                start: span.0,
                end: span.1,
            },
            "unknown field",
        )
        .with_suggestion(suggestion)
    }

    fn diagnostic(span: (usize, usize), suggestion: &str) -> Diagnostic {
        coded_diagnostic(diagnostic_code!("type.unknown_field"), span, suggestion)
    }

    fn only_fixit(source: &str, span: (usize, usize), suggestion: &str) -> Option<Fixit> {
        let mut fixits = fixits_for(&diagnostic(span, suggestion), source);
        assert!(fixits.len() <= 1, "{fixits:?}");
        fixits.pop()
    }

    /// The population: the caret is exactly the misspelled name, so the edit is
    /// exactly the caret.
    #[test]
    fn a_caret_on_the_misspelled_name_earns_an_exact_replacement() {
        let source = "  compaction summarise\n";
        let fixit = only_fixit(source, (13, 22), &did_you_mean("summarize"))
            .expect("a caret on the name earns a fixit");
        assert_eq!(fixit.applicability, Applicability::Exact);
        assert_eq!(fixit.title, "replace `summarise` with `summarize`");
        assert_eq!(
            fixit.apply_to(source).as_deref(),
            Some("  compaction summarize\n")
        );
    }

    /// A CANDIDATE THAT ONLY SORTED FIRST IS NOT A FACT. `xode` is one edit from
    /// both `mode` and `node`; the closeness policy breaks that tie
    /// alphabetically, which is the right answer for a sentence a person reads
    /// and a coin flip for a patch a `--fix` commits without one. So the clause
    /// names both, and the rung drops to `likely`.
    ///
    /// Driven through `suggest_then` rather than a hand-written clause on
    /// purpose: the tie is detected in `closest_rivals`, written by
    /// `did_you_mean_of`, and read back by `suggested_candidate`, and this is the
    /// one test that walks the whole trip. A hand-written sentence would prove
    /// only that the reader can parse a form nothing produces.
    #[test]
    fn a_tied_candidate_is_named_in_the_clause_and_is_only_likely() {
        let suggestion = suggest_then("xode", ["mode", "node"], "pick a mode");
        assert_eq!(suggestion, "did you mean `mode` or `node`? pick a mode");
        let source = "  strategy xode
";
        let fixit = only_fixit(source, (11, 15), &suggestion)
            .expect("a tie is still worth offering; it is just not `exact`");
        assert_eq!(
            fixit.applicability,
            Applicability::Likely,
            "`exact` must mean the compiler knows the edit, not that it guessed consistently"
        );
        // The edit itself is unchanged — the deterministic winner is still the
        // one offered, so an editor shows a repair and only the trust level
        // moved.
        assert_eq!(fixit.title, "replace `xode` with `mode`");
        assert_eq!(
            fixit.apply_to(source).as_deref(),
            Some(
                "  strategy mode
"
            )
        );

        // The control: take the rival out of the universe and the SAME target,
        // caret and helper produce `exact`. Nothing but the tie moved.
        let alone = suggest_then("xode", ["mode"], "pick a mode");
        assert_eq!(alone, "did you mean `mode`? pick a mode");
        assert_eq!(
            only_fixit(source, (11, 15), &alone)
                .expect("an unrivalled candidate earns a fixit")
                .applicability,
            Applicability::Exact
        );

        // A DUPLICATED UNIVERSE IS NOT A TIE. Sites assemble candidates from
        // several tables and hand over what they collected, duplicates and all.
        // Found in the corpus, not imagined: `WorkItem` reaches
        // `type.unknown_schema` twice, and reading the second copy as a rival
        // printed "did you mean `WorkItem` or `WorkItem`?" and demoted a fixit
        // the compiler did know.
        let doubled = suggest_then("xode", ["mode", "mode"], "pick a mode");
        assert_eq!(doubled, alone);
        assert_eq!(
            only_fixit(source, (11, 15), &doubled)
                .expect("a duplicated candidate still earns a fixit")
                .applicability,
            Applicability::Exact,
            "the same name twice is one candidate, not two"
        );
    }

    /// THE AUTHORITY REFUSAL. `spec/error-handling.md` "Suggestions And Fixits":
    /// do not suggest granting broader authority, and do not suggest disabling a
    /// safety check. A fixit is the strongest form of suggesting — nobody reads
    /// it before it is applied — so no diagnostic in `capability.*` or
    /// `security.*` earns one, whatever its text says.
    ///
    /// Nothing in those namespaces reaches this today. That is the reason to
    /// write the guard now: the population is small, the two namespaces already
    /// carry COVERED codes with did-you-mean-shaped suggestions, and a caret
    /// narrowing anywhere in them would otherwise mint an authority edit for
    /// free.
    #[test]
    fn an_authority_diagnostic_earns_no_fixit() {
        let source = "  vault secretz
";
        let clause = did_you_mean("secrets");
        // The control FIRST, so the refusal below is known to be the only thing
        // declining these: identical source, identical caret, identical clause.
        assert!(
            !fixits_for(&diagnostic((8, 15), &clause), source).is_empty(),
            "the shape itself earns a fixit outside the authority namespaces"
        );
        for code in [
            diagnostic_code!("capability.not_granted"),
            diagnostic_code!("security.script_disabled"),
        ] {
            assert_eq!(
                fixits_for(&coded_diagnostic(code, (8, 15), &clause), source),
                Vec::new(),
                "`{}` may not be repaired by a machine",
                code.as_str()
            );
        }
    }

    /// A suggestion that offers no candidate is advice, not an edit. This is the
    /// majority of the ninety-seven sites at any given compile: the candidate
    /// half of the sentence is only there when a name is close enough.
    #[test]
    fn a_suggestion_without_a_candidate_earns_nothing() {
        let source = "  compaction summarise\n";
        assert_eq!(
            fixits_for(
                &diagnostic((13, 22), "supported strategies are `summarize` and `none`"),
                source
            ),
            Vec::new(),
            "a fallback's backticked prose is not a replacement"
        );
        // The clause is recognised only where its producer puts it, at the
        // START. A hand-written sentence that happens to quote a name and then
        // ask a question has the same characters in it and means something else
        // entirely.
        assert_eq!(
            fixits_for(
                &diagnostic((13, 22), "was `summarize`? check the manifest"),
                source
            ),
            Vec::new(),
            "a backtick pair mid-sentence is prose, not a candidate"
        );
    }

    /// THE REFUSAL THIS MODULE EXISTS FOR. The caret covers a whole statement
    /// while the candidate is one name inside it, which is the shape three of
    /// `examples/invalid/misspelled-name.whip`'s diagnostics have. Replacing the
    /// caret would delete the statement.
    #[test]
    fn a_caret_wider_than_the_name_earns_nothing() {
        let source = "  record Resolutoin { note \"done\" }\n";
        assert_eq!(
            only_fixit(source, (2, 34), &did_you_mean("Resolution")),
            None
        );
        // The dotted path, which `spec/error-handling.md` prints as its
        // rendering example: `priority` for the whole of `issue.prioirty` would
        // delete the binding.
        let path = "  when Issue as issue where issue.prioirty == 1\n";
        assert_eq!(only_fixit(path, (28, 42), &did_you_mean("priority")), None);
    }

    /// A multi-word candidate against a single-word caret: the declaration-block
    /// clause heads (`partition by`) suggest a phrase, and the caret is on the
    /// FIRST word only, so the edit would leave the second word behind.
    #[test]
    fn a_multi_word_candidate_earns_nothing() {
        let source = "  partiton by tenant\n";
        assert_eq!(
            only_fixit(source, (2, 10), &did_you_mean("partition by")),
            None
        );
    }

    /// The caret is on a name, and the candidate is a name, but they are not the
    /// same mistake — the caret is on the BINDING while the suggestion is about
    /// the schema. Nothing enumerates such sites; the near-miss test declines
    /// them by asking the text.
    #[test]
    fn a_caret_on_an_unrelated_name_earns_nothing() {
        let source = "  when Incidnt as incident\n";
        assert_eq!(
            only_fixit(source, (7, 14), &did_you_mean("Incident")),
            Some(Fixit::replace(
                "replace `Incidnt` with `Incident`",
                SourceSpan { start: 7, end: 14 },
                "Incident",
                Applicability::Exact,
            ))
        );
        // Same source, caret moved to `when`: a real name, far from the
        // candidate, so no edit.
        assert_eq!(only_fixit(source, (2, 6), &did_you_mean("Incident")), None);
    }

    /// A caret that lands on a SLICE of a longer identifier would splice the
    /// candidate into the middle of a name. The whole-token boundary check is
    /// the only thing standing between that and an edit, since the slice itself
    /// reads as a perfectly good bare name.
    #[test]
    fn a_caret_inside_a_longer_identifier_earns_nothing() {
        // The slice is a genuine near miss of the candidate, so every other
        // condition passes and the boundary check is the only refusal standing
        // between it and an edit that would produce `responder_two`.
        let source = "  tell responderr_two \"go\"\n";
        assert_eq!(
            only_fixit(source, (7, 17), &did_you_mean("responder")),
            None,
            "`responderr` inside `responderr_two` is not a token"
        );
        // Both ends, since the check has two halves: a caret on the TAIL of a
        // longer name is the same defect from the other side.
        let tail = "  tell two_responderr \"go\"\n";
        assert_eq!(
            only_fixit(tail, (11, 21), &did_you_mean("responder")),
            None,
            "`responderr` inside `two_responderr` is not a token"
        );
    }

    /// An annotation and a bare word are different vocabularies, and the pairs
    /// that cross the boundary are ONE edit apart — exactly the distance the
    /// near-miss test admits — so nothing but this check stands between them and
    /// an edit that drops or invents the `@`.
    #[test]
    fn an_annotation_is_never_repaired_to_a_bare_word() {
        let annotated = "  @bounded\n";
        assert_eq!(
            only_fixit(annotated, (2, 10), &did_you_mean("bounded")),
            None,
            "dropping the sigil is not a spelling repair"
        );
        let bare = "  bounded\n";
        assert_eq!(
            only_fixit(bare, (2, 9), &did_you_mean("@bounded")),
            None,
            "inventing a sigil is not a spelling repair"
        );
    }

    /// A caret that spans a SEPARATOR is not on a name, even when the text under
    /// it is one edit from the candidate. The field-path shape is the one that
    /// matters: `priorit.y` reaches `priority` by deleting a dot, and applying
    /// that would fuse two path segments into a single field name.
    #[test]
    fn a_caret_that_spans_a_separator_earns_nothing() {
        let source = "  when Issue as issue where priorit.y == 1\n";
        assert_eq!(
            only_fixit(source, (28, 37), &did_you_mean("priority")),
            None
        );
    }

    /// A span the source cannot answer for — off the end, or off a character
    /// boundary inside a multi-byte character — is not an edit site.
    #[test]
    fn an_unreadable_span_earns_nothing() {
        // No trailing newline, so a span clamped to the end of the source would
        // land exactly on the misspelled name and produce a fixit from a span
        // the diagnostic never had.
        let source = "  compaction summarise";
        assert_eq!(
            only_fixit(source, (13, 900), &did_you_mean("summarize")),
            None
        );
        // Byte 15 is inside the `é` that starts at byte 14, so the slice is not
        // a string and the source cannot answer for the span at all.
        let wide = "  compaction résumé\n";
        assert_eq!(only_fixit(wide, (13, 15), &did_you_mean("resume")), None);
    }

    /// `apply_to` is the one applier, so its edge cases are pinned here rather
    /// than rediscovered by each consumer.
    #[test]
    fn apply_to_refuses_what_it_cannot_place() {
        let source = "hello world";
        let good = Fixit::replace(
            "t",
            SourceSpan { start: 6, end: 11 },
            "there",
            Applicability::Exact,
        );
        assert_eq!(good.apply_to(source).as_deref(), Some("hello there"));
        let past_end = Fixit::replace(
            "t",
            SourceSpan { start: 6, end: 99 },
            "there",
            Applicability::Exact,
        );
        assert_eq!(past_end.apply_to(source), None);
        let overlapping = Fixit {
            title: "t".to_owned(),
            edits: vec![
                FixitEdit {
                    span: SourceSpan { start: 0, end: 6 },
                    replacement: "x".to_owned(),
                },
                FixitEdit {
                    span: SourceSpan { start: 3, end: 9 },
                    replacement: "y".to_owned(),
                },
            ],
            applicability: Applicability::Exact,
        };
        assert_eq!(overlapping.apply_to(source), None);
    }
}
