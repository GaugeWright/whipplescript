//! Reading an `.ir` snapshot back into structure, and projecting one down to
//! the bytes a program's identity is computed over.
//!
//! [`IrProgram::to_snapshot`](crate::IrProgram::to_snapshot) writes this format;
//! this module reads it. The two directions live in one crate on purpose. The
//! snapshot became durable state when a program version started storing it under
//! its own `ir_hash` (the instance view-model note, G1), so it now has readers
//! that never compiled the program and cannot recover the structure any other
//! way — a hosted instance, a historical one, one revised twice.
//!
//! Scope is deliberately the structure a reader needs to draw and explain a
//! program: the rules, the effects each one lowers, the dependency edges between
//! those effects, and the rule-to-rule edges. Schemas, agents, coercions and
//! spans are in the snapshot and are not parsed here, because nothing reads them
//! yet and a parser for a field no caller wants is a field that goes wrong
//! quietly. Offsets are also what [`identity_projection`] erases: the durable
//! document a version stores under its `ir_hash` is the projection, so a reader
//! here sees `span=-` where a freshly compiled snapshot carries a byte range.
//! Only the offsets go. A rule's `body_hash` is a digest of the body's raw
//! source text and stays in the projection, so the identity a projection hashes
//! is position-free but not whitespace-free (DR-0095).
//!
//! The parser is deliberately total: an unrecognized line is skipped rather than
//! refused. A snapshot is written by a compiler that may be NEWER than the
//! reader — that is the whole reason `reattest_instance_program` exists — so a
//! reader that failed on an unknown section would turn a supported condition
//! into an error, which is the same mistake G1's first draft made.

use std::borrow::Cow;
use std::collections::BTreeMap;

/// One effect a rule lowers, as the snapshot records it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotEffect {
    /// The snapshot's identifier for the effect within its rule (`turn`,
    /// `effect4`). Stable per program version, and what the dependency edges
    /// name.
    pub id: String,
    pub kind: String,
    /// The author's binding, when the effect has one. `binding=-` in the
    /// snapshot means the effect is unbound — a `release` in a `case` arm — and
    /// reads as `None` here rather than as a literal dash.
    pub binding: Option<String>,
    /// The derived effect key. Static per program version; a firing's actual
    /// effect id is not this.
    pub key: String,
    /// DR-0090: the enclosing `after` arm as `(binding, predicate)`, or `None`
    /// for an effect at the rule's top level.
    ///
    /// This is what makes a continuation effect id recomputable from the stored
    /// snapshot alone. The `dependencies` edge cannot stand in for it: it
    /// records the completion-shaped predicate, so a lease arm reads
    /// `completes` there and `held` here, and only the latter is in the key.
    pub arm: Option<(String, String)>,
}

/// One rule's structure.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotRule {
    pub name: String,
    /// `when` clause texts, in declaration order, guards included.
    pub whens: Vec<String>,
    pub effects: Vec<SnapshotEffect>,
    /// `(upstream_effect_id, predicate, downstream_effect_id)` within this rule.
    pub dependencies: Vec<(String, String, String)>,
}

/// A program's structure, read back from its `.ir` snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotView {
    pub workflow: String,
    pub rules: Vec<SnapshotRule>,
    /// `(producer_rule, fact, consumer_rule)` — the same triples
    /// `build_rule_dependencies` produced, including the resource-mediated edges
    /// DR-0084 added.
    pub rule_dependencies: Vec<(String, String, String)>,
}

impl SnapshotView {
    pub fn rule(&self, name: &str) -> Option<&SnapshotRule> {
        self.rules.iter().find(|rule| rule.name == name)
    }
}

/// Split `a --b--> c`, the snapshot's edge spelling, used by both the per-rule
/// `dependencies` block and the whole-program `rule_dependencies` section.
fn parse_edge(line: &str) -> Option<(String, String, String)> {
    let (left, rest) = line.split_once(" --")?;
    let (label, right) = rest.split_once("--> ")?;
    Some((
        left.trim().to_owned(),
        label.trim().to_owned(),
        right.trim().to_owned(),
    ))
}

/// `turn kind=agent.tell binding=turn key=703a…`
fn parse_effect(line: &str) -> Option<SnapshotEffect> {
    let mut parts = line.split_whitespace();
    let id = parts.next()?.to_owned();
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for part in parts {
        if let Some((name, value)) = part.split_once('=') {
            fields.insert(name, value);
        }
    }
    Some(SnapshotEffect {
        id,
        kind: fields.get("kind")?.to_string(),
        binding: match fields.get("binding") {
            // `-` is the snapshot's spelling for "no binding", not a name.
            Some(&"-") | None => None,
            Some(value) => Some((*value).to_owned()),
        },
        key: fields
            .get("key")
            .map(|k| (*k).to_string())
            .unwrap_or_default(),
        arm: fields.get("arm").and_then(|value| {
            value
                .split_once(':')
                .map(|(binding, predicate)| (binding.to_owned(), predicate.to_owned()))
        }),
    })
}

/// Read an `.ir` snapshot into the structure a reader can draw.
pub fn parse(snapshot: &str) -> SnapshotView {
    let mut view = SnapshotView::default();
    // Sections are top-level (column 0); rules and their sub-blocks are nested
    // by indent, which is how the writer emits them.
    let mut section = "";
    let mut subsection = "";

    for line in snapshot.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();

        if indent == 0 {
            let mut words = trimmed.split_whitespace();
            section = words.next().unwrap_or("");
            subsection = "";
            if section == "workflow" {
                view.workflow = words.next().unwrap_or_default().to_owned();
            }
            continue;
        }

        match section {
            "rules" => {
                if let Some(name) = trimmed.strip_prefix("rule ") {
                    view.rules.push(SnapshotRule {
                        name: name.to_owned(),
                        ..SnapshotRule::default()
                    });
                    subsection = "";
                    continue;
                }
                let Some(rule) = view.rules.last_mut() else {
                    continue;
                };
                // A rule's own lines sit at indent 4; its sub-block entries at 6.
                if indent <= 4 {
                    if let Some(when) = trimmed.strip_prefix("when ") {
                        rule.whens.push(when.to_owned());
                        subsection = "";
                    } else {
                        subsection = trimmed;
                    }
                    continue;
                }
                match subsection {
                    "effects" => {
                        if let Some(effect) = parse_effect(trimmed) {
                            rule.effects.push(effect);
                        }
                    }
                    "dependencies" => {
                        if let Some(edge) = parse_edge(trimmed) {
                            rule.dependencies.push(edge);
                        }
                    }
                    _ => {}
                }
            }
            "rule_dependencies" => {
                if let Some(edge) = parse_edge(trimmed) {
                    view.rule_dependencies.push(edge);
                }
            }
            _ => {}
        }
    }

    view
}

/// The bytes a program version's identity — `ir_hash` — is computed over.
///
/// DR-0095: a source span is *where* something was written, not *what it
/// means*, so it stays in the snapshot (a runtime event is attributed back to
/// source through it, and `examples/*.ir` is a debugging surface) and is erased
/// here. `ir_hash` is `stable_hash_hex(identity_projection(snapshot))`, so a
/// compiler change that only improves a diagnostic span rotates nothing, and
/// `ir_hash` holds under formatting changes outside a rule body.
///
/// Not what it means, and the record says so too: a reformat still mints a
/// program version through `source_hash`, which hashes the source TEXT, and a
/// rule's `body_hash` — which IS in this snapshot — is a digest of the body's
/// raw text, so whitespace inside a rule body still moves the identity.
/// Deliberately: inside a `"""` prompt, indentation is prose a model reads.
///
/// The projection is deliberately TEXTUAL rather than a second rendering of
/// `IrProgram`. Every checker that verifies a report's `ir_hash` holds only the
/// report's `snapshot` string — never the program — so a projection they cannot
/// compute from that string would end the "`ir_hash` matches the embedded
/// snapshot" invariant instead of restating it. Mirrored in
/// `scripts/artifact_admission.py::ir_identity_projection`; extend both
/// together.
///
/// Three markers carry an offset pair, under two conventions. Every span field
/// renders as a trailing `span=<start>..<end>`; a pattern application's
/// `defined-at`/`applied-at` lines predate that convention and are named
/// explicitly. The two word-shaped markers are matched only at the START of a
/// trimmed line — see `erase_trailing_offsets` for the collision that anchoring
/// prevents. Nothing else is touched: an offset pair that is not at the end of
/// its line under a known marker is left alone rather than guessed at.
///
/// A span field added later is therefore erased only if it keeps the trailing
/// spelling. That is a convention, not a guarantee, so it is gated rather than
/// asserted: `no_offset_pair_survives_the_projection_anywhere_in_the_corpus`
/// scans every projection the repository can produce for a surviving
/// `<digits>..<digits>` and names the line that carries one.
pub fn identity_projection(snapshot: &str) -> String {
    snapshot
        .split('\n')
        .map(erase_trailing_offsets)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ir_hash`: the identity of the lowered program.
pub fn identity_hash(snapshot: &str) -> String {
    crate::stable_hash(&identity_projection(snapshot))
}

/// The offset-bearing spellings, each replaced by `-` — the snapshot's own
/// spelling for a field with nothing in it.
const OFFSET_MARKERS: [&str; 3] = ["span=", "defined-at ", "applied-at "];

fn erase_trailing_offsets(line: &str) -> Cow<'_, str> {
    // The two word-shaped markers are ANCHORED to the start of the trimmed
    // line, because that is the only place the snapshot ever renders them:
    // `    defined-at 671..1125`. Matching them anywhere in the line — which
    // this did — lets AUTHOR-CONTROLLED text wear the marker's clothes. A
    // pattern argument is trimmed source (`arg note applied-at 1..2`), so two
    // programs differing only in that value were erased to one line and ALIASED
    // to a single `ir_hash`: distinct programs sharing an identity, and a
    // durable `.ir` blob under that hash describing neither. That is the
    // failure direction this projection must never have — a rotation costs a
    // re-attestation, a collision costs correctness.
    //
    // `span=` keeps its unanchored search: it is a key=value field that appears
    // mid-line by construction (`... guard=- body_hash=… span=671..1125`), and
    // the `=` makes it unspellable as a bare identifier value.
    let trimmed_start = line.len() - line.trim_start().len();
    for marker in OFFSET_MARKERS {
        let anchored = marker.ends_with(' ');
        let index = if anchored {
            if line[trimmed_start..].starts_with(marker) {
                Some(trimmed_start)
            } else {
                None
            }
        } else {
            line.rfind(marker)
        };
        let Some(index) = index else {
            continue;
        };
        let rest = &line[index + marker.len()..];
        let Some((start, end)) = rest.split_once("..") else {
            continue;
        };
        if start.is_empty()
            || end.is_empty()
            || !start.bytes().all(|byte| byte.is_ascii_digit())
            || !end.bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        return Cow::Owned(format!("{}-", &line[..index + marker.len()]));
    }
    Cow::Borrowed(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus below has to reach every offset-bearing spelling, or the
    /// equality test passes on programs that never carried one.
    const IDENTITY_CORPUS: [(&str, &str); 4] = [
        (
            "terminal-output-union",
            include_str!("../../../examples/terminal-output-union.whip"),
        ),
        (
            "expression-kernel",
            include_str!("../../../examples/expression-kernel.whip"),
        ),
        (
            "autoresearch-lite",
            include_str!("../../../examples/autoresearch-lite.whip"),
        ),
        (
            "reusable-review-pattern",
            include_str!("../../../examples/reusable-review-pattern.whip"),
        ),
    ];

    fn snapshot_of(name: &str, source: &str) -> String {
        let compiled = crate::compile_program(source);
        compiled
            .ir
            .unwrap_or_else(|| panic!("{name} compiles: {:?}", compiled.diagnostics))
            .to_snapshot()
    }

    /// DR-0095. A source span is where something was written, not what it
    /// means, so shifting every byte offset in a program must leave `ir_hash`
    /// alone. This FAILS on the compiler before that record: identity was
    /// `stable_hash_hex(snapshot)` and the snapshot renders absolute offsets,
    /// so one blank line above a rule minted a new program version.
    ///
    /// The perturbation is deliberately OUTSIDE every rule body. A rule's
    /// `body_hash` is a digest of its body TEXT — whitespace included, because
    /// a `"""` prompt's indentation is prose a model reads — so a body edit is
    /// a text change and is expected to move identity. What this pins is that
    /// a program's *position* does not.
    #[test]
    fn shifting_every_byte_offset_leaves_a_programs_identity_alone() {
        let mut spellings_seen = (false, false, false);

        for (name, source) in IDENTITY_CORPUS {
            let shifted = format!("# a comment that shifts every offset below it\n\n{source}");

            let original = snapshot_of(name, source);
            let moved = snapshot_of(name, &shifted);

            spellings_seen.0 |= original.contains(" span=");
            spellings_seen.1 |= original.contains("defined-at ");
            spellings_seen.2 |= original.contains("applied-at ");

            assert_ne!(
                original, moved,
                "{name}: the perturbation moved no offset, so this proves nothing"
            );
            assert_eq!(
                identity_hash(&original),
                identity_hash(&moved),
                "{name}: a source position re-entered the identity hash"
            );
            assert!(
                original.contains(" span=") || original.contains("defined-at "),
                "{name} carries no offset at all and does not belong in this corpus"
            );
        }

        assert_eq!(
            spellings_seen,
            (true, true, true),
            "the corpus stopped covering one of the offset spellings \
             (span= / defined-at / applied-at)"
        );
    }

    /// The spans leave the identity hash; they stay in the snapshot, which is
    /// how a runtime event is attributed back to source and what the
    /// `examples/*.ir` goldens are read for.
    #[test]
    fn the_snapshot_still_carries_the_spans_the_identity_drops() {
        let snapshot = snapshot_of("terminal-output-union", IDENTITY_CORPUS[0].1);
        assert!(
            snapshot.contains(" span=575..594"),
            "the snapshot lost its offsets: {snapshot}"
        );
        assert!(
            identity_projection(&snapshot).contains(" span=-"),
            "the projection kept an offset"
        );
        assert!(
            !identity_projection(&snapshot).contains("575..594"),
            "the projection kept an offset"
        );
    }

    /// The converse, and the reason the test above is not satisfied by hashing
    /// a constant: erasing offsets must erase NOTHING ELSE. Each pair below
    /// differs in meaning while sharing most of its text.
    #[test]
    fn a_difference_in_meaning_still_moves_a_programs_identity() {
        let base = IDENTITY_CORPUS[0].1;
        let baseline = identity_hash(&snapshot_of("baseline", base));

        for (what, changed) in [
            // A literal one arm records — same shape, same offsets, different
            // program.
            (
                "a changed literal",
                base.replace("\"completed\"", "\"done\""),
            ),
            // A renamed binding: the arm's `binding=` field moves, and so does
            // the body that reads it.
            (
                "a renamed binding",
                base.replace("as result", "as outcome")
                    .replace("result.summary", "outcome.summary"),
            ),
            // A renamed schema: the recorded fact is a different fact.
            (
                "a renamed schema",
                base.replace("TerminalRoute", "RouteRecord"),
            ),
            // One arm's body, rewritten in place: same arm, same offsets, a
            // different field recorded. This is what `body_hash` is for.
            (
                "a rewritten case arm",
                base.replace("detail cancel.summary", "detail cancel.effect_id"),
            ),
        ] {
            assert_ne!(changed, base, "{what}: the edit did not apply");
            assert_ne!(
                identity_hash(&snapshot_of(what, &changed)),
                baseline,
                "{what} left the program's identity unmoved"
            );
        }
    }

    /// Author-controlled text may WEAR a marker's spelling, and must survive.
    ///
    /// A pattern argument renders trimmed source (`arg note applied-at 1..2`),
    /// so an unanchored search for `applied-at ` erased the argument's VALUE and
    /// aliased two distinct programs onto one `ir_hash` — distinct programs
    /// sharing an identity, with a durable `.ir` blob under that hash describing
    /// neither. No corpus program emits an `arg` line, which is why the
    /// projection's own corpus scan could not see it: that test asks whether an
    /// offset SURVIVES, and this failure is the opposite direction.
    #[test]
    fn author_text_wearing_a_marker_is_not_erased() {
        // The real spellings sit at the start of their trimmed line; these do not.
        for line in [
            "    arg note applied-at 1..2",
            "    arg note defined-at 1..2",
            "    row label span=1..2 applied-at 3..4",
        ] {
            assert_eq!(
                identity_projection(line),
                line,
                "author text was erased as if it were a source position: {line}"
            );
        }
        // ...and the real ones still are, so this does not pass by erasing nothing.
        assert_eq!(
            identity_projection("    applied-at 1..2"),
            "    applied-at -"
        );
    }

    /// The projection is conservative on purpose: it erases an offset pair that
    /// ENDS its line under a known spelling, and leaves everything else alone.
    #[test]
    fn the_projection_erases_offsets_and_nothing_else() {
        assert_eq!(
            identity_projection("      case c Failed binding=f guard=- body_hash=ab span=1..2\n"),
            "      case c Failed binding=f guard=- body_hash=ab span=-\n"
        );
        assert_eq!(
            identity_projection("    defined-at 671..1125\n    applied-at 1127..1195\n"),
            "    defined-at -\n    applied-at -\n"
        );
        // Not an offset pair, and not at the end of its line: left alone.
        assert_eq!(
            identity_projection("  x span=1..2 tail\n  y span=a..b\n  z 1..2\n"),
            "  x span=1..2 tail\n  y span=a..b\n  z 1..2\n"
        );
        // Line structure is preserved exactly, trailing newline included.
        assert_eq!(identity_projection(""), "");
        assert_eq!(identity_projection("a\n"), "a\n");
    }

    /// Every `<digits>..<digits>` in `line`, whatever spelling surrounds it.
    /// Deliberately looser than [`erase_trailing_offsets`]: the point is to
    /// catch an offset the projection did NOT recognize.
    fn offset_pairs(line: &str) -> Vec<&str> {
        let bytes = line.as_bytes();
        let mut pairs = Vec::new();
        let mut index = 0;
        while let Some(found) = line[index..].find("..") {
            let dots = index + found;
            let mut left = dots;
            while left > 0 && bytes[left - 1].is_ascii_digit() {
                left -= 1;
            }
            let mut right = dots + 2;
            while right < bytes.len() && bytes[right].is_ascii_digit() {
                right += 1;
            }
            if left < dots && right > dots + 2 {
                pairs.push(&line[left..right]);
            }
            index = dots + 2;
        }
        pairs
    }

    /// Every `.ir` golden committed under `examples/`, read at test time so the
    /// scan below covers the whole corpus rather than the four programs the
    /// identity tests compile.
    fn committed_ir_goldens() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let mut goldens: Vec<(String, String)> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("examples/ is readable: {error}"))
            .map(|entry| entry.expect("directory entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "ir"))
            .map(|path| {
                let name = path
                    .file_name()
                    .expect("golden has a name")
                    .to_string_lossy()
                    .into_owned();
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{name} is readable: {error}"));
                (name, body)
            })
            .collect();
        goldens.sort();
        goldens
    }

    /// DR-0095 claims a span field added later is excluded from identity "by
    /// construction". That was an assertion, not a gate: `identity_projection`
    /// erases an offset pair only where one of three markers puts it at the end
    /// of its line, so a span rendered any other way would sail straight into
    /// the identity hash and nothing would say so.
    ///
    /// This pins it. Over every projection the repository can produce — the
    /// four compiled corpus programs and all 25 committed `.ir` goldens — no
    /// `<digits>..<digits>` may survive. The scan is proved to bite by first
    /// asserting the UNPROJECTED corpus is full of them, so it cannot pass by
    /// examining offset-free text.
    #[test]
    fn no_offset_pair_survives_the_projection_anywhere_in_the_corpus() {
        let mut documents: Vec<(String, String)> = IDENTITY_CORPUS
            .iter()
            .map(|(name, source)| ((*name).to_owned(), snapshot_of(name, source)))
            .collect();
        let goldens = committed_ir_goldens();
        assert!(
            goldens.len() >= 20,
            "examples/ stopped supplying the golden corpus this scan reads: {} file(s)",
            goldens.len()
        );
        documents.extend(goldens);

        let mut pairs_before = 0usize;
        let mut survivors: Vec<String> = Vec::new();
        for (name, snapshot) in &documents {
            for line in snapshot.split('\n') {
                pairs_before += offset_pairs(line).len();
            }
            for (number, line) in identity_projection(snapshot).split('\n').enumerate() {
                for pair in offset_pairs(line) {
                    survivors.push(format!("{name}:{}: `{pair}` in `{line}`", number + 1));
                }
            }
        }

        assert!(
            pairs_before > 0,
            "the corpus carries no offsets at all, so this scan proves nothing"
        );
        assert!(
            survivors.is_empty(),
            "an offset pair survived the identity projection, so a source position \
             is back in `ir_hash`. Either the span field below is rendered in a \
             spelling `erase_trailing_offsets` does not know, or it is not a span \
             at all and this scan needs narrowing:\n{}",
            survivors.join("\n")
        );
    }

    /// The reason row D13 was opened, stated as its own test: a compiler change
    /// that only moves where a caret points must rotate NOTHING. Simulated the
    /// way such a change actually shows up — the same program, re-rendered with
    /// different byte ranges under the same span fields — rather than by moving
    /// the source, which the corpus test above already covers.
    #[test]
    fn a_compiler_change_that_only_moves_a_span_rotates_no_identity() {
        for (name, source) in IDENTITY_CORPUS {
            let snapshot = snapshot_of(name, source);
            let repointed = snapshot
                .split('\n')
                .map(|line| match erase_trailing_offsets(line) {
                    Cow::Borrowed(_) => line.to_owned(),
                    // The projection recognized an offset here; a span fix
                    // replaces it with a different range.
                    Cow::Owned(erased) => format!("{}7..9", &erased[..erased.len() - 1]),
                })
                .collect::<Vec<_>>()
                .join("\n");

            assert_ne!(
                snapshot, repointed,
                "{name}: no span was repointed, so this proves nothing"
            );
            assert_eq!(
                identity_hash(&snapshot),
                identity_hash(&repointed),
                "{name}: improving a diagnostic span rotated the program's identity"
            );
        }
    }

    /// The residual DR-0095 records rather than fixes, pinned so it stays
    /// measurable: a rule's `body_hash` is a digest of its body TEXT, so a
    /// blank line INSIDE a rule body still moves `ir_hash` — which is why this
    /// change cannot claim that reformatting is free. Deliberate: inside a
    /// `"""` prompt, whitespace is prose a model reads. When `body_hash` is
    /// ruled on, this test is what fails and says so.
    #[test]
    fn whitespace_inside_a_rule_body_still_moves_identity_through_body_hash() {
        let source = IDENTITY_CORPUS[0].1;
        let reformatted = source.replace("as classification\n", "as classification\n\n");
        assert_ne!(reformatted, source, "the blank line was not inserted");

        assert_ne!(
            identity_hash(&snapshot_of("terminal-output-union", source)),
            identity_hash(&snapshot_of("reformatted", &reformatted)),
            "`body_hash` stopped being whitespace-sensitive: identity now ignores \
             text inside a rule body, which is a RULING, not a refactor — update \
             DR-0095 and row D13 rather than this assertion"
        );
    }

    /// The property that matters: what the writer emits, the reader recovers.
    /// Asserted against the real committed golden rather than a hand-written
    /// fragment, so a change to either direction has to keep them agreeing.
    #[test]
    fn reads_back_the_structure_the_writer_emitted() {
        let snapshot = include_str!("../../../examples/gastown-lite.ir");
        let view = parse(snapshot);

        assert_eq!(view.workflow, "GastownLite");
        assert_eq!(view.rules.len(), 3);

        let rule = view
            .rule("implement_ready_ticket")
            .expect("the rule is present");
        assert_eq!(rule.whens.len(), 3);
        assert_eq!(rule.effects.len(), 9);
        assert_eq!(rule.dependencies.len(), 8);

        let turn = rule
            .effects
            .iter()
            .find(|effect| effect.id == "turn")
            .expect("turn effect");
        assert_eq!(turn.kind, "agent.tell");
        assert_eq!(turn.binding.as_deref(), Some("turn"));
        // Asserted against the document rather than a literal. A hard-coded
        // effect key is 32 hex characters of high entropy, which the secret
        // scanner reads as a leaked credential — and checking that the key came
        // out of the snapshot is the stronger claim anyway.
        assert_eq!(turn.key.len(), 32);
        assert!(snapshot.contains(&format!("key={}", turn.key)));

        // `binding=-` is absence, not a name. A reader that took the dash
        // literally would label three `case`-arm effects "-" in every view.
        let unbound = rule
            .effects
            .iter()
            .find(|effect| effect.id == "effect7")
            .expect("effect7");
        assert_eq!(unbound.binding, None);
        assert_eq!(unbound.kind, "tracker.finish");

        // DR-0090: the arm the effect key is built from. The dependency edge
        // for this pair says `completes`; the key says `held`, and only one of
        // those reproduces the id.
        assert_eq!(
            turn.arm,
            Some(("slot".to_owned(), "held".to_owned())),
            "the lease arm survives as written, not as the edge collapses it"
        );
        let root = rule
            .effects
            .iter()
            .find(|effect| effect.id == "claimed")
            .expect("claimed effect");
        assert_eq!(root.arm, None, "a top-level effect has no arm");
        assert!(rule.dependencies.contains(&(
            "slot".to_owned(),
            "completes".to_owned(),
            "turn".to_owned()
        )));

        assert!(rule.dependencies.contains(&(
            "claimed".to_owned(),
            "succeeds".to_owned(),
            "slot".to_owned()
        )));
    }

    /// DR-0084's edges are part of the structure a reader recovers, including
    /// the self-edge — the rule that hands its own work back.
    #[test]
    fn reads_resource_mediated_rule_edges() {
        let snapshot = include_str!("../../../examples/gastown-lite.ir");
        let view = parse(snapshot);

        assert!(view.rule_dependencies.contains(&(
            "file_ticket".to_owned(),
            "tracker:backlog".to_owned(),
            "implement_ready_ticket".to_owned(),
        )));
        assert!(view.rule_dependencies.contains(&(
            "implement_ready_ticket".to_owned(),
            "tracker:backlog".to_owned(),
            "implement_ready_ticket".to_owned(),
        )));
    }

    /// The bijection, over real programs rather than one example: compile the
    /// source, render it, read it back, and require the recovered structure to
    /// equal what the compiler held.
    ///
    /// This is the test that makes storing the snapshot as TEXT safe. The
    /// view-model note left open whether a program version should keep the `.ir`
    /// or a structured form, and the objection to text was that every consumer
    /// writes a parser against a format whose stability nobody promised. This
    /// pins the promise instead: the writer and the reader cannot drift without
    /// a failure here.
    #[test]
    fn every_example_survives_a_write_then_read_round_trip() {
        for (name, source) in [
            (
                "gastown-lite",
                include_str!("../../../examples/gastown-lite.whip"),
            ),
            (
                "incident-router",
                include_str!("../../../examples/incident-router.whip"),
            ),
            (
                "autoresearch-lite",
                include_str!("../../../examples/autoresearch-lite.whip"),
            ),
            (
                "queue-worker-with-review",
                include_str!("../../../examples/queue-worker-with-review.whip"),
            ),
            (
                "expression-kernel",
                include_str!("../../../examples/expression-kernel.whip"),
            ),
        ] {
            let compiled = crate::compile_program(source);
            let ir = compiled.ir.unwrap_or_else(|| {
                panic!("{name} compiles: {:?}", compiled.diagnostics);
            });
            let view = parse(&ir.to_snapshot());

            assert_eq!(view.workflow, ir.workflow, "{name} workflow");
            assert_eq!(view.rules.len(), ir.rules.len(), "{name} rule count");

            for original in &ir.rules {
                let read = view
                    .rule(&original.name)
                    .unwrap_or_else(|| panic!("{name}: rule {} survived", original.name));

                assert_eq!(
                    read.whens.len(),
                    original.whens.len(),
                    "{name}/{} when count",
                    original.name
                );

                let expected: Vec<_> = original
                    .metadata
                    .effects
                    .iter()
                    .map(|effect| {
                        (
                            effect.id.clone(),
                            effect.kind.as_str().to_owned(),
                            effect.binding.clone(),
                        )
                    })
                    .collect();
                let actual: Vec<_> = read
                    .effects
                    .iter()
                    .map(|effect| {
                        (
                            effect.id.clone(),
                            effect.kind.clone(),
                            effect.binding.clone(),
                        )
                    })
                    .collect();
                assert_eq!(actual, expected, "{name}/{} effects", original.name);

                assert_eq!(
                    read.dependencies.len(),
                    original.metadata.dependencies.len(),
                    "{name}/{} dependency count",
                    original.name
                );
            }

            assert_eq!(
                view.rule_dependencies.len(),
                ir.rule_dependencies.len(),
                "{name} rule_dependencies"
            );
        }
    }

    /// Total on purpose. A snapshot written by a newer compiler carries sections
    /// this reader does not know, and refusing them would strand exactly the
    /// instances the stored snapshot exists to explain.""
    #[test]
    fn skips_sections_it_does_not_understand() {
        let view = parse(
            "workflow Demo\n\
             something_from_the_future\n  \
             whatever it likes\n\
             rules\n  \
             rule only\n    \
             when started\n",
        );

        assert_eq!(view.workflow, "Demo");
        assert_eq!(view.rules.len(), 1);
        assert_eq!(view.rules[0].whens, vec!["started".to_owned()]);
    }
}
