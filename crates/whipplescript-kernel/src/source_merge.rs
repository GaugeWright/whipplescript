//! Declaration-granularity whip-source merge with slice certificates
//! (spec/versioned-workspace-research-note.md §6.1 "Whip source — the real
//! engine"; untie-substrate readiness tracker Phase 1; semantics modeled
//! in merge-slice.maude).
//!
//! Source is a set of declarations, not a text file. The three-way runs
//! at whole-declaration granularity over the branch-point base:
//! both-modified-same-declaration is trivially a conflict; disjoint
//! changed declarations earn a certificate ONLY when the composition
//! theorem's anti-dependence discipline holds — one side's
//! write-or-consume fact footprint must not intersect the other's
//! read-or-write-or-consume footprint, computed from the parser's rule
//! metadata across every version of each changed rule (the blast radius
//! covers before and after). This is what grants same-file merges git
//! could never certify AND refuses cross-declaration interference git
//! silently mis-merges.
//!
//! v1 is fail-closed at every uncertainty, per the tracker: any side that
//! does not compile, a lossy declaration split, a changed NON-rule
//! declaration (classes, stores, headers — no footprint model yet), a
//! changed rule with projection reads (query heads are not yet folded
//! into the read footprint), duplicate identities, or a merged result
//! that does not re-compile — every one escalates to an honest conflict
//! rather than guessing.

use std::collections::{BTreeMap, BTreeSet};

use whipplescript_parser::{
    canonical_declarations, compile_program, parse_program, DeclCanon, IrProgram,
};
use whipplescript_store::vcs::{CanonDecl, DeclCanonicalizer, SourceMergeVerdict, SourceMerger};

/// The parser-backed source merger the hosts install into `WorkspaceVcs`.
pub struct WhipSourceMerger;

/// The parser-backed DR-0054 canonicalizer the hosts install next to the
/// merger (the change-unit index's declaration-level sub-rows ride it).
pub struct WhipDeclCanonicalizer;

impl DeclCanonicalizer for WhipDeclCanonicalizer {
    fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
        Some(
            canonical_declarations(source)?
                .into_iter()
                .map(|declaration| CanonDecl {
                    identity: declaration.identity,
                    canon_hash: declaration.canon_hash,
                    rename_hash: declaration.rename_hash,
                })
                .collect(),
        )
    }
}

/// One top-level declaration block: the identity (its normalized first
/// line) and the exact source text (reassembly is lossless by check).
#[derive(Clone, Debug, Eq, PartialEq)]
struct DeclBlock {
    identity: String,
    text: String,
}

/// The offset of the start of the line containing `offset`. An item's span
/// points at the declaration's payload (`use`'s name, `include`'s path), so
/// the block boundary is the start of the line that declaration opens.
fn line_start(source: &str, offset: usize) -> usize {
    let mut cut = offset.min(source.len());
    while !source.is_char_boundary(cut) {
        cut -= 1;
    }
    source[..cut].rfind('\n').map_or(0, |newline| newline + 1)
}

/// Split source into declaration blocks by the PARSER's top-level item
/// spans, so the decomposition cannot disagree with the grammar: every
/// `Item` the grammar admits opens a block, and a declaration keyword the
/// grammar grows is recognized here the day it parses. A hand-kept keyword
/// list could not say that — the keywords it lacked were glued onto the
/// preceding block, which then answered for them under the preceding
/// declaration's identity, and a non-rule edit smuggled in that way earned
/// a certificate the footprint wall was supposed to refuse.
///
/// Each block runs from the start of its declaration's line to the start of
/// the next one, so blank lines and the comments above a declaration ride
/// the block before it; the reassembly check below still proves the split
/// loses nothing.
///
/// `None` = the split cannot be trusted (the source does not parse cleanly,
/// duplicate identities, or reassembly is not byte-identical) — the caller
/// fails closed.
fn split_declarations(source: &str) -> Option<Vec<DeclBlock>> {
    let parsed = parse_program(source);
    // REFUSAL: a source the grammar cannot read has no trustworthy decomposition
    if !parsed.diagnostics.is_empty() {
        return None;
    }
    let program = parsed.program;
    // Depth-zero units only: a `workflow X { … }` block is ONE unit and its
    // nested items ride inside it, matching DR-0054 canonicalization.
    let mut starts: Vec<usize> = Vec::new();
    if let Some(workflow) = &program.workflow {
        starts.push(line_start(source, workflow.span.start));
    }
    for pattern in &program.patterns {
        starts.push(line_start(source, pattern.span.start));
    }
    for item in &program.items {
        starts.push(line_start(source, item.span().start));
    }
    for workflow in &program.workflows {
        starts.push(line_start(source, workflow.span.start));
    }
    starts.sort_unstable();
    // The compact contract signature desugars several items onto ONE line;
    // a line the source cannot separate is one editable unit.
    starts.dedup();

    let mut blocks: Vec<DeclBlock> = Vec::new();
    let first = starts.first().copied().unwrap_or(source.len());
    if first > 0 {
        // Leading prose before the first declaration: a synthetic preamble
        // block keyed by its own text.
        let text = &source[..first];
        blocks.push(DeclBlock {
            identity: format!("preamble:{}", text.lines().next().unwrap_or("").trim()),
            text: text.to_owned(),
        });
    }
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(source.len());
        let text = &source[start..end];
        blocks.push(DeclBlock {
            identity: text
                .lines()
                .next()
                .unwrap_or("")
                .trim_end()
                .trim_end_matches('{')
                .trim_end()
                .to_owned(),
            text: text.to_owned(),
        });
    }

    // Lossless + unambiguous, or nothing.
    let reassembled: String = blocks.iter().map(|block| block.text.as_str()).collect();
    if reassembled != source {
        return None;
    }
    let mut seen = BTreeSet::new();
    for block in &blocks {
        if !seen.insert(block.identity.clone()) {
            return None;
        }
    }
    Some(blocks)
}

/// A changed rule's fact footprint, unioned across every version of the
/// declaration (base and edited) — the whole blast radius.
#[derive(Clone, Debug, Default)]
struct Footprint {
    reads: BTreeSet<String>,
    writes: BTreeSet<String>,
    consumes: BTreeSet<String>,
    /// Projection reads present anywhere in the rule: no certificate (the
    /// query head is not yet folded into the read footprint).
    opaque: bool,
}

impl Footprint {
    fn absorb_rule(&mut self, program: &IrProgram, rule_name: &str) -> bool {
        let Some(rule) = program.rules.iter().find(|rule| rule.name == rule_name) else {
            return false;
        };
        self.reads.extend(rule.metadata.fact_reads.iter().cloned());
        self.writes
            .extend(rule.metadata.fact_writes.iter().cloned());
        self.consumes
            .extend(rule.metadata.fact_consumes.iter().cloned());
        if !rule.metadata.projection_reads.is_empty() {
            self.opaque = true;
        }
        true
    }

    fn write_or_consume(&self) -> BTreeSet<String> {
        self.writes.union(&self.consumes).cloned().collect()
    }

    fn touched_or_read(&self) -> BTreeSet<String> {
        let mut all = self.write_or_consume();
        all.extend(self.reads.iter().cloned());
        all
    }
}

/// The anti-dependence certificate over two changed-rule footprints,
/// exactly merge-slice.maude's guard: neither side's write-or-consume
/// may meet the other's read-or-write-or-consume.
fn slices_disjoint(a: &Footprint, b: &Footprint) -> bool {
    if a.opaque || b.opaque {
        return false;
    }
    a.write_or_consume().is_disjoint(&b.touched_or_read())
        && b.write_or_consume().is_disjoint(&a.touched_or_read())
}

fn compile_ir(source: &str) -> Option<IrProgram> {
    compile_program(source).ir
}

/// Trailing whitespace is block PACKAGING (a following addition donates a
/// separator newline to the previous block), not content — comparisons
/// normalize it away; assembly keeps the raw text.
fn norm(text: &str) -> &str {
    text.trim_end()
}

/// The identities changed between base and a side (modified, added, or
/// deleted), with the per-identity verdict deferred to the caller.
fn changed_identities(
    base: &BTreeMap<String, String>,
    side: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut changed = BTreeSet::new();
    for (identity, text) in side {
        if base.get(identity).map(|base_text| norm(base_text)) != Some(norm(text)) {
            changed.insert(identity.clone());
        }
    }
    for identity in base.keys() {
        if !side.contains_key(identity) {
            changed.insert(identity.clone());
        }
    }
    changed
}

impl SourceMerger for WhipSourceMerger {
    fn merge_source(&self, base: Option<&str>, ours: &str, theirs: &str) -> SourceMergeVerdict {
        let Some(base) = base else {
            // Divergent add/add of a whole source file: no base to compose
            // over.
            return SourceMergeVerdict::Conflict;
        };
        // Fail closed unless every side compiles.
        let (Some(base_ir), Some(ours_ir), Some(theirs_ir)) =
            (compile_ir(base), compile_ir(ours), compile_ir(theirs))
        else {
            return SourceMergeVerdict::Conflict;
        };
        let (Some(base_blocks), Some(ours_blocks), Some(theirs_blocks)) = (
            split_declarations(base),
            split_declarations(ours),
            split_declarations(theirs),
        ) else {
            return SourceMergeVerdict::Conflict;
        };
        let base_map: BTreeMap<String, String> = base_blocks
            .iter()
            .map(|block| (block.identity.clone(), block.text.clone()))
            .collect();
        let ours_map: BTreeMap<String, String> = ours_blocks
            .iter()
            .map(|block| (block.identity.clone(), block.text.clone()))
            .collect();
        let theirs_map: BTreeMap<String, String> = theirs_blocks
            .iter()
            .map(|block| (block.identity.clone(), block.text.clone()))
            .collect();

        let ours_changed = changed_identities(&base_map, &ours_map);
        let theirs_changed = changed_identities(&base_map, &theirs_map);

        // DR-0054 canonical maps (identity -> canon). The merge already
        // requires every side to compile, so these should exist; a `None`
        // simply forfeits the refinements below (fail-closed to the pre-DR
        // verdicts, never the other direction).
        let canon_map = |source: &str| -> Option<BTreeMap<String, DeclCanon>> {
            Some(
                canonical_declarations(source)?
                    .into_iter()
                    .map(|declaration| (declaration.identity.clone(), declaration))
                    .collect(),
            )
        };
        let base_canon = canon_map(base);
        let ours_canon = canon_map(ours);
        let theirs_canon = canon_map(theirs);

        // Both-modified-same-declaration: a conflict unless both sides
        // landed the identical text (one change, reunified) or the DR-0054
        // dissolve applies — canonically equal sides (formatting, comments,
        // binding names) are one change; ours' text is the deterministic
        // pick at assembly.
        for identity in ours_changed.intersection(&theirs_changed) {
            if ours_map.get(identity).map(|text| norm(text))
                == theirs_map.get(identity).map(|text| norm(text))
            {
                continue;
            }
            let canonically_equal = match (&ours_canon, &theirs_canon) {
                (Some(ours_canon), Some(theirs_canon)) => matches!(
                    (ours_canon.get(identity), theirs_canon.get(identity)),
                    (Some(ours_decl), Some(theirs_decl))
                        if ours_decl.canon_hash == theirs_decl.canon_hash
                ),
                _ => false,
            };
            if !canonically_equal {
                return SourceMergeVerdict::Conflict;
            }
        }

        // DR-0054 rename carry: within one side, a deleted identity and an
        // added identity of matching `rename_hash` are one declaration
        // renamed — exempt from the footprint requirement (a pure rename's
        // fact-flow delta is nil; the final compile gate still applies).
        // Fail-closed walls: exact canonical match only, unambiguous
        // pairing (one deleted + one added per key), and the OTHER side
        // touched neither identity.
        let mut carried: BTreeSet<String> = BTreeSet::new();
        if let Some(base_canon) = &base_canon {
            let mut detect = |changed: &BTreeSet<String>,
                              side_map: &BTreeMap<String, String>,
                              side_canon: &Option<BTreeMap<String, DeclCanon>>,
                              other_changed: &BTreeSet<String>| {
                let Some(side_canon) = side_canon else {
                    return;
                };
                let mut deleted_by_key: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
                let mut added_by_key: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
                for identity in changed {
                    if base_map.contains_key(identity) && !side_map.contains_key(identity) {
                        if let Some(declaration) = base_canon.get(identity) {
                            deleted_by_key
                                .entry(declaration.rename_hash.as_str())
                                .or_default()
                                .push(identity);
                        }
                    } else if !base_map.contains_key(identity) && side_map.contains_key(identity) {
                        if let Some(declaration) = side_canon.get(identity) {
                            added_by_key
                                .entry(declaration.rename_hash.as_str())
                                .or_default()
                                .push(identity);
                        }
                    }
                }
                for (key, deleted) in &deleted_by_key {
                    let Some(added) = added_by_key.get(key) else {
                        continue;
                    };
                    if deleted.len() != 1 || added.len() != 1 {
                        continue;
                    }
                    if other_changed.contains(deleted[0]) || other_changed.contains(added[0]) {
                        continue;
                    }
                    carried.insert(deleted[0].clone());
                    carried.insert(added[0].clone());
                }
            };
            detect(&ours_changed, &ours_map, &ours_canon, &theirs_changed);
            detect(&theirs_changed, &theirs_map, &theirs_canon, &ours_changed);
        }

        // The certificate: every changed declaration must be a rule with a
        // computable footprint, and the two sides' slices must be disjoint
        // under the anti-dependence discipline.
        let footprint_for = |identity: &str,
                             side_ir: &IrProgram,
                             side_map: &BTreeMap<String, String>|
         -> Option<Footprint> {
            let Some(rule_name) = identity.strip_prefix("rule ") else {
                // Modifying or deleting a non-rule declaration has no
                // footprint model — fail closed.
                if base_map.contains_key(identity) || !side_map.contains_key(identity) {
                    return None;
                }
                // An ADDED non-rule declaration is footprint-free only if it
                // contributed nothing to the fact graph. A `class` qualifies:
                // it declares a type. A `table`, `view` or `apply` does NOT --
                // each lowers into fact-writing rules -- and an `assert` reads
                // the fact sets it names without producing a rule at all.
                //
                // Splitting by parser spans is what made those reachable here:
                // while the decomposition was a 15-keyword scan, every one of
                // them glued into the preceding block instead of arriving as
                // its own identity, so this branch only ever saw the kinds the
                // list happened to name. The question is therefore asked of the
                // lowered IR rather than of a second keyword list, which is the
                // failure this decomposition was rewritten to end.
                //
                // Attribution is deliberately coarse: a generated rule does not
                // carry which declaration produced it, so a side that generated
                // ANY rule fails closed for ALL of its added non-rule
                // declarations rather than guessing which one owns it.
                let declared_rules: BTreeSet<&str> = side_map
                    .keys()
                    .filter_map(|key| key.strip_prefix("rule "))
                    .map(str::trim)
                    .collect();
                let base_rules: BTreeSet<&str> = base_ir
                    .rules
                    .iter()
                    .map(|rule| rule.name.as_str())
                    .collect();
                let generated = side_ir.rules.iter().any(|rule| {
                    !base_rules.contains(rule.name.as_str())
                        && !declared_rules.contains(rule.name.as_str())
                });
                if generated || side_ir.assertions != base_ir.assertions {
                    return None;
                }
                return Some(Footprint::default());
            };
            let rule_name = rule_name.trim().to_owned();
            let mut footprint = Footprint::default();
            let mut present_anywhere = false;
            if base_map.contains_key(identity) {
                present_anywhere |= footprint.absorb_rule(&base_ir, &rule_name);
            }
            if side_map.contains_key(identity) {
                present_anywhere |= footprint.absorb_rule(side_ir, &rule_name);
            }
            present_anywhere.then_some(footprint)
        };
        let mut ours_footprints = Vec::new();
        for identity in &ours_changed {
            if theirs_changed.contains(identity) || carried.contains(identity) {
                continue; // both-sides-admitted change, or a carried rename
            }
            let Some(footprint) = footprint_for(identity, &ours_ir, &ours_map) else {
                return SourceMergeVerdict::Conflict;
            };
            ours_footprints.push(footprint);
        }
        let mut theirs_footprints = Vec::new();
        for identity in &theirs_changed {
            if ours_changed.contains(identity) || carried.contains(identity) {
                continue;
            }
            let Some(footprint) = footprint_for(identity, &theirs_ir, &theirs_map) else {
                return SourceMergeVerdict::Conflict;
            };
            theirs_footprints.push(footprint);
        }
        for ours_footprint in &ours_footprints {
            for theirs_footprint in &theirs_footprints {
                if !slices_disjoint(ours_footprint, theirs_footprint) {
                    return SourceMergeVerdict::Conflict;
                }
            }
        }

        // Assemble: base order with per-identity replacement/deletion;
        // additions append (ours' then theirs'), separated as blocks.
        let take = |identity: &str| -> Option<String> {
            if ours_changed.contains(identity) {
                ours_map.get(identity).cloned()
            } else if theirs_changed.contains(identity) {
                theirs_map.get(identity).cloned()
            } else {
                base_map.get(identity).cloned()
            }
        };
        let mut merged = String::new();
        for block in &base_blocks {
            if let Some(text) = take(&block.identity) {
                merged.push_str(&text);
            }
        }
        let mut append_new = |changed: &BTreeSet<String>, map: &BTreeMap<String, String>| {
            for identity in changed {
                if !base_map.contains_key(identity) {
                    if !merged.ends_with("\n\n") {
                        merged.push('\n');
                    }
                    merged.push_str(map.get(identity).expect("added block"));
                }
            }
        };
        append_new(&ours_changed, &ours_map);
        let mut theirs_only = theirs_changed.clone();
        theirs_only.retain(|identity| !ours_changed.contains(identity));
        append_new(&theirs_only, &theirs_map);

        // The merged result must itself compile, or nothing moved.
        if compile_ir(&merged).is_none() {
            return SourceMergeVerdict::Conflict;
        }
        SourceMergeVerdict::Certified { merged }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "workflow Demo\n\noutput result Report\n\nclass Report {\n  message string\n}\n\nclass Ticket {\n  status string\n}\n\nrule triage\n  when started\n=> {\n  record Ticket {\n    status \"open\"\n  }\n}\n\nrule close\n  when Ticket as t\n=> {\n  complete result {\n    message \"done\"\n  }\n}\n";

    /// An ADDED non-rule declaration takes the empty-footprint branch, and
    /// that branch is only sound when the declaration touched no facts. An
    /// `assert` READS the fact sets it names while producing no rule of its
    /// own, so a side adding one against a side that WRITES that fact is the
    /// anti-dependence `slices_disjoint` exists to refuse.
    ///
    /// This certified while the decomposition was a keyword scan, because
    /// `assert` was one of the eighteen kinds the scan did not name and it
    /// glued into the preceding rule instead of arriving as its own identity.
    #[test]
    fn an_added_assert_over_a_written_fact_conflicts() {
        let ours = format!("{BASE}\nassert count(Ticket) == 1\n");
        let theirs = format!(
            "{BASE}\nrule seed_more\n  when started\n=> {{\n  record Ticket {{\n    status \"extra\"\n  }}\n}}\n"
        );
        assert!(
            matches!(
                WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
                SourceMergeVerdict::Conflict
            ),
            "an assert reading Ticket must not certify against a rule writing it"
        );
    }

    /// The control that proves the guard above is about the fact flow and not
    /// about `assert` in particular: the same flow with the read expressed as
    /// a rule conflicts too, and always did.
    #[test]
    fn the_same_flow_expressed_as_a_rule_also_conflicts() {
        let ours = format!(
            "{BASE}\nrule watch\n  when Ticket as t\n=> {{\n  record Report {{\n    message \"seen\"\n  }}\n}}\n"
        );
        let theirs = format!(
            "{BASE}\nrule seed_more\n  when started\n=> {{\n  record Ticket {{\n    status \"extra\"\n  }}\n}}\n"
        );
        assert!(matches!(
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
            SourceMergeVerdict::Conflict
        ));
    }

    /// Disjoint rule edits to the SAME file certify: ours rewrites
    /// `close`'s message, theirs adds an independent logging rule over a
    /// different fact — the merged source carries both and compiles (the
    /// case git can never grant).
    #[test]
    fn disjoint_rule_edits_certify_and_compose() {
        let ours = BASE.replace("message \"done\"", "message \"finished\"");
        let theirs = format!(
            "{BASE}\nclass Audit {{\n  note string\n}}\n\nrule log_start\n  when started\n=> {{\n  record Audit {{\n    note \"started\"\n  }}\n}}\n"
        );
        let SourceMergeVerdict::Certified { merged } =
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs)
        else {
            panic!("expected a certificate");
        };
        assert!(merged.contains("message \"finished\""));
        assert!(merged.contains("rule log_start"));
        assert!(compile_program(&merged).ir.is_some());
    }

    /// The cross-declaration semantic conflict (merge-slice.maude's
    /// essential bite, at source granularity): ours changes what `triage`
    /// WRITES; theirs changes `close`, which READS that fact. Different
    /// declarations — a text merge would silently accept — but the
    /// write∩read slice overlap refuses the certificate.
    #[test]
    fn write_read_interference_across_rules_refuses_the_certificate() {
        let ours = BASE.replace("status \"open\"", "status \"reopened\"");
        let theirs = BASE.replace("message \"done\"", "message \"closed out\"");
        // ours changed `triage` (writes Ticket); theirs changed `close`
        // (reads Ticket): write-or-consume ∩ read ⇒ no certificate.
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
            SourceMergeVerdict::Conflict
        );
    }

    /// Both-modified-same-declaration is trivially a conflict; the
    /// IDENTICAL change on both sides reunifies as one change.
    #[test]
    fn same_declaration_conflicts_unless_identical() {
        let ours = BASE.replace("message \"done\"", "message \"ours\"");
        let theirs = BASE.replace("message \"done\"", "message \"theirs\"");
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
            SourceMergeVerdict::Conflict
        );
        let same = BASE.replace("message \"done\"", "message \"agreed\"");
        assert!(matches!(
            WhipSourceMerger.merge_source(Some(BASE), &same, &same.clone()),
            SourceMergeVerdict::Certified { .. }
        ));
    }

    /// DR-0054 dissolve: both sides touched the SAME declaration but the
    /// difference is canonically nil (each renamed the local binding) —
    /// one change, reunified, ours' text is the deterministic pick.
    #[test]
    fn canonically_equal_both_sided_change_dissolves() {
        let ours = BASE.replace("when Ticket as t", "when Ticket as ticket");
        let theirs = BASE.replace("when Ticket as t", "when Ticket as item");
        let SourceMergeVerdict::Certified { merged } =
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs)
        else {
            panic!("expected the canonical dissolve to certify");
        };
        assert!(merged.contains("when Ticket as ticket"));
    }

    /// DR-0054 rename carry: ours renames `class Ticket` to `class Issue`
    /// (updating the referencing rules); theirs is untouched. The class
    /// delete+add pair matches on `rename_hash` and is carried instead of
    /// hitting the no-footprint-model wall.
    #[test]
    fn pure_class_rename_carries_instead_of_failing_closed() {
        let ours = BASE.replace("Ticket", "Issue");
        let SourceMergeVerdict::Certified { merged } =
            WhipSourceMerger.merge_source(Some(BASE), &ours, BASE)
        else {
            panic!("expected the rename carry to certify");
        };
        assert!(merged.contains("class Issue"));
        assert!(!merged.contains("class Ticket"));
    }

    /// The carry is exact-match-only: a rule rename PLUS an edit is not a
    /// rename (Decision 3), so its footprint is checked — and here it
    /// interferes with theirs' write. A PURE rename of the same rule is
    /// semantically untouched and certifies over the very same theirs.
    #[test]
    fn rename_plus_edit_is_not_carried() {
        let theirs = BASE.replace("status \"open\"", "status \"reopened\"");
        let pure_rename = BASE.replace("rule close\n", "rule closed_out\n");
        assert!(matches!(
            WhipSourceMerger.merge_source(Some(BASE), &pure_rename, &theirs),
            SourceMergeVerdict::Certified { .. }
        ));
        let rename_and_edit = pure_rename.replace("message \"done\"", "message \"finished\"");
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), &rename_and_edit, &theirs),
            SourceMergeVerdict::Conflict
        );
    }

    /// The carry demands an untouched other side: theirs modified the very
    /// declaration ours renamed away — honest conflict.
    #[test]
    fn rename_conflicts_when_the_other_side_touched_the_identity() {
        let ours = BASE.replace("rule close\n", "rule closed_out\n");
        let theirs = BASE.replace("message \"done\"", "message \"theirs\"");
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
            SourceMergeVerdict::Conflict
        );
    }

    /// Fail-closed walls: a non-rule change (class), a non-compiling
    /// side, and a missing base all refuse.
    #[test]
    fn non_rule_changes_and_broken_sides_fail_closed() {
        let ours = BASE.replace("message string", "message string\n  extra int");
        let theirs = format!(
            "{BASE}\nclass Audit {{\n  note string\n}}\n\nrule log_start\n  when started\n=> {{\n  record Audit {{\n    note \"x\"\n  }}\n}}\n"
        );
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), &ours, &theirs),
            SourceMergeVerdict::Conflict,
            "a changed class has no footprint model: fail closed"
        );
        assert_eq!(
            WhipSourceMerger.merge_source(Some(BASE), "not whip at all", BASE),
            SourceMergeVerdict::Conflict
        );
        assert_eq!(
            WhipSourceMerger.merge_source(None, BASE, BASE),
            SourceMergeVerdict::Conflict
        );
    }
}

#[cfg(test)]
mod glued_declaration_tests {
    use super::*;

    /// A base whose top-level `counter` and `lease` sit BETWEEN two rules —
    /// the declaration shapes a hand-kept keyword list did not name, and so
    /// glued onto the preceding `rule triage` block.
    const COORD_BASE: &str = "workflow Demo\n\nuse std.coord\n\noutput result Report\n\nclass Report {\n  message string\n}\n\nclass Ticket {\n  status string\n}\n\nrule triage\n  when started\n=> {\n  record Ticket {\n    status \"open\"\n  }\n}\n\ncounter attempts {\n  key Ticket\n  cap 3\n  reset daily\n  timezone \"America/New_York\"\n}\n\nlease deploy_slot {\n  key Ticket\n  slots 1\n  ttl 10m\n}\n\nrule close\n  when Ticket as t\n=> {\n  complete result {\n    message \"done\"\n  }\n}\n";

    /// Theirs: an independent rule over its own fact — disjoint from every
    /// rule in the base, so the certificate turns entirely on what OURS is
    /// judged to have changed.
    fn independent_addition(base: &str) -> String {
        format!(
            "{base}\nclass Audit {{\n  note string\n}}\n\nrule log_start\n  when started\n=> {{\n  record Audit {{\n    note \"started\"\n  }}\n}}\n"
        )
    }

    /// A side whose ONLY edit is a top-level `counter` has no footprint
    /// model, so the merge must refuse. Decomposed by a keyword list, the
    /// counter was part of `rule triage`'s block: the edit answered under
    /// that rule's identity, borrowed that rule's footprint, and the
    /// composition was certified with no model of the real edit at all.
    #[test]
    fn counter_only_edit_has_no_footprint_model() {
        let ours = COORD_BASE.replace("cap 3", "cap 5");
        assert_ne!(ours, COORD_BASE, "the counter edit must actually change");
        assert_eq!(
            WhipSourceMerger.merge_source(
                Some(COORD_BASE),
                &ours,
                &independent_addition(COORD_BASE)
            ),
            SourceMergeVerdict::Conflict
        );
    }

    /// The same wall for a top-level `lease`: changing how many slots a
    /// lease has is not a rule edit and has no footprint model.
    #[test]
    fn lease_only_edit_has_no_footprint_model() {
        let ours = COORD_BASE.replace("slots 1", "slots 2");
        assert_ne!(ours, COORD_BASE, "the lease edit must actually change");
        assert_eq!(
            WhipSourceMerger.merge_source(
                Some(COORD_BASE),
                &ours,
                &independent_addition(COORD_BASE)
            ),
            SourceMergeVerdict::Conflict
        );
    }

    /// A source the grammar cannot read has no trustworthy decomposition:
    /// the split refuses rather than handing back a partial item list whose
    /// gaps would glue declarations back together.
    #[test]
    fn a_source_that_does_not_parse_has_no_split() {
        assert!(split_declarations("not whip at all").is_none());
    }

    /// The decomposition itself: every top-level declaration is its own
    /// block, whatever keyword opens it, and the preceding rule keeps only
    /// its own text.
    #[test]
    fn every_top_level_declaration_is_its_own_block() {
        let identities: Vec<String> = split_declarations(COORD_BASE)
            .expect("the base splits")
            .into_iter()
            .map(|block| block.identity)
            .collect();
        assert_eq!(
            identities,
            vec![
                "workflow Demo",
                "use std.coord",
                "output result Report",
                "class Report",
                "class Ticket",
                "rule triage",
                "counter attempts",
                "lease deploy_slot",
                "rule close",
            ]
        );
    }
}
