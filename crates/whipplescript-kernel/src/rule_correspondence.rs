//! The revision rule correspondence (DR-0077).
//!
//! A rule renamed across a revision re-fires for a trigger it already fired on,
//! because candidate selection suppresses a live match only when an old firing
//! carries the same rule NAME. This module derives which removed rule looks like
//! which added rule, so a revision can say so.
//!
//! What it deliberately does not do is decide anything. The derivation is
//! **evidence**: no content hash separates a rename from a delete-plus-copy —
//! an author who copies a rule's body into a new rule produces a unique match
//! that is not a rename — so acting on it automatically would trade a duplicate
//! the operator can see for a missing emission they cannot. Suppression follows
//! an explicit operator carry; this only supplies what the operator is shown.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use whipplescript_parser::canonical_declarations;

/// One removed rule and one added rule whose canonical bodies agree once their
/// names are blanked — a rename, as far as content can tell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedRename {
    pub removed: String,
    pub added: String,
}

/// A `rename_hash` shared by more than one removed or added rule. Reported, and
/// never proposed: two canonically identical rules hold distinct identities, so
/// there is no way to say which became which.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousMatch {
    pub removed: Vec<String>,
    pub added: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleCorrespondence {
    /// Unique matches, offered to the operator as carries.
    pub proposed: Vec<ProposedRename>,
    /// Removed rules matching nothing added. A firing recorded under one of
    /// these is never carried, so its rule cannot re-fire — but anything the
    /// revision adds in its place will.
    pub refire_sites: Vec<String>,
    /// Matches that cannot be proposed, with the rules that collided.
    pub ambiguous: Vec<AmbiguousMatch>,
    /// The canonicalizer refused one of the two programs, so nothing was
    /// derived. Reported rather than swallowed: an empty correspondence and an
    /// underivable one are different answers, and only the second is a reason
    /// to distrust the report.
    pub underivable: bool,
}

/// The bare rule name inside a canonical declaration identity: `rule work` is
/// the identity, `work` is what a firing records and what the rule pass matches
/// on. Everything crossing the operator surface uses the bare name.
pub fn rule_name(identity: &str) -> &str {
    identity.strip_prefix("rule ").unwrap_or(identity)
}

/// An operator's statement that one rule became another across a revision.
///
/// This is an **instruction**, and the only thing that suppresses a firing.
/// [`RuleCorrespondence`] is evidence and suppresses nothing: no content hash
/// separates a rename from a delete-plus-copy, so the judgement belongs to the
/// party holding the intent (DR-0077 Decision 4). The two are recorded apart
/// and never merged.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuleCarry {
    pub from: String,
    pub to: String,
}

impl RuleCarry {
    /// Parse one `old=new` argument. Either side may be written as the bare
    /// name or as the canonical identity (`rule old`), because the report
    /// prints identities in its prose and a paste of either should work.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let Some((from, to)) = spec.split_once('=') else {
            return Err(format!("expected `old=new` after `--carry`, got `{spec}`"));
        };
        let from = rule_name(from.trim()).trim();
        let to = rule_name(to.trim()).trim();
        if from.is_empty() || to.is_empty() {
            return Err(format!(
                "`--carry {spec}` names an empty rule; expected `old=new`"
            ));
        }
        if from == to {
            return Err(format!(
                "`--carry {spec}` carries `{from}` to itself; a rule whose name \
                 survives is never a rename"
            ));
        }
        Ok(Self {
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }
}

/// Serialize carries for the activation record. Stored as a list of objects
/// rather than a map so the record reads the same way it was written, and so a
/// reader never has to know whether the key was the old or the new name.
pub fn carries_to_json(carries: &[RuleCarry]) -> Value {
    Value::Array(
        carries
            .iter()
            .map(|carry| json!({ "from": carry.from, "to": carry.to }))
            .collect(),
    )
}

/// Read carries back out of a recorded activation. A malformed or absent record
/// yields no carries, which is the no-suppression direction — the same place an
/// un-carried revision already sits.
pub fn carries_from_json(value: &Value) -> Vec<RuleCarry> {
    value
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    let from = entry.get("from")?.as_str()?;
                    let to = entry.get("to")?.as_str()?;
                    Some(RuleCarry {
                        from: from.to_owned(),
                        to: to.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// DR-0077 Decision 5. Translate a rule name recorded at `recorded_epoch`
/// forward to what the active program calls it, through the carries of every
/// revision that activated after that epoch, in order.
///
/// `chain` is `(activated_epoch, carries)` per revision, ascending. The epoch
/// bound is what keeps a later revision's reuse of a retired name from being
/// dragged backwards through an earlier carry: a carry applies only to names
/// recorded before it was given.
pub fn translate_forward(
    name: &str,
    recorded_epoch: i64,
    chain: &[(i64, Vec<RuleCarry>)],
) -> String {
    let mut current = name.to_owned();
    for (epoch, carries) in chain {
        if *epoch <= recorded_epoch {
            continue;
        }
        if let Some(carry) = carries.iter().find(|carry| carry.from == current) {
            current = carry.to.clone();
        }
    }
    current
}

fn rule_declarations(source: &str) -> Option<BTreeMap<String, String>> {
    let declarations = canonical_declarations(source)?;
    Some(
        declarations
            .into_iter()
            .filter(|declaration| declaration.identity.starts_with("rule "))
            .map(|declaration| (declaration.identity, declaration.rename_hash))
            .collect(),
    )
}

/// Derive the correspondence between the active program's rules and a
/// candidate's. Pure: both sources in, evidence out, nothing consulted and
/// nothing recorded.
pub fn derive(active_source: &str, candidate_source: &str) -> RuleCorrespondence {
    let (Some(active), Some(candidate)) = (
        rule_declarations(active_source),
        rule_declarations(candidate_source),
    ) else {
        return RuleCorrespondence {
            underivable: true,
            ..RuleCorrespondence::default()
        };
    };

    // Candidates are rules present in one program and not the other BY
    // IDENTITY. A rule whose name survives is not a rename however its body
    // changed, and a swap -- two rules exchanging bodies -- leaves both
    // identities present in both programs and so produces no candidates at all.
    // That case is a known limit of this framing, recorded in DR-0077.
    let mut removed_by_hash: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (identity, hash) in &active {
        if !candidate.contains_key(identity) {
            removed_by_hash
                .entry(hash.as_str())
                .or_default()
                .push(identity.clone());
        }
    }
    let mut added_by_hash: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (identity, hash) in &candidate {
        if !active.contains_key(identity) {
            added_by_hash
                .entry(hash.as_str())
                .or_default()
                .push(identity.clone());
        }
    }

    let mut correspondence = RuleCorrespondence::default();
    for (hash, removed) in &removed_by_hash {
        match added_by_hash.get(hash) {
            None => correspondence.refire_sites.extend(removed.iter().cloned()),
            Some(added) if removed.len() == 1 && added.len() == 1 => {
                correspondence.proposed.push(ProposedRename {
                    removed: removed[0].clone(),
                    added: added[0].clone(),
                });
            }
            Some(added) => correspondence.ambiguous.push(AmbiguousMatch {
                removed: removed.clone(),
                added: added.clone(),
            }),
        }
    }
    correspondence.refire_sites.sort();
    correspondence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(rules: &[(&str, &str)]) -> String {
        let mut source = String::from(
            "workflow Rev\n\noutput result Done\n\nclass Job {\n  id string\n}\n\n\
             class Done {\n  note string\n}\n\n",
        );
        for (name, note) in rules {
            source.push_str(&format!(
                "rule {name}\n  when Job as j\n=> {{\n  complete result {{\n    note \"{note}\"\n  }}\n}}\n\n"
            ));
        }
        source
    }

    #[test]
    fn a_carry_accepts_either_vocabulary() {
        // The report's prose names identities and its suggestion names bare
        // rules; a paste of either must land on the same carry.
        assert_eq!(
            RuleCarry::parse("work=renamed").expect("bare"),
            RuleCarry::parse(" rule work = rule renamed ").expect("identity")
        );
    }

    #[test]
    fn a_carry_to_itself_is_refused() {
        // Not a harmless no-op: a rule whose name survives is never a rename,
        // so this argument means the operator believes something the mechanism
        // does not do. Refusing says so; accepting it silently would not.
        assert!(RuleCarry::parse("work=work").is_err());
        assert!(RuleCarry::parse("work").is_err());
        assert!(RuleCarry::parse("=renamed").is_err());
    }

    #[test]
    fn carries_survive_the_round_trip_through_a_record() {
        let carries = vec![
            RuleCarry {
                from: "work".to_owned(),
                to: "renamed".to_owned(),
            },
            RuleCarry {
                from: "audit".to_owned(),
                to: "review".to_owned(),
            },
        ];
        assert_eq!(carries_from_json(&carries_to_json(&carries)), carries);
    }

    #[test]
    fn a_record_that_does_not_parse_carries_nothing() {
        // The no-suppression direction, which is where an un-carried revision
        // already sits -- never a guessed carry recovered from a broken record.
        assert!(carries_from_json(&json!("nonsense")).is_empty());
        assert!(carries_from_json(&json!([{ "from": "work" }])).is_empty());
    }

    #[test]
    fn a_carry_composes_along_the_chain() {
        let chain = vec![
            (
                1,
                vec![RuleCarry {
                    from: "work".to_owned(),
                    to: "middle".to_owned(),
                }],
            ),
            (
                2,
                vec![RuleCarry {
                    from: "middle".to_owned(),
                    to: "final".to_owned(),
                }],
            ),
        ];
        assert_eq!(translate_forward("work", 0, &chain), "final");
    }

    #[test]
    fn a_carry_never_reaches_backwards_past_its_own_epoch() {
        // A revision that RETIRES `work` at epoch 1 and a later one that
        // introduces a fresh `work` at epoch 2: the epoch-2 firing is a
        // different rule that happens to share a retired name, and the epoch-1
        // carry must not touch it. This is the reuse case that an unbounded
        // "apply every carry" translation gets wrong.
        let chain = vec![(
            1,
            vec![RuleCarry {
                from: "work".to_owned(),
                to: "renamed".to_owned(),
            }],
        )];
        assert_eq!(translate_forward("work", 0, &chain), "renamed");
        assert_eq!(translate_forward("work", 1, &chain), "work");
        assert_eq!(translate_forward("work", 2, &chain), "work");
    }

    #[test]
    fn an_untouched_name_translates_to_itself() {
        let chain = vec![(
            1,
            vec![RuleCarry {
                from: "work".to_owned(),
                to: "renamed".to_owned(),
            }],
        )];
        assert_eq!(translate_forward("other", 0, &chain), "other");
    }

    #[test]
    fn a_renamed_rule_is_proposed() {
        let correspondence = derive(&program(&[("work", "a")]), &program(&[("renamed", "a")]));
        assert_eq!(
            correspondence.proposed,
            vec![ProposedRename {
                removed: "rule work".to_owned(),
                added: "rule renamed".to_owned(),
            }]
        );
        assert!(correspondence.refire_sites.is_empty());
    }

    #[test]
    fn a_body_change_under_one_name_is_not_a_candidate() {
        // The identity survives, so it is not a rename however the body moved.
        // It is also already suppressed by the name-keyed filter, which is
        // DR-0043's behaviour and not this module's business.
        let correspondence = derive(&program(&[("work", "a")]), &program(&[("work", "b")]));
        assert_eq!(correspondence, RuleCorrespondence::default());
    }

    #[test]
    fn a_delete_plus_copy_is_proposed_and_that_is_why_it_is_only_evidence() {
        // `work` is deleted; `audit` is added carrying a copy of its body. No
        // content hash can tell this from a rename, so the derivation proposes
        // it -- which is exactly why a proposal may not suppress anything on its
        // own. The operator declines, and `audit` fires as a new rule should.
        let correspondence = derive(&program(&[("work", "a")]), &program(&[("audit", "a")]));
        assert_eq!(
            correspondence.proposed.len(),
            1,
            "indistinguishable by content"
        );
    }

    #[test]
    fn a_swap_yields_no_candidates_at_all() {
        // Both identities are present in both programs, so neither is removed
        // nor added and the framing sees nothing. DR-0077 records this as a
        // known limit rather than claiming coverage it does not have.
        let correspondence = derive(
            &program(&[("a", "one"), ("b", "two")]),
            &program(&[("a", "two"), ("b", "one")]),
        );
        assert_eq!(correspondence, RuleCorrespondence::default());
    }

    #[test]
    fn two_added_rules_sharing_a_hash_are_ambiguous_not_proposed() {
        let correspondence = derive(
            &program(&[("work", "a")]),
            &program(&[("renamed", "a"), ("extra", "a")]),
        );
        assert!(
            correspondence.proposed.is_empty(),
            "never guess between two"
        );
        assert_eq!(correspondence.ambiguous.len(), 1);
        assert_eq!(correspondence.ambiguous[0].added.len(), 2);
    }

    #[test]
    fn a_removed_rule_matching_nothing_is_a_refire_site() {
        let correspondence = derive(&program(&[("work", "a")]), &program(&[("other", "b")]));
        assert_eq!(correspondence.refire_sites, vec!["rule work".to_owned()]);
        assert!(correspondence.proposed.is_empty());
    }

    #[test]
    fn an_uncanonicalizable_program_is_underivable_not_empty() {
        // Canonicalization refuses a program holding two declarations of one
        // identity, since it could not key them apart.
        let duplicated = program(&[("work", "a"), ("work", "b")]);
        let correspondence = derive(&duplicated, &program(&[("work", "a")]));
        assert!(
            correspondence.underivable,
            "distinguish refusal from no matches"
        );
    }
}
