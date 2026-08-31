//! Reading an `.ir` snapshot back into structure.
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
//! quietly.
//!
//! The parser is deliberately total: an unrecognized line is skipped rather than
//! refused. A snapshot is written by a compiler that may be NEWER than the
//! reader — that is the whole reason `reattest_instance_program` exists — so a
//! reader that failed on an unknown section would turn a supported condition
//! into an error, which is the same mistake G1's first draft made.

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

#[cfg(test)]
mod tests {
    use super::*;

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
