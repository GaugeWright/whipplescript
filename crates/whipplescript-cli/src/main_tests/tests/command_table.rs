//! `COMMANDS` is the CLI's only statement of its command grammar. These tests
//! hold it to that: every entry is documented and indexed, `whip help` names
//! exactly the dispatchable commands, and `main` dispatches nothing by hand
//! that a reader of the table would not find.
//!
//! The grammar used to be stated four times — the dispatch match, the `whip
//! help` index, the `--help` lookup, and the out-of-line usage consts — and it
//! had drifted: eight dispatched, documented commands (`assert`, `changes`,
//! `credential-proxy`, `ingest`, `provider`, `publish`, `repair`, `undo`) were
//! in no `whip help` group at all, so the index the CLI tells operators to read
//! did not name them.

use super::*;

/// The names `main` still matches by hand. Neither of the first two is a
/// command: `agent` is a rename tombstone that must keep refusing with its own
/// message, and `turn-once` is the internal batch seam a trusted scheduler
/// drives rather than an operator verb. The rest are the help entry points.
/// This list is asserted EXACT, so a command added as a hand-written arm
/// instead of a table entry fails here.
const NON_TABLE_ARMS: &[&str] = &["agent", "turn-once", "help", "--help", "-h"];

/// The group labels rendered by `whip help`, in the order `COMMANDS` first
/// mentions them.
fn rendered_groups() -> Vec<String> {
    let mut groups: Vec<String> = Vec::new();
    for spec in COMMANDS {
        if !groups.iter().any(|group| group == spec.group) {
            groups.push(spec.group.to_owned());
        }
    }
    groups
}

/// The command names the rendered `whip help` index actually lists, read back
/// out of its group lines (not out of `COMMANDS`).
fn indexed_command_names() -> BTreeSet<String> {
    let groups = rendered_groups();
    let text = usage_text();
    let mut names = BTreeSet::new();
    let mut lines_seen = 0usize;
    for line in text.lines() {
        let Some((label, rest)) = line.split_once(':') else {
            continue;
        };
        if !groups.iter().any(|group| group == label) {
            continue;
        }
        lines_seen += 1;
        for name in rest.split_whitespace() {
            if names.insert(name.to_owned()) {
                continue;
            }
            // A repeat is legitimate only when ALSO_LISTED_IN asks for it.
            // The index carried exactly one such entry before the table
            // existed, and losing it is the kind of regression a rewrite of a
            // hand-written list makes silently.
            assert!(
                ALSO_LISTED_IN
                    .iter()
                    .any(|(cross, group)| *cross == name && *group == label),
                "`{name}` is listed twice in the help index without an ALSO_LISTED_IN entry"
            );
        }
    }
    assert_eq!(
        lines_seen,
        groups.len(),
        "every group in the table gets exactly one help line"
    );
    names
}

/// Every entry carries the three things the rest of the CLI reads it for: the
/// `whip help` group, the `--help` text, and a name nothing else claims.
#[test]
fn every_command_entry_has_a_group_and_a_usage_string() {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for spec in COMMANDS {
        assert!(!spec.name.is_empty(), "a command entry has no name");
        assert!(
            seen.insert(spec.name),
            "`{}` appears twice in COMMANDS",
            spec.name
        );
        assert!(
            !spec.group.is_empty(),
            "`{}` has no `whip help` group",
            spec.name
        );
        assert!(
            spec.usage.starts_with("usage: whip "),
            "`{}` has no `--help` usage string (got {:?})",
            spec.name,
            spec.usage
        );
        assert_eq!(
            command_usage(spec.name),
            Some(spec.usage),
            "`whip {} --help` resolves through the table",
            spec.name
        );
    }
    assert!(
        !seen.is_empty(),
        "the command table is the CLI's grammar; it is never empty"
    );
}

/// A group's entries are contiguous, which is what makes "print the groups in
/// first-appearance order" a well-defined rendering: a stray entry filed under
/// an earlier group would otherwise want a second heading for it.
#[test]
fn command_groups_are_contiguous_in_the_table() {
    let mut closed: BTreeSet<&str> = BTreeSet::new();
    let mut current: Option<&str> = None;
    for spec in COMMANDS {
        if current == Some(spec.group) {
            continue;
        }
        if let Some(previous) = current {
            closed.insert(previous);
        }
        assert!(
            !closed.contains(spec.group),
            "group `{}` is split: `{}` is filed under it after the group's block closed",
            spec.group,
            spec.name
        );
        current = Some(spec.group);
    }
}

/// Every deliberate cross-listing names a real command and a group that the
/// table actually renders, and lands under a group that is not the command's
/// own — so the list cannot rot into a duplicate of `group`.
#[test]
fn every_cross_listing_is_a_real_command_in_a_real_group() {
    let groups = rendered_groups();
    for (name, group) in ALSO_LISTED_IN {
        let spec = command_spec(name)
            .unwrap_or_else(|| panic!("`{name}` is cross-listed but is not a command"));
        assert!(
            groups.iter().any(|rendered| rendered == group),
            "`{name}` is cross-listed under `{group}`, which no command table entry names"
        );
        assert_ne!(
            spec.group, *group,
            "`{name}` is cross-listed under its own group"
        );
    }
}

/// The `whip help` index still names `evidence` under `improve`. It did before
/// the command table existed, and a `CommandSpec` carrying exactly one group
/// is precisely what would have dropped it.
#[test]
fn the_improve_group_still_names_evidence() {
    let improve = usage_text()
        .lines()
        .find_map(|line| line.strip_prefix("improve:").map(str::to_owned))
        .expect("`whip help` renders an improve group");
    assert!(
        improve.split_whitespace().any(|name| name == "evidence"),
        "the improve group lost `evidence`: {improve:?}"
    );
}

/// The acceptance the four-way drift broke: the rendered `whip help` index
/// names every dispatchable command, and names nothing that is not one.
#[test]
fn the_help_index_names_every_dispatchable_command() {
    let indexed = indexed_command_names();
    let dispatchable: BTreeSet<String> = COMMANDS.iter().map(|spec| spec.name.to_owned()).collect();

    let missing: Vec<&String> = dispatchable.difference(&indexed).collect();
    assert!(
        missing.is_empty(),
        "dispatchable but absent from the `whip help` index: {missing:?}"
    );
    let phantom: Vec<&String> = indexed.difference(&dispatchable).collect();
    assert!(
        phantom.is_empty(),
        "listed by `whip help` but not dispatchable: {phantom:?}"
    );

    // The eight the index used to hide, named so a future regrouping cannot
    // quietly drop them again.
    for name in [
        "assert",
        "changes",
        "credential-proxy",
        "ingest",
        "provider",
        "publish",
        "repair",
        "undo",
    ] {
        assert!(
            indexed.contains(name),
            "`whip help` must name `{name}`; it was dispatchable and documented but unindexed"
        );
    }
}

/// `main` dispatches by table lookup. The only string arms left in it are the
/// help entry points and the two names that are deliberately not commands — so
/// a command cannot be added in a second place.
#[test]
fn main_dispatches_no_command_outside_the_table() {
    let source = include_str!("../../main.rs");
    let body = source
        .split_once("fn main() -> ExitCode {")
        .expect("main.rs defines `fn main`")
        .1;
    let body = body.split_once("\n}\n").expect("`fn main` closes").0;

    let mut arms: BTreeSet<&str> = BTreeSet::new();
    let mut rest = body;
    while let Some((_, after)) = rest.split_once("Some(\"") {
        let (name, tail) = after.split_once('"').expect("a closed string pattern");
        if tail.starts_with(')') {
            arms.insert(name);
        }
        rest = tail;
    }

    let expected: BTreeSet<&str> = NON_TABLE_ARMS.iter().copied().collect();
    assert_eq!(
        arms, expected,
        "`fn main` matches command names by hand; every command belongs in COMMANDS"
    );
    for name in NON_TABLE_ARMS {
        assert!(
            command_spec(name).is_none(),
            "`{name}` is both a hand-written arm and a table entry"
        );
    }
}
