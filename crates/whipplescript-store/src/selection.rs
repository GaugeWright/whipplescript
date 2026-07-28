//! The provenance-native selection algebra (vw note §7.3; untie
//! readiness tracker Phase 2): a revset-shaped composable expression
//! language over recorded change-units, feeding the three selective
//! verbs (`undo <selection>`, `transport <selection>`, `adopt --only`)
//! and the archaeology queries.
//!
//! Grammar (union `|` loosest, then difference `~`, then intersection
//! `&`, parens group):
//!
//! ```text
//! expr   := diff ( '|' diff )*
//! diff   := inter ( '~' inter )*
//! inter  := prim ( '&' prim )*
//! prim   := atom | '(' expr ')'
//! atom   := path(<glob>) | by-effect(<prefix>) | by-origin(<prefix>)
//!         | in-branch(<id>) | change(<id>) | cut(<id>)
//!         | since(<stamp>) | until(<stamp>) | dependents-of(expr)
//! ```
//!
//! The unit of selection is one recorded write: (cut, path,
//! before → after), derived from cut lineage. `dependents-of` is the
//! slicer seam's conservative floor: path-level dependence (a later
//! unit on the same path consumed the earlier one's output). The
//! declaration/slice-granularity atoms (`decl(...)`, `slice-of(...)`)
//! arrive when the slicer joins as this algebra's client — the grammar
//! is closed under adding atoms.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One recorded change-unit: what one cut did to one path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChangeUnit {
    /// Position in the branch's cut order, oldest first — the
    /// dependence direction.
    pub seq: usize,
    pub cut_id: String,
    pub change_id: String,
    pub branch_id: String,
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub origin: Option<String>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelExpr {
    Union(Box<SelExpr>, Box<SelExpr>),
    Intersect(Box<SelExpr>, Box<SelExpr>),
    Difference(Box<SelExpr>, Box<SelExpr>),
    Atom(SelAtom),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelAtom {
    Path(String),
    ByEffect(String),
    ByOrigin(String),
    InBranch(String),
    Change(String),
    Cut(String),
    Since(String),
    Until(String),
    DependentsOf(Box<SelExpr>),
}

/// Parse a selection expression. Errors carry the offending position's
/// remainder — enough for a CLI message.
pub fn parse(input: &str) -> Result<SelExpr, String> {
    let mut parser = Parser {
        rest: input.trim(),
        depth: 0,
    };
    let expr = parser.expr()?;
    if !parser.rest.is_empty() {
        return Err(format!("unexpected trailing input: `{}`", parser.rest));
    }
    Ok(expr)
}

/// Recursion-depth ceiling for the selection grammar. Every `(` and
/// `dependents-of(...)` nesting level descends through `prim`, so bounding it
/// there returns an ordinary `Err` on a pathologically nested selection
/// expression (a CLI arg) instead of overflowing the stack. Far above any real
/// selection.
const MAX_SELECTION_DEPTH: usize = 256;

struct Parser<'a> {
    rest: &'a str,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn eat(&mut self, token: char) -> bool {
        self.skip_ws();
        if let Some(stripped) = self.rest.strip_prefix(token) {
            self.rest = stripped;
            true
        } else {
            false
        }
    }

    fn expr(&mut self) -> Result<SelExpr, String> {
        let mut left = self.diff()?;
        while self.eat('|') {
            let right = self.diff()?;
            left = SelExpr::Union(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn diff(&mut self) -> Result<SelExpr, String> {
        let mut left = self.inter()?;
        while self.eat('~') {
            let right = self.inter()?;
            left = SelExpr::Difference(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn inter(&mut self) -> Result<SelExpr, String> {
        let mut left = self.prim()?;
        while self.eat('&') {
            let right = self.prim()?;
            left = SelExpr::Intersect(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn prim(&mut self) -> Result<SelExpr, String> {
        self.depth += 1;
        if self.depth > MAX_SELECTION_DEPTH {
            self.depth -= 1;
            return Err(format!(
                "selection expression is nested too deeply (limit {MAX_SELECTION_DEPTH})"
            ));
        }
        let result = self.prim_inner();
        self.depth -= 1;
        result
    }

    fn prim_inner(&mut self) -> Result<SelExpr, String> {
        self.skip_ws();
        if self.eat('(') {
            let inner = self.expr()?;
            if !self.eat(')') {
                return Err(format!("expected `)` at `{}`", self.rest));
            }
            return Ok(inner);
        }
        let name_len = self
            .rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(self.rest.len());
        let name = &self.rest[..name_len];
        if name.is_empty() {
            return Err(format!("expected a selection atom at `{}`", self.rest));
        }
        self.rest = &self.rest[name_len..];
        if !self.eat('(') {
            return Err(format!("expected `(` after `{name}`"));
        }
        if name == "dependents-of" {
            let inner = self.expr()?;
            if !self.eat(')') {
                return Err(format!("expected `)` at `{}`", self.rest));
            }
            return Ok(SelExpr::Atom(SelAtom::DependentsOf(Box::new(inner))));
        }
        // A plain-argument atom: the argument runs to the matching `)`.
        let close = self
            .rest
            .find(')')
            .ok_or_else(|| format!("unterminated `{name}(`"))?;
        let arg = self.rest[..close].trim().to_owned();
        self.rest = &self.rest[close + 1..];
        let atom = match name {
            "path" => SelAtom::Path(arg),
            "by-effect" => SelAtom::ByEffect(arg),
            "by-origin" => SelAtom::ByOrigin(arg),
            "in-branch" => SelAtom::InBranch(arg),
            "change" => SelAtom::Change(arg),
            "cut" => SelAtom::Cut(arg),
            "since" => SelAtom::Since(arg),
            "until" => SelAtom::Until(arg),
            other => return Err(format!("unknown selection atom `{other}`")),
        };
        Ok(SelExpr::Atom(atom))
    }
}

/// A `*`/`?` glob match (segments are not special: `*` crosses `/`,
/// matching the whole-path selection intent).
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    // Iterative two-pointer glob with single-star backtracking: O(len(pattern)
    // * len(value)) worst case. The prior recursion was `*`-splits with no
    // memoization, so a pattern with interleaved stars against a non-matching
    // value (e.g. `a*a*a*...*Z` vs `aaaa...`) backtracked exponentially and hung
    // the process on an operator/agent-supplied `path(<glob>)` atom.
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0usize, 0usize);
    // The last `*` seen and the value position to resume from if the tail fails.
    let (mut star, mut resume) = (None, 0usize);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            // Record this star and provisionally match zero characters.
            star = Some(p);
            resume = v;
            p += 1;
        } else if let Some(star_p) = star {
            // Mismatch: let the last star absorb one more value byte.
            p = star_p + 1;
            resume += 1;
            v = resume;
        } else {
            return false;
        }
    }
    // Trailing pattern must be all stars to match the consumed value.
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Evaluate an expression over a change-unit universe, returning the
/// selected indices.
pub fn eval(expr: &SelExpr, universe: &[ChangeUnit]) -> BTreeSet<usize> {
    match expr {
        SelExpr::Union(a, b) => eval(a, universe)
            .union(&eval(b, universe))
            .copied()
            .collect(),
        SelExpr::Intersect(a, b) => eval(a, universe)
            .intersection(&eval(b, universe))
            .copied()
            .collect(),
        SelExpr::Difference(a, b) => eval(a, universe)
            .difference(&eval(b, universe))
            .copied()
            .collect(),
        SelExpr::Atom(atom) => eval_atom(atom, universe),
    }
}

fn eval_atom(atom: &SelAtom, universe: &[ChangeUnit]) -> BTreeSet<usize> {
    let pick = |predicate: &dyn Fn(&ChangeUnit) -> bool| -> BTreeSet<usize> {
        universe
            .iter()
            .enumerate()
            .filter(|(_, unit)| predicate(unit))
            .map(|(index, _)| index)
            .collect()
    };
    match atom {
        SelAtom::Path(glob) => pick(&|unit| glob_matches(glob, &unit.path)),
        SelAtom::ByEffect(prefix) => pick(&|unit| unit.cut_id.starts_with(prefix.as_str())),
        SelAtom::ByOrigin(prefix) => pick(&|unit| {
            unit.origin
                .as_deref()
                .is_some_and(|origin| origin.starts_with(prefix.as_str()))
        }),
        SelAtom::InBranch(branch) => pick(&|unit| unit.branch_id == *branch),
        SelAtom::Change(change) => pick(&|unit| unit.change_id == *change),
        SelAtom::Cut(cut) => pick(&|unit| unit.cut_id == *cut),
        SelAtom::Since(stamp) => pick(&|unit| unit.recorded_at.as_str() >= stamp.as_str()),
        SelAtom::Until(stamp) => pick(&|unit| unit.recorded_at.as_str() <= stamp.as_str()),
        SelAtom::DependentsOf(inner) => {
            // The conservative dependence floor: a later unit on the
            // same path consumed the earlier one's output. Closure over
            // the universe; includes the seeds.
            let seeds = eval(inner, universe);
            let mut selected = seeds.clone();
            for &seed in &seeds {
                let seed_unit = &universe[seed];
                for (index, unit) in universe.iter().enumerate() {
                    if unit.path == seed_unit.path && unit.seq > seed_unit.seq {
                        selected.insert(index);
                    }
                }
            }
            selected
        }
    }
}

/// The stranding check (selective-undo.maude, the slicer's 7th client at
/// its path-level floor): undoing `selected` strands every RETAINED
/// later unit whose path input came from an undone write. Returns the
/// stranded indices — empty means the exclusion's dependency closure is
/// clean and the proposal is safe.
pub fn stranded_by_undo(selected: &BTreeSet<usize>, universe: &[ChangeUnit]) -> BTreeSet<usize> {
    let mut stranded = BTreeSet::new();
    for &chosen in selected {
        let undone = &universe[chosen];
        for (index, unit) in universe.iter().enumerate() {
            if unit.path == undone.path && unit.seq > undone.seq && !selected.contains(&index) {
                stranded.insert(index);
            }
        }
    }
    stranded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(seq: usize, cut: &str, path: &str, at: &str) -> ChangeUnit {
        ChangeUnit {
            seq,
            cut_id: cut.to_owned(),
            change_id: cut.to_owned(),
            branch_id: "b1".to_owned(),
            path: path.to_owned(),
            before: None,
            after: Some(format!("h{seq}")),
            origin: Some(format!("write:{path}")),
            recorded_at: at.to_owned(),
        }
    }

    #[test]
    fn grammar_parses_composition_with_precedence() {
        let expr = parse("path(src/*.md) & since(t3) | by-effect(eff_) ~ cut(c9)").expect("parse");
        // `|` binds loosest: (path & since) | (by-effect ~ cut).
        let SelExpr::Union(left, right) = expr else {
            panic!("expected a union at the top");
        };
        assert!(matches!(*left, SelExpr::Intersect(..)));
        assert!(matches!(*right, SelExpr::Difference(..)));
        assert!(parse("path(unclosed").is_err());
        assert!(parse("nonsense(x)").is_err());
        assert!(parse("path(a) extra").is_err());
    }

    #[test]
    fn deeply_nested_selection_errors_instead_of_overflowing_the_stack() {
        // A pathologically nested selection expression (a CLI arg) must return
        // a normal Err, not abort the process. Run on a production-sized stack.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let deep = format!("{}path(a){}", "(".repeat(4000), ")".repeat(4000));
                let result = parse(&deep);
                assert!(
                    result
                        .as_ref()
                        .err()
                        .is_some_and(|message| message.contains("nested too deeply")),
                    "expected a depth-limit diagnostic, got {result:?}"
                );
                let ok = format!("{}path(a){}", "(".repeat(64), ")".repeat(64));
                assert!(parse(&ok).is_ok(), "64-deep nesting must parse");
            })
            .expect("spawn")
            .join()
            .expect("nested-selection parse must not crash");
    }

    #[test]
    fn atoms_select_by_provenance_dimensions() {
        let universe = vec![
            unit(0, "eff_1-f0", "src/a.md", "t1"),
            unit(1, "eff_2-f0", "src/b.md", "t2"),
            unit(2, "cut_x", "notes/c.txt", "t3"),
        ];
        let by_path = eval(&parse("path(src/*.md)").expect("parse"), &universe);
        assert_eq!(by_path, BTreeSet::from([0, 1]));
        let by_effect = eval(&parse("by-effect(eff_2)").expect("parse"), &universe);
        assert_eq!(by_effect, BTreeSet::from([1]));
        let since = eval(&parse("since(t2)").expect("parse"), &universe);
        assert_eq!(since, BTreeSet::from([1, 2]));
        let composed = eval(
            &parse("path(src/*.md) ~ by-effect(eff_2)").expect("parse"),
            &universe,
        );
        assert_eq!(composed, BTreeSet::from([0]));
        let grouped = eval(
            &parse("(path(src/*.md) | path(notes/*)) & until(t2)").expect("parse"),
            &universe,
        );
        assert_eq!(grouped, BTreeSet::from([0, 1]));
    }

    /// The model's fixture, verbatim: e1 wrote p1; e2, e3 wrote p2.
    /// Undoing p1 strands e3's path-level input? No — path-level
    /// dependence binds within a path: undoing e2 strands e3 (later on
    /// p2, retained); undoing p2 entirely (e2 AND e3) strands nothing;
    /// dependents-of(e2) pulls e3 into the selection.
    #[test]
    fn stranding_and_dependents_mirror_the_model() {
        let universe = vec![
            unit(0, "e1", "p1", "t1"),
            unit(1, "e2", "p2", "t2"),
            unit(2, "e3", "p2", "t3"),
        ];
        // Undo e2 alone: e3 is retained and read e2's output — stranded.
        let sel = eval(&parse("cut(e2)").expect("parse"), &universe);
        assert_eq!(stranded_by_undo(&sel, &universe), BTreeSet::from([2]));
        // Undo the whole path: the reader is inside the selection.
        let sel = eval(&parse("path(p2)").expect("parse"), &universe);
        assert!(stranded_by_undo(&sel, &universe).is_empty());
        // The closure operator repairs the stranding selection.
        let sel = eval(&parse("dependents-of(cut(e2))").expect("parse"), &universe);
        assert_eq!(sel, BTreeSet::from([1, 2]));
        assert!(stranded_by_undo(&sel, &universe).is_empty());
        // Undoing e1 strands nothing: nothing later touched p1.
        let sel = eval(&parse("cut(e1)").expect("parse"), &universe);
        assert!(stranded_by_undo(&sel, &universe).is_empty());
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_matches("src/*.md", "src/deep/a.md"));
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "ac"));
        assert!(!glob_matches("src/*.md", "src/a.txt"));
        // Multi-star and edge forms the two-pointer matcher must still get right.
        assert!(glob_matches("a*b*c", "axxbyyc"));
        assert!(glob_matches("**", "anything"));
        assert!(glob_matches("*.md", ".md"));
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "x"));
        assert!(!glob_matches("a*b", "axxbx")); // trailing literal must anchor
        assert!(glob_matches("a*b", "ab"));
    }

    #[test]
    fn glob_worst_case_is_linear_not_exponential() {
        // The classic exponential-backtracking trigger: many stars interleaved
        // with a literal that never appears in a long value. The linear matcher
        // returns promptly; the old recursion hung for effectively forever.
        let pattern = "a*".repeat(30) + "Z";
        let value = "a".repeat(60);
        assert!(!glob_matches(&pattern, &value));
    }
}
