//! Typed norm compatibility (norm-plane §11.1, slice U1).
//!
//! A norm's typed part is a conjunction of atoms over declared variables with
//! finite domains: Booleans, closed enumerations and bounded integers. Region
//! overlap only nominates norms for comparison; what decides is whether one
//! assignment satisfies every norm that shares a variable, jointly. Pairwise
//! checks are not enough: `x = y`, `y = z` and `x != z` are pairwise
//! satisfiable and jointly inconsistent.
//!
//! The check is bounded and says so. A component whose assignments exceed the
//! budget is `unresolved`, never assumed compatible. A compatible component
//! names its witness assignment; an incompatible one names a minimal subset of
//! its norms that is already inconsistent. Prose outside the typed part is not
//! checked and is reported as such by the caller.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A variable's finite domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Domain {
    Bool,
    Enum { values: Vec<String> },
    Int { min: i64, max: i64 },
}

impl Domain {
    fn values(&self) -> Vec<Value> {
        match self {
            Domain::Bool => vec![Value::Bool(false), Value::Bool(true)],
            Domain::Enum { values } => values.iter().cloned().map(Value::Text).collect(),
            Domain::Int { min, max } => (*min..=*max).map(Value::Int).collect(),
        }
    }
    fn size(&self) -> u128 {
        match self {
            Domain::Bool => 2,
            Domain::Enum { values } => values.len() as u128,
            Domain::Int { min, max } => (i128::from(*max) - i128::from(*min) + 1).max(0) as u128,
        }
    }
}

/// One value of a domain.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Text(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Comparison {
    #[serde(rename = "=")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
}

/// The right side of an atom: another variable or a literal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operand {
    Variable(String),
    Literal(Value),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Atom {
    pub left: String,
    pub comparison: Comparison,
    pub right: Operand,
}

/// One norm's typed part: its variables' domains and its atoms, all of which
/// must hold.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TypedNorm {
    pub variables: BTreeMap<String, Domain>,
    pub atoms: Vec<Atom>,
}

/// How one group of overlapping norms came out.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// One assignment satisfies every norm: the witness.
    Compatible { witness: BTreeMap<String, Value> },
    /// No assignment does; `core` is a minimal inconsistent subset.
    Incompatible { core: Vec<String> },
    /// The check could not decide, and says why.
    Unresolved { reason: String },
}

/// One component: the norms connected through shared variables.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Component {
    pub norms: Vec<String>,
    pub variables: Vec<String>,
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// Parse a norm's declarations and formula.
///
/// Declarations are `name: bool`, `name: enum(a, b)` or `name: int(lo..hi)`,
/// one per entry. The formula is atoms joined by `and`: `left op right`,
/// where `right` is a variable, an integer, `true`/`false`, or a quoted enum
/// value.
pub fn parse(declarations: &[String], formula: &str) -> Result<TypedNorm, String> {
    let mut norm = TypedNorm::default();
    for declaration in declarations {
        let (name, kind) = declaration
            .split_once(':')
            .ok_or_else(|| format!("declaration `{declaration}` needs `name: type`"))?;
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(format!("variable name `{name}` is not an identifier"));
        }
        let kind = kind.trim();
        let domain = if kind == "bool" {
            Domain::Bool
        } else if let Some(values) = kind.strip_prefix("enum(").and_then(|v| v.strip_suffix(')')) {
            let values: Vec<String> = values.split(',').map(|v| v.trim().to_owned()).collect();
            let unique: BTreeSet<&String> = values.iter().collect();
            if values.iter().any(String::is_empty) || unique.len() != values.len() {
                return Err(format!("enum `{name}` needs distinct nonempty values"));
            }
            Domain::Enum { values }
        } else if let Some(range) = kind.strip_prefix("int(").and_then(|v| v.strip_suffix(')')) {
            let (min, max) = range
                .split_once("..")
                .ok_or_else(|| format!("int `{name}` needs `int(lo..hi)`"))?;
            let min: i64 = min
                .trim()
                .parse()
                .map_err(|_| format!("int `{name}` bound"))?;
            let max: i64 = max
                .trim()
                .parse()
                .map_err(|_| format!("int `{name}` bound"))?;
            if min > max {
                return Err(format!("int `{name}` has an empty range"));
            }
            Domain::Int { min, max }
        } else {
            return Err(format!(
                "variable `{name}` has an unsupported type `{kind}`"
            ));
        };
        if norm.variables.insert(name.to_owned(), domain).is_some() {
            return Err(format!("variable `{name}` is declared twice"));
        }
    }
    for atom in formula
        .split(" and ")
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        let (left, comparison, right) = ["!=", "<=", ">=", "=", "<", ">"]
            .iter()
            .find_map(|op| {
                atom.split_once(op).map(|(left, right)| {
                    let comparison = match *op {
                        "=" => Comparison::Eq,
                        "!=" => Comparison::Ne,
                        "<" => Comparison::Lt,
                        "<=" => Comparison::Le,
                        ">" => Comparison::Gt,
                        _ => Comparison::Ge,
                    };
                    (left.trim(), comparison, right.trim())
                })
            })
            .ok_or_else(|| format!("atom `{atom}` has no comparison"))?;
        let domain = norm
            .variables
            .get(left)
            .ok_or_else(|| format!("atom `{atom}` uses undeclared `{left}`"))?
            .clone();
        let operand = if let Some(text) = right.strip_prefix('"').and_then(|r| r.strip_suffix('"'))
        {
            Operand::Literal(Value::Text(text.to_owned()))
        } else if right == "true" || right == "false" {
            Operand::Literal(Value::Bool(right == "true"))
        } else if let Ok(number) = right.parse::<i64>() {
            Operand::Literal(Value::Int(number))
        } else {
            let other = norm
                .variables
                .get(right)
                .ok_or_else(|| format!("atom `{atom}` uses undeclared `{right}`"))?;
            if std::mem::discriminant(other) != std::mem::discriminant(&domain) {
                return Err(format!(
                    "atom `{atom}` compares variables of different types"
                ));
            }
            Operand::Variable(right.to_owned())
        };
        let ordered = matches!(
            comparison,
            Comparison::Lt | Comparison::Le | Comparison::Gt | Comparison::Ge
        );
        if ordered && !matches!(domain, Domain::Int { .. }) {
            return Err(format!("atom `{atom}` orders a non-integer variable"));
        }
        norm.atoms.push(Atom {
            left: left.to_owned(),
            comparison,
            right: operand,
        });
    }
    Ok(norm)
}

fn holds(norm: &TypedNorm, assignment: &BTreeMap<String, Value>) -> bool {
    norm.atoms.iter().all(|atom| {
        let left = &assignment[&atom.left];
        let right = match &atom.right {
            Operand::Variable(name) => &assignment[name],
            Operand::Literal(value) => value,
        };
        match atom.comparison {
            Comparison::Eq => left == right,
            Comparison::Ne => left != right,
            Comparison::Lt => left < right,
            Comparison::Le => left <= right,
            Comparison::Gt => left > right,
            Comparison::Ge => left >= right,
        }
    })
}

/// A model of every one of these norms, by bounded enumeration, or `None`.
/// `Err` when the assignments exceed the budget.
fn model(
    norms: &[&TypedNorm],
    variables: &BTreeMap<String, Domain>,
    budget: u128,
) -> Result<Option<BTreeMap<String, Value>>, String> {
    let space = variables
        .values()
        .try_fold(1u128, |space, domain| space.checked_mul(domain.size()))
        .unwrap_or(u128::MAX);
    if space > budget {
        return Err(format!(
            "{space} assignments exceed the bounded check's budget of {budget}"
        ));
    }
    let names: Vec<&String> = variables.keys().collect();
    let domains: Vec<Vec<Value>> = variables.values().map(Domain::values).collect();
    let mut index = vec![0usize; names.len()];
    loop {
        let assignment: BTreeMap<String, Value> = names
            .iter()
            .zip(&index)
            .zip(&domains)
            .map(|((name, at), values)| ((*name).clone(), values[*at].clone()))
            .collect();
        if norms.iter().all(|norm| holds(norm, &assignment)) {
            return Ok(Some(assignment));
        }
        let mut position = 0;
        loop {
            if position == index.len() {
                return Ok(None);
            }
            index[position] += 1;
            if index[position] < domains[position].len() {
                break;
            }
            index[position] = 0;
            position += 1;
        }
    }
}

/// Check norms jointly within each group that shares a variable. Norms whose
/// variables' declarations disagree cannot be compared, and say so.
pub fn check(norms: &BTreeMap<String, TypedNorm>, budget: u128) -> Vec<Component> {
    check_with(norms, budget, &|_, _| true)
}

/// As `check`, comparing two norms only where `comparable` says their
/// regions overlap: overlap nominates norms for comparison and decides
/// nothing itself.
pub fn check_with(
    norms: &BTreeMap<String, TypedNorm>,
    budget: u128,
    comparable: &dyn Fn(&str, &str) -> bool,
) -> Vec<Component> {
    // Components: norms connected through a shared variable name.
    let ids: Vec<&String> = norms.keys().collect();
    let mut group: BTreeMap<&String, usize> =
        ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let find = |group: &BTreeMap<&String, usize>, id: &String| group[id];
    for (i, a) in ids.iter().enumerate() {
        for b in &ids[i + 1..] {
            let shared = comparable(a, b)
                && norms[*a]
                    .variables
                    .keys()
                    .any(|name| norms[*b].variables.contains_key(name));
            if shared {
                let (from, to) = (find(&group, b), find(&group, a));
                for value in group.values_mut() {
                    if *value == from {
                        *value = to;
                    }
                }
            }
        }
    }
    let mut components: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (id, root) in &group {
        components.entry(*root).or_default().push((*id).clone());
    }
    components
        .into_values()
        .map(|members| {
            let mut variables: BTreeMap<String, Domain> = BTreeMap::new();
            let mut clash = None;
            for member in &members {
                for (name, domain) in &norms[member].variables {
                    match variables.get(name) {
                        Some(existing) if existing != domain => {
                            clash =
                                Some(format!("`{name}` is declared with two different domains"));
                        }
                        _ => {
                            variables.insert(name.clone(), domain.clone());
                        }
                    }
                }
            }
            let outcome = match clash {
                Some(reason) => Outcome::Unresolved { reason },
                None => {
                    let all: Vec<&TypedNorm> = members.iter().map(|m| &norms[m]).collect();
                    match model(&all, &variables, budget) {
                        Err(reason) => Outcome::Unresolved { reason },
                        Ok(Some(witness)) => Outcome::Compatible { witness },
                        Ok(None) => {
                            // Shrink to a minimal inconsistent core by
                            // deletion: drop a norm whenever the rest stays
                            // inconsistent.
                            let mut core = members.clone();
                            let mut at = 0;
                            while at < core.len() {
                                let rest: Vec<String> = core
                                    .iter()
                                    .enumerate()
                                    .filter(|(i, _)| *i != at)
                                    .map(|(_, m)| m.clone())
                                    .collect();
                                let norms_rest: Vec<&TypedNorm> =
                                    rest.iter().map(|m| &norms[m]).collect();
                                let vars_rest: BTreeMap<String, Domain> = variables
                                    .iter()
                                    .filter(|(name, _)| {
                                        norms_rest.iter().any(|n| n.variables.contains_key(*name))
                                    })
                                    .map(|(name, domain)| (name.clone(), domain.clone()))
                                    .collect();
                                if matches!(model(&norms_rest, &vars_rest, budget), Ok(None)) {
                                    core = rest;
                                } else {
                                    at += 1;
                                }
                            }
                            Outcome::Incompatible { core }
                        }
                    }
                }
            };
            Component {
                variables: variables.keys().cloned().collect(),
                norms: members,
                outcome,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(declarations: &[&str], formula: &str) -> TypedNorm {
        parse(
            &declarations
                .iter()
                .map(|d| (*d).to_owned())
                .collect::<Vec<_>>(),
            formula,
        )
        .unwrap()
    }

    #[test]
    fn a_pairwise_compatible_triple_is_jointly_inconsistent() {
        let bools = ["x: bool", "y: bool", "z: bool"];
        let norms = BTreeMap::from([
            ("a".to_owned(), norm(&bools, "x = y")),
            ("b".to_owned(), norm(&bools, "y = z")),
            ("c".to_owned(), norm(&bools, "x != z")),
        ]);
        // Every pair has a model.
        for (left, right) in [("a", "b"), ("a", "c"), ("b", "c")] {
            let pair: BTreeMap<String, TypedNorm> = [left, right]
                .iter()
                .map(|id| ((*id).to_owned(), norms[*id].clone()))
                .collect();
            assert!(matches!(
                check(&pair, 1024)[0].outcome,
                Outcome::Compatible { .. }
            ));
        }
        let joint = check(&norms, 1024);
        assert_eq!(joint.len(), 1);
        assert_eq!(
            joint[0].outcome,
            Outcome::Incompatible {
                core: vec!["a".into(), "b".into(), "c".into()]
            }
        );
    }

    #[test]
    fn overlap_that_agrees_is_compatible_with_a_witness_and_a_core_is_minimal() {
        let norms = BTreeMap::from([
            (
                "strict".to_owned(),
                norm(&["mode: enum(strict, lax)"], "mode = \"strict\""),
            ),
            (
                "ceiling".to_owned(),
                norm(&["limit: int(0..10)"], "limit <= 5"),
            ),
            (
                "floor".to_owned(),
                norm(&["limit: int(0..10)"], "limit >= 3"),
            ),
            ("separate".to_owned(), norm(&["on: bool"], "on = true")),
        ]);
        let components = check(&norms, 1024);
        assert_eq!(components.len(), 3, "{components:?}");
        let limits = components
            .iter()
            .find(|c| c.variables == ["limit"])
            .unwrap();
        let Outcome::Compatible { witness } = &limits.outcome else {
            panic!("{limits:?}");
        };
        assert_eq!(witness["limit"], Value::Int(3));
        // Adding a conflicting norm leaves the agreeing one out of the core.
        let mut conflicting = norms.clone();
        conflicting.insert(
            "ceiling-2".into(),
            norm(&["limit: int(0..10)"], "limit <= 2"),
        );
        let limits = check(&conflicting, 1024)
            .into_iter()
            .find(|c| c.variables == ["limit"])
            .unwrap();
        assert_eq!(
            limits.outcome,
            Outcome::Incompatible {
                core: vec!["ceiling-2".into(), "floor".into()]
            }
        );
    }

    #[test]
    fn beyond_its_budget_or_across_disagreeing_domains_the_check_is_unresolved() {
        let wide = BTreeMap::from([(
            "a".to_owned(),
            norm(&["n: int(0..1000)", "m: int(0..1000)"], "n = m"),
        )]);
        assert!(matches!(
            check(&wide, 1024)[0].outcome,
            Outcome::Unresolved { .. }
        ));
        let clash = BTreeMap::from([
            ("a".to_owned(), norm(&["v: bool"], "v = true")),
            ("b".to_owned(), norm(&["v: int(0..3)"], "v = 1")),
        ]);
        assert!(matches!(
            check(&clash, 1024)[0].outcome,
            Outcome::Unresolved { .. }
        ));
    }

    #[test]
    fn typed_parts_refuse_what_they_cannot_type() {
        // Each refusal names its own reason, so a refusal that stopped
        // happening is not hidden behind a later one.
        let refused = |declarations: &[&str], formula: &str| {
            parse(
                &declarations
                    .iter()
                    .map(|d| (*d).to_owned())
                    .collect::<Vec<_>>(),
                formula,
            )
            .expect_err("refused")
        };
        for (declarations, formula, why) in [
            (&["x: float"][..], "", "unsupported type `float`"),
            (&["x y: bool"], "x y = true", "`x y` is not an identifier"),
            (&[": bool"], "", "`` is not an identifier"),
            (&["x bool"], "", "needs `name: type`"),
            (&["x: bool", "x: bool"], "", "declared twice"),
            (&["n: int(3..1)"], "", "empty range"),
            (&["e: enum(a, a)"], "", "distinct nonempty values"),
        ] {
            let refusal = refused(declarations, formula);
            assert!(refusal.contains(why), "{why}: {refusal}");
        }
        for (declarations, formula) in [
            (&["x: bool"][..], "y = true"),
            (&["x: bool", "n: int(0..3)"], "x = n"),
            (&["x: bool"], "x < true"),
        ] {
            refused(declarations, formula);
        }
    }
}
