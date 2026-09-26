//! The typed ledger query of norm-plane §8 (DR-0098 §6; Q1).
//!
//! One algebra, two types. A *record set* is a set of records as they stand
//! at one frontier; a *region set* is a set of artifact paths at one cut.
//! Both take the set operators `|`, `&` and `-`, and an operator never
//! joins the two: anchoring and dependency are explicit joins — `related`
//! follows a declared relation family's live edges, `members` opens a
//! manifest, `anchored` and `anchors` cross between a region and the
//! requirements whose declared domains cover it. A status predicate names
//! its vocabulary and is checked against that vocabulary's declared domain
//! before any record is matched. Evaluation is pure over a view projected at
//! a named frontier: it runs no check, admits nothing, and reads nothing
//! outside the captured history and the captured artifact. Every result
//! says what it could not see: whether the inventory it read was completely
//! classified, whether the artifact binding was complete, and how many
//! records the view redacted, so an empty result is never read as an empty
//! world.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_core::selection::glob_matches;

use crate::norm::NormRecord;
use crate::norm_resources::ResourceInventory;
use crate::norm_views::{RecordHead, ViewContext};
use crate::{StoreError, StoreResult};

/// A record atom: what a record set is made of.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordAtom {
    /// Every record at the frontier.
    All,
    /// Records of a vocabulary, at any version or at one.
    Vocabulary {
        name: String,
        version: Option<String>,
    },
    /// Records of a vocabulary in a declared status.
    Status {
        vocabulary: String,
        version: Option<String>,
        status: String,
    },
    /// Records with an active effective revision.
    Effective,
    /// One record, by id or ledger-local alias.
    Record(String),
    /// The record one revision belongs to.
    Revision(String),
    /// Records at the far end of a family's live edges from a set.
    Related {
        family: String,
        from: Box<Query>,
        direction: Direction,
    },
    /// The records whose revisions the manifests in a set list.
    Members(Box<Query>),
    /// Requirements whose declared domain covers a path of a region.
    Anchored(Box<Query>),
}

/// A region atom: what a region set is made of.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegionAtom {
    /// Every path of the artifact.
    Workspace,
    /// Paths matching a glob.
    Path(String),
    /// One path.
    File(String),
    /// Every path under a directory.
    Subtree(String),
    /// The paths the requirements in a set are bound to.
    Anchors(Box<Query>),
}

/// Which way a dependency join follows a family's edges.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From sources in the set to their targets.
    Targets,
    /// From targets in the set to their sources.
    Sources,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetOp {
    Union,
    Intersect,
    Difference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Query {
    Records(RecordAtom),
    Regions(RegionAtom),
    Set(SetOp, Box<Query>, Box<Query>),
}

/// The type of a query: which kind of set it denotes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Records,
    Regions,
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Records => "a record set",
            Self::Regions => "a region set",
        })
    }
}

fn refused(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

impl Query {
    /// The type of the query, or the refusal when an operator joins the two
    /// types: they share operators but are different types (§8).
    pub fn type_of(&self) -> StoreResult<QueryType> {
        match self {
            Self::Records(atom) => {
                if let RecordAtom::Related { from, .. } | RecordAtom::Members(from) = atom {
                    expect_type(from, QueryType::Records, "a dependency join")?;
                }
                if let RecordAtom::Anchored(region) = atom {
                    expect_type(region, QueryType::Regions, "anchored")?;
                }
                Ok(QueryType::Records)
            }
            Self::Regions(atom) => {
                if let RegionAtom::Anchors(records) = atom {
                    expect_type(records, QueryType::Records, "anchors")?;
                }
                Ok(QueryType::Regions)
            }
            Self::Set(_, left, right) => {
                let (l, r) = (left.type_of()?, right.type_of()?);
                if l != r {
                    return Err(refused(format!(
                        "region and record sets share operators but are different types: {l} against {r}"
                    )));
                }
                Ok(l)
            }
        }
    }

    /// The canonical spelling of the query.
    pub fn render(&self) -> String {
        match self {
            Self::Records(atom) => match atom {
                RecordAtom::All => "all".into(),
                RecordAtom::Vocabulary { name, version } => match version {
                    Some(version) => format!("vocabulary({name}@{version})"),
                    None => format!("vocabulary({name})"),
                },
                RecordAtom::Status {
                    vocabulary,
                    version,
                    status,
                } => match version {
                    Some(version) => format!("status({vocabulary}@{version}, {status})"),
                    None => format!("status({vocabulary}, {status})"),
                },
                RecordAtom::Effective => "effective".into(),
                RecordAtom::Record(id) => format!("record({id})"),
                RecordAtom::Revision(id) => format!("revision({id})"),
                RecordAtom::Related {
                    family,
                    from,
                    direction,
                } => format!(
                    "related({family}, {}, {})",
                    from.render(),
                    match direction {
                        Direction::Targets => "targets",
                        Direction::Sources => "sources",
                    }
                ),
                RecordAtom::Members(from) => format!("members({})", from.render()),
                RecordAtom::Anchored(region) => format!("anchored({})", region.render()),
            },
            Self::Regions(atom) => match atom {
                RegionAtom::Workspace => "workspace".into(),
                RegionAtom::Path(glob) => format!("path({glob})"),
                RegionAtom::File(path) => format!("file({path})"),
                RegionAtom::Subtree(root) => format!("subtree({root})"),
                RegionAtom::Anchors(records) => format!("anchors({})", records.render()),
            },
            Self::Set(op, left, right) => format!(
                "({} {} {})",
                left.render(),
                match op {
                    SetOp::Union => "|",
                    SetOp::Intersect => "&",
                    SetOp::Difference => "-",
                },
                right.render()
            ),
        }
    }

    /// Whether evaluating the query needs the artifact at a cut.
    pub fn needs_artifact(&self) -> bool {
        match self {
            Self::Records(RecordAtom::Anchored(_)) | Self::Regions(_) => true,
            Self::Records(RecordAtom::Related { from, .. })
            | Self::Records(RecordAtom::Members(from)) => from.needs_artifact(),
            Self::Records(_) => false,
            Self::Set(_, left, right) => left.needs_artifact() || right.needs_artifact(),
        }
    }
}

fn expect_type(query: &Query, wanted: QueryType, what: &str) -> StoreResult<()> {
    let found = query.type_of()?;
    if found != wanted {
        return Err(refused(format!("{what} takes {wanted}, not {found}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsing

/// Parse the query's text: atoms with parenthesized arguments, joined by
/// `|`, `&` and `-`, grouped by parentheses; `-` binds like `&`, and both
/// bind tighter than `|`.
pub fn parse(text: &str) -> StoreResult<Query> {
    let mut parser = Parser {
        chars: text.chars().collect(),
        at: 0,
    };
    let query = parser.union()?;
    parser.skip_space();
    if parser.at < parser.chars.len() {
        return Err(refused(format!(
            "unexpected `{}` at {} in the query",
            parser.chars[parser.at], parser.at
        )));
    }
    query.type_of()?;
    Ok(query)
}

struct Parser {
    chars: Vec<char>,
    at: usize,
}

impl Parser {
    fn skip_space(&mut self) {
        while self.at < self.chars.len() && self.chars[self.at].is_whitespace() {
            self.at += 1;
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.skip_space();
        self.chars.get(self.at).copied()
    }

    fn eat(&mut self, wanted: char) -> StoreResult<()> {
        if self.peek() == Some(wanted) {
            self.at += 1;
            Ok(())
        } else {
            Err(refused(format!(
                "expected `{wanted}` at {} in the query",
                self.at
            )))
        }
    }

    fn union(&mut self) -> StoreResult<Query> {
        let mut left = self.intersection()?;
        while self.peek() == Some('|') {
            self.at += 1;
            let right = self.intersection()?;
            left = Query::Set(SetOp::Union, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn intersection(&mut self) -> StoreResult<Query> {
        let mut left = self.primary()?;
        loop {
            match self.peek() {
                Some('&') => {
                    self.at += 1;
                    let right = self.primary()?;
                    left = Query::Set(SetOp::Intersect, Box::new(left), Box::new(right));
                }
                Some('-') => {
                    self.at += 1;
                    let right = self.primary()?;
                    left = Query::Set(SetOp::Difference, Box::new(left), Box::new(right));
                }
                _ => return Ok(left),
            }
        }
    }

    fn primary(&mut self) -> StoreResult<Query> {
        if self.peek() == Some('(') {
            self.at += 1;
            let inner = self.union()?;
            self.eat(')')?;
            return Ok(inner);
        }
        let name = self.word()?;
        if self.peek() != Some('(') {
            return match name.as_str() {
                "all" => Ok(Query::Records(RecordAtom::All)),
                "effective" => Ok(Query::Records(RecordAtom::Effective)),
                "workspace" => Ok(Query::Regions(RegionAtom::Workspace)),
                other => Err(refused(format!("unknown query atom `{other}`"))),
            };
        }
        self.at += 1;
        let query = match name.as_str() {
            "vocabulary" => {
                let (name, version) = split_version(&self.argument()?);
                Query::Records(RecordAtom::Vocabulary { name, version })
            }
            "status" => {
                let (vocabulary, version) = split_version(&self.argument()?);
                self.eat(',')?;
                let status = self.argument()?;
                Query::Records(RecordAtom::Status {
                    vocabulary,
                    version,
                    status,
                })
            }
            "record" => Query::Records(RecordAtom::Record(self.argument()?)),
            "revision" => Query::Records(RecordAtom::Revision(self.argument()?)),
            "related" => {
                let family = self.argument()?;
                self.eat(',')?;
                let from = self.union()?;
                let direction = if self.peek() == Some(',') {
                    self.at += 1;
                    match self.argument()?.as_str() {
                        "targets" => Direction::Targets,
                        "sources" => Direction::Sources,
                        other => {
                            return Err(refused(format!(
                                "a dependency join follows `targets` or `sources`, not `{other}`"
                            )))
                        }
                    }
                } else {
                    Direction::Targets
                };
                Query::Records(RecordAtom::Related {
                    family,
                    from: Box::new(from),
                    direction,
                })
            }
            "members" => Query::Records(RecordAtom::Members(Box::new(self.union()?))),
            "anchored" => Query::Records(RecordAtom::Anchored(Box::new(self.union()?))),
            "anchors" => Query::Regions(RegionAtom::Anchors(Box::new(self.union()?))),
            "path" => Query::Regions(RegionAtom::Path(self.argument()?)),
            "file" => Query::Regions(RegionAtom::File(self.argument()?)),
            "subtree" => Query::Regions(RegionAtom::Subtree(self.argument()?)),
            other => return Err(refused(format!("unknown query atom `{other}`"))),
        };
        self.eat(')')?;
        Ok(query)
    }

    fn word(&mut self) -> StoreResult<String> {
        self.skip_space();
        let start = self.at;
        while self.at < self.chars.len()
            && (self.chars[self.at].is_alphanumeric() || self.chars[self.at] == '_')
        {
            self.at += 1;
        }
        if start == self.at {
            return Err(refused(format!("expected a query atom at {start}")));
        }
        Ok(self.chars[start..self.at].iter().collect())
    }

    /// A literal argument: everything up to the next `,` or `)` at depth 0.
    fn argument(&mut self) -> StoreResult<String> {
        self.skip_space();
        let start = self.at;
        while self.at < self.chars.len() && !matches!(self.chars[self.at], ',' | ')') {
            self.at += 1;
        }
        let text: String = self.chars[start..self.at]
            .iter()
            .collect::<String>()
            .trim()
            .to_owned();
        if text.is_empty() {
            return Err(refused(format!(
                "expected an argument at {start} in the query"
            )));
        }
        Ok(text)
    }
}

fn split_version(text: &str) -> (String, Option<String>) {
    match text.split_once('@') {
        Some((name, version)) => (name.to_owned(), Some(version.to_owned())),
        None => (text.to_owned(), None),
    }
}

// ---------------------------------------------------------------------------
// Evaluation

/// What a query is evaluated over: the view at its frontier, and — when the
/// query reaches the artifact — the resource inventory bound at a cut and
/// the artifact's paths. `redacted` is how many records the view withheld
/// from this caller; the full-ledger command surface passes zero.
pub struct QueryInput<'a> {
    pub context: &'a ViewContext<'a>,
    pub resources: Option<&'a ResourceInventory>,
    pub artifact_paths: Option<&'a BTreeSet<String>>,
    pub redacted: usize,
}

/// What a result could and could not see.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCompleteness {
    /// Every record in the view has a declared role and interpretable fields.
    pub classification_complete: bool,
    /// The artifact's paths are bound to requirements without gaps, when a
    /// cut was read; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_complete: Option<bool>,
    /// Records the view withheld from the caller.
    pub redacted: usize,
    /// Whether the result may be read as the complete answer.
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMembers {
    Records { heads: Vec<RecordHead> },
    Regions { cut: String, paths: Vec<String> },
}

/// A query's answer at a frontier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResult {
    pub frontier: Vec<String>,
    pub expression: String,
    pub members: QueryMembers,
    pub completeness: QueryCompleteness,
}

#[derive(Debug)]
enum Evaluated {
    Records(BTreeSet<String>),
    Regions(BTreeSet<String>),
}

/// Evaluate a parsed query over its input.
pub fn evaluate(query: &Query, input: &QueryInput<'_>) -> StoreResult<QueryResult> {
    let query_type = query.type_of()?;
    if query.needs_artifact() && (input.resources.is_none() || input.artifact_paths.is_none()) {
        return Err(refused(
            "a query over the artifact needs a resource point: name the cut",
        ));
    }
    let view = input.context.view;
    let evaluated = eval(query, input)?;
    let inventory = view.requirement_inventory()?;
    let mut reasons = Vec::new();
    if !inventory.classification_complete {
        reasons.push("the inventory at this frontier is not completely classified".into());
    }
    let binding_complete = input.resources.map(|resources| resources.binding_complete);
    if binding_complete == Some(false) {
        reasons.push("the artifact's resource binding is incomplete".into());
    }
    if input.redacted > 0 {
        reasons.push(format!(
            "{} record(s) withheld from this view",
            input.redacted
        ));
    }
    let completeness = QueryCompleteness {
        classification_complete: inventory.classification_complete,
        binding_complete,
        redacted: input.redacted,
        complete: reasons.is_empty(),
        reasons,
    };
    let members = match evaluated {
        Evaluated::Records(ids) => QueryMembers::Records {
            heads: ids
                .iter()
                .filter_map(|id| view.records.get(id))
                .map(|record| head_of(input.context, record))
                .collect(),
        },
        Evaluated::Regions(paths) => QueryMembers::Regions {
            cut: input
                .resources
                .map(|resources| resources.artifact.cut.clone())
                .unwrap_or_default(),
            paths: paths.into_iter().collect(),
        },
    };
    debug_assert!(matches!(
        (&members, query_type),
        (QueryMembers::Records { .. }, QueryType::Records)
            | (QueryMembers::Regions { .. }, QueryType::Regions)
    ));
    Ok(QueryResult {
        frontier: view.frontier.iter().cloned().collect(),
        expression: query.render(),
        members,
        completeness,
    })
}

fn head_of(context: &ViewContext<'_>, record: &NormRecord) -> RecordHead {
    RecordHead {
        id: record.id.clone(),
        alias: context.aliases.get(&record.id).cloned(),
        vocabulary: record.vocabulary.clone(),
        revision: record.content_head.clone(),
        status: record.status.clone(),
        head: record.head.clone(),
    }
}

fn eval(query: &Query, input: &QueryInput<'_>) -> StoreResult<Evaluated> {
    match query {
        Query::Records(atom) => eval_records(atom, input).map(Evaluated::Records),
        Query::Regions(atom) => eval_regions(atom, input).map(Evaluated::Regions),
        Query::Set(op, left, right) => {
            let (left, right) = (eval(left, input)?, eval(right, input)?);
            let combine = |l: BTreeSet<String>, r: BTreeSet<String>| match op {
                SetOp::Union => l.union(&r).cloned().collect(),
                SetOp::Intersect => l.intersection(&r).cloned().collect(),
                SetOp::Difference => l.difference(&r).cloned().collect(),
            };
            match (left, right) {
                (Evaluated::Records(l), Evaluated::Records(r)) => {
                    Ok(Evaluated::Records(combine(l, r)))
                }
                (Evaluated::Regions(l), Evaluated::Regions(r)) => {
                    Ok(Evaluated::Regions(combine(l, r)))
                }
                _ => Err(refused(
                    "region and record sets share operators but are different types",
                )),
            }
        }
    }
}

fn records_of(query: &Query, input: &QueryInput<'_>) -> StoreResult<BTreeSet<String>> {
    if query.type_of()? != QueryType::Records {
        return Err(refused("a record set was expected"));
    }
    match eval(query, input)? {
        Evaluated::Records(ids) | Evaluated::Regions(ids) => Ok(ids),
    }
}

fn regions_of(query: &Query, input: &QueryInput<'_>) -> StoreResult<BTreeSet<String>> {
    if query.type_of()? != QueryType::Regions {
        return Err(refused("a region set was expected"));
    }
    match eval(query, input)? {
        Evaluated::Regions(paths) | Evaluated::Records(paths) => Ok(paths),
    }
}

fn eval_records(atom: &RecordAtom, input: &QueryInput<'_>) -> StoreResult<BTreeSet<String>> {
    let context = input.context;
    let view = context.view;
    match atom {
        RecordAtom::All => Ok(view.records.keys().cloned().collect()),
        RecordAtom::Vocabulary { name, version } => Ok(view
            .records
            .values()
            .filter(|record| {
                record.vocabulary.name == *name
                    && version
                        .as_ref()
                        .is_none_or(|version| record.vocabulary.version == *version)
            })
            .map(|record| record.id.clone())
            .collect()),
        RecordAtom::Status {
            vocabulary,
            version,
            status,
        } => {
            // Narrow to the vocabulary and version first, and check the
            // literal against what that declaration admits before matching.
            let declared: Vec<_> = view
                .charter
                .vocabularies
                .iter()
                .filter(|entry| {
                    entry.definition.name == *vocabulary
                        && version
                            .as_ref()
                            .is_none_or(|version| entry.definition.version == *version)
                })
                .collect();
            if declared.is_empty() {
                return Err(refused(format!(
                    "the charter declares no vocabulary `{vocabulary}`{}",
                    version
                        .as_ref()
                        .map(|v| format!(" at version {v}"))
                        .unwrap_or_default()
                )));
            }
            if !declared.iter().any(|entry| {
                entry
                    .definition
                    .status
                    .values
                    .iter()
                    .any(|value| value == status)
            }) {
                return Err(refused(format!(
                    "`{status}` is not a status of vocabulary `{vocabulary}`"
                )));
            }
            Ok(view
                .records
                .values()
                .filter(|record| {
                    record.vocabulary.name == *vocabulary
                        && version
                            .as_ref()
                            .is_none_or(|version| record.vocabulary.version == *version)
                        && record.status == *status
                })
                .map(|record| record.id.clone())
                .collect())
        }
        RecordAtom::Effective => Ok(view.effective_records.keys().cloned().collect()),
        RecordAtom::Record(named) => {
            let id = context
                .aliases
                .iter()
                .find(|(_, alias)| *alias == named)
                .map(|(id, _)| id.clone())
                .unwrap_or_else(|| named.clone());
            if !view.records.contains_key(&id) {
                return Err(refused(format!(
                    "no norm record `{named}` at this frontier"
                )));
            }
            Ok([id].into_iter().collect())
        }
        RecordAtom::Revision(revision) => {
            let record = view.revision(revision).ok_or_else(|| {
                refused(format!(
                    "no admitted revision `{revision}` at this frontier"
                ))
            })?;
            Ok([record.id.clone()].into_iter().collect())
        }
        RecordAtom::Related {
            family,
            from,
            direction,
        } => {
            let from = records_of(from, input)?;
            let edges = view.relation_family(family)?;
            let mut found = BTreeSet::new();
            for edge in &edges.edges {
                let (near, far) = match direction {
                    Direction::Targets => (&edge.source, &edge.target),
                    Direction::Sources => (&edge.target, &edge.source),
                };
                let near_record = view
                    .revision(near)
                    .map(|r| r.id.clone())
                    .unwrap_or_else(|| near.clone());
                if from.contains(&near_record) {
                    let far_record = view
                        .revision(far)
                        .map(|r| r.id.clone())
                        .unwrap_or_else(|| far.clone());
                    found.insert(far_record);
                }
            }
            Ok(found)
        }
        RecordAtom::Members(from) => {
            let from = records_of(from, input)?;
            let mut found = BTreeSet::new();
            for id in &from {
                let Some(record) = view.records.get(id) else {
                    continue;
                };
                let Some(declaration) = view
                    .charter
                    .vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == record.vocabulary.name)
                    .and_then(|entry| entry.manifest.as_ref())
                else {
                    continue;
                };
                for reference in record
                    .fields
                    .get(&declaration.members)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if let Some(member) = view.revision(reference) {
                        found.insert(member.id.clone());
                    }
                }
            }
            Ok(found)
        }
        RecordAtom::Anchored(region) => {
            let paths = regions_of(region, input)?;
            let resources = input
                .resources
                .ok_or_else(|| refused("no resource inventory was captured for this query"))?;
            Ok(resources
                .bindings
                .iter()
                .filter(|(_, binding)| binding.resources.iter().any(|path| paths.contains(path)))
                .map(|(requirement, _)| requirement.clone())
                .collect())
        }
    }
}

fn eval_regions(atom: &RegionAtom, input: &QueryInput<'_>) -> StoreResult<BTreeSet<String>> {
    let paths = input
        .artifact_paths
        .ok_or_else(|| refused("no artifact paths were captured for this query"))?;
    match atom {
        RegionAtom::Workspace => Ok(paths.clone()),
        RegionAtom::Path(glob) => Ok(paths
            .iter()
            .filter(|path| glob_matches(glob, path))
            .cloned()
            .collect()),
        RegionAtom::File(file) => Ok(paths.iter().filter(|path| *path == file).cloned().collect()),
        RegionAtom::Subtree(root) => {
            let root = root.trim_end_matches('/');
            Ok(paths
                .iter()
                .filter(|path| {
                    path.strip_prefix(root)
                        .is_some_and(|rest| rest.starts_with('/'))
                })
                .cloned()
                .collect())
        }
        RegionAtom::Anchors(records) => {
            let records = records_of(records, input)?;
            let resources = input
                .resources
                .ok_or_else(|| refused("no resource inventory was captured for this query"))?;
            Ok(resources
                .bindings
                .iter()
                .filter(|(requirement, _)| records.contains(*requirement))
                .flat_map(|(_, binding)| binding.resources.iter().cloned())
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm::{
        NormAct, NormActor, NormCharter, NormStatement, NormVerifier, NormView, SignedNormEvent,
    };
    use std::collections::BTreeMap;

    /// A verifier that trusts every signature: these tests are about the
    /// query, not custody.
    struct Permissive;

    impl NormVerifier for Permissive {
        fn verify(&self, _: &NormActor, _: &[u8], _: &str) -> Result<(), String> {
            Ok(())
        }
        fn authorize_creation(&self, _: &str, _: &NormActor) -> Result<(), String> {
            Ok(())
        }
    }

    /// A ledger bootstrapped from the bundled charter, and its view.
    fn bootstrapped() -> NormView {
        let mut store = crate::items::WorkItemStore::open_in_memory().expect("a store");
        let charter = NormCharter::bundled().expect("the bundled charter");
        let statement = NormStatement {
            protocol: "whipplescript.norm/v1".into(),
            actor: NormActor {
                principal: "owner".into(),
                algorithm: "fixture".into(),
                key_id: "owner-key".into(),
            },
            nonce: "genesis".into(),
            created_at: "2026-09-23T00:00:00Z".into(),
            action: NormAct::Bootstrap {
                creator: "owner".into(),
                charter,
            },
            premises: None,
        };
        store
            .append_norm_event(
                &SignedNormEvent {
                    statement,
                    signature: "trusted".into(),
                    successor_signature: None,
                },
                &Permissive,
            )
            .expect("bootstraps");
        store.norm_view(&Permissive).expect("a view")
    }

    fn message(result: StoreResult<impl std::fmt::Debug>) -> String {
        format!("{:?}", result.expect_err("a refusal was expected"))
    }

    #[test]
    fn evaluation_refuses_what_it_cannot_answer_by_name() {
        let view = bootstrapped();
        let aliases = BTreeMap::new();
        let manifests = BTreeMap::new();
        let context = ViewContext {
            view: &view,
            aliases: &aliases,
            manifests: &manifests,
        };
        let input = QueryInput {
            context: &context,
            resources: None,
            artifact_paths: None,
            redacted: 0,
        };
        // Nothing is admitted yet: every record set is empty and complete.
        let all = evaluate(&parse("all").unwrap(), &input).unwrap();
        assert!(matches!(&all.members, QueryMembers::Records { heads } if heads.is_empty()));
        assert!(all.completeness.complete);
        assert_eq!(all.completeness.binding_complete, None);
        assert!(message(evaluate(&parse("workspace").unwrap(), &input))
            .contains("a query over the artifact needs a resource point: name the cut"));
        // Bypassing the pre-check reaches the evaluator's own, different words.
        assert!(
            message(eval(&Query::Regions(RegionAtom::Workspace), &input))
                .contains("no artifact paths were captured for this query")
        );
        let paths = BTreeSet::new();
        let with_paths = QueryInput {
            context: &context,
            resources: None,
            artifact_paths: Some(&paths),
            redacted: 0,
        };
        assert!(message(eval(
            &Query::Records(RecordAtom::Anchored(Box::new(Query::Regions(
                RegionAtom::Workspace
            )))),
            &with_paths
        ))
        .contains("no resource inventory was captured for this query"));
        assert!(message(eval(
            &Query::Regions(RegionAtom::Anchors(Box::new(Query::Records(
                RecordAtom::All
            )))),
            &with_paths
        ))
        .contains("no resource inventory was captured for this query"));
        // The typer keeps an operator from crossing the types; handed one
        // directly, the evaluator refuses in its own words.
        let crossed = Query::Set(
            SetOp::Union,
            Box::new(Query::Records(RecordAtom::All)),
            Box::new(Query::Regions(RegionAtom::Workspace)),
        );
        assert!(message(evaluate(&crossed, &input)).contains(
            "region and record sets share operators but are different types: a record set against a region set"
        ));
        assert_eq!(
            message(eval(&crossed, &with_paths)),
            "Conflict(\"region and record sets share operators but are different types\")"
        );
        assert_eq!(
            message(records_of(&Query::Regions(RegionAtom::Workspace), &input)),
            "Conflict(\"a record set was expected\")"
        );
        assert_eq!(
            message(regions_of(&Query::Records(RecordAtom::All), &input)),
            "Conflict(\"a region set was expected\")"
        );
        // A status names its vocabulary, and both must be declared.
        let declared = view
            .charter
            .vocabularies
            .iter()
            .find(|entry| !entry.definition.status.values.is_empty())
            .expect("a vocabulary with statuses");
        let name = declared.definition.name.clone();
        let status = declared.definition.status.values[0].clone();
        let found = evaluate(
            &parse(&format!("status({name}, {status})")).unwrap(),
            &input,
        )
        .unwrap();
        assert!(matches!(&found.members, QueryMembers::Records { heads } if heads.is_empty()));
        assert!(message(evaluate(
            &parse(&format!("status({name}, not-a-status)")).unwrap(),
            &input
        ))
        .contains(&format!(
            "`not-a-status` is not a status of vocabulary `{name}`"
        )));
        assert!(message(evaluate(
            &parse("status(no-such-vocabulary, x)").unwrap(),
            &input
        ))
        .contains("the charter declares no vocabulary `no-such-vocabulary`"));
        assert!(message(evaluate(
            &parse(&format!("status({name}@999, {status})")).unwrap(),
            &input
        ))
        .contains(&format!(
            "the charter declares no vocabulary `{name}` at version 999"
        )));
        assert!(message(evaluate(&parse("record(nobody)").unwrap(), &input))
            .contains("no norm record `nobody` at this frontier"));
        assert!(
            message(evaluate(&parse("revision(nothing)").unwrap(), &input))
                .contains("no admitted revision `nothing` at this frontier")
        );
    }

    #[test]
    fn the_grammar_types_its_operators_and_names_what_it_refuses() {
        let query = parse("vocabulary(task) & status(task, open) | record(T1)").unwrap();
        assert_eq!(
            query.render(),
            "((vocabulary(task) & status(task, open)) | record(T1))"
        );
        assert_eq!(query.type_of().unwrap(), QueryType::Records);
        assert!(!query.needs_artifact());
        let joined =
            parse("related(implementation, anchored(path(src/**)), sources) - effective").unwrap();
        assert!(joined.needs_artifact());
        assert_eq!(
            joined.render(),
            "(related(implementation, anchored(path(src/**)), sources) - effective)"
        );
        assert_eq!(
            parse("anchors(vocabulary(requirement@1))")
                .unwrap()
                .type_of()
                .unwrap(),
            QueryType::Regions
        );
        let mixed = format!(
            "{:?}",
            parse("vocabulary(task) | path(src/**)").unwrap_err()
        );
        assert!(mixed.contains("region and record sets share operators but are different types: a record set against a region set"), "{mixed}");
        let wrong_join = format!("{:?}", parse("members(path(src/**))").unwrap_err());
        assert!(
            wrong_join.contains("a dependency join takes a record set, not a region set"),
            "{wrong_join}"
        );
        let wrong_anchor = format!("{:?}", parse("anchored(vocabulary(task))").unwrap_err());
        assert!(
            wrong_anchor.contains("anchored takes a region set, not a record set"),
            "{wrong_anchor}"
        );
        let unknown = format!("{:?}", parse("claimed").unwrap_err());
        assert!(
            unknown.contains("unknown query atom `claimed`"),
            "{unknown}"
        );
        let trailing = format!("{:?}", parse("all )").unwrap_err());
        assert!(
            trailing.contains("unexpected `)` at 4 in the query"),
            "{trailing}"
        );
        let direction = format!("{:?}", parse("related(work, all, sideways)").unwrap_err());
        assert!(
            direction.contains("a dependency join follows `targets` or `sources`, not `sideways`"),
            "{direction}"
        );
        let empty = format!("{:?}", parse("record()").unwrap_err());
        assert!(
            empty.contains("expected an argument at 7 in the query"),
            "{empty}"
        );
        let missing = format!("{:?}", parse("(all").unwrap_err());
        assert!(
            missing.contains("expected `)` at 4 in the query"),
            "{missing}"
        );
        let bare = format!("{:?}", parse("").unwrap_err());
        assert!(bare.contains("expected a query atom at 0"), "{bare}");
        let atom = format!("{:?}", parse("nonsense(x)").unwrap_err());
        assert!(atom.contains("unknown query atom `nonsense`"), "{atom}");
    }
}
