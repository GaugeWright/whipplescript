//! The labeled action graph of DR-0124 §14.2 at the wrapper.
//!
//! Three things live here, all pure: the Home's label policy over a cut's
//! paths and which principal holds which labels; a principal's projection of
//! a cut — the manifest their labels permit, identified by its own digest,
//! naming the regions it could not observe; and the classification of a
//! build result by everything that shaped it. The classification is the
//! package ceiling, the outcome the qualification experiment chose: an
//! action's result is classified by the join of the labels of every path in
//! its package's listing — what its build file's globs could observe,
//! membership and absence included — of every rule file that build file
//! loads, and of its inputs, for the target and every target it depends on.
//! A rule's declared label never narrows that; refusal is reported as a
//! refusal, and what a view could not observe is unobserved, never absent.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// A labeled region of a cut: the path `prefix` itself and every path under
/// it carry `label`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Region {
    pub prefix: String,
    pub label: String,
}

/// The Home's label policy over a cut's paths. A path outside every region
/// carries no label and is readable by every principal.
#[derive(Clone, Debug, Default)]
pub(crate) struct LabelPolicy {
    regions: Vec<Region>,
}

impl LabelPolicy {
    pub fn new(regions: Vec<Region>) -> Result<Self, String> {
        for region in &regions {
            if region.prefix.trim().is_empty() || region.label.trim().is_empty() {
                return Err("a labeled region needs a nonempty prefix and a nonempty label".into());
            }
        }
        Ok(Self { regions })
    }

    /// Every label the policy declares: the organization-wide ceiling.
    pub fn labels(&self) -> BTreeSet<String> {
        self.regions.iter().map(|r| r.label.clone()).collect()
    }

    pub fn labels_of(&self, path: &str) -> BTreeSet<String> {
        self.regions
            .iter()
            .filter(|region| in_region(path, &region.prefix))
            .map(|region| region.label.clone())
            .collect()
    }

    /// The region prefixes a principal's labels do not permit.
    pub fn hidden_from(&self, principal: &Principal) -> Vec<String> {
        let mut hidden: Vec<String> = self
            .regions
            .iter()
            .filter(|region| !principal.labels.contains(&region.label))
            .map(|region| region.prefix.clone())
            .collect();
        hidden.sort();
        hidden.dedup();
        hidden
    }
}

fn in_region(path: &str, prefix: &str) -> bool {
    path == prefix
        || path.starts_with(prefix)
            && (prefix.ends_with('/') || path[prefix.len()..].starts_with('/'))
}

/// A principal the wrapper acts for: a trust binding and the labels it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Principal {
    pub name: String,
    pub labels: BTreeSet<String>,
}

impl Principal {
    pub fn holds(&self, labels: &BTreeSet<String>) -> bool {
        labels.is_subset(&self.labels)
    }
}

/// A principal's view of a cut: the paths their labels permit, identified
/// by the digest of exactly those entries, and the regions they could not
/// observe — named by prefix, never by what the regions contain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Projection {
    pub id: String,
    pub include: BTreeSet<String>,
    pub unobserved: Vec<String>,
}

pub(crate) const PROJECTION_PREFIX: &str = "projection:";

pub(crate) fn project(
    manifest: &BTreeMap<String, String>,
    policy: &LabelPolicy,
    principal: &Principal,
) -> Projection {
    let mut hash = Sha256::new();
    let mut include = BTreeSet::new();
    for (path, digest) in manifest {
        if principal.holds(&policy.labels_of(path)) {
            hash.update(path.as_bytes());
            hash.update(b"\0");
            hash.update(digest.as_bytes());
            hash.update(b"\n");
            include.insert(path.clone());
        }
    }
    Projection {
        id: format!("{PROJECTION_PREFIX}{}", hex(&hash.finalize())),
        include,
        unobserved: policy.hidden_from(principal),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One `[section]` of a `.buckconfig`: its `key = value` lines.
fn config_section(text: &str, section: &str) -> Vec<(String, String)> {
    let mut in_section = false;
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == format!("[{section}]");
            continue;
        }
        if in_section {
            if let Some((key, value)) = line.split_once('=') {
                entries.push((key.trim().to_owned(), value.trim().to_owned()));
            }
        }
    }
    entries
}

/// The names that make a file a build file, from a cell's `.buckconfig`
/// (`[buildfile] name = …`), or Buck2's defaults when it names none.
pub(crate) fn build_file_names(buckconfig: Option<&str>) -> Vec<String> {
    if let Some(text) = buckconfig {
        for (key, value) in config_section(text, "buildfile") {
            if key == "name" && !value.is_empty() {
                return vec![value];
            }
        }
    }
    ["BUCK", "BUCK.v2", "TARGETS", "TARGETS.v2"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// The cells of a tree: the explicit mapping from a cell's name to its
/// directory (GaugeWright DR-0125), read from the root `.buckconfig`'s
/// `[cells]`, with each cell's build-file names from its own `.buckconfig`.
/// A tree that declares no cells is one root cell. A path belongs to the
/// innermost cell whose directory holds it, and a cell's globs stop at a
/// nested cell's boundary, so its listing does too.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Cells {
    /// (name, directory relative to the root, `""` for the root cell),
    /// innermost first.
    dirs: Vec<(String, String)>,
    build_files: BTreeMap<String, Vec<String>>,
}

pub(crate) const ROOT_CELL: &str = "root";

impl Cells {
    /// From the root `.buckconfig` and a reader for each cell's own.
    pub fn from_configs(root: Option<&str>, read: impl Fn(&str) -> Option<String>) -> Self {
        let mut dirs: Vec<(String, String)> = Vec::new();
        if let Some(text) = root {
            for (name, dir) in config_section(text, "cells") {
                let dir = dir.trim_start_matches("./").trim_end_matches('/');
                let dir = if dir == "." { "" } else { dir };
                dirs.push((name, dir.to_owned()));
            }
        }
        if !dirs.iter().any(|(_, dir)| dir.is_empty()) {
            dirs.push((ROOT_CELL.to_owned(), String::new()));
        }
        dirs.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        let root_files = build_file_names(root);
        let build_files = dirs
            .iter()
            .map(|(name, dir)| {
                let own = if dir.is_empty() {
                    root_files.clone()
                } else {
                    match read(dir) {
                        Some(text) => build_file_names(Some(&text)),
                        None => root_files.clone(),
                    }
                };
                (name.clone(), own)
            })
            .collect();
        Self { dirs, build_files }
    }

    /// The cell a tree path belongs to: its name and its directory.
    pub fn cell_of(&self, path: &str) -> (&str, &str) {
        self.dirs
            .iter()
            .find(|(_, dir)| dir.is_empty() || in_region(path, dir))
            .map(|(name, dir)| (name.as_str(), dir.as_str()))
            .unwrap_or((ROOT_CELL, ""))
    }

    /// A cell's directory relative to the root, or none for an unknown cell.
    pub fn dir(&self, name: &str) -> Option<&str> {
        self.dirs
            .iter()
            .find(|(cell, _)| cell == name)
            .map(|(_, dir)| dir.as_str())
    }

    pub fn build_files(&self, name: &str) -> &[String] {
        self.build_files.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// A cell-relative path as a tree path.
    pub fn tree_path(&self, name: &str, relative: &str) -> Option<String> {
        let dir = self.dir(name)?;
        Some(if dir.is_empty() {
            relative.to_owned()
        } else if relative.is_empty() {
            dir.to_owned()
        } else {
            format!("{dir}/{relative}")
        })
    }
}

/// The packages of a cut: every directory holding its cell's build file,
/// named by cell and cell-relative directory, the root package of a cell
/// being `""`. A path's listing belongs to the nearest package at or above
/// it within its cell, which is exactly what that package's globs can
/// observe.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Packages {
    cells: Cells,
    dirs: BTreeSet<(String, String)>,
}

impl Packages {
    pub fn of_manifest(manifest: &BTreeMap<String, String>, cells: &Cells) -> Self {
        let dirs = manifest
            .keys()
            .filter_map(|path| {
                let (cell, cell_dir) = cells.cell_of(path);
                let relative = strip_dir(path, cell_dir);
                let (dir, name) = relative.rsplit_once('/').unwrap_or(("", relative));
                cells
                    .build_files(cell)
                    .iter()
                    .any(|build_file| build_file == name)
                    .then(|| (cell.to_owned(), dir.to_owned()))
            })
            .collect();
        Self {
            cells: cells.clone(),
            dirs,
        }
    }

    /// The package whose listing holds `path` — its cell and cell-relative
    /// directory — or none when no build file stands at or above it in its
    /// cell.
    pub fn package_of(&self, path: &str) -> Option<(String, String)> {
        let (cell, cell_dir) = self.cells.cell_of(path);
        let relative = strip_dir(path, cell_dir);
        let mut dir = relative.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
        loop {
            if self.dirs.contains(&(cell.to_owned(), dir.to_owned())) {
                return Some((cell.to_owned(), dir.to_owned()));
            }
            if dir.is_empty() {
                return None;
            }
            dir = dir.rsplit_once('/').map(|(parent, _)| parent).unwrap_or("");
        }
    }

    pub fn listing<'m>(
        &self,
        manifest: &'m BTreeMap<String, String>,
        cell: &str,
        package: &str,
    ) -> Vec<&'m str> {
        manifest
            .keys()
            .filter(|path| {
                self.package_of(path)
                    .is_some_and(|(c, p)| c == cell && p == package)
            })
            .map(String::as_str)
            .collect()
    }
}

fn strip_dir<'p>(path: &'p str, dir: &str) -> &'p str {
    if dir.is_empty() {
        path
    } else {
        path.strip_prefix(dir)
            .map(|rest| rest.trim_start_matches('/'))
            .unwrap_or(path)
    }
}

/// What shaped one target's actions, as the wrapper learned it from Buck2:
/// the cell and package its build file evaluated in, the rule files that
/// build file loaded, and the source files its actions read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionInfluences {
    pub target: String,
    pub cell: String,
    pub package: String,
    pub includes: Vec<String>,
    pub inputs: Vec<String>,
}

/// One observation that shaped a result, with the labels it carried.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct Influence {
    pub kind: &'static str,
    pub subject: String,
    pub labels: BTreeSet<String>,
}

pub(crate) const PACKAGE_CEILING: &str = "package-ceiling/v1";

/// A result's classification under the package ceiling, with the account of
/// what influenced it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct Classification {
    pub labels: BTreeSet<String>,
    pub influences: Vec<Influence>,
}

impl Classification {
    /// The basis string a record carries: the ceiling's name and the labels.
    pub fn basis(&self) -> String {
        format!("{PACKAGE_CEILING}:{}", join(&self.labels))
    }

    /// The labels a recorded basis names. The interim organization ceiling of
    /// the first half names every label the policy declares.
    pub fn labels_of_basis(basis: &str, policy: &LabelPolicy) -> Result<BTreeSet<String>, String> {
        if basis == super::build_commands::ORGANIZATION_CEILING {
            return Ok(policy.labels());
        }
        match basis
            .strip_prefix(PACKAGE_CEILING)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            Some(labels) => Ok(labels
                .split(',')
                .filter(|label| !label.is_empty())
                .map(str::to_owned)
                .collect()),
            None => Err(format!("unknown classification basis {basis}")),
        }
    }
}

fn join(labels: &BTreeSet<String>) -> String {
    labels.iter().cloned().collect::<Vec<_>>().join(",")
}

/// The package ceiling over a target and everything it depends on.
pub(crate) fn classify(
    manifest: &BTreeMap<String, String>,
    policy: &LabelPolicy,
    packages: &Packages,
    influences: &[ActionInfluences],
) -> Classification {
    let mut labels = BTreeSet::new();
    let mut account = Vec::new();
    let mut note = |kind: &'static str, subject: String, found: BTreeSet<String>| {
        labels.extend(found.iter().cloned());
        account.push(Influence {
            kind,
            subject,
            labels: found,
        });
    };
    for target in influences {
        let listing: BTreeSet<String> = packages
            .listing(manifest, &target.cell, &target.package)
            .into_iter()
            .flat_map(|path| policy.labels_of(path))
            .collect();
        note(
            "package-listing",
            format!("{}//{}", target.cell, target.package),
            listing,
        );
        for include in &target.includes {
            note("include", include.clone(), policy.labels_of(include));
        }
        for input in &target.inputs {
            note("input", input.clone(), policy.labels_of(input));
        }
    }
    Classification {
        labels,
        influences: account,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> BTreeMap<String, String> {
        [
            (".buckconfig", "c0"),
            ("FIXTURE", "f0"),
            ("rules.bzl", "r0"),
            ("tests/passing.sh", "p0"),
            ("secret-gate/FIXTURE", "f1"),
            ("secret-gate/protected/flag", "s0"),
            ("inner/.buckconfig", "c1"),
            ("inner/FIXTURE", "f2"),
            ("inner/note.txt", "n0"),
        ]
        .into_iter()
        .map(|(path, digest)| (path.to_owned(), digest.to_owned()))
        .collect()
    }

    fn cells() -> Cells {
        Cells::from_configs(
            Some("[cells]\nroot = .\ninner = inner\n[buildfile]\nname = FIXTURE\n"),
            |dir| (dir == "inner").then(|| "[buildfile]\nname = FIXTURE\n".to_owned()),
        )
    }

    fn policy() -> LabelPolicy {
        LabelPolicy::new(vec![Region {
            prefix: "secret-gate/protected/".into(),
            label: "protected".into(),
        }])
        .expect("a policy")
    }

    fn principal(name: &str, labels: &[&str]) -> Principal {
        Principal {
            name: name.into(),
            labels: labels.iter().map(|l| l.to_string()).collect(),
        }
    }

    #[test]
    fn a_projection_holds_what_the_labels_permit_and_names_what_it_could_not_observe() {
        let dev = principal("dev", &[]);
        let owner = principal("owner", &["protected"]);
        let projection = project(&manifest(), &policy(), &dev);
        assert!(!projection.include.contains("secret-gate/protected/flag"));
        assert!(projection.include.contains("secret-gate/FIXTURE"));
        assert_eq!(
            projection.unobserved,
            vec!["secret-gate/protected/".to_owned()]
        );
        assert!(projection.id.starts_with(PROJECTION_PREFIX));
        let whole = project(&manifest(), &policy(), &owner);
        assert_eq!(whole.include.len(), manifest().len());
        assert!(whole.unobserved.is_empty());
        assert_ne!(whole.id, projection.id);
        // A region prefix names a directory or an exact path, never a name prefix.
        let policy = LabelPolicy::new(vec![Region {
            prefix: "secret".into(),
            label: "x".into(),
        }])
        .unwrap();
        assert!(policy.labels_of("secret-gate/FIXTURE").is_empty());
        assert_eq!(policy.labels_of("secret").len(), 1);
        assert_eq!(policy.labels_of("secret/a").len(), 1);
        assert_eq!(
            LabelPolicy::new(vec![Region {
                prefix: " ".into(),
                label: "x".into()
            }])
            .unwrap_err(),
            "a labeled region needs a nonempty prefix and a nonempty label"
        );
    }

    #[test]
    fn cells_are_the_explicit_mapping_and_a_path_belongs_to_the_innermost() {
        let cells = cells();
        assert_eq!(cells.cell_of("tests/passing.sh"), ("root", ""));
        assert_eq!(cells.cell_of("inner/note.txt"), ("inner", "inner"));
        assert_eq!(cells.cell_of("innermost/x"), ("root", ""));
        assert_eq!(cells.dir("inner"), Some("inner"));
        assert_eq!(cells.dir("nope"), None);
        assert_eq!(cells.build_files("inner"), &["FIXTURE".to_owned()]);
        assert_eq!(
            cells.tree_path("inner", "note.txt").as_deref(),
            Some("inner/note.txt")
        );
        assert_eq!(
            cells.tree_path("root", "FIXTURE").as_deref(),
            Some("FIXTURE")
        );
        assert_eq!(cells.tree_path("inner", "").as_deref(), Some("inner"));
        // A tree with no cells is one root cell with Buck2's default names.
        let lone = Cells::from_configs(None, |_| None);
        assert_eq!(lone.cell_of("a/b"), ("root", ""));
        assert_eq!(lone.build_files("root").len(), 4);
        // A cell without its own config takes the root's build-file name.
        let inherited = Cells::from_configs(
            Some("[cells]\nroot = .\ninner = inner\n[buildfile]\nname = FIXTURE\n"),
            |_| None,
        );
        assert_eq!(inherited.build_files("inner"), &["FIXTURE".to_owned()]);
        assert_eq!(
            build_file_names(Some("[cells]\nroot = .\n[buildfile]\nname = FIXTURE\n")),
            vec!["FIXTURE".to_owned()]
        );
    }

    #[test]
    fn packages_are_where_build_files_stand_and_a_listing_stops_at_a_sub_package_and_a_cell() {
        let manifest = manifest();
        let packages = Packages::of_manifest(&manifest, &cells());
        assert_eq!(
            packages.package_of("tests/passing.sh"),
            Some(("root".into(), "".into()))
        );
        assert_eq!(
            packages.package_of("secret-gate/protected/flag"),
            Some(("root".into(), "secret-gate".into()))
        );
        assert_eq!(
            packages.package_of("inner/note.txt"),
            Some(("inner".into(), "".into()))
        );
        let root = packages.listing(&manifest, "root", "");
        assert!(root.contains(&"tests/passing.sh"));
        assert!(!root.contains(&"secret-gate/protected/flag"));
        assert!(
            !root.contains(&"inner/note.txt"),
            "a cell's listing stops at a nested cell"
        );
        let inner = packages.listing(&manifest, "inner", "");
        assert_eq!(
            inner,
            vec!["inner/.buckconfig", "inner/FIXTURE", "inner/note.txt"]
        );
        let none = Packages::of_manifest(&manifest, &Cells::from_configs(None, |_| None));
        assert_eq!(none.package_of("FIXTURE"), None);
    }

    #[test]
    fn the_package_ceiling_classifies_a_result_by_what_shaped_it() {
        let manifest = manifest();
        let packages = Packages::of_manifest(&manifest, &cells());
        let gate = classify(
            &manifest,
            &policy(),
            &packages,
            &[ActionInfluences {
                target: "root//secret-gate:gate".into(),
                cell: "root".into(),
                package: "secret-gate".into(),
                includes: vec!["rules.bzl".into()],
                inputs: vec![],
            }],
        );
        assert_eq!(gate.basis(), "package-ceiling/v1:protected");
        assert_eq!(gate.influences[0].kind, "package-listing");
        assert_eq!(gate.influences[0].subject, "root//secret-gate");
        assert_eq!(gate.influences[0].labels.len(), 1);
        let passing = classify(
            &manifest,
            &policy(),
            &packages,
            &[ActionInfluences {
                target: "root//:passing".into(),
                cell: "root".into(),
                package: String::new(),
                includes: vec!["rules.bzl".into()],
                inputs: vec!["tests/passing.sh".into()],
            }],
        );
        assert_eq!(passing.basis(), "package-ceiling/v1:");
        assert!(principal("dev", &[]).holds(&passing.labels));
        assert!(!principal("dev", &[]).holds(&gate.labels));
        assert!(principal("owner", &["protected"]).holds(&gate.labels));
        assert_eq!(
            Classification::labels_of_basis("ceiling:organization", &policy()).unwrap(),
            policy().labels()
        );
        assert_eq!(
            Classification::labels_of_basis("package-ceiling/v1:a,b", &policy())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            Classification::labels_of_basis("nonsense", &policy()).unwrap_err(),
            "unknown classification basis nonsense"
        );
    }
}
