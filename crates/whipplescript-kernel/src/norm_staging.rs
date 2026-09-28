//! What a run is given to read (norm-plane §3.4, reuse under an enforced
//! ceiling).
//!
//! A protected interpreter reads only the files it is staged. So a protected
//! run of a requirement bound to a managed domain is staged that domain's
//! files at the cut and nothing else: the domain is the ceiling its support
//! rests on, and the tested artifact is those files. Support therefore carries
//! to any cut where they are unchanged, whatever changed outside. A
//! cooperative run, whose reads nothing encloses, and a requirement with no
//! bound domain are staged the whole cut, so any change invalidates them.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_store::norm_resources::RequirementResources;

use crate::norm_runner::{candidate_identity, PythonEngine};

/// The files a run is staged, and the domain that encloses them when a
/// protected interpreter enforces it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Staging {
    pub files: BTreeMap<String, String>,
    pub ceiling: Option<String>,
}

impl Staging {
    /// The tested artifact's identity: the staged files, membership included.
    pub fn identity(&self) -> String {
        candidate_identity(&self.files)
    }
}

/// Stage a run of `engine` over a cut's `files`, given its requirement's
/// resource binding at that cut.
pub fn stage(
    engine: &PythonEngine,
    binding: Option<&RequirementResources>,
    files: &BTreeMap<String, String>,
) -> Staging {
    match (engine, binding) {
        (PythonEngine::Cpython3147Wasi { .. }, Some(binding)) => Staging {
            files: files
                .iter()
                .filter(|(path, _)| binding.resources.contains(*path))
                .map(|(path, content)| (path.clone(), content.clone()))
                .collect(),
            ceiling: Some(binding.domain.clone()),
        },
        _ => Staging {
            files: files.clone(),
            ceiling: None,
        },
    }
}

/// Why a requirement's support carried across a change: the domain that
/// encloses what its run could read, and every changed path outside it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SupportCeiling {
    pub domain: String,
    pub outside: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cut() -> BTreeMap<String, String> {
        [
            ("README.md", "readme"),
            ("src/auth.py", "auth"),
            ("src/parser.py", "parser"),
            ("checks/q0.json", "cases"),
        ]
        .into_iter()
        .map(|(path, body)| (path.to_owned(), body.to_owned()))
        .collect()
    }

    fn bound() -> RequirementResources {
        RequirementResources {
            domain: "authorization".into(),
            subject: "src/auth.py".into(),
            subject_present: true,
            resources: ["src/auth.py", "src/parser.py", "checks/q0.json"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    fn protected() -> PythonEngine {
        PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/reactor.wasm".into(),
            artifact_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn a_protected_run_is_staged_its_domain_and_nothing_else() {
        let staged = stage(&protected(), Some(&bound()), &cut());
        assert_eq!(staged.ceiling.as_deref(), Some("authorization"));
        assert_eq!(
            staged.files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["checks/q0.json", "src/auth.py", "src/parser.py"]
        );
        // A change outside the domain leaves the tested artifact the same; a
        // change inside it, or a new file in it, does not.
        let mut readme = cut();
        readme.insert("README.md".into(), "edited".into());
        assert_eq!(
            stage(&protected(), Some(&bound()), &readme).identity(),
            staged.identity()
        );
        let mut parser = cut();
        parser.insert("src/parser.py".into(), "edited".into());
        let mut widened = bound();
        widened.resources.insert("src/new.py".into());
        let mut created = cut();
        created.insert("src/new.py".into(), "new".into());
        for (files, binding) in [(&parser, bound()), (&created, widened)] {
            assert_ne!(
                stage(&protected(), Some(&binding), files).identity(),
                staged.identity()
            );
        }
    }

    #[test]
    fn a_cooperative_or_unbound_run_is_staged_the_whole_cut() {
        for (engine, binding) in [
            (PythonEngine::Cpython {}, Some(bound())),
            (protected(), None),
        ] {
            let staged = stage(&engine, binding.as_ref(), &cut());
            assert_eq!(staged.ceiling, None);
            assert_eq!(staged.files, cut());
            let mut readme = cut();
            readme.insert("README.md".into(), "edited".into());
            assert_ne!(
                stage(&engine, binding.as_ref(), &readme).identity(),
                staged.identity()
            );
        }
    }
}
