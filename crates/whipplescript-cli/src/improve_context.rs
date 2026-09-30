//! Exact, bounded text context carried beside a `.whip` improve candidate.
//! A context root is an explicit author grant, never an ambient workspace walk.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ContextSnapshot {
    pub files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextEdit {
    pub path: String,
    /// `None` deletes an existing file; `Some` adds or replaces it.
    pub content: Option<String>,
}

pub(crate) fn checked_relative_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.contains('\\') || raw.contains('\0') {
        return Err(format!("invalid context path `{raw}`"));
    }
    if raw
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!(
            "context path `{raw}` must use canonical relative components"
        ));
    }
    let path = Path::new(raw);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("context path `{raw}` must stay under its root"));
    }
    Ok(path.to_path_buf())
}

impl ContextSnapshot {
    pub fn capture(root: &Path) -> Result<(PathBuf, Self), String> {
        let kind = std::fs::symlink_metadata(root)
            .map_err(|error| format!("cannot read context root {}: {error}", root.display()))?;
        if !kind.is_dir() || kind.file_type().is_symlink() {
            return Err("context root must be a real directory".to_owned());
        }
        let root = root
            .canonicalize()
            .map_err(|error| format!("cannot resolve context root: {error}"))?;
        let mut snapshot = Self::default();
        Self::read_tree(&root, &root, &mut snapshot)?;
        snapshot.validate_limits()?;
        Ok((root, snapshot))
    }

    fn read_tree(root: &Path, dir: &Path, result: &mut Self) -> Result<(), String> {
        let mut entries = std::fs::read_dir(dir)
            .map_err(|error| format!("cannot read context directory {}: {error}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate context directory: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "context symlink is not admitted: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                Self::read_tree(root, &path, result)?;
                continue;
            }
            if !metadata.is_file() {
                return Err(format!(
                    "context entry is not a regular file: {}",
                    path.display()
                ));
            }
            if metadata.len() as usize > MAX_FILE_BYTES {
                return Err(format!(
                    "context file exceeds {MAX_FILE_BYTES} bytes: {}",
                    path.display()
                ));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "context path escaped its root".to_owned())?
                .to_str()
                .ok_or("context path must be UTF-8")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            checked_relative_path(&relative)?;
            let body = std::fs::read_to_string(&path).map_err(|error| {
                format!(
                    "context file must be readable UTF-8 ({}): {error}",
                    path.display()
                )
            })?;
            result.files.insert(relative, body);
            result.validate_limits()?;
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<(), String> {
        if self.files.len() > MAX_FILES {
            return Err(format!("context root exceeds {MAX_FILES} files"));
        }
        let mut total = 0usize;
        for (path, body) in &self.files {
            checked_relative_path(path)?;
            if body.len() > MAX_FILE_BYTES {
                return Err(format!(
                    "context file `{path}` exceeds {MAX_FILE_BYTES} bytes"
                ));
            }
            total += body.len();
        }
        if total > MAX_TOTAL_BYTES {
            return Err(format!("context root exceeds {MAX_TOTAL_BYTES} bytes"));
        }
        Ok(())
    }

    pub fn edited(&self, edits: &[ContextEdit]) -> Result<Self, String> {
        let mut result = self.clone();
        let mut seen = std::collections::BTreeSet::new();
        for edit in edits {
            checked_relative_path(&edit.path)?;
            if !seen.insert(edit.path.as_str()) {
                return Err(format!("context path `{}` edited twice", edit.path));
            }
            match &edit.content {
                Some(content) => {
                    result.files.insert(edit.path.clone(), content.clone());
                }
                None => {
                    if result.files.remove(&edit.path).is_none() {
                        return Err(format!("cannot delete absent context file `{}`", edit.path));
                    }
                }
            }
        }
        result.validate_limits()?;
        Ok(result)
    }

    pub fn diff(&self, candidate: &Self) -> Vec<Value> {
        self.files
            .keys()
            .chain(candidate.files.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|path| {
                let before = self.files.get(path);
                let after = candidate.files.get(path);
                (before != after).then(|| {
                    json!({
                        "path": path,
                        "change": match (before, after) {
                            (None, Some(_)) => "added",
                            (Some(_), None) => "deleted",
                            _ => "modified",
                        },
                        "before_hash": before.map(|body| crate::sha256_hex(body.as_bytes())),
                        "after_hash": after.map(|body| crate::sha256_hex(body.as_bytes())),
                    })
                })
            })
            .collect()
    }

    pub fn hash_with_program(&self, program_hash: &str) -> String {
        // Length-prefix both path and body, so concatenation is injective.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(program_hash.as_bytes());
        for (path, body) in &self.files {
            bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
            bytes.extend_from_slice(body.as_bytes());
        }
        crate::sha256_hex(&bytes)
    }

    pub fn manifest(&self) -> Vec<Value> {
        self.files
            .iter()
            .map(|(path, body)| json!({"path": path, "hash": crate::sha256_hex(body.as_bytes()), "bytes": body.len()}))
            .collect()
    }

    pub fn materialize(&self, dest: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dest)
            .map_err(|error| format!("cannot stage context workspace: {error}"))?;
        for (relative, body) in &self.files {
            let path = dest.join(checked_relative_path(relative)?);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot stage context directory: {error}"))?;
            }
            std::fs::write(&path, body).map_err(|error| {
                format!("cannot stage context file {}: {error}", path.display())
            })?;
        }
        Ok(())
    }

    /// Apply only changed paths. Callers compare a fresh capture with the
    /// pinned baseline first; on an ordinary failure they call this again in
    /// reverse for rollback. Each replacement is an atomic file rename.
    pub fn write_delta(root: &Path, before: &Self, after: &Self) -> Result<Vec<String>, String> {
        let mut changed = Vec::new();
        for change in before.diff(after) {
            let relative = change["path"].as_str().ok_or("context diff lost path")?;
            let path = root.join(checked_relative_path(relative)?);
            if let Some(body) = after.files.get(relative) {
                let parent = path.parent().ok_or("context file has no parent")?;
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create context directory: {error}"))?;
                let resolved_parent = parent
                    .canonicalize()
                    .map_err(|error| format!("cannot resolve context directory: {error}"))?;
                if !resolved_parent.starts_with(root) {
                    return Err(format!("context path `{relative}` escaped its root"));
                }
                let temp = path.with_extension(format!("whip-improve-{}.tmp", std::process::id()));
                std::fs::write(&temp, body)
                    .map_err(|error| format!("cannot stage context file `{relative}`: {error}"))?;
                if let Err(error) = std::fs::rename(&temp, &path) {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!("cannot adopt context file `{relative}`: {error}"));
                }
            } else {
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|error| {
                        format!("cannot delete context file `{relative}`: {error}")
                    })?;
                }
            }
            changed.push(relative.to_owned());
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_edits_are_path_bound_and_change_harness_identity() {
        let mut baseline = ContextSnapshot::default();
        baseline
            .files
            .insert("AGENTS.md".to_owned(), "Use title".to_owned());
        let candidate = baseline
            .edited(&[
                ContextEdit {
                    path: "AGENTS.md".to_owned(),
                    content: Some("Use body".to_owned()),
                },
                ContextEdit {
                    path: "skills/triage/SKILL.md".to_owned(),
                    content: Some("skill text".to_owned()),
                },
            ])
            .unwrap();
        assert_eq!(baseline.diff(&candidate).len(), 2);
        assert_ne!(
            baseline.hash_with_program("p"),
            candidate.hash_with_program("p")
        );
        assert!(baseline
            .edited(&[ContextEdit {
                path: "../escape".to_owned(),
                content: Some("x".to_owned())
            }])
            .is_err());
        assert!(checked_relative_path("a//b").is_err());
        assert!(checked_relative_path("a/./b").is_err());
        let pruned = candidate
            .edited(&[ContextEdit {
                path: "AGENTS.md".to_owned(),
                content: None,
            }])
            .unwrap();
        assert!(!pruned.files.contains_key("AGENTS.md"));
    }

    #[test]
    fn capture_and_materialize_keep_an_exact_text_tree() {
        let base =
            std::env::temp_dir().join(format!("whip-context-{}-{}", std::process::id(), line!()));
        let root = base.join("source");
        std::fs::create_dir_all(root.join("skills/demo")).unwrap();
        std::fs::write(root.join("AGENTS.md"), "Project instructions").unwrap();
        std::fs::write(root.join("skills/demo/SKILL.md"), "Skill instructions").unwrap();
        let (_, snapshot) = ContextSnapshot::capture(&root).unwrap();
        assert_eq!(snapshot.files.len(), 2);
        let target = base.join("target");
        snapshot.materialize(&target).unwrap();
        let (_, restored) = ContextSnapshot::capture(&target).unwrap();
        assert_eq!(snapshot, restored);
        std::fs::write(root.join("binary.dat"), [0xff, 0x00]).unwrap();
        assert!(ContextSnapshot::capture(&root).is_err());
        std::fs::remove_file(root.join("binary.dat")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("AGENTS.md", root.join("shortcut.md")).unwrap();
            assert!(ContextSnapshot::capture(&root).is_err());
        }
        let _ = std::fs::remove_dir_all(base);
    }
}
