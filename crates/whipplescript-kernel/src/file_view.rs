//! The model-visible namespace over a turn's admitted file-store roots
//! (DR-0148).
//!
//! A file-store [`ResourceRef`] selects a stored root and may present it to the
//! model at another path. Both hosts that serve `ResourceRef`s, the native
//! governed host and the Durable Object host, resolve every model path through
//! this one view, so what the model sees cannot differ between placements.
//!
//! Paths here are workspace-relative strings with `/` separators, and `""` is
//! the workspace root. A path the model gives is *presented*; the path a host
//! stores and records is *stored*. A root that presents nothing is visible at
//! its stored path, exactly as before presentation existed.

use serde::{Deserialize, Serialize};

use crate::host_protocol::ResourceRef;

/// One admitted file-store root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewRoot {
    pub handle: String,
    /// The normalized selector (`""` for the whole workspace).
    pub stored: String,
    /// The normalized presented path, when the reference presents its root.
    pub presented: Option<String>,
    pub writable: bool,
}

impl ViewRoot {
    /// Where the model sees this root.
    pub fn visible(&self) -> &str {
        self.presented.as_deref().unwrap_or(&self.stored)
    }
}

/// What a model path names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewResolution {
    /// A path inside an admitted root: its stored path, and whether any root
    /// admitting it is writable.
    Stored { stored: String, writable: bool },
    /// A directory that exists only in the view because roots lie beneath it.
    Synthetic,
}

/// One entry of a directory that exists only in the view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewEntry {
    pub name: String,
    /// The stored root when this entry is itself an admitted root; `None` when
    /// it is a further directory that exists only in the view.
    pub root: Option<String>,
}

/// A rename of a presented root, admitted or refused by the host's resolver.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootRename {
    pub handle: String,
    /// The stored root, which the rename does not move.
    pub selector: String,
    pub from: String,
    pub to: String,
}

/// The model-visible namespace of one turn.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileView {
    roots: Vec<ViewRoot>,
}

impl FileView {
    /// The view over the file-store references among `resources`. References
    /// that present nothing are accepted exactly as the hosts accepted them
    /// before DR-0148; a presented path is refused when it could overlap
    /// another visible root or expose a presented root's selector.
    pub fn from_resources(resources: &[ResourceRef]) -> Result<Self, String> {
        let mut roots: Vec<ViewRoot> = Vec::new();
        for resource in resources
            .iter()
            .filter(|resource| resource.kind == "file_store")
        {
            let stored = normalize_stored_path(resource.selector.as_deref().unwrap_or(""))?;
            let presented = resource
                .presented_as
                .as_deref()
                .map(normalize_presented_path)
                .transpose()?;
            let writable = resource.writable.unwrap_or(true);
            match roots
                .iter_mut()
                .find(|root| root.stored == stored && root.presented == presented)
            {
                Some(existing) => existing.writable |= writable,
                None => roots.push(ViewRoot {
                    handle: resource.handle.clone(),
                    stored,
                    presented,
                    writable,
                }),
            }
        }
        roots.sort_by(|left, right| {
            (&left.stored, &left.presented).cmp(&(&right.stored, &right.presented))
        });
        let view = Self { roots };
        view.validate()?;
        Ok(view)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.presents() {
            return Ok(());
        }
        let presented = self
            .roots
            .iter()
            .filter(|root| root.presented.is_some())
            .collect::<Vec<_>>();
        for (index, root) in presented.iter().enumerate() {
            let visible = root.visible();
            for other in &presented[index + 1..] {
                if overlaps(visible, other.visible()) {
                    return Err(format!(
                        "presented paths `{visible}` and `{}` overlap",
                        other.visible()
                    ));
                }
                if root.stored == other.stored {
                    return Err(format!(
                        "one stored root is presented as both `{visible}` and `{}`",
                        other.visible()
                    ));
                }
            }
            for other in self.roots.iter().filter(|other| other.presented.is_none()) {
                if overlaps(visible, &other.stored) || overlaps(&root.stored, &other.stored) {
                    return Err(format!(
                        "presented path `{visible}` overlaps an unpresented file-store root"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> &[ViewRoot] {
        &self.roots
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Whether any root is presented somewhere other than its selector.
    pub fn presents(&self) -> bool {
        self.roots.iter().any(|root| root.presented.is_some())
    }

    /// The presented roots, where the model sees them.
    pub fn presented_roots(&self) -> Vec<String> {
        self.roots
            .iter()
            .filter_map(|root| root.presented.clone())
            .collect()
    }

    /// Resolve a model path. An error names the path as the model gave it,
    /// never a selector the view hides.
    pub fn resolve(&self, path: &str) -> Result<ViewResolution, String> {
        let model = normalize_stored_path(path)?;
        if let Some(root) = self.presenting_root_of(&model) {
            let presented = root.presented.as_deref().unwrap_or_default();
            return Ok(ViewResolution::Stored {
                stored: join(&root.stored, remainder(&model, presented)),
                writable: root.writable,
            });
        }
        let hidden = self
            .roots
            .iter()
            .any(|root| root.presented.is_some() && is_within(&model, &root.stored));
        let admitting = self
            .roots
            .iter()
            .filter(|root| root.presented.is_none() && is_within(&model, &root.stored))
            .collect::<Vec<_>>();
        if !hidden && !admitting.is_empty() {
            return Ok(ViewResolution::Stored {
                writable: admitting.iter().any(|root| root.writable),
                stored: model,
            });
        }
        if !hidden
            && self.presents()
            && self
                .roots
                .iter()
                .any(|root| is_strictly_within(root.visible(), &model))
        {
            return Ok(ViewResolution::Synthetic);
        }
        Err(format!(
            "workspace path `{path}` is outside the admitted file-store selectors"
        ))
    }

    /// Where the model sees a stored path, or `None` when the view hides it.
    pub fn presented(&self, stored: &str) -> Option<String> {
        if let Some(root) = self
            .roots
            .iter()
            .filter(|root| root.presented.is_some() && is_within(stored, &root.stored))
            .max_by_key(|root| root.stored.len())
        {
            let presented = root.presented.as_deref().unwrap_or_default();
            return Some(join(presented, remainder(stored, &root.stored)));
        }
        self.roots
            .iter()
            .any(|root| root.presented.is_none() && is_within(stored, &root.stored))
            .then(|| stored.to_owned())
    }

    /// Whether a stored path lies inside an admitted root.
    pub fn admits_stored(&self, stored: &str) -> bool {
        self.roots
            .iter()
            .any(|root| is_within(stored, &root.stored))
    }

    /// Whether a stored path lies inside a writable admitted root.
    pub fn writable_stored(&self, stored: &str) -> bool {
        self.roots
            .iter()
            .any(|root| root.writable && is_within(stored, &root.stored))
    }

    /// The entries of a directory that exists only in the view, sorted by
    /// name. `directory` is a model path.
    pub fn children(&self, directory: &str) -> Vec<ViewEntry> {
        let Ok(directory) = normalize_stored_path(directory) else {
            return Vec::new();
        };
        let mut entries: Vec<ViewEntry> = Vec::new();
        for root in &self.roots {
            let visible = root.visible();
            if !is_strictly_within(visible, &directory) {
                continue;
            }
            let rest = remainder(visible, &directory);
            let (name, deeper) = match rest.split_once('/') {
                Some((name, _)) => (name, true),
                None => (rest, false),
            };
            if entries.iter().any(|entry| entry.name == name) {
                continue;
            }
            entries.push(ViewEntry {
                name: name.to_owned(),
                root: (!deeper).then(|| root.stored.clone()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    }

    /// Validate a rename of the presented root at `from` to `to`. The view is
    /// unchanged; [`FileView::apply_renames`] applies an admitted one.
    pub fn rename(&self, from: &str, to: &str) -> Result<RootRename, String> {
        let from = normalize_stored_path(from)?;
        let Some(root) = self
            .roots
            .iter()
            .find(|root| root.presented.as_deref() == Some(from.as_str()))
        else {
            return Err(format!("`{from}` is not a presented file-store root"));
        };
        let to = normalize_presented_path(to)?;
        let rename = RootRename {
            handle: root.handle.clone(),
            selector: root.stored.clone(),
            from,
            to,
        };
        let mut renamed = self.clone();
        renamed.apply(&rename);
        renamed.validate()?;
        Ok(rename)
    }

    /// Present each renamed root at its new path, where this view still
    /// presents it at the path the rename started from. A rename a later turn
    /// reference has already absorbed, or that a host has since overtaken,
    /// therefore no longer applies.
    pub fn apply_renames(&mut self, renames: &[RootRename]) -> Result<(), String> {
        for rename in renames {
            self.apply(rename);
        }
        self.validate()
    }

    fn apply(&mut self, rename: &RootRename) {
        if let Some(root) = self.roots.iter_mut().find(|root| {
            root.stored == rename.selector && root.presented.as_deref() == Some(&rename.from)
        }) {
            root.presented = Some(rename.to.clone());
        }
    }

    fn presenting_root_of(&self, model: &str) -> Option<&ViewRoot> {
        self.roots.iter().find(|root| {
            root.presented
                .as_deref()
                .is_some_and(|presented| is_within(model, presented))
        })
    }
}

/// Normalize a presented path: relative, `/`-separated, and free of empty,
/// `.` and `..` segments, backslashes and control characters.
pub fn normalize_presented_path(path: &str) -> Result<String, String> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return Err(format!("presented path `{path}` must be a relative path"));
    }
    if path
        .chars()
        .any(|character| character == '\\' || character.is_control())
    {
        return Err(format!(
            "presented path `{}` has a backslash or control character",
            path.escape_default()
        ));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(format!(
            "presented path `{path}` has an empty, `.` or `..` segment"
        ));
    }
    Ok(path.to_owned())
}

/// Normalize a workspace path the way both hosts always have: `""` or `.` is
/// the workspace root, empty and `.` segments are dropped, and an absolute
/// path, a backslash or a `..` segment escapes the capability.
pub fn normalize_stored_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "." {
        return Ok(String::new());
    }
    if trimmed.starts_with('/') || trimmed.contains('\\') {
        return Err(format!("workspace path `{path}` escapes its capability"));
    }
    let mut components = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(format!("workspace path `{path}` escapes its capability")),
            component => components.push(component),
        }
    }
    Ok(components.join("/"))
}

/// Whether `path` is `root` or lies beneath it; everything lies within `""`.
pub fn is_within(path: &str, root: &str) -> bool {
    root.is_empty()
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_strictly_within(path: &str, directory: &str) -> bool {
    path != directory && is_within(path, directory)
}

fn overlaps(left: &str, right: &str) -> bool {
    is_within(left, right) || is_within(right, left)
}

fn remainder<'a>(path: &'a str, root: &str) -> &'a str {
    if root.is_empty() {
        path
    } else {
        path[root.len()..].trim_start_matches('/')
    }
}

fn join(root: &str, rest: &str) -> String {
    match (root.is_empty(), rest.is_empty()) {
        (true, _) => rest.to_owned(),
        (_, true) => root.to_owned(),
        _ => format!("{root}/{rest}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(
        handle: &str,
        selector: Option<&str>,
        presented: Option<&str>,
        writable: bool,
    ) -> ResourceRef {
        ResourceRef {
            handle: handle.to_owned(),
            kind: "file_store".to_owned(),
            selector: selector.map(str::to_owned),
            writable: Some(writable),
            presented_as: presented.map(str::to_owned),
        }
    }

    fn targets() -> FileView {
        FileView::from_resources(&[
            store("target:a", Some("targets/t-a"), Some("api"), true),
            store("target:b", Some("targets/t-b"), Some("web"), false),
            store("manifest", Some(".runtime/target-set.json"), None, false),
        ])
        .expect("valid view")
    }

    fn stored(view: &FileView, path: &str) -> (String, bool) {
        match view.resolve(path).expect("admitted") {
            ViewResolution::Stored { stored, writable } => (stored, writable),
            ViewResolution::Synthetic => panic!("`{path}` is synthetic"),
        }
    }

    #[test]
    fn a_presented_path_maps_to_its_selector_and_back() {
        let view = targets();
        assert_eq!(
            stored(&view, "api/src/main.rs"),
            ("targets/t-a/src/main.rs".into(), true)
        );
        assert_eq!(stored(&view, "./web/"), ("targets/t-b".into(), false));
        assert_eq!(
            view.presented("targets/t-a/src/main.rs").as_deref(),
            Some("api/src/main.rs")
        );
        assert_eq!(view.presented("targets/t-b").as_deref(), Some("web"));
        assert_eq!(
            view.presented(".runtime/target-set.json").as_deref(),
            Some(".runtime/target-set.json")
        );
        assert_eq!(view.presented("targets/t-c/x"), None);
    }

    #[test]
    fn a_presented_roots_selector_is_hidden_from_the_model() {
        let view = targets();
        let error = view.resolve("targets/t-a/src/main.rs").unwrap_err();
        assert!(
            error.contains("`targets/t-a/src/main.rs` is outside"),
            "{error}"
        );
        assert!(
            view.resolve("targets").is_err(),
            "no directory leads to a hidden selector"
        );
    }

    #[test]
    fn the_root_and_its_ancestors_exist_only_in_the_view() {
        let view = targets();
        assert_eq!(view.resolve(".").unwrap(), ViewResolution::Synthetic);
        assert_eq!(view.resolve(".runtime").unwrap(), ViewResolution::Synthetic);
        let names = view
            .children("")
            .into_iter()
            .map(|entry| (entry.name, entry.root))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                (".runtime".to_owned(), None),
                ("api".to_owned(), Some("targets/t-a".to_owned())),
                ("web".to_owned(), Some("targets/t-b".to_owned())),
            ]
        );
    }

    #[test]
    fn without_presentation_resolution_is_unchanged() {
        let view = FileView::from_resources(&[
            store("a", Some("targets/t-a"), None, true),
            store("m", Some("manifest.json"), None, false),
        ])
        .unwrap();
        assert_eq!(
            stored(&view, "targets/t-a/x"),
            ("targets/t-a/x".into(), true)
        );
        assert!(view.resolve(".").is_err(), "the legacy root stays unlisted");
        let whole = FileView::from_resources(&[store("p", None, None, true)]).unwrap();
        assert_eq!(
            stored(&whole, "anything/here"),
            ("anything/here".into(), true)
        );
    }

    #[test]
    fn overlapping_or_exposing_presentations_are_refused() {
        for resources in [
            vec![
                store("a", Some("t/a"), Some("api"), true),
                store("b", Some("t/b"), Some("api/x"), true),
            ],
            vec![
                store("a", Some("t/a"), Some("api"), true),
                store("b", Some("t/a"), Some("web"), true),
            ],
            vec![
                store("a", Some("t/a"), Some("api"), true),
                store("p", None, None, true),
            ],
            vec![
                store("a", Some("t/a"), Some("api"), true),
                store("t", Some("t"), None, true),
            ],
            vec![
                store("a", Some("t/a"), Some("api"), true),
                store("u", Some("api/x"), None, true),
            ],
        ] {
            assert!(
                FileView::from_resources(&resources).is_err(),
                "{resources:?}"
            );
        }
        for invalid in [
            "", "/api", "api/", "a//b", "./api", "a/../b", "a\\b", "a\nb",
        ] {
            assert!(normalize_presented_path(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn a_rename_is_validated_and_then_applied_where_it_still_applies() {
        let view = targets();
        let rename = view.rename("api", "backend").expect("admissible");
        assert_eq!(
            rename,
            RootRename {
                handle: "target:a".into(),
                selector: "targets/t-a".into(),
                from: "api".into(),
                to: "backend".into(),
            }
        );
        assert!(view.rename("api", "web").is_err(), "a taken name");
        assert!(
            view.rename("api", "web/api").is_err(),
            "inside another root"
        );
        assert!(
            view.rename("api", ".runtime").is_err(),
            "onto an unpresented root's path"
        );
        assert!(
            view.rename("targets/t-a", "x").is_err(),
            "not a presented root"
        );
        let mut renamed = view.clone();
        renamed
            .apply_renames(std::slice::from_ref(&rename))
            .unwrap();
        assert_eq!(
            stored(&renamed, "backend/x"),
            ("targets/t-a/x".into(), true)
        );
        assert!(renamed.resolve("api/x").is_err());
        // A later reference that already presents the new name is unaffected.
        let mut later = FileView::from_resources(&[store(
            "target:a",
            Some("targets/t-a"),
            Some("renamed-again"),
            true,
        )])
        .unwrap();
        later.apply_renames(&[rename]).unwrap();
        assert_eq!(later.presented_roots(), vec!["renamed-again".to_owned()]);
    }
}
