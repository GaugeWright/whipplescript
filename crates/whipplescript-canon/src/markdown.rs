//! Markdown sections by heading path (norm-plane §9).
//!
//! A section is a heading and the text up to the next heading of any level;
//! its identity is the path of heading texts from the document's top to it.
//! Heading text is semantic content: retitling "Required" to "Optional"
//! changes the section's identity, and every nested section's with it, even
//! when every body is identical. The rename hash erases the heading's own
//! text, so a pure retitle is recognisable as one — a continuity advisory, not
//! a preservation of the evidence the old heading carried. Two sections with
//! one path are ambiguous and fall to the file's unkeyed unit, as does text
//! before the first heading. Fenced code is body text, never a heading.

use whipplescript_store::vcs::{CanonDecl, DeclCanonicalizer};

use crate::{digest, UNKEYED};

const VERSION: &str = "whipplescript.canon.markdown/1";

/// Markdown files, sectioned by ATX heading path.
pub struct MarkdownSections;

struct Section {
    path: String,
    heading: String,
    level: usize,
    body: Vec<String>,
}

/// An ATX heading: its level and its text, trailing closing hashes removed.
fn heading(line: &str) -> Option<(usize, String)> {
    let trimmed = line.trim_start();
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let level = trimmed.chars().take_while(|c| *c == '#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = &trimmed[level..];
    if !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')) {
        return None;
    }
    let text = rest.trim().trim_end_matches('#').trim_end();
    Some((level, text.split_whitespace().collect::<Vec<_>>().join(" ")))
}

impl DeclCanonicalizer for MarkdownSections {
    fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
        self.canonical_declarations_at("README.md", source)
    }

    fn canonical_declarations_at(&self, file: &str, source: &str) -> Option<Vec<CanonDecl>> {
        let mut preamble = Vec::new();
        let mut sections: Vec<Section> = Vec::new();
        let mut stack: Vec<(usize, String)> = Vec::new();
        let mut fence: Option<String> = None;
        for line in source.lines() {
            let trimmed = line.trim_start();
            let marker: String = trimmed
                .chars()
                .take_while(|c| *c == '`' || *c == '~')
                .collect();
            if marker.len() >= 3
                && marker
                    .chars()
                    .all(|c| c == marker.chars().next().unwrap_or('`'))
            {
                match &fence {
                    Some(open) if marker.starts_with(open.as_str()) => fence = None,
                    None => fence = Some(marker.clone()),
                    _ => {}
                }
            }
            let parsed = if fence.is_none() && marker.len() < 3 {
                heading(line)
            } else {
                None
            };
            if let Some((level, text)) = parsed {
                while stack.last().is_some_and(|(open, _)| *open >= level) {
                    stack.pop();
                }
                stack.push((level, text.clone()));
                let path = stack
                    .iter()
                    .map(|(level, text)| format!("{} {text}", "#".repeat(*level)))
                    .collect::<Vec<_>>()
                    .join(" > ");
                sections.push(Section {
                    path,
                    heading: text,
                    level,
                    body: Vec::new(),
                });
                continue;
            }
            // Trailing whitespace is not content; everything else is.
            let kept = line.trim_end().to_owned();
            match sections.last_mut() {
                Some(section) => section.body.push(kept),
                None => preamble.push(kept),
            }
        }
        let normalized = |lines: &[String]| {
            let mut text = lines.join("\n");
            while text.ends_with('\n') {
                text.pop();
            }
            text.trim_start_matches('\n').to_owned()
        };
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        for section in &sections {
            *counts.entry(section.path.as_str()).or_default() += 1;
        }
        let mut unkeyed = Vec::new();
        let preamble = normalized(&preamble);
        if !preamble.is_empty() {
            unkeyed.push(preamble);
        }
        let mut decls = Vec::new();
        for section in &sections {
            let body = normalized(&section.body);
            let print = format!("{} {}\n{body}", "#".repeat(section.level), section.heading);
            if counts[section.path.as_str()] > 1 {
                unkeyed.push(print);
                continue;
            }
            let rename = format!("{} _\n{body}", "#".repeat(section.level));
            decls.push(CanonDecl {
                identity: format!("section {file} {}", section.path),
                canon_hash: digest(VERSION, &print),
                rename_hash: digest(VERSION, &rename),
            });
        }
        if !unkeyed.is_empty() {
            let print = unkeyed.join("\n");
            decls.push(CanonDecl {
                identity: format!("{UNKEYED} {file}"),
                canon_hash: digest(VERSION, &print),
                rename_hash: digest(VERSION, &print),
            });
        }
        decls.sort_by(|a, b| a.identity.cmp(&b.identity));
        Some(decls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decls(source: &str) -> std::collections::BTreeMap<String, CanonDecl> {
        MarkdownSections
            .canonical_declarations(source)
            .unwrap()
            .into_iter()
            .map(|decl| (decl.identity.clone(), decl))
            .collect()
    }

    #[test]
    fn sections_are_keyed_by_heading_path_and_a_retitle_is_a_new_identity() {
        let base = "# Policy\n\nIntro.\n\n## Required\n\nDeny the worker.\n\n### Scope\n\nsrc/\n";
        let sections = decls(base);
        assert!(sections.contains_key("section README.md # Policy"));
        assert!(sections.contains_key("section README.md # Policy > ## Required"));
        assert!(sections.contains_key("section README.md # Policy > ## Required > ### Scope"));
        // Trailing whitespace and extra spaces in a heading are not changes.
        let spaced = base
            .replace("Deny the worker.", "Deny the worker.   ")
            .replace("## Required", "##   Required");
        assert_eq!(decls(&spaced), sections);
        // Retitling Required to Optional changes the section and everything
        // nested in it, though every body is the same; the retitle is
        // recognisable by its rename hash, and that recognition is all it is.
        let optional = decls(&base.replace("## Required", "## Optional"));
        assert!(!optional.contains_key("section README.md # Policy > ## Required"));
        let before = &sections["section README.md # Policy > ## Required"];
        let after = &optional["section README.md # Policy > ## Optional"];
        assert_ne!(before.canon_hash, after.canon_hash);
        assert_eq!(before.rename_hash, after.rename_hash);
        assert!(optional.contains_key("section README.md # Policy > ## Optional > ### Scope"));
        // A body edit changes the section's content and keeps its identity.
        let edited = decls(&base.replace("Deny the worker.", "Allow the worker."));
        assert_ne!(
            edited["section README.md # Policy > ## Required"].canon_hash,
            before.canon_hash
        );
        assert_eq!(
            edited["section README.md # Policy"].canon_hash,
            sections["section README.md # Policy"].canon_hash,
            "a parent's own text is unchanged by a child's edit"
        );
    }

    #[test]
    fn duplicate_paths_preamble_and_fenced_headings_are_not_guessed() {
        let duplicated = decls("Preface.\n\n# A\n\none\n\n# A\n\ntwo\n\n# B\n\nthree\n");
        assert!(!duplicated.contains_key("section README.md # A"));
        assert!(duplicated.contains_key("section README.md # B"));
        assert!(duplicated.contains_key("unkeyed README.md"));
        let fenced = decls("# A\n\n```md\n# Not a heading\n```\n");
        assert_eq!(fenced.len(), 1, "{:?}", fenced.keys().collect::<Vec<_>>());
        // A missing section is simply absent: evidence keyed to it goes stale.
        assert!(!decls("# B\n").contains_key("section README.md # A"));
    }
}
