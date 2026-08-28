//! Project-instruction discovery (context-assembly tracker Phase 3).
//!
//! Discovers the Managed harness's hierarchical `AGENTS.md` files and injects
//! them verbatim into the system prompt as a `<project_context>` contribution.
//! Discovery is deterministic and
//! host-agnostic in shape (the bytes are content-addressable); the durable object,
//! which has no filesystem, resolves the same content from the store (a later
//! follow-on — the DO agent turn is still a no-tools stub).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Candidate project-instruction filenames, in precedence order (first match per
/// directory wins).
const CONTEXT_FILENAME: &str = "AGENTS.md";

/// Env flag disabling project-instruction injection (pi's `--no-context-files`).
const DISABLE_ENV: &str = "WHIPPLESCRIPT_NO_CONTEXT_FILES";

// The instruction type + renderer live in the kernel (shared with the DO's
// store-resolution path — context-assembly Phase 3 item 4).
pub use whipplescript_kernel::context_assembly::{render_project_context, ProjectInstruction};

/// Discover project-instruction files for a turn rooted at `cwd`.
///
/// Order mirrors pi: the global agent directory first (if any), then the cwd →
/// filesystem-root chain injected **root-most first, nearest-cwd last**. The first
/// `AGENTS.md` in each directory is cumulative; paths are de-duped. Returns empty when
/// `WHIPPLESCRIPT_NO_CONTEXT_FILES` is set.
pub fn discover_project_instructions(
    cwd: &Path,
    global_dir: Option<&Path>,
) -> Vec<ProjectInstruction> {
    // The env read lives in this thin wrapper so the walk is unit-testable without
    // touching process-global env (which races across parallel tests).
    discover_project_instructions_inner(cwd, global_dir, std::env::var_os(DISABLE_ENV).is_some())
}

fn discover_project_instructions_inner(
    cwd: &Path,
    global_dir: Option<&Path>,
    disabled: bool,
) -> Vec<ProjectInstruction> {
    if disabled {
        return Vec::new();
    }

    let mut out: Vec<ProjectInstruction> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push = |instruction: ProjectInstruction| {
        if seen.insert(instruction.path.clone()) {
            out.push(instruction);
        }
    };

    if let Some(dir) = global_dir {
        if let Some(found) = first_context_file(dir) {
            push(found);
        }
    }

    // Walk cwd → root, then reverse so the root-most directory is injected first
    // and the nearest-cwd directory last (pi's precedence: nearest wins by
    // appearing last, closest to the model's attention).
    let mut chain: Vec<PathBuf> = Vec::new();
    let mut current = Some(cwd.to_path_buf());
    while let Some(dir) = current {
        current = dir.parent().map(Path::to_path_buf);
        chain.push(dir);
    }
    chain.reverse();
    for dir in chain {
        if let Some(found) = first_context_file(&dir) {
            push(found);
        }
    }

    out
}

/// The Managed instruction file in `dir`, when readable.
fn first_context_file(dir: &Path) -> Option<ProjectInstruction> {
    let path = dir.join(CONTEXT_FILENAME);
    if path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return Some(ProjectInstruction {
                path: path.to_string_lossy().into_owned(),
                content,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir).expect("mkdir");
        std::fs::write(dir.join(name), body).expect("write");
    }

    #[test]
    fn discovers_root_most_first_nearest_last_with_filename_precedence() {
        let base = std::env::temp_dir().join(format!("whip-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // base/AGENTS.md (root-most) and base/child/AGENTS.md (nearest cwd).
        write(&base, "AGENTS.md", "root rules");
        let child = base.join("child");
        write(&child, "AGENTS.md", "child agents");
        write(&child, "CLAUDE.md", "child claude");

        let found = discover_project_instructions_inner(&child, None, false);
        let bodies: Vec<&str> = found.iter().map(|i| i.content.as_str()).collect();
        // Root-most first, nearest last; CLAUDE.md is not a Managed source.
        assert_eq!(bodies, vec!["root rules", "child agents"]);

        let rendered = render_project_context(&found);
        assert!(rendered.starts_with("<project_context>"));
        assert!(rendered.contains("<project_instructions path="));
        assert!(rendered.contains("root rules"));
        assert!(rendered.contains("child agents"));
        assert!(rendered.trim_end().ends_with("</project_context>"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn claude_md_is_not_a_managed_context_source() {
        let base = std::env::temp_dir().join(format!("whip-ctx-claude-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        write(&base, "CLAUDE.md", "provider-specific ambient instruction");
        assert!(discover_project_instructions_inner(&base, None, false).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn disabled_flag_suppresses_discovery() {
        let base = std::env::temp_dir().join(format!("whip-ctx-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        write(&base, "AGENTS.md", "rules");
        // The disabled flag (env-driven in production) short-circuits discovery.
        assert!(discover_project_instructions_inner(&base, None, true).is_empty());
        assert!(!discover_project_instructions_inner(&base, None, false).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }
}
