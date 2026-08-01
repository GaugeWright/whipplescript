//! Owned-harness context assembly (context-assembly-tracker Phase 1). The owned
//! brokered harness used to ship a single hardcoded system-prompt constant; this
//! module composes the system prompt from an ordered list of provenance-tagged
//! bundles, mirroring pi's recipe (persona, tool snippets, guidelines, doc
//! pointers, project context, available skills, date, cwd).
//!
//! The assembler is pure and host-agnostic: the host (native CLI or the durable
//! object) supplies each bundle's rendered body -- the persona/guidelines text,
//! the one-line tool snippets, the date/cwd strings, and later the project-context
//! files and skills catalogue. This keeps the seam DO-portable (no filesystem or
//! clock in the kernel) per DR-0033.
//!
//! Two invariants from the Phase 0 models are honoured here:
//! - catalogue/prompt determinism: bundles render in a fixed slot order
//!   ([`BundleKind`]) regardless of the order the host adds them, so the same
//!   bundle set yields byte-identical output (and a stable, cacheable prefix);
//! - provenance completeness: [`assemble`] returns one [`BundleProvenance`] per
//!   included bundle so the turn runner can record a `context.bundle` evidence
//!   row for each.

use crate::rule_lowering::stable_hash_hex;

/// One progressively-disclosed Agent Skill advertised to a model. The full
/// `SKILL.md` remains at `location` and is loaded with the ordinary read tool
/// only when the model decides the skill matches the task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCatalogueEntry {
    pub name: String,
    pub description: String,
    pub location: String,
}

/// Render the Agent Skills discovery catalogue used by both native and Durable
/// Object turns. This mirrors pi's metadata-first contract: only name,
/// description, and location are always present; instructions and resources
/// stay on demand.
pub fn render_available_skills(skills: &[SkillCatalogueEntry]) -> String {
    let mut body = String::from(
        "Skills provide specialized instructions for specific tasks. Before responding, inspect the available skill descriptions. If a skill clearly applies to the user's request, your first action must be to use the read tool to load its SKILL.md from the listed location; do not answer from memory or prior knowledge. Follow the loaded instructions, including any directions to read supporting resources, before producing the response. Resolve relative paths in the skill against the directory containing its SKILL.md.\n<available_skills>",
    );
    for skill in skills {
        body.push_str(&format!(
            "\n  <skill name=\"{}\" location=\"{}\">\n  {}\n  </skill>",
            skill.name, skill.location, skill.description
        ));
    }
    body.push_str("\n</available_skills>");
    body
}

/// The slot a bundle occupies in the assembled system prompt, in pi's fixed order.
/// The variant declaration order IS the render order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BundleKind {
    Persona,
    Tools,
    Guidelines,
    DocPointers,
    ProjectContext,
    AvailableSkills,
    Date,
    Cwd,
}

impl BundleKind {
    /// Stable tag for the evidence store / provenance rows.
    pub fn tag(self) -> &'static str {
        match self {
            BundleKind::Persona => "persona",
            BundleKind::Tools => "tools",
            BundleKind::Guidelines => "guidelines",
            BundleKind::DocPointers => "doc_pointers",
            BundleKind::ProjectContext => "project_context",
            BundleKind::AvailableSkills => "available_skills",
            BundleKind::Date => "date",
            BundleKind::Cwd => "cwd",
        }
    }
}

/// One provenance-tagged section of the assembled system prompt. `body` is the
/// already-rendered text of the section; the assembler computes its content hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextBundle {
    pub kind: BundleKind,
    /// Where the bundle came from: e.g. `builtin:persona`, `fs:/repo/AGENTS.md`.
    pub source: String,
    /// A stable version marker for the source (e.g. `v1`, or a file hash later).
    pub version: String,
    pub body: String,
}

impl ContextBundle {
    pub fn new(
        kind: BundleKind,
        source: impl Into<String>,
        version: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            source: source.into(),
            version: version.into(),
            body: body.into(),
        }
    }
}

/// Per-bundle provenance for the evidence store: one row per included bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleProvenance {
    pub kind: BundleKind,
    pub source: String,
    pub version: String,
    pub content_hash: String,
}

/// One project-instruction document (AGENTS.md / CLAUDE.md): its path (for the
/// wrapper attribute) and verbatim content. Discovered from the filesystem on
/// native; resolved content-addressed from the store on the durable object
/// (context-assembly Phase 3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInstruction {
    pub path: String,
    pub content: String,
}

/// Render the `<project_context>` bundle body: each file wrapped verbatim in a
/// `<project_instructions path="…">` element (pi's exact wrapper). Shared by
/// the native fs-discovery path and the DO store-resolution path so both hosts
/// inject byte-identical content.
pub fn render_project_context(instructions: &[ProjectInstruction]) -> String {
    let mut body = String::from("<project_context>");
    for instruction in instructions {
        body.push_str(&format!(
            "\n<project_instructions path=\"{}\">\n{}\n</project_instructions>",
            instruction.path,
            instruction.content.trim_end()
        ));
    }
    body.push_str("\n</project_context>");
    body
}

/// The assembled system prompt plus per-bundle provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledContext {
    pub system_prompt: String,
    pub bundles: Vec<BundleProvenance>,
}

/// Assemble bundles into the owned-harness system prompt.
///
/// Bundles render in canonical slot order ([`BundleKind`]); bundles sharing a slot
/// keep the host's insertion order (the sort is stable). Empty-body bundles are
/// dropped (a slot with no content emits nothing and no provenance row). Bodies
/// are joined with a blank line. Deterministic: the same bundle set yields
/// byte-identical output regardless of insertion order.
pub fn assemble(mut bundles: Vec<ContextBundle>) -> AssembledContext {
    bundles.retain(|bundle| !bundle.body.trim().is_empty());
    bundles.sort_by_key(|bundle| bundle.kind);
    let system_prompt = bundles
        .iter()
        .map(|bundle| bundle.body.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    let provenance = bundles
        .into_iter()
        .map(|bundle| BundleProvenance {
            content_hash: stable_hash_hex(&bundle.body),
            kind: bundle.kind,
            source: bundle.source,
            version: bundle.version,
        })
        .collect();
    AssembledContext {
        system_prompt,
        bundles: provenance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(kind: BundleKind, body: &str) -> ContextBundle {
        ContextBundle::new(kind, format!("builtin:{}", kind.tag()), "v1", body)
    }

    #[test]
    fn renders_bundles_in_canonical_slot_order_regardless_of_insertion() {
        let forward = assemble(vec![
            bundle(BundleKind::Persona, "PERSONA"),
            bundle(BundleKind::Tools, "TOOLS"),
            bundle(BundleKind::Date, "DATE"),
            bundle(BundleKind::Cwd, "CWD"),
        ]);
        // Same bundles added in a scrambled order must produce identical bytes.
        let scrambled = assemble(vec![
            bundle(BundleKind::Cwd, "CWD"),
            bundle(BundleKind::Date, "DATE"),
            bundle(BundleKind::Tools, "TOOLS"),
            bundle(BundleKind::Persona, "PERSONA"),
        ]);
        assert_eq!(forward.system_prompt, scrambled.system_prompt);
        assert_eq!(forward.system_prompt, "PERSONA\n\nTOOLS\n\nDATE\n\nCWD");
        assert_eq!(forward.bundles, scrambled.bundles);
    }

    #[test]
    fn same_slot_bundles_keep_insertion_order() {
        let out = assemble(vec![
            bundle(BundleKind::ProjectContext, "FIRST"),
            bundle(BundleKind::ProjectContext, "SECOND"),
        ]);
        assert_eq!(out.system_prompt, "FIRST\n\nSECOND");
    }

    #[test]
    fn empty_body_bundles_are_dropped_with_no_provenance_row() {
        let out = assemble(vec![
            bundle(BundleKind::Persona, "PERSONA"),
            bundle(BundleKind::AvailableSkills, "   "),
        ]);
        assert_eq!(out.system_prompt, "PERSONA");
        assert_eq!(out.bundles.len(), 1);
        assert_eq!(out.bundles[0].kind, BundleKind::Persona);
    }

    #[test]
    fn every_included_bundle_gets_a_provenance_row_with_a_content_hash() {
        let out = assemble(vec![
            bundle(BundleKind::Persona, "PERSONA"),
            bundle(BundleKind::Tools, "TOOLS"),
        ]);
        assert_eq!(out.bundles.len(), 2);
        assert_eq!(out.bundles[0].content_hash, stable_hash_hex("PERSONA"));
        assert_eq!(out.bundles[1].content_hash, stable_hash_hex("TOOLS"));
        assert_ne!(out.bundles[0].content_hash, out.bundles[1].content_hash);
    }

    #[test]
    fn skill_catalogue_requires_loading_a_matching_skill_before_responding() {
        let rendered = render_available_skills(&[SkillCatalogueEntry {
            name: "triage".to_owned(),
            description: "Triage the inbox.".to_owned(),
            location: ".agents/skills/triage/SKILL.md".to_owned(),
        }]);
        assert!(rendered.contains("If a skill clearly applies"));
        assert!(rendered.contains("first action must be to use the read tool"));
        assert!(rendered.contains("do not answer from memory or prior knowledge"));
        assert!(rendered.contains("including any directions to read supporting resources"));
        assert!(rendered.contains("Resolve relative paths"));
    }
}
