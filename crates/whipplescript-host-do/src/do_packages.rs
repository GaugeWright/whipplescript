//! DO-plane package bootstrap (spec/durable-object-runtime-tracker.md "DO-plane
//! package bootstrap"; the std-package campaign's Wave 1 tail).
//!
//! The native host seeds the embedded std manifests into its store at instance
//! setup (`register_locked_packages`, cli/main.rs) so the admission gate is REAL
//! for coordination / file / tracker / ingress kinds — an unbound kind blocks as
//! `blocked_by_capability` rather than being waved through by a builtin
//! exemption. This module is the DO counterpart: the same always-embedded
//! manifest set, registered via the DO store's `register_package_manifest`
//! (which fans a manifest out into the capability/provider/profile/binding
//! tables exactly as the native store does, skipping operator-plane rows).
//!
//! The set is the non-feature-gated half of cli's `EMBEDDED_STD_MANIFESTS`: the
//! `std.agent.codex` / `std.agent.claude` thin provider packages are compiled in
//! only behind the `codex` / `claude` cargo features, which the wasm DO build
//! does not enable, so their provider-KIND rows (operator-plane, admission-inert
//! anyway) are correctly absent here. `embedded_std_manifest_names_cover_the_do_admission_set`
//! (this module's tests) guards the set against drift: it reads `std/manifests/`
//! and fails if a shipped package is missing from the list, because a missing
//! one leaves the hosted path knowing a smaller package universe than the
//! native one (DR-0074 §12) — its effects refuse at the admission gate.

use whipplescript_store::{RuntimeStore, StoreError};

/// The always-embedded std manifests (name, JSON source), byte-identical to the
/// files cli embeds. Paths are relative to this source file
/// (`crates/whipplescript-host-do/src/`), the same depth as cli's.
pub const EMBEDDED_STD_MANIFESTS: &[(&str, &str)] = &[
    (
        "std.agent",
        include_str!("../../../std/manifests/agent.json"),
    ),
    (
        "std.coercion",
        include_str!("../../../std/manifests/coercion.json"),
    ),
    (
        "std.coord",
        include_str!("../../../std/manifests/coord.json"),
    ),
    (
        "std.files",
        include_str!("../../../std/manifests/files.json"),
    ),
    (
        "std.ingress",
        include_str!("../../../std/manifests/ingress.json"),
    ),
    // DR-0074 §12. Registered here in the same change as the CLI so the hosted
    // path never knows a smaller package universe than the native one.
    (
        "std.custody",
        include_str!("../../../std/manifests/custody.json"),
    ),
    (
        "std.memory",
        include_str!("../../../std/manifests/memory.json"),
    ),
    // DR-0052 R4 / DO-parity. The DO dispatches `vcs.promote` and the selective
    // `vcs.undo` / `vcs.transport` verbs (do_instance.rs), and the admission gate
    // reaches those arms only if this manifest's capability / provider / binding
    // rows are seeded: without them a `capability.call` naming `vcs.promote`
    // refuses as `blocked_by_capability` before any provider runs.
    ("std.vcs", include_str!("../../../std/manifests/vcs.json")),
    (
        "std.messaging",
        include_str!("../../../std/manifests/messaging.json"),
    ),
    (
        "std.script",
        include_str!("../../../std/manifests/script.json"),
    ),
    (
        "std.telemetry",
        include_str!("../../../std/manifests/telemetry.json"),
    ),
    ("std.time", include_str!("../../../std/manifests/time.json")),
    (
        "std.tracker",
        include_str!("../../../std/manifests/tracker.json"),
    ),
];

/// Seed the embedded std manifests into the DO store so the admission gate is
/// real for their effect kinds. Idempotent: `register_package_manifest` writes
/// `ON CONFLICT DO UPDATE`, so a rehydrated isolate re-seeding is a no-op. Call
/// at instance setup, before the first worker pass admits any effect.
pub fn register_embedded_std_packages<S: RuntimeStore>(store: &S) -> Result<(), StoreError> {
    for (_name, json) in EMBEDDED_STD_MANIFESTS {
        store.register_package_manifest(json)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::EMBEDDED_STD_MANIFESTS;
    use std::collections::BTreeSet;

    /// The two thin agent-provider packages cli embeds behind `#[cfg(feature =
    /// "codex")]` / `#[cfg(feature = "claude")]`. The wasm DO build enables
    /// neither, and their rows are operator-plane (provider kinds), so they are
    /// deliberately absent from the DO set.
    const FEATURE_GATED_PACKAGES: &[&str] = &["std.agent.codex", "std.agent.claude"];

    /// The module doc promises this guard: the DO admission set is the
    /// non-feature-gated half of cli's `EMBEDDED_STD_MANIFESTS`, and a std
    /// package that lands under `std/manifests/` without being seeded here
    /// leaves the hosted path knowing a SMALLER package universe than the
    /// native one (DR-0074 §12) — its effects block as `blocked_by_capability`
    /// at the DO admission gate because no `capability_schemas` row exists,
    /// which no test notices because the DO providers are driven directly.
    #[test]
    fn embedded_std_manifest_names_cover_the_do_admission_set() {
        let manifests_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../std/manifests");
        let entries = std::fs::read_dir(&manifests_dir)
            .expect("std/manifests directory must exist and be readable");
        let mut shipped = BTreeSet::new();
        for entry in entries {
            let path = entry.expect("std/manifests entry must be readable").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("could not read `{}`: {error}", path.display()));
            let manifest: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|error| panic!("`{}` is not valid JSON: {error}", path.display()));
            let name = manifest
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("`{}` is missing a top-level `name`", path.display()))
                .to_owned();
            if FEATURE_GATED_PACKAGES.contains(&name.as_str()) {
                continue;
            }
            shipped.insert(name);
        }
        let embedded: BTreeSet<String> = EMBEDDED_STD_MANIFESTS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert_eq!(
            embedded, shipped,
            "the DO admission set must carry every non-feature-gated std manifest; \
             a package shipped under std/manifests/ but missing here makes its effects \
             block as `blocked_by_capability` on a bootstrapped DO while they run natively"
        );
    }
}
