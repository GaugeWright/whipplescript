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
//! guards the set against drift.

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
    (
        "std.memory",
        include_str!("../../../std/manifests/memory.json"),
    ),
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
