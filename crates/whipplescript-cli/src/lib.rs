//! Public native integration surface for WhippleScript hosts.
//!
//! The CLI binary and embedding hosts must cross the same governance trust
//! boundary. Keeping these modules in the package library prevents a host from
//! reimplementing envelope parsing, attestation verification, or IFC semantics.

pub use whipplescript_kernel::{gov, host_policy, host_protocol, ifc, principal};
pub mod host_runtime;

/// The std package manifests shipped with this crate.
///
/// These live in the library, not the binary, for the reason stated above: a
/// host that cannot seed them either cannot run governed effects at all, or
/// reimplements the seeding and drifts from what the CLI does. Since 0.2.2 the
/// admission gate is real for `std.files` / `std.coord` / `std.tracker` /
/// `std.ingress` — an effect whose capability rows were never seeded blocks as
/// `blocked_by_capability` — so this is load-bearing for any host that runs a
/// workflow rather than only an agent turn.
///
/// The files are vendored under this crate so a published tarball is
/// self-contained; the workspace root's `std/` remains the source of truth and
/// `scripts/check-vendored-std.sh` fails the gate on drift.
pub mod std_manifests {
    /// `(import name, manifest JSON)` for every embedded std package (M5
    /// "embedded manifest"). The crate is its own supply chain, so a workflow
    /// that `use`s one of these names (e.g. `use std.memory`) validates and
    /// runs with no `--package-lock` at all. Std packages live in the reserved
    /// `std.*` namespace and a package lock can never claim such a name, so the
    /// embedded copy always wins. Add more by appending
    /// `(name, include_str!(..))` pairs here.
    pub const EMBEDDED_STD_MANIFESTS: &[(&str, &str)] = &[
        // Boundary/taxonomy package for the agent-provider seam (spec/std-agent.md
        // "Manifest"): the `agent.tell` effect-contract mirror (parser owns the
        // grammar; merge-folds, drift surfaces as `effect_contract_duplicate` —
        // rides the embedded-copy privilege door), the grandfathered `agent.turn`
        // capability row, and OPERATOR-PLANE provider rows (`"agent_provider":
        // true`) contributing the built-in provider kinds
        // owned/fixture/native-fixture/command to the open provider registry.
        // Operator-plane rows are admission-inert by construction: the kind set is
        // visibility data the provider-kind-known check reads, never a grant.
        (
            "std.agent",
            include_str!("../vendored-std/manifests/agent.json"),
        ),
        // Thin provider package (spec/std-agent.md "Providers"): contributes
        // provider kind `codex` iff the `codex` cargo feature compiles the adapter
        // in — manifest presence and adapter presence agree by construction. A
        // binary without the feature genuinely does not know the kind, and the
        // registry reports it as a missing package, which is the truth.
        #[cfg(feature = "codex")]
        (
            "std.agent.codex",
            include_str!("../vendored-std/manifests/agent-codex.json"),
        ),
        // Thin provider package: provider kind `claude` iff the `claude` cargo
        // feature compiles the sidecar adapter in (see std.agent.codex above).
        #[cfg(feature = "claude")]
        (
            "std.agent.claude",
            include_str!("../vendored-std/manifests/agent-claude.json"),
        ),
        // Operator-config package for the core `schema.coerce` effect
        // (spec/std-coercion.md "Manifest"): capability/provider/profile/binding
        // rows plus the `schema.coerce` effect contract. The contract mirrors the
        // parser-compiled one (parser owns the grammar — zero constructs here) and
        // merge-folds against it; a shape drift between the two would surface as
        // an `effect_contract_duplicate` diagnostic. Declaring a core effect kind
        // rides the embedded-copy privilege door (`manifest_is_embedded_copy`).
        (
            "std.coercion",
            include_str!("../vendored-std/manifests/coercion.json"),
        ),
        // Runtime identity for the coordination package (spec/std-coord.md
        // "Manifest", slice 4): four coordination effect contracts (mirroring the
        // parser-compiled ones — merge-folds, drift surfaces as
        // `effect_contract_duplicate`), seven construct rows (three
        // `declaration_block`/`metadata_only` decls + four
        // `effect_operation`/`resource_effect` verbs — the catalog's first
        // `resource_effect` producer, admitted through the authorability door's
        // privilege-tuple leg), and the capability/provider/profile/binding rows
        // that make the NATIVE admission gate real for coordination kinds (the
        // builtin exemption is deleted, store/lib.rs `policy_block_on`).
        // `lease.renew` ships admission rows (capability/provider/binding) but no
        // contract: the verb is live in lowering + handler while its contract
        // surface rides the std.tracker renew design (spec/std-coord.md "Deferred
        // with cause"). The DECL GRAMMAR stays in std/grammars/coord.json
        // (build.rs-only): the manifest authorizes, it does not parse (M1).
        (
            "std.coord",
            include_str!("../vendored-std/manifests/coord.json"),
        ),
        // Runtime identity for the files package (spec/std-files.md, slices
        // F2/F5): four `file.*` effect contracts mirroring the parser-compiled
        // ones (merge-folds, drift surfaces as `effect_contract_duplicate`), five
        // construct rows (one `declaration_block`/`metadata_only` decl + four
        // `effect_operation`/`typed_effect_call` verbs — making the catalog's
        // "promoted for std.files" claim TRUE, E4: attribution + admission, no
        // rekey), and the capability/provider/profile/binding rows that make the
        // NATIVE admission gate real for `file.*` kinds (the builtin exemption is
        // deleted, store/lib.rs `policy_block_on`; the DO mirror keeps its
        // exemption until the DO bootstrap registers packages). The DECL GRAMMAR
        // stays in std/grammars/files.json (build.rs-only): the manifest
        // authorizes, it does not parse (M1).
        (
            "std.files",
            include_str!("../vendored-std/manifests/files.json"),
        ),
        // Runtime identity for the typed signal-admission package
        // (spec/std-ingress.md "Manifest", slice I2b): the `signal.emit` effect
        // contract (mirroring the parser-compiled one — merge-folds, drift
        // surfaces as `effect_contract_duplicate`), three construct rows (the
        // `signal` declaration_block, the `source` source_declaration exercising
        // the `signal_source` lowering class, and the `emit signal … to`
        // effect_operation on `signal_emit` — `signal`/`emit` are reserved
        // keywords admitted through the authorability door's privilege-tuple leg,
        // `source` through the embedded-copy leg), and the
        // capability/provider/binding rows that make the NATIVE admission gate
        // real for `signal.emit` (the builtin exemption is deleted, store/lib.rs
        // `policy_block_on`; the DO mirror keeps its exemption until the DO
        // bootstrap registers packages). The operator-plane provider rows carry
        // the static "Provider Contract" descriptors for the cli/stdio/file/http
        // admission drivers (E3 defers probed capability reports demand-side);
        // they also feed the provider-kind-known source-header check. The clock
        // provider row lives in std/manifests/time.json, not here (E2 boundary).
        // Sources have NO grammar file: the `signal`/`source` decls are
        // hand-parsed core grammar (M1), the manifest authorizes, it does not
        // parse.
        (
            "std.ingress",
            include_str!("../vendored-std/manifests/ingress.json"),
        ),
        // DR-0074 §12: custody as the fifteenth std package, so `seal` is a
        // construct instance rather than a core effect kind. The `credential`
        // DECLARATION stays core and rides `vendored-std/grammars/`; this
        // manifest carries the `custody.wrap` capability and the `seal`
        // effect_operation. It also carries credential custody's DR-0053 half:
        // the `custody.request` effect contract and the custodian provider that
        // serves it — the effect egresses carrying sentinels, so the provider is
        // the only party that ever holds material.
        (
            "std.custody",
            include_str!("../vendored-std/manifests/custody.json"),
        ),
        (
            "std.memory",
            include_str!("../vendored-std/manifests/memory.json"),
        ),
        // Runtime identity for the versioned-workspace package (DR-0052
        // grammar pass): the `vcs.promote` effect contract + the `promote
        // <stream>` effect_operation construct (the parser grammar rides
        // the same manifest via STD_MANIFESTS), and the capability /
        // provider / binding rows admitting the boundary hop natively
        // (`std.vcs.native`) or under the fixture. The `stream` DECL
        // grammar stays in std/grammars/vcs-grammar.json (build.rs-only):
        // the manifest authorizes, it does not parse (M1).
        (
            "std.vcs",
            include_str!("../vendored-std/manifests/vcs.json"),
        ),
        (
            "std.messaging",
            include_str!("../vendored-std/manifests/messaging.json"),
        ),
        // Contracts-only: `exec` is core grammar (never manifest-authored — the
        // package pipeline forbids `core_effect` lowering), so this manifest
        // carries the library identity and the `script.raw` capability row shape;
        // the `script.<name>` family is instantiated from the operator script
        // manifest at seeding time (spec/std-script.md). Deliberately absent from
        // the parser build.rs manifest list, which is grammar-only.
        (
            "std.script",
            include_str!("../vendored-std/manifests/script.json"),
        ),
        // Operator-plane only (std-telemetry.md T3): library identity plus the
        // `otlp` exporter's registry defaults. Zero constructs, zero effect
        // contracts, zero capabilities — the package deliberately contributes
        // nothing to the admission plane; `whip otel-export` reads the provider
        // row's config as its defaults (env/flags override).
        (
            "std.telemetry",
            include_str!("../vendored-std/manifests/telemetry.json"),
        ),
        // Identity-only (std-time.md T1): the `timer.wait` contract is compiled
        // into the parser, so this manifest carries library identity and nothing
        // an enforcement point reads (no capabilities, no contracts).
        (
            "std.time",
            include_str!("../vendored-std/manifests/time.json"),
        ),
        // Runtime identity for the work-tracker package (spec/std-tracker.md
        // "Manifest", slice T4): four tracker effect contracts mirroring the
        // parser-compiled ones (merge-folds, drift surfaces as
        // `effect_contract_duplicate`), six construct rows (one
        // `declaration_block`/`metadata_only` decl + five
        // `effect_operation`/`typed_effect_call` verbs — the claim/renew/release
        // rows are the first real exercisers of the reserved-keyword privilege
        // tuples, admitted through the authorability door's privilege-tuple leg),
        // and the capability/provider/profile/binding rows that make the NATIVE
        // admission gate real for `tracker.*` kinds (the builtin exemption is
        // deleted, store/lib.rs `policy_block_on`; the DO mirror keeps its
        // exemption until the DO bootstrap registers packages). `tracker.renew`
        // now ships a full effect contract too (T3 landed the renew end-to-end +
        // claim TTL, spec/std-tracker.md "Renew/TTL semantics"): its manifest
        // contract row merge-folds against the parser-compiled `tracker.renew`
        // contract. The DECL GRAMMAR stays in std/grammars/tracker.json
        // (build.rs-only): the manifest authorizes, it does not parse (M1).
        (
            "std.tracker",
            include_str!("../vendored-std/manifests/tracker.json"),
        ),
    ];

    /// Seed every embedded std manifest into `store`.
    ///
    /// Idempotent: `register_package_manifest` is `ON CONFLICT DO UPDATE`, so
    /// calling this on an already-seeded store is a no-op. A caller holding a
    /// package lock should register the lock first and skip names it covers —
    /// the lock is authoritative for any name it shares.
    pub fn register_all(
        store: &whipplescript_store::SqliteStore,
    ) -> Result<(), whipplescript_store::StoreError> {
        for (_, json) in EMBEDDED_STD_MANIFESTS {
            store.register_package_manifest(json)?;
        }
        Ok(())
    }
}
