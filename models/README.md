# Formal Models

Status: draft

This directory holds formal and semi-formal models for the new WhippleScript kernel.

The split is intentional:

```text
Maude        rule/effect-graph kernel and generated program checks
TLA+         control-plane lifecycle, leases, recovery, and event-log ordering
Veil/Lean    later high-assurance transition-system proofs
Trace        Rust-level conformance checker for implementation traces
```

The models are not product code. They are design tools and future regression
checks.

## Model-scope rules (what a model must include to be sound)

These are enforced by review, not tooling. They exist because a real
soundness bug (the 2026-07-22 cross-clone lease-destruction bug) lived in a
seam that two correct-but-narrow models each abstracted away — one modelled
lease exclusivity with no lease id and no merge, the other modelled the merge
fold with no lease events. Both passed; the bug was in their union.

1. **Model the identity, not just the state.** If the projection a model
   verifies is keyed by an identity (a lease id, event id, comment id), the
   identity's *minting* is part of the semantics and must appear in the model.
   An `INSERT OR IGNORE` / dedup on a primary key makes the id the entire
   correctness story: `tracker-lease-merge.maude` mints the acquire id and
   shows the alias-keyed collision as its negative fixture.
2. **A merge/fold model must cover every event kind the fold consumes.** A
   fold that handles field/lifecycle events but not lease/relation/comment
   events proves nothing about those projections. Extend the model or open a
   sibling model per event family (`tracker-lease-merge.maude` is the lease
   sibling of `tracker-merge.maude`).
3. **Prove the bite with a negative fixture.** Every No-solution invariant
   search must be paired with a sibling module (`*-ALIAS`, `*-TIEBREAK`,
   `REACTIVE-*`) that reproduces the forbidden outcome as a Solution — so the
   No-solution has demonstrated content, not a vacuous LHS. NoSolution targets
   need a `RESIDUAL:Cfg`/`C:Cfg` soup variable so the search ranges over the
   whole configuration.

## Current Tooling Check

As of this pass in the local workspace:

```text
maude: installed, tested with scripts/check-formal-models.sh
java: provided by the repo Nix dev shell
apalache: provided by the repo Nix dev shell
lake/lean: lake found on PATH
```

The Maude kernel checks are currently runnable directly in this environment.
TLA+/Apalache checks run through `scripts/check-tla-models.sh`, which enters the
repo Nix dev shell when needed. Lean/Veil remains a planned follow-on validation
layer rather than an active check.

See also:

- [trace-conformance.md](trace-conformance.md) for the first runtime trace
  checker contract.
