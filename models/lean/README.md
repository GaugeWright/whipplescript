# Lean proof layer — the IFC algebra, machine-checked

Maude and TLA+ give fast, bounded design feedback (they check concrete fixtures).
They do **not** prove universal algebraic facts. After the report-vs-check bug
(2026-06-27) showed that "we have formal models" had been quietly meaning "we have
bounded smoke tests," this layer proves the **load-bearing algebra** the Rust
checker and the Maude models only asserted in comments.

It is deliberately **Mathlib-free** and pinned to an installed toolchain
(`lean-toolchain` → v4.30.0), so it builds **offline and hermetically** in the
gate — and, crucially, the acts-for order is proven about **our own** closure, not
imported from a library (importing `Relation.ReflTransGen` would not answer
"is *our* `can_act` the preorder").

## What is proven

`Whipple/ActsFor.lean` — the order:
- `actsFor_refl`, `actsFor_trans` → acts-for is a **preorder**.
- `public_is_bottom`, `public_acts_for_only_public` → `public` is its **bottom**
  and holds **no authority** (mirroring the Rust `if p == PUBLIC { return false }`).
- `integ_is_conf_dual` → integrity is confidentiality with the axes swapped and
  endpoints reversed — the exact sense in which `injects` reuses `can_act`.
- `conf_to_public_needs_public_source` → the **fail-closed sticky boundary**:
  confidential data cannot reach a public sink without a declassify.

`Whipple/Decide.lean` — the algorithm is the order:
- `fuel_sound` + `actsFor_complete` + `canAct_iff` → the bounded forward search
  the Rust `Envelope::can_act` and the Maude `reach` run is **sound and complete**
  against `ActsFor`. It decides **exactly** the preorder — no more, no less.

`Whipple/Boundary.lean` — the bug class, fixed at the type level:
- `consumer_relies_on_genuine`, `no_verified_for_tampered` → a `Verified` artifact
  is constructible only with a genuineness proof, so **every** consumer is gated by
  construction. This is the discipline the report-vs-check bug violated; the Rust
  `VerifiedEnvelope` refactor (pending) is its realization.

## Trust base

`#print axioms Whipple.canAct_iff` → `[propext, Quot.sound]` (Lean's standard core;
no `sorryAx`, not even `Classical.choice`). The bottom and boundary theorems depend
on **no axioms at all**.

## Map to the implementation

| Lean | Rust (`crates/whipplescript-cli/src/ifc.rs`) | Maude |
| --- | --- | --- |
| `ActsFor` / `canAct_iff` | `Envelope::can_act` | `canAct` / `reach` |
| `FlowConf` (= `¬ leaks`) | `Envelope::leaks` | `infoflow-confidentiality` |
| `FlowInteg` (= `¬ injects`) | `Envelope::injects` | `infoflow-integrity` |
| `Verified` boundary | `gov::SignedEnvelope::verify` (→ `VerifiedEnvelope`, pending) | `subworkflow-attestation` |

## Running

```sh
scripts/check-lean-models.sh   # builds + rejects any sorry/admit/axiom/native_decide
```

`Whipple/ReaderSets.lean` — the label is a SET of compartments:
- `canRead_nil` (∅ is the public bottom), `canRead_append` (union is the join — a
  party reads the combination iff it reads both parts), `canRead_append_comm`,
  `canRead_mono` (higher clearance reads at least as much). The confidentiality
  label forms a join-semilattice; the single-authority `Label.reader` is the leaf.
- `leak_safe`, `dominates_singleton`, `dominates_split`, `inject_safe` → the Rust
  leak/inject checks lift from one reader/writer to set labels without changing the
  underlying acts-for lattice.
- `shared_cell_clearance_not_nmif` → two incomparable clearances can both dominate
  a shared cell label; leak-safety for the cell does **not** create an authority
  flow/NMIF relation among the clearances.
- `same_principal_flow_trivial` → self-coordination is reflexive, justifying the
  `|P(R)|≤1` skip for coordination gates.

`Whipple/NMIF.lean` — robust declassification (nonmalleable information flow):
- `untrusted_declassify_only_public` (the NMIF guarantee: attacker-controlled data
  — integrity at the public bottom — can be released only to public, so an attacker
  cannot influence a downgrade in their favor; **zero axioms**),
  `endorsed_enables_declassify` (vouch first, then release), `robustDeclassify_mono`.

## Not yet proven here (next obligations)
- Durable **label carriage** across persistence/instance boundaries (I-IFC7) — that
  is a transition-system property; the natural home is Veil (Lean) or TLA+, not this
  algebraic core.
