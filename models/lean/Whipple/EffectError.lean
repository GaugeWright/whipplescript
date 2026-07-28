/-
Typed effect failures — the `EffectError` family's base/extras soundness.

Companion to models/maude/effect-error.maude. The Maude model bites the checker on
concrete bad programs; this module machine-checks the two type-theoretic claims that
make DR-0032's "commit to the base, defer the extras behind narrowing" sound (per
spec/decision-records/0032-typed-effect-failures.md, Decisions 0/3 and the
formal-model plan):

  (1) base ⊆ every variant: a base field is in every effect kind's failure schema,
      so a base read is well-typed in every narrowed scope AND in the un-narrowed
      scope — i.e. the un-narrowed base read is total;
  (2) extras-behind-narrowing: a non-base field that is in some kind's schema is in
      that kind's EXTRAS — so it is reachable only by narrowing to that kind. This is
      why adding a variant's extras later cannot change any existing base read
      (non-breaking by construction).

Non-dependent: a schema is a base predicate plus a per-kind extras predicate over an
abstract field type. No Mathlib.
-/
namespace Whipple
namespace EffectError

/-- A failure schema over effect `Kind`s and abstract `Field`s: the kind-independent
    `base` (shared by every effect failure) plus per-kind `extras`. The whole point
    is that `base` does not depend on `Kind`. -/
structure Schema (Kind : Type) (Field : Type) where
  base : Field → Prop
  extras : Kind → Field → Prop

variable {Kind : Type} {Field : Type}

/-- A field is in kind `k`'s failure schema iff it is a base field or one of `k`'s
    extras. This is what `after <k-effect> fails as f` narrows `f.field` against. -/
def inSchema (s : Schema Kind Field) (k : Kind) (f : Field) : Prop :=
  s.base f ∨ s.extras k f

/-- (1) base ⊆ every variant: every base field is in every kind's schema, so a base
    read type-checks in any narrowed scope. -/
theorem base_subset_variant (s : Schema Kind Field) (k : Kind) (f : Field)
    (h : s.base f) : inSchema s k f := Or.inl h

/-- (1, un-narrowed totality): the un-narrowed read surface is exactly `base`, and it
    is contained in every variant — so an un-narrowed base read can never become
    ill-typed when a variant is added. -/
theorem unnarrowed_base_total (s : Schema Kind Field) (k : Kind) (f : Field)
    (h : s.base f) : inSchema s k f := base_subset_variant s k f h

/-- (2) extras-behind-narrowing: a non-base field that is in kind `k`'s schema must be
    one of `k`'s extras — there is no other way it could be in scope, so it is
    reachable only by narrowing to `k`. -/
theorem extra_requires_narrowing (s : Schema Kind Field) (k : Kind) (f : Field)
    (hbase : ¬ s.base f) (h : inSchema s k f) : s.extras k f := by
  cases h with
  | inl hb => exact absurd hb hbase
  | inr he => exact he

/-- Corollary (additivity): adding extras to a kind cannot change which fields are
    base-readable. If `f` is base under `s`, it is base under any schema that only
    differs in `extras` — base reads are invariant under variant extension. -/
theorem base_invariant_under_extension
    (base : Field → Prop) (e e' : Kind → Field → Prop) (f : Field)
    (h : (Schema.mk base e).base f) : (Schema.mk base e').base f := h

end EffectError
end Whipple
