/-
Discriminated-family narrowing — the static soundness of branch-local `case`.

Companion to models/maude/case-family.maude. The Maude model bites the checker on
concrete bad programs; this module machine-checks the underlying type-theoretic
claims (per spec/decision-records/discriminated-families-design.md section 6.1):

  (a) per-arm scope judgment: the binding matched in arm `t` has exactly tag `t`'s
      payload type;
  (b) non-interference: that binding is out of scope in any other arm — a cross-arm
      payload read evaluates to `none`, a same-arm read yields the value;
  (c) a field read is typed against the MATCHED tag's payload (so a field of another
      variant cannot be applied);
  (d) exhaustiveness ⇒ totality: every declared tag is handled by its own arm or the
      wildcard — the static half of Total Outcome Settlement.

Non-dependent: finite tags + a flat payload-type per tag. No Mathlib.
-/
namespace Whipple
namespace Narrowing

/-- A discriminated family: a finite list of declared tags and a flat payload type
    per tag. (A payload is a flat record type, never another family — exhaustiveness
    stays decidable over a finite tag set.) -/
structure Family (Tag : Type) where
  tags : List Tag
  payload : Tag → Type

variable {Tag : Type}

/-- (a) The scope of arm `t`: the binding visible inside it has type `payload t`.
    Narrowing assigns the matched tag's payload, nothing else. -/
def armScope (fam : Family Tag) (t : Tag) : Type := fam.payload t

theorem armScope_eq (fam : Family Tag) (t : Tag) :
    armScope fam t = fam.payload t := rfl

/-- A narrowed binding inside arm `t`: the payload value for exactly that tag. -/
structure Narrowed (fam : Family Tag) (t : Tag) where
  value : fam.payload t

/-- A guarded read of tag `u`'s payload from inside arm `t`: defined only when the
    tags coincide (you are in arm `u`), `none` otherwise. This is the elimination
    discipline — a payload field is reachable only within its own arm. -/
def tryRead [DecidableEq Tag] (fam : Family Tag) {t : Tag}
    (n : Narrowed fam t) (u : Tag) : Option (fam.payload u) :=
  if h : t = u then some (h ▸ n.value) else none

/-- (b) Non-interference, cross-arm: reading another arm's payload yields `none`.
    The binding from arm `t` is not in scope at a use site tagged `u ≠ t`. -/
theorem tryRead_cross_arm_none [DecidableEq Tag] (fam : Family Tag) {t : Tag}
    (n : Narrowed fam t) {u : Tag} (h : t ≠ u) : tryRead fam n u = none := by
  unfold tryRead
  simp [h]

/-- (b) Non-interference, same-arm: reading your own arm's payload yields the value.
    Covers a guard in arm `t` reading `t`'s bound payload — the terminal-guard case
    where the bound payload type is in scope. -/
theorem tryRead_self_some [DecidableEq Tag] (fam : Family Tag) (t : Tag)
    (n : Narrowed fam t) : tryRead fam n t = some n.value := by
  unfold tryRead
  simp

/-- A scope predicate: the binding introduced by matching tag `t` is in scope at a
    use site tagged `u` exactly when `t = u`. -/
def inScope [DecidableEq Tag] (t u : Tag) : Bool := decide (t = u)

theorem binding_not_in_scope_cross_arm [DecidableEq Tag] {t u : Tag}
    (h : t ≠ u) : inScope t u = false := by
  unfold inScope
  simp [h]

theorem binding_in_scope_self [DecidableEq Tag] (t : Tag) :
    inScope t t = true := by
  unfold inScope
  simp

/-- (c) A field read is typed against the matched tag's payload: the projector
    `f : fam.payload t → F` is over arm `t`'s payload, so a field of a different
    variant (`fam.payload u`) cannot be applied here. -/
def readField (fam : Family Tag) {t : Tag} {F : Type}
    (f : fam.payload t → F) (n : Narrowed fam t) : F := f n.value

theorem readField_uses_matched_payload (fam : Family Tag) {t : Tag} {F : Type}
    (f : fam.payload t → F) (n : Narrowed fam t) :
    readField fam f n = f n.value := rfl

/-- Coverage of a `case`: which tags have an unguarded arm, and whether a wildcard
    arm is present. A guarded arm never sets `covered` (it may fail at runtime), so
    coverage counts only unguarded arms — matching case-family.maude. -/
structure Coverage (Tag : Type) where
  covered : Tag → Bool
  wild : Bool

/-- Exhaustive: a wildcard is present, or every declared tag has an unguarded arm. -/
def Exhaustive (fam : Family Tag) (c : Coverage Tag) : Prop :=
  c.wild = true ∨ ∀ t, t ∈ fam.tags → c.covered t = true

/-- Total: every declared tag is dispatched — by its own arm or the wildcard. -/
def Total (fam : Family Tag) (c : Coverage Tag) : Prop :=
  ∀ t, t ∈ fam.tags → (c.covered t = true ∨ c.wild = true)

/-- (d) THE GUARANTEE: exhaustiveness implies totality. Every outcome of the case is
    handled, so no tag can fall through unhandled — the static half of Total Outcome
    Settlement (the runtime half is auto-fail; see rule-autofail.maude). -/
theorem exhaustive_total (fam : Family Tag) (c : Coverage Tag)
    (h : Exhaustive fam c) : Total fam c := by
  intro t ht
  rcases h with hw | hcov
  · exact Or.inr hw
  · exact Or.inl (hcov t ht)

/-- Conversely, a non-exhaustive case (no wildcard, a declared tag uncovered) is not
    total — there is an unhandled outcome. This is the rejected program: the `case`
    that case-family.maude flags `rejectNonExhaustive`. -/
theorem not_total_of_gap (fam : Family Tag) (c : Coverage Tag)
    (hw : c.wild = false) {t : Tag} (ht : t ∈ fam.tags)
    (hgap : c.covered t = false) : ¬ Total fam c := by
  intro htot
  rcases htot t ht with hcov | hwild
  · exact absurd hcov (by simp [hgap])
  · exact absurd hwild (by simp [hw])

end Narrowing
end Whipple
