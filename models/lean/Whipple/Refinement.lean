/-
Family B refinement — value-conditioned field presence, machine-checked.

Companion to models/maude/discriminant-schema.maude. Per
spec/decision-records/discriminated-families-design.md sections 5.7, 5.8, 6.3, the
field-presence claim is non-dependent: a finite map from the discriminant value to the
set of present fields. This module proves:

  * consistency: in a well-formed value, every field narrowing brings into scope is
    actually present (static narrowing is true of the runtime value);
  * narrowing = the conditioned set: a field is in scope in arm `d` iff it is
    conditioned on `d`;
  * no over-rejection: admission is the soundness-minimal POSITIVE obligation, so a
    value carrying an inapplicable present sibling (the all-keys-present webhook shape)
    is still well-formed.

No Mathlib.
-/
namespace Whipple
namespace Refinement

/-- A discriminant-string schema: each conditioned field names the discriminant value
    it is present under. v1: a single literal-union discriminant. -/
structure Schema (Disc Field : Type) where
  cond : Field → Disc

/-- A runtime value: the discriminant value and which fields are present. -/
structure Value (Disc Field : Type) where
  disc : Disc
  present : Field → Bool

variable {Disc Field : Type}

/-- Admission (section 5.7 Finding 2): conditional REQUIRED-presence only. A value is
    well-formed when every field conditioned on the current discriminant value is
    present. Fields conditioned on other values (inapplicable siblings) are NOT
    constrained -- the soundness-minimal positive obligation. -/
def WellFormed [DecidableEq Disc] (s : Schema Disc Field) (val : Value Disc Field) : Prop :=
  ∀ f, s.cond f = val.disc → val.present f = true

/-- The fields narrowing brings into scope in arm `d`: exactly those conditioned on `d`. -/
def narrowed [DecidableEq Disc] (s : Schema Disc Field) (d : Disc) (f : Field) : Bool :=
  decide (s.cond f = d)

/-- Narrowing yields EXACTLY the conditioned set: in scope in arm `d` iff conditioned on `d`. -/
theorem narrowed_iff_cond [DecidableEq Disc] (s : Schema Disc Field) (d : Disc) (f : Field) :
    narrowed s d f = true ↔ s.cond f = d := by
  unfold narrowed
  exact decide_eq_true_iff

/-- Consistency: in a well-formed value, every field narrowing brings into scope is
    actually present -- so the static narrowing is a true statement about the value. -/
theorem narrowed_present [DecidableEq Disc] (s : Schema Disc Field)
    (val : Value Disc Field) (wf : WellFormed s val) (f : Field)
    (hn : narrowed s val.disc f = true) : val.present f = true :=
  wf f ((narrowed_iff_cond s val.disc f).mp hn)

/-- No over-rejection: a well-formed value stays well-formed when an inapplicable
    sibling (conditioned on a different value) is forced present. Admission accepts the
    all-keys-present webhook shape; narrowing soundness needs positive presence, not
    absence of inapplicable siblings (section 5.7 Finding 2, the d' bite). -/
theorem wellformed_allows_inapplicable [DecidableEq Disc] [DecidableEq Field]
    (s : Schema Disc Field) (val : Value Disc Field) (wf : WellFormed s val)
    (g : Field) (hg : s.cond g ≠ val.disc) :
    WellFormed s { disc := val.disc,
                   present := fun x => if x = g then true else val.present x } := by
  intro f hf
  by_cases h : f = g
  · subst h; simp
  · simp only [h, if_false]; exact wf f hf

end Refinement
end Whipple
