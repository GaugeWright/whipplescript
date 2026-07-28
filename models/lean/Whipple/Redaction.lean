/-
Per-field redaction — the soundness substrate for `redact` (Tier 1) and label-driven
auto-redaction / per-field flow signatures (Tier 2).

The default information-flow analysis is the rule-level OPAQUE join box (I-IFC2): a
value read from a resource carries that resource's whole label. `redact` is an
explicit, audited crossing that gets LOCAL value-precision: it projects a record to a
chosen subset of fields, and the projection carries only the join of the KEPT fields'
labels. This module models a record as a list of fields, each with a confidentiality
label (a reader-authority set, reusing `ReaderSets.canRead`), and proves the three
properties the checker relies on:

  1. RELEASE IS DETERMINED ONLY BY THE KEPT FIELDS (`canRead_redact`). Whoever may read
     the redaction is fixed by the kept fields alone — the dropped fields are
     non-interfering for the release decision. This is what makes a declassify scoped
     to a redaction sound: the released value provably cannot constrain on / carry a
     dropped field.
  2. REDACTION ONLY LOWERS THE LABEL (`redact_refines`). Anyone cleared for the whole
     record is cleared for any projection of it, so redaction is a conservative
     refinement of the opaque box — it never widens what must be protected.
  3. KEEPING EVERYTHING IS THE OPAQUE BOX (`redact_keep_all`). The whole-record join is
     the degenerate redaction, so the I-IFC2 default is the keep-all case and the
     refinement is sound by construction.

Builds on `Whipple.ReaderSets`; Mathlib-free.
-/
import Whipple.ReaderSets

namespace Whipple

variable {P : Type}

/-- A record field: a name (abstracted as a `Nat`) and its confidentiality label as a
    reader-authority set. -/
structure Field (P : Type) where
  name : Nat
  readers : List P

/-- The whole-record confidentiality label: the JOIN (union) of every field's reader
    set — the opaque-box label a non-redacted read carries (I-IFC2). -/
def recordReaders : List (Field P) → List P
  | [] => []
  | f :: rest => f.readers ++ recordReaders rest

/-- A party `a` may read a record iff it may read EVERY field — the join decomposes
    field-wise. (The set-join `canRead_append` lifted across the field list.) -/
theorem canRead_record (d : List (P × P)) (pub a : P) (fs : List (Field P)) :
    canRead d pub a (recordReaders fs) ↔ ∀ f ∈ fs, canRead d pub a f.readers := by
  induction fs with
  | nil =>
    constructor
    · intro _ f hf; cases hf
    · intro _; exact canRead_nil d pub a
  | cons f rest ih =>
    constructor
    · intro h
      rw [recordReaders, canRead_append] at h
      intro g hg
      rcases List.mem_cons.mp hg with hgf | hgr
      · subst hgf; exact h.1
      · exact (ih.mp h.2) g hgr
    · intro h
      rw [recordReaders, canRead_append]
      exact ⟨h f List.mem_cons_self,
             ih.mpr (fun g hg => h g (List.mem_cons_of_mem f hg))⟩

/-- Redact a record to the fields the predicate `keep` selects (a by-name `keep` list,
    modeled as a decidable predicate on field names). -/
def redact (keep : Nat → Bool) : List (Field P) → List (Field P)
  | [] => []
  | f :: rest =>
    if keep f.name then f :: redact keep rest else redact keep rest

/-- Membership in the redaction: exactly the fields that were present AND kept. -/
theorem mem_redact (keep : Nat → Bool) (fs : List (Field P)) (f : Field P) :
    f ∈ redact keep fs ↔ f ∈ fs ∧ keep f.name = true := by
  induction fs with
  | nil => simp [redact]
  | cons g rest ih =>
    by_cases hg : keep g.name = true
    · rw [redact, if_pos hg]
      constructor
      · intro hf
        rcases List.mem_cons.mp hf with hfg | hfr
        · subst hfg; exact ⟨List.mem_cons_self, hg⟩
        · exact ⟨List.mem_cons_of_mem g (ih.mp hfr).1, (ih.mp hfr).2⟩
      · rintro ⟨hf, hk⟩
        rcases List.mem_cons.mp hf with hfg | hfr
        · subst hfg; exact List.mem_cons_self
        · exact List.mem_cons_of_mem g (ih.mpr ⟨hfr, hk⟩)
    · rw [redact, if_neg hg]
      constructor
      · intro hf
        exact ⟨List.mem_cons_of_mem g (ih.mp hf).1, (ih.mp hf).2⟩
      · rintro ⟨hf, hk⟩
        rcases List.mem_cons.mp hf with hfg | hfr
        · subst hfg; exact absurd hk hg
        · exact ih.mpr ⟨hfr, hk⟩

/-- THE SOUNDNESS THEOREM. Who may read a redaction is determined ENTIRELY by the kept
    fields: a party may read it iff it may read every field that was both present and
    kept. The dropped fields never appear in the release condition — they are
    non-interfering — so a declassify scoped to a redaction can only ever expose the
    kept fields. -/
theorem canRead_redact (d : List (P × P)) (pub a : P) (keep : Nat → Bool)
    (fs : List (Field P)) :
    canRead d pub a (recordReaders (redact keep fs))
      ↔ ∀ f ∈ fs, keep f.name = true → canRead d pub a f.readers := by
  rw [canRead_record]
  constructor
  · intro h f hf hk
    exact h f ((mem_redact keep fs f).mpr ⟨hf, hk⟩)
  · intro h f hf
    rcases (mem_redact keep fs f).mp hf with ⟨hpres, hk⟩
    exact h f hpres hk

/-- REDACTION ONLY LOWERS THE LABEL: anyone cleared for the whole record is cleared for
    any projection of it. So `redact` is a conservative refinement of the opaque box —
    it never enlarges the protected set, only shrinks it (widening who may receive). -/
theorem redact_refines (d : List (P × P)) (pub a : P) (keep : Nat → Bool)
    (fs : List (Field P)) (h : canRead d pub a (recordReaders fs)) :
    canRead d pub a (recordReaders (redact keep fs)) := by
  rw [canRead_record] at h
  rw [canRead_redact]
  intro f hf _; exact h f hf

/-- KEEPING EVERYTHING IS THE OPAQUE BOX: the all-fields redaction is the record
    itself, so the I-IFC2 whole-record label is the degenerate `redact` and the
    refinement reduces to it exactly. -/
theorem redact_keep_all (fs : List (Field P)) :
    redact (fun _ => true) fs = fs := by
  induction fs with
  | nil => rfl
  | cons f rest ih => rw [redact, if_pos rfl, ih]

end Whipple
