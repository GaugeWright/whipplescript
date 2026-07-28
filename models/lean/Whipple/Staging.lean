/-
Phase/provenance-typed turn outputs (DR-0030 Direction B; Maude
`infoflow-staging.maude`).

The finding this module makes precise: Direction B needs NO new label theory, only
finer GRANULARITY. A record field whip-assembled from several turn outputs carries
the JOIN over the contributing turns (the same `joinReaders` join as everywhere
else), per field. So:

  * a field is INDEPENDENT of any turn that does not feed it — reading it never
    requires clearance for a secret that turn read (`field_independent_of_unread`);
  * the per-rule box is a sound, looser over-approximation of the per-turn box, and
    both over-approximate the true flow — soundness is just transitivity of set
    inclusion (`soundDecl_trans`, `perTurn_refines_perRule`);
  * the REJECTED version — labelling a sub-field of a SINGLE model output below the
    turn's join — is unsound: claiming a sub-field public when the turn read a secret
    admits the PUBLIC reader illegally (`single_output_subfield_unsound`), the same
    leak `FlowSignature.absent_admits_illegal_read` rules out.

Reuses `Whipple.FlowSignature` (`joinReaders`, `soundDecl`, `canRead_sound`).
Mathlib-free.
-/
import Whipple.FlowSignature

namespace Whipple

variable {P : Type}

/-! ### Membership in a join, and field independence -/

/-- A reader is in the join of a fan of paths iff some path carries it. -/
theorem mem_joinReaders {ls : List (List P)} {r : P} :
    r ∈ joinReaders ls ↔ ∃ l, l ∈ ls ∧ r ∈ l := by
  induction ls with
  | nil =>
    constructor
    · intro h; cases h
    · rintro ⟨l, hl, _⟩; cases hl
  | cons l ls ih =>
    have hsplit : r ∈ joinReaders (l :: ls) ↔ r ∈ l ∨ r ∈ joinReaders ls :=
      List.mem_append
    rw [hsplit, ih]
    constructor
    · rintro (h | ⟨l', hl', hr⟩)
      · exact ⟨l, List.mem_cons_self, h⟩
      · exact ⟨l', List.mem_cons_of_mem l hl', hr⟩
    · rintro ⟨l', hl', hr⟩
      rcases List.mem_cons.mp hl' with h | h
      · subst h; exact Or.inl hr
      · exact Or.inr ⟨l', h, hr⟩

/-- FIELD INDEPENDENCE — the per-turn win. If no turn feeding a field read the secret,
    the field's reader-set does not contain the secret, so reading the field never
    requires clearance for it. A secret turn elsewhere in the rule cannot taint a
    field it does not feed. -/
theorem field_independent_of_unread {ls : List (List P)} {secret : P}
    (h : ∀ l ∈ ls, secret ∉ l) : secret ∉ joinReaders ls := by
  intro hmem
  rcases mem_joinReaders.mp hmem with ⟨l, hl, hr⟩
  exact h l hl hr

/-! ### The refinement chain: true ⊆ per-turn ⊆ per-rule -/

/-- Soundness of a declared label composes: if `a`'s readers are covered by `b` and
    `b`'s by `c`, then `a`'s are covered by `c`. (`soundDecl` is set inclusion.) -/
theorem soundDecl_trans {a b c : List P}
    (hab : soundDecl a b) (hbc : soundDecl b c) : soundDecl a c :=
  fun r hr => hbc r (hab r hr)

/-- The per-RULE box (the join of EVERY turn's readers) is a sound over-approximation
    of the per-TURN box (this field's contributing turns): a field's readers are a
    sub-fan of the whole rule's. So both boxes are sound; the per-turn box is just the
    tighter one. Here `perTurn = joinReaders fieldPaths` and
    `perRule = joinReaders allPaths` with `fieldPaths ⊆ allPaths`. -/
theorem perTurn_refines_perRule (fieldPaths allPaths : List (List P))
    (hsub : ∀ l ∈ fieldPaths, l ∈ allPaths) :
    soundDecl (joinReaders fieldPaths) (joinReaders allPaths) := by
  intro r hr
  rcases mem_joinReaders.mp hr with ⟨l, hl, hrl⟩
  exact mem_joinReaders.mpr ⟨l, hsub l hl, hrl⟩

/-- Consequently, an audience the conservative per-rule box admits is also safe for the
    actual field flow — the precise per-turn box never under-restricts. (Composition of
    `perTurn_refines_perRule` with `canRead_sound`.) -/
theorem perRule_admits_implies_field_safe (d : List (P × P)) (pub a : P)
    (fieldPaths allPaths : List (List P))
    (hsub : ∀ l ∈ fieldPaths, l ∈ allPaths)
    (h : canRead d pub a (joinReaders allPaths)) :
    canRead d pub a (joinReaders fieldPaths) :=
  canRead_sound d pub a (joinReaders fieldPaths) (joinReaders allPaths)
    (perTurn_refines_perRule fieldPaths allPaths hsub) h

/-! ### The rejected version is unsound -/

/-- THE LAUNDERING BUG, ruled out: you cannot label a sub-field of a SINGLE model
    output below the turn's join. A single turn that read a secret produces an output
    whose only sound label is the turn's join; claiming a sub-field is public (the
    empty reader-set) admits the PUBLIC reader, but the true secret flow forbids it.
    Per-field precision is sound only ACROSS whip-assembled turns. -/
theorem single_output_subfield_unsound (d : List (P × P)) (pub secret : P)
    (hne : secret ≠ pub) :
    canRead d pub pub ([] : List P) ∧ ¬ canRead d pub pub [secret] :=
  absent_admits_illegal_read d pub secret hne

end Whipple
