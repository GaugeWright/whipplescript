/-
The decision PROCEDURE is correct.

`Whipple.ActsFor` is the order (a preorder with `public` bottom). But the Rust
`Envelope::can_act` and the Maude `reach` model compute it with a bounded forward
search over the delegation edges. This module proves that search **sound and
complete** against `ActsFor`: the algorithm decides exactly the order — closing
the gap between "the order is a preorder" and "our code computes that order."
-/
import Whipple.ActsFor

namespace Whipple

variable {P : Type} [DecidableEq P]

/-- The reach algorithm, fuel-bounded (the Rust BFS-with-visited, as a structural
    recursion): `p` reaches `q` in ≤ `n` steps if `p = q`, `q` is the bottom, or
    some edge `p → m` (with `p` not the bottom) reaches `q` in ≤ `n-1`. -/
def canActFuel (d : List (P × P)) (pub : P) : Nat → P → P → Bool
  | 0, p, q => decide (p = q) || decide (q = pub)
  | n + 1, p, q =>
      decide (p = q) || decide (q = pub) ||
      (decide (p ≠ pub) && d.any (fun e => decide (e.1 = p) && canActFuel d pub n e.2 q))

/-- The procedure's verdict: reachable within some fuel. -/
def CanAct (d : List (P × P)) (pub p q : P) : Prop :=
  ∃ n, canActFuel d pub n p q = true

/-- SOUNDNESS: anything the procedure accepts really is in the order. -/
theorem fuel_sound (d : List (P × P)) (pub : P) :
    ∀ (n : Nat) (p q : P), canActFuel d pub n p q = true → ActsFor d pub p q := by
  intro n
  induction n with
  | zero =>
    intro p q h
    simp only [canActFuel, Bool.or_eq_true, decide_eq_true_eq] at h
    rcases h with h | h
    · rw [h]; exact actsFor_refl d pub q
    · rw [h]; exact public_is_bottom d pub p
  | succ n ih =>
    intro p q h
    simp only [canActFuel, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq,
      List.any_eq_true] at h
    rcases h with (h | h) | ⟨hpub, ⟨e1, e2⟩, hmem, hep, hrec⟩
    · rw [h]; exact actsFor_refl d pub q
    · rw [h]; exact public_is_bottom d pub p
    · -- edge p → e2 (p is renamed to e1 by the witness equation), IH carries e2 to q
      subst hep
      have hstep : Step d pub e1 e2 := Or.inr ⟨hpub, hmem⟩
      exact Star.head hstep (ih e2 q hrec)

/-- COMPLETENESS: anything in the order is accepted at some fuel. -/
theorem actsFor_complete (d : List (P × P)) (pub : P) (p q : P)
    (h : ActsFor d pub p q) : ∃ n, canActFuel d pub n p q = true := by
  induction h with
  | refl a =>
    exact ⟨0, by simp [canActFuel]⟩
  | @head a b c hab hbc ih =>
    obtain ⟨n, hn⟩ := ih
    refine ⟨n + 1, ?_⟩
    rcases hab with hb | ⟨hane, hmem⟩
    · -- step to the bottom: then c = pub, so the verdict is immediate
      have hc : c = pub := star_pub_sink hbc hb
      simp [canActFuel, hc]
    · -- real edge a → b: witness it in the any, carry c via the IH at fuel n
      simp only [canActFuel, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq,
        List.any_eq_true]
      exact Or.inr ⟨hane, (a, b), hmem, rfl, hn⟩

/-- The procedure decides exactly the order — sound AND complete. -/
theorem canAct_iff (d : List (P × P)) (pub p q : P) :
    CanAct d pub p q ↔ ActsFor d pub p q := by
  constructor
  · rintro ⟨n, hn⟩; exact fuel_sound d pub n p q hn
  · intro h; exact actsFor_complete d pub p q h

end Whipple
