/-
Per-tool flow SIGNATURE soundness — the cut-implies-bound lemma and the
fail-closed fallback (DR-0030 Direction A; Maude `infoflow-signature.maude`).

A signature refines the opaque join box per input-to-result edge into one of
`direct` (the result carries the input full label), `absent` (the input provably
does not flow), or `mediated(C)` (the input flows ONLY through a crossing C, a
declassify, so the result carries C bounded TARGET label). The mediated edge is a
CONDITIONAL discount, valid only when the consumer grants C; ungranted it falls
back to `direct`, never `absent`.

This module proves the two claims the feature rests on, in the reader-set algebra
of `Whipple.ReaderSets`:

  * cut implies bound — when EVERY path from the input to the result traverses the
    crossing (a cut), the result reader-set is exactly the crossing target, so the
    input own reader is dropped; a single BYPASS path reintroduces the input reader
    and destroys the discount. The result carries the JOIN over paths (union of
    reader-sets, `canRead_append`), so a bypass cannot be hidden.

  * fail-closed fallback — an ungranted mediated edge equals `direct`, which is a
    sound over-approximation of the true (unchanged) flow; treating it as `absent`
    is unsound and concretely lets the PUBLIC read a non-public input.

It also bridges to NMIF: a real confidentiality discount on attacker-controlled
data is impossible (`untrusted_no_discount`). Mathlib-free.
-/
import Whipple.ReaderSets
import Whipple.NMIF

namespace Whipple

variable {P : Type}

/-! ### The join of per-path reader-sets -/

/-- The reader-set the result carries from a set of paths is the union of what each
    path delivers: reading the result requires clearance for EVERY path. This is the
    join box (I-IFC2) over a fan of flow paths. -/
def joinReaders : List (List P) → List P
  | [] => []
  | l :: ls => l ++ joinReaders ls

/-- A party may read the joined result iff it may read what EVERY path delivers — the
    `canRead_append` join lifted from two parts to a list of paths. So a path that
    delivers a restrictive reader-set cannot be hidden inside the join. -/
theorem canRead_joinReaders (d : List (P × P)) (pub a : P) (ls : List (List P)) :
    canRead d pub a (joinReaders ls) ↔ ∀ l ∈ ls, canRead d pub a l := by
  induction ls with
  | nil =>
    constructor
    · intro _ l hl; cases hl
    · intro _; exact canRead_nil d pub a
  | cons l ls ih =>
    have hsplit :
        canRead d pub a (joinReaders (l :: ls))
          ↔ canRead d pub a l ∧ canRead d pub a (joinReaders ls) :=
      canRead_append d pub a l (joinReaders ls)
    rw [hsplit, ih]
    constructor
    · rintro ⟨hl, htl⟩ x hx
      rcases List.mem_cons.mp hx with h | h
      · subst h; exact hl
      · exact htl x h
    · intro h
      exact ⟨h l List.mem_cons_self, fun x hx => h x (List.mem_cons_of_mem l hx)⟩

/-! ### The edge model (mirrors the Maude `contrib`) -/

/-- An internal crossing carries its declassify TARGET reader (the bounded ceiling
    the released value lands on). -/
structure Crossing (P : Type) where
  target : P

/-- A per-edge departure from the join box. -/
inductive Edge (P : Type) where
  | direct
  | absent
  | mediated (c : Crossing P)

/-- The reader-set a declared edge presents, given the input reader and whether the
    consumer granted the crossing. `mediated` granted yields the target; UNGRANTED it
    falls back to `direct` (the input reader), never to `absent` (the empty set). -/
def edgeReaders (inputReader : P) (granted : Bool) : Edge P → List P
  | .direct      => [inputReader]
  | .absent      => []
  | .mediated c  => match granted with
                    | true  => [c.target]
                    | false => [inputReader]

/-! ### Producer soundness: declared over-approximates actual -/

/-- A declared reader-set is a SOUND over-approximation of the actual one when every
    actual compartment is covered by the declaration. Then passing the declared check
    guarantees the real flow is safe. -/
def soundDecl (actual declared : List P) : Prop := ∀ r ∈ actual, r ∈ declared

/-- THE PRODUCER OBLIGATION, discharged: if the declaration over-approximates the
    actual flow, then any audience the checker admits on the DECLARED label is in
    fact cleared for the ACTUAL flow. Soundness reduces to set inclusion. -/
theorem canRead_sound (d : List (P × P)) (pub a : P) (actual declared : List P)
    (hs : soundDecl actual declared) (h : canRead d pub a declared) :
    canRead d pub a actual := fun r hr => h r (hs r hr)

/-- `direct` is always sound: the result never carries more than the input reader
    from a single input, so claiming the full input reader can only over-restrict. -/
theorem direct_sound (inputReader : P) (g : Bool) :
    soundDecl [inputReader] (edgeReaders inputReader g Edge.direct) :=
  fun _ hr => hr

/-- `absent` is sound exactly when the actual flow is empty (the producer must prove
    no-reach); over any nonempty flow it is unsound (witnessed below). -/
theorem absent_sound_only_noreach (inputReader : P) (g : Bool) :
    soundDecl [] (edgeReaders inputReader g Edge.absent) := by
  intro r hr; cases hr

/-! ### Cut implies bound -/

/-- CUT IMPLIES BOUND. When the only path from the input to the result is through the
    granted crossing (the result reader-set is the crossing target alone), reading
    the result is governed by the TARGET — the bounded ceiling — and nothing else. -/
theorem cut_bound (d : List (P × P)) (pub a inputReader : P) (c : Crossing P)
    (h : canRead d pub a (edgeReaders inputReader true (Edge.mediated c))) :
    ActsFor d pub a c.target :=
  (h : canRead d pub a [c.target]) c.target (List.mem_singleton.mpr rfl)

/-- The discount is REAL: under a cut the result reader-set does not contain the
    input own reader, so reading the result never forces clearance for the input.
    (With `cut_bound`: cleared-for-target suffices, cleared-for-input is not needed.) -/
theorem mediated_drops_input (inputReader : P) (c : Crossing P)
    (hne : c.target ≠ inputReader) :
    inputReader ∉ edgeReaders inputReader true (Edge.mediated c) := by
  intro h
  exact hne (List.mem_singleton.mp (h : inputReader ∈ [c.target])).symm

/-- A BYPASS destroys the bound. If some path delivers the input directly alongside
    the crossing path, the joined result reader-set contains the input reader, so
    reading the result REQUIRES clearance for the input — the discount is gone. This
    is why mediation must be a cut, not mere reachance. -/
theorem bypass_requires_input (d : List (P × P)) (pub a inputReader : P) (c : Crossing P)
    (h : canRead d pub a (joinReaders [[c.target], [inputReader]])) :
    ActsFor d pub a inputReader := by
  rw [canRead_joinReaders] at h
  have hmem : [inputReader] ∈ [[c.target], [inputReader]] :=
    List.mem_cons_of_mem _ (List.mem_singleton.mpr rfl)
  exact (h [inputReader] hmem) inputReader (List.mem_singleton.mpr rfl)

/-- Correspondingly, declaring `mediated` over a flow that has a bypass is UNSOUND:
    the actual (joined) flow carries the input reader, which the declared target-only
    label fails to cover. The producer attestation must reject a bypassed mediation. -/
theorem mediated_unsound_under_bypass (inputReader : P) (c : Crossing P)
    (hne : inputReader ≠ c.target) :
    ¬ soundDecl (joinReaders [[c.target], [inputReader]])
                (edgeReaders inputReader true (Edge.mediated c)) := by
  intro hs
  have hin : inputReader ∈ joinReaders [[c.target], [inputReader]] :=
    (List.mem_cons_of_mem _ (List.mem_singleton.mpr rfl)
      : inputReader ∈ [c.target, inputReader])
  exact hne (List.mem_singleton.mp (hs inputReader hin : inputReader ∈ [c.target]))

/-! ### Fail-closed fallback -/

/-- The fallback identity: an UNGRANTED mediated edge presents exactly the `direct`
    reader-set. Ungranted is `direct`, by construction. -/
theorem ungranted_mediated_eq_direct (inputReader : P) (c : Crossing P) :
    edgeReaders inputReader false (Edge.mediated c)
      = edgeReaders inputReader false Edge.direct := rfl

/-- Fallback is SOUND: when the crossing is ungranted the declassify never fires, so
    the true flow is the unchanged input reader, which the `direct` fallback covers. -/
theorem ungranted_fallback_sound (inputReader : P) (c : Crossing P) :
    soundDecl [inputReader] (edgeReaders inputReader false (Edge.mediated c)) :=
  fun _ hr => hr

/-- THE CATASTROPHIC BUG, ruled out: treating an ungranted mediated edge as `absent`
    is unsound. With a non-public input, the `absent` empty label admits the PUBLIC
    reader (everyone reads the empty label), but the true `direct` flow correctly
    forbids it — the public is not cleared for a non-public input. So the fallback
    MUST be `direct`, never `absent`. -/
theorem absent_admits_illegal_read (d : List (P × P)) (pub inputReader : P)
    (hne : inputReader ≠ pub) :
    canRead d pub pub ([] : List P) ∧ ¬ canRead d pub pub [inputReader] := by
  refine ⟨canRead_nil d pub pub, ?_⟩
  intro h
  exact hne (public_acts_for_only_public (h inputReader (List.mem_singleton.mpr rfl)))

/-! ### NMIF bridge -/

/-- No discount on untrusted data: a robust declassify of an attacker-controllable
    value (integrity at the public bottom) can only target the public bottom, so a
    mediated edge buys NO real confidentiality discount over untrusted input. The
    discount is legitimate only for vouched-for data (DR-0030 Direction A, I-IFC3). -/
theorem untrusted_no_discount (d : List (P × P)) (pub : P) (v : Label P) (target : P)
    (huntrusted : v.integ = pub) (h : robustDeclassify d pub v target) : target = pub :=
  untrusted_declassify_only_public d pub v target huntrusted h

end Whipple
