/-
Reader/writer SETS — the confidentiality label as a set of compartments.

The single-authority model (`Label.reader : P`) is the leaf case; a real
confidentiality label is a SET of reader authorities (compartments), and a party
may read a value only if it is cleared for EVERY compartment. This module proves
that set forms a join-semilattice with the empty set as bottom: union is the join
(combining data restricts to the readers common to both), so the label algebra the
checker will grow into is sound. Builds on `Whipple.ActsFor`; still Mathlib-free.
-/
import Whipple.ActsFor

namespace Whipple

variable {P : Type}

/-- A confidentiality label as a set of reader authorities (compartments). A party
    with authority `a` may read a value labeled `rs` iff it acts-for EVERY
    compartment — it must be cleared for all of them. -/
def canRead (d : List (P × P)) (pub : P) (a : P) (rs : List P) : Prop :=
  ∀ r ∈ rs, ActsFor d pub a r

/-- The empty label is the public bottom: everyone may read it (vacuously). -/
theorem canRead_nil (d : List (P × P)) (pub a : P) : canRead d pub a [] := by
  intro r hr
  cases hr

/-- The JOIN of two confidentiality labels is their union: a party may read the
    combination iff it may read BOTH parts. So union is the least upper bound —
    combining data restricts to the readers common to both inputs (the set form of
    the join box, I-IFC2). -/
theorem canRead_append (d : List (P × P)) (pub a : P) (rs ss : List P) :
    canRead d pub a (rs ++ ss) ↔ canRead d pub a rs ∧ canRead d pub a ss := by
  constructor
  · intro h
    exact ⟨fun r hr => h r (List.mem_append.mpr (Or.inl hr)),
           fun s hs => h s (List.mem_append.mpr (Or.inr hs))⟩
  · rintro ⟨h1, h2⟩ x hx
    rcases List.mem_append.mp hx with hr | hs
    · exact h1 x hr
    · exact h2 x hs

/-- Join is commutative w.r.t. readership: `rs ++ ss` and `ss ++ rs` have the same
    readers. (Idempotence and associativity follow likewise from `canRead_append`.) -/
theorem canRead_append_comm (d : List (P × P)) (pub a : P) (rs ss : List P) :
    canRead d pub a (rs ++ ss) ↔ canRead d pub a (ss ++ rs) := by
  rw [canRead_append, canRead_append, and_comm]

/-- Readership is MONOTONE in clearance: a higher-authority party reads at least as
    much. If `a` acts-for `b` and `b` may read `rs`, then `a` may read `rs` — so the
    acts-for order on principals lifts to the label order. -/
theorem canRead_mono (d : List (P × P)) (pub a b : P) (rs : List P)
    (hab : ActsFor d pub a b) (h : canRead d pub b rs) : canRead d pub a rs := by
  intro r hr
  exact actsFor_trans d pub hab (h r hr)

/-- The checker's leak decision, as a relation on label sets: `provider` DOMINATES
    `required` iff every compartment of `required` is covered by SOME compartment of
    `provider` (a party with that provider authority acts-for it). This is exactly
    the `dominates` the Rust `Envelope` computes for a flow `source -> sink`
    (`provider` = the sink's reader set, `required` = the source's): the sink must
    cover every compartment that gates the source. -/
def dominates (d : List (P × P)) (pub : P) (provider required : List P) : Prop :=
  ∀ r ∈ required, ∃ s ∈ provider, ActsFor d pub s r

/-- SOUNDNESS of the leak check (E6). If the sink's reader set dominates the
    source's, then every party that may read the sink may also read the source — so
    routing source-labeled data into a sink-labeled channel never exposes it to an
    under-cleared reader. This is the theorem the Rust `leaks` returning `false`
    stands on: `dominates(readers(sink), readers(source))` ⟹ no party gains
    unauthorized read access. -/
theorem leak_safe (d : List (P × P)) (pub : P) (source sink : List P)
    (dom : dominates d pub sink source) :
    ∀ a, canRead d pub a sink → canRead d pub a source := by
  intro a ha r hr
  obtain ⟨s, hs_mem, hs_act⟩ := dom r hr
  exact actsFor_trans d pub (ha s hs_mem) hs_act

/-- AGREEMENT / the leaf case (M1): with a singleton provider set the `dominates`
    check is exactly the single-authority `canRead` the legacy checker computed. So
    the set algebra is a conservative refinement of the published acts-for order —
    a one-compartment label behaves precisely as the single role it replaces. -/
theorem dominates_singleton (d : List (P × P)) (pub : P) (s : P) (rs : List P) :
    dominates d pub [s] rs ↔ canRead d pub s rs := by
  constructor
  · intro h r hr
    obtain ⟨x, hx_mem, hx_act⟩ := h r hr
    rw [List.mem_singleton] at hx_mem
    exact hx_mem ▸ hx_act
  · intro h r hr
    exact ⟨s, List.mem_singleton.mpr rfl, h r hr⟩

/-- The leak check RESPECTS the join: dominating a combined (joined = unioned) label
    is dominating each part. So the set form of the join box (`canRead_append`) is
    enforced compartment-wise — a sink that clears a merged secret clears both
    inputs. -/
theorem dominates_split (d : List (P × P)) (pub : P) (provider rs ss : List P) :
    dominates d pub provider (rs ++ ss)
      ↔ dominates d pub provider rs ∧ dominates d pub provider ss := by
  constructor
  · intro h
    exact ⟨fun r hr => h r (List.mem_append.mpr (Or.inl hr)),
           fun s hs => h s (List.mem_append.mpr (Or.inr hs))⟩
  · rintro ⟨h1, h2⟩ x hx
    rcases List.mem_append.mp hx with hr | hs
    · exact h1 x hr
    · exact h2 x hs

/-- Domination is MONOTONE in the provider: enriching the sink's reader set never
    breaks a flow that was already safe — adding a compartment only adds covering
    candidates. (The Maude `infoflow-reader-sets` bite: a richer sink still
    dominates.) -/
theorem dominates_mono_provider (d : List (P × P)) (pub : P) (p1 p2 required : List P)
    (sub : ∀ x ∈ p1, x ∈ p2) (h : dominates d pub p1 required) :
    dominates d pub p2 required := by
  intro r hr
  obtain ⟨s, hs_mem, hs_act⟩ := h r hr
  exact ⟨s, sub s hs_mem, hs_act⟩

/-- A shared cell can be readable by two incomparable clearances without creating a
    flow order between those clearances. Both `a` and `b` dominate the cell label
    `[r]`, but neither dominates the other. This is the algebraic point behind the
    coordination exception: `leak_safe` for the cell does not imply NMIF/authority
    flow among distinct users of that cell. -/
theorem shared_cell_clearance_not_nmif (d : List (P × P)) (pub a b r : P)
    (har : ActsFor d pub a r) (hbr : ActsFor d pub b r)
    (hab : ¬ ActsFor d pub a b) (hba : ¬ ActsFor d pub b a) :
    dominates d pub [a] [r] ∧ dominates d pub [b] [r] ∧
      ¬ dominates d pub [a] [b] ∧ ¬ dominates d pub [b] [a] := by
  constructor
  · intro x hx
    have hx' : x = r := List.mem_singleton.mp hx
    subst x
    exact ⟨a, List.mem_singleton.mpr rfl, har⟩
  constructor
  · intro x hx
    have hx' : x = r := List.mem_singleton.mp hx
    subst x
    exact ⟨b, List.mem_singleton.mpr rfl, hbr⟩
  constructor
  · intro h
    have hb_mem : b ∈ [b] := List.mem_singleton.mpr rfl
    obtain ⟨s, hs_mem, hs_act⟩ := h b hb_mem
    have hs_eq : s = a := List.mem_singleton.mp hs_mem
    subst s
    exact hab hs_act
  · intro h
    have ha_mem : a ∈ [a] := List.mem_singleton.mpr rfl
    obtain ⟨s, hs_mem, hs_act⟩ := h a ha_mem
    have hs_eq : s = b := List.mem_singleton.mp hs_mem
    subst s
    exact hba hs_act

/-- Self-coordination is label-trivial: a principal's singleton clearance dominates
    itself by reflexivity of acts-for. This justifies skipping the coordination
    NMIF gate when all contending users collapse to one workflow principal. -/
theorem same_principal_flow_trivial (d : List (P × P)) (pub p : P) :
    dominates d pub [p] [p] := by
  intro r hr
  have hr' : r = p := List.mem_singleton.mp hr
  subst r
  exact ⟨p, List.mem_singleton.mpr rfl, actsFor_refl d pub p⟩

/-- The INTEGRITY dual (M1, writer sets). `dominates` is axis-agnostic — it is a
    relation on the acts-for order, not on a chosen axis. On the integrity axis the
    same relation runs with the READ's provided vouchers covering the WRITE's
    required ones, and the dual soundness holds by the same argument: if the read's
    integrity set dominates the write's requirement, any authority clearing the read
    clears the write. So the writer set forms the dual semilattice with no new
    machinery. -/
theorem inject_safe (d : List (P × P)) (pub : P) (write read : List P)
    (dom : dominates d pub read write) :
    ∀ a, canRead d pub a read → canRead d pub a write :=
  leak_safe d pub write read dom

end Whipple
