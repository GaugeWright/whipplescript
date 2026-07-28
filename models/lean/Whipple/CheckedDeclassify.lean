/-
Semantic checked declassifier (DR-0030 Direction C; Maude
`infoflow-declassifier.maude`).

A declassify gated by a trusted predicate inherits the adaptive-oracle risk, so its
soundness argument is STRUCTURAL: NMIF on the SELECTOR. The novelty over `Whipple.NMIF`
is the target of the robustness condition — not the value being released, but the
SELECTOR (which release is asked). This module proves:

  * a privileged release requires a TRUSTED selector — an attacker-controllable
    selector can drive a release only to the public bottom, so there is no adaptive
    oracle to a privileged reader (`untrusted_selector_only_public`,
    `privileged_release_needs_trusted_selector`);
  * the REFUSAL channel — a refusal that depends only on a fixed PUBLIC budget is
    publicly observable, but a refusal that depends on the secret is NOT, so it is
    itself a flow; hence a budget must be fixed/public, never a data-dependent
    refuse-when-dangerous (`refusal_channel`).

The budget BACKSTOP (bounded release count) is a state-machine property bitten in the
Maude model. Reuses `Whipple.ActsFor` / `Whipple.ReaderSets` / `Whipple.NMIF`.
Mathlib-free.
-/
import Whipple.ReaderSets
import Whipple.NMIF

namespace Whipple

variable {P : Type}

/-! ### NMIF on the selector -/

/-- The release authority is GOVERNED BY THE SELECTOR: the selector that chose which
    release to ask must carry integrity covering the release authority. This is
    `robustDeclassify` aimed at the selector instead of the released value. -/
def selectorGoverns (d : List (P × P)) (pub : P) (sel : Label P) (releaseAuth : P) : Prop :=
  ActsFor d pub sel.integ releaseAuth

/-- An attacker-controllable selector (integrity at the public bottom) can drive a
    release ONLY to the public bottom. The attacker cannot choose a privileged
    release — the adaptive oracle to a privileged reader does not exist. -/
theorem untrusted_selector_only_public (d : List (P × P)) (pub : P) (sel : Label P)
    (releaseAuth : P) (huntrusted : sel.integ = pub)
    (h : selectorGoverns d pub sel releaseAuth) : releaseAuth = pub := by
  unfold selectorGoverns at h
  rw [huntrusted] at h
  exact public_acts_for_only_public h

/-- Contrapositive — the no-adaptive-oracle guarantee stated forward: a release to ANY
    privileged (non-public) reader REQUIRES a trusted (non-public-integrity) selector.
    So the leak is bounded by the trusted, author-fixed query set, not by an adaptive
    adversary. -/
theorem privileged_release_needs_trusted_selector (d : List (P × P)) (pub : P)
    (sel : Label P) (releaseAuth : P) (h : selectorGoverns d pub sel releaseAuth)
    (hpriv : releaseAuth ≠ pub) : sel.integ ≠ pub := by
  intro hpub
  exact hpriv (untrusted_selector_only_public d pub sel releaseAuth hpub h)

/-- A trusted selector is monotone: a more-trusted selector governs at least as wide a
    release. (The legitimate path — vouch for the query, then it may drive a release.) -/
theorem selectorGoverns_mono (d : List (P × P)) (pub : P) (sel sel' : Label P)
    (releaseAuth : P) (hmono : ActsFor d pub sel.integ sel'.integ)
    (h : selectorGoverns d pub sel' releaseAuth) : selectorGoverns d pub sel releaseAuth :=
  actsFor_trans d pub hmono h

/-! ### The refusal channel -/

/-- THE REFUSAL CHANNEL. A refusal whose decision depends only on a fixed PUBLIC budget
    carries the empty (public) reader-set, so the public may observe it. A refusal whose
    decision depends on the secret carries the secret in its reader-set, so the public
    may NOT observe it — the refusal is itself a flow. Hence a budget must be fixed and
    public; a data-dependent refuse-when-dangerous leaks through its own refusals. -/
theorem refusal_channel (d : List (P × P)) (pub secret : P) (hne : secret ≠ pub) :
    canRead d pub pub ([] : List P) ∧ ¬ canRead d pub pub [secret] := by
  refine ⟨canRead_nil d pub pub, ?_⟩
  intro h
  exact hne (public_acts_for_only_public (h secret (List.mem_singleton.mpr rfl)))

end Whipple
