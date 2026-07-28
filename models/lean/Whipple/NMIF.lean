/-
Nonmalleable information flow (NMIF) — robust declassification.

A declassification lowers confidentiality. It is sound only if it is ROBUST: the
decision may not be influenced by data less trusted than the downgrade itself, so
an attacker who controls the data cannot choose what gets released (Cecchetti /
Myers / Arden). In our two-axis model that condition is: the value being
declassified must carry INTEGRITY covering the release authority. This module
proves the core NMIF guarantee — attacker-controlled data cannot be released to a
privileged reader — reusing `public_acts_for_only_public`. Mathlib-free.
-/
import Whipple.ActsFor

namespace Whipple

variable {P : Type}

/-- Robust declassification: value `v` may be released to authority `releaseAuth`
    only if the value's INTEGRITY covers the release — the data being downgraded is
    vouched-for at the level of the release decision (NMIF). -/
def robustDeclassify (d : List (P × P)) (pub : P) (v : Label P) (releaseAuth : P) : Prop :=
  ActsFor d pub v.integ releaseAuth

/-- THE NMIF GUARANTEE: an UNTRUSTED value — integrity at the public bottom, i.e.
    attacker-controllable — can be robustly declassified ONLY to the public bottom.
    You cannot release attacker-controlled data to any privileged reader, so an
    attacker cannot influence a downgrade in their favor. -/
theorem untrusted_declassify_only_public (d : List (P × P)) (pub : P) (v : Label P)
    (releaseAuth : P) (huntrusted : v.integ = pub)
    (h : robustDeclassify d pub v releaseAuth) : releaseAuth = pub := by
  unfold robustDeclassify at h
  rw [huntrusted] at h
  exact public_acts_for_only_public h

/-- Endorsement enables declassification, dually: raising a value's integrity to a
    vouching authority that covers the release makes the declassify robust. This is
    the legitimate path — vouch for the data first, then release it. -/
theorem endorsed_enables_declassify (d : List (P × P)) (pub : P) (v : Label P)
    (releaseAuth : P) (h : ActsFor d pub v.integ releaseAuth) :
    robustDeclassify d pub v releaseAuth :=
  h

/-- Robust declassification is monotone in the value's integrity: a more-trusted
    value may be released at least as widely. -/
theorem robustDeclassify_mono (d : List (P × P)) (pub : P) (v w : Label P)
    (releaseAuth : P) (hvw : ActsFor d pub v.integ w.integ)
    (h : robustDeclassify d pub w releaseAuth) : robustDeclassify d pub v releaseAuth :=
  actsFor_trans d pub hvw h

end Whipple
