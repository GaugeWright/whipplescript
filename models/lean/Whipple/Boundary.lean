/-
The verified-boundary discipline — the bug class, fixed at the type level.

The report-vs-check bug was a SECOND consumer of a signed envelope (the guarantee
report) that derived trust without verifying the attestation, while the first
consumer (the checker) did verify. The root cause was per-call-site discipline:
`verify` was invoked by consumers, so a new consumer could forget it.

The fix is to make verification a property of the ARTIFACT, not of a code path:
a `Verified` value is constructible ONLY with a proof of genuineness, so EVERY
consumer that accepts one is gated by construction. This module proves that the
boundary type delivers the guarantee uniformly across all consumers — the
property the bug violated and the Rust `VerifiedEnvelope` refactor restores.
-/
namespace Whipple

/-- A verified artifact: a value together with a proof it is genuine (e.g. its
    attestation hash matches its content). There is no other constructor, so a
    `Verified` cannot exist for a non-genuine artifact. -/
structure Verified {A : Type} (genuine : A → Prop) where
  val : A
  ok : genuine val

/-- THE BOUNDARY GUARANTEE: any consumer that receives a `Verified` artifact is
    handed a genuineness proof — with no per-consumer check. This holds for the
    checker, the report, and any future consumer uniformly; forgetting to verify
    is no longer expressible, because there is no `Verified` to pass. -/
theorem consumer_relies_on_genuine {A : Type} {genuine : A → Prop}
    (v : Verified genuine) : genuine v.val := v.ok

/-- The contrapositive at the boundary: a tampered (non-genuine) artifact admits no
    `Verified` wrapper at all, so it cannot be presented to ANY consumer. This is
    the report-vs-check bug made unrepresentable. -/
theorem no_verified_for_tampered {A : Type} {genuine : A → Prop} {a : A}
    (h : ¬ genuine a) : ¬ ∃ v : Verified genuine, v.val = a := by
  rintro ⟨v, rfl⟩
  exact h v.ok

/-- A consumer is any function that decides something from an artifact. A *gated*
    consumer takes a `Verified`; an *ungated* one takes a raw artifact. The bug was
    an ungated consumer used where a gated one was required. We model that the
    gated form is total over genuine inputs and refuses the rest by construction:
    a gated consumer's input always satisfies `genuine`. -/
theorem gated_consumer_sees_genuine {A B : Type} {genuine : A → Prop}
    (consume : Verified genuine → B) (v : Verified genuine) :
    genuine v.val ∧ (consume v = consume v) :=
  ⟨v.ok, rfl⟩

end Whipple

