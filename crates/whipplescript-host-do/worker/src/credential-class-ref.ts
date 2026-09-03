/**
 * The credential id a public session presents when it resolves its provider
 * binding against the release's signed host policy.
 *
 * A release closure carries the provider's credential **class** raw
 * (`managed-openai`), because the edge compares that string against the
 * deployment config. The signed envelope names the same credential in
 * WhippleScript custody's canonical `credential:<name>` form, because custody
 * admits nothing else. `VerifiedEnvelope::resolve_provider_binding` compares
 * the id this runtime presents with the envelope's `credential_ref` by exact
 * equality, so the runtime must present whichever spelling the envelope
 * carries — and only a spelling that is genuinely this class, never a value
 * copied out of the envelope unexamined, or the check would prove nothing.
 *
 * GaugeDesk derives the canonical form in
 * `crates/app/src/account.rs::canonical_credential_class_ref`; nothing at
 * compile time relates the two, so `credential-class-ref.test.ts` pins the
 * literal for `managed-openai` and the GaugeDesk publisher test pins the same
 * one from its side. Change both together.
 */

const CANONICAL_CLASS_PREFIX = "credential:gaugedesk/class/";

function hexOf(text: string): string {
  return Array.from(new TextEncoder().encode(text), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** `managed-openai` → `credential:gaugedesk/class/6d616e616765642d6f70656e6169`. */
export function canonicalCredentialClassRef(credentialClass: string): string {
  return `${CANONICAL_CLASS_PREFIX}${hexOf(credentialClass)}`;
}

/** The `credential_ref` the signed envelope's provider binding names, or
 *  `undefined` when the envelope cannot be read as a signed WhippleScript
 *  policy. Reading it here decides only which admissible spelling to present;
 *  the kernel still verifies the signature and resolves the binding. */
export function envelopeBindingCredentialRef(
  signedEnvelope: string,
  providerBindingRef: string,
): string | undefined {
  // A signed envelope is the policy content itself with an `attestation`
  // block added (`SignedEnvelope::to_json`), so the bindings sit at the top
  // level. Only the shape is read here; the kernel verifies the signature.
  try {
    const policy = JSON.parse(signedEnvelope) as {
      provider_bindings?: Record<string, { credential_ref?: unknown }>;
    };
    const ref = policy.provider_bindings?.[providerBindingRef]?.credential_ref;
    return typeof ref === "string" ? ref : undefined;
  } catch {
    return undefined;
  }
}

/** The credential id to present for a public session's provider binding.
 *
 *  Releases published before GaugeDesk canonicalized the envelope name the raw
 *  class on both sides; releases published after name the canonical form in
 *  the envelope and the raw class in the closure. Both are the same class, so
 *  both are admitted: the runtime presents the canonical form exactly when the
 *  envelope names it, and the raw class otherwise. Any other spelling in the
 *  envelope is left to fail the kernel's exact comparison, as it should. */
export function credentialIdForHostPolicy(hostPolicy: {
  credential_class: string;
  provider_binding_ref: string;
  signed_envelope: string;
}): string {
  const canonical = canonicalCredentialClassRef(hostPolicy.credential_class);
  const named = envelopeBindingCredentialRef(
    hostPolicy.signed_envelope,
    hostPolicy.provider_binding_ref,
  );
  return named === canonical ? canonical : hostPolicy.credential_class;
}
