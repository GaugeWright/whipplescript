import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalCredentialClassRef,
  credentialIdForHostPolicy,
  envelopeBindingCredentialRef,
} from "./credential-class-ref.ts";

/** The literal GaugeDesk's `envelope_names_the_canonical_class_ref` pins from
 *  the other side (`crates/app/src/account.rs::canonical_credential_class_ref`).
 *  Nothing at compile time relates the two; this is the coupling made visible. */
const MANAGED_OPENAI_CANONICAL =
  "credential:gaugedesk/class/6d616e616765642d6f70656e6169";

/** The shape `SignedEnvelope::to_json` writes: the policy content itself with
 *  an `attestation` block beside it. */
function signedEnvelopeNaming(credentialRef: string): string {
  return JSON.stringify({
    provider_bindings: {
      model: {
        provider: "cloudflare-ai-gateway",
        model: "gpt-5.6-terra",
        credential_ref: credentialRef,
      },
    },
    placements: { "public-do": { provider_bindings: ["model"] } },
    attestation: {
      envelope_hash: "sha256:0",
      signer: "gaugedesk:local-user",
      algorithm: "gaugedesk-p256-v1",
      signature: "00",
      epoch: 1,
      authority: "gaugedesk:local-user",
    },
  });
}

test("the canonical class ref matches GaugeDesk's derivation byte for byte", () => {
  assert.equal(canonicalCredentialClassRef("managed-openai"), MANAGED_OPENAI_CANONICAL);
});

test("a release whose envelope names the canonical form is presented that form", () => {
  assert.equal(
    credentialIdForHostPolicy({
      credential_class: "managed-openai",
      provider_binding_ref: "model",
      signed_envelope: signedEnvelopeNaming(MANAGED_OPENAI_CANONICAL),
    }),
    MANAGED_OPENAI_CANONICAL,
  );
});

test("a release whose envelope names the raw class is still presented the raw class", () => {
  // Every release published before 2026-08-27 — theo, gw-guide — spells the
  // class raw on both sides and must keep resolving.
  assert.equal(
    credentialIdForHostPolicy({
      credential_class: "managed-openai",
      provider_binding_ref: "model",
      signed_envelope: signedEnvelopeNaming("managed-openai"),
    }),
    "managed-openai",
  );
});

test("an envelope naming some other credential is not echoed back to the kernel", () => {
  // Presenting whatever the envelope says would make the kernel's exact
  // comparison vacuous. A foreign spelling stays a refusal.
  assert.equal(
    credentialIdForHostPolicy({
      credential_class: "managed-openai",
      provider_binding_ref: "model",
      signed_envelope: signedEnvelopeNaming("credential:gaugedesk/class/deadbeef"),
    }),
    "managed-openai",
  );
});

test("an unreadable envelope falls back to the raw class rather than throwing", () => {
  assert.equal(envelopeBindingCredentialRef("not json", "model"), undefined);
  assert.equal(
    credentialIdForHostPolicy({
      credential_class: "managed-openai",
      provider_binding_ref: "model",
      signed_envelope: "not json",
    }),
    "managed-openai",
  );
});
