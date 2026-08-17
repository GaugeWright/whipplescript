import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { existsSync } from "node:fs";
import test from "node:test";

import {
  ALGORITHM,
  canaryPolicy,
  canonicalJson,
  composeSignedPolicy,
  keyIdFrom,
  signingBytesV2,
  verifyWithRuntime,
} from "./mint-canary-governance-root.mjs";

const keyPair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });

test("canonical JSON sorts keys and adds no whitespace", () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 3, c: 4 }] }), '{"a":[2,{"c":4,"d":3}],"b":1}');
});

test("the v2 preimage is length-prefixed under its own domain tag", () => {
  const bytes = signingBytesV2({
    envelopeHash: "ab",
    signer: "root",
    keyId: "04ff",
    epoch: 7,
    authority: "gaugedesk",
  }).toString("utf8");
  assert.equal(
    bytes,
    "whipplescript-governance-envelope:v2;2:ab;4:root;11:p256-sha256;4:04ff;1:7;9:gaugedesk;",
  );
  // The v1 tag must not be reachable from here: a v1 signature does not cover
  // the epoch, and the hosted path refuses it.
  assert(!bytes.includes(":v1;"));
});

test("the length prefix counts bytes, not UTF-16 units", () => {
  // A multi-byte signer would otherwise be prefixed with a shorter length than
  // Rust's `str::len()`, and the mismatch surfaces as an invalid signature.
  const bytes = signingBytesV2({
    envelopeHash: "ab",
    signer: "rôot",
    keyId: "04",
    epoch: 1,
    authority: "a",
  }).toString("utf8");
  assert(bytes.includes("5:rôot;"), bytes);
});

test("every field of the preimage changes the bytes", () => {
  const base = { envelopeHash: "ab", signer: "root", keyId: "04ff", epoch: 1, authority: "gaugedesk" };
  const seen = new Set([signingBytesV2(base).toString("hex")]);
  for (const change of [
    { envelopeHash: "ac" }, { signer: "other" }, { keyId: "04fe" },
    { epoch: 2 }, { authority: "beta" },
  ]) {
    seen.add(signingBytesV2({ ...base, ...change }).toString("hex"));
  }
  assert.equal(seen.size, 6, "a field is not covered by the signature");
});

test("key_id is the uncompressed SEC1 point", () => {
  const keyId = keyIdFrom(createPublicKey(keyPair().privateKey));
  assert.match(keyId, /^04[0-9a-f]{128}$/);
});

test("the signature is raw r‖s over the v2 preimage, not DER", () => {
  // Node emits DER for EC unless told otherwise, and the runtime's
  // `Signature::from_slice` takes the fixed 64-byte form. A DER signature fails
  // as "invalid signature", which reads like the wrong key.
  const { privateKey, publicKey } = keyPair();
  const keyId = keyIdFrom(publicKey);
  const signed = composeSignedPolicy({
    privateKey, keyId, signer: "root", epoch: 3, authority: "gaugedesk", policy: canaryPolicy(),
  });
  assert.match(signed.signature, /^[0-9a-f]{128}$/);
  assert(
    verify(
      "sha256",
      signingBytesV2({
        envelopeHash: signed.envelopeHash, signer: "root", keyId, epoch: 3, authority: "gaugedesk",
      }),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signed.signature, "hex"),
    ),
  );
});

test("the envelope hash covers the policy without its attestation", () => {
  const { privateKey, publicKey } = keyPair();
  const signed = composeSignedPolicy({
    privateKey, keyId: keyIdFrom(publicKey), signer: "root", epoch: 1,
    authority: "gaugedesk", policy: canaryPolicy(),
  });
  const parsed = JSON.parse(signed.text);
  const { attestation, ...body } = parsed;
  assert.equal(
    signed.envelopeHash,
    createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"),
  );
  assert.equal(attestation.envelope_hash, signed.envelopeHash);
});

test("the attestation states epoch and authority, so it is a v2 envelope", () => {
  // Both present selects v2; exactly one is malformed and refused rather than
  // silently downgraded. The hosted path requires the epoch to be signed.
  const { privateKey, publicKey } = keyPair();
  const signed = composeSignedPolicy({
    privateKey, keyId: keyIdFrom(publicKey), signer: "root", epoch: 9,
    authority: "gaugedesk", policy: canaryPolicy(),
  });
  const { attestation } = JSON.parse(signed.text);
  assert.equal(attestation.algorithm, ALGORITHM);
  assert.equal(attestation.epoch, 9);
  assert.equal(attestation.authority, "gaugedesk");
  assert.equal(typeof attestation.signature, "string");
});

test("the policy carries what the canary suite reads out of it", () => {
  // `managedPolicy` in production-wiring-canary.mjs requires a 64-hex envelope
  // hash, at least one provider binding with a credential_ref, and at least one
  // placement. A policy that signs cleanly and then fails those assertions
  // would be a red lane with a misleading reason.
  const policy = canaryPolicy();
  const [, provider] = Object.entries(policy.provider_bindings)[0];
  assert.equal(typeof provider.credential_ref, "string");
  assert(Object.keys(policy.placements).length > 0);
});

test("a missing wasm build refuses rather than emitting an unverified envelope", () => {
  assert.throws(
    () => verifyWithRuntime({
      text: "{}", signer: "root", keyId: "04", pkgPath: "/nonexistent/pkg.js",
    }),
    /nodejs wasm build is missing/,
  );
});

// The guarantee this script exists for, against the verifier that will judge
// it. Skipped when the nodejs wasm has not been built — this is the deep half,
// not part of the ordinary gate — but never quietly passed: a skip says so.
//
//   cargo build -p whipplescript-host-do --no-default-features \
//     --target wasm32-unknown-unknown --release
//   wasm-bindgen ../../../target/wasm32-unknown-unknown/release/\
// whipplescript_host_do.wasm --out-dir pkg-node --target nodejs
//   printf '{"type":"commonjs"}\n' > pkg-node/package.json
const PKG = new URL("../pkg-node/whipplescript_host_do.js", import.meta.url).pathname;
const built = existsSync(PKG);

test("the runtime accepts what this composes, and refuses every corruption of it", { skip: built ? false : "pkg-node is not built" }, () => {
  const { privateKey, publicKey } = keyPair();
  const other = keyPair();
  const keyId = keyIdFrom(publicKey);
  const signer = "whipplescript-canary-root";
  const signed = composeSignedPolicy({
    privateKey, keyId, signer, epoch: 1, authority: "gaugedesk", policy: canaryPolicy(),
  });
  const check = (text, s = signer, k = keyId) =>
    verifyWithRuntime({ text, signer: s, keyId: k, pkgPath: PKG });

  assert.equal(check(signed.text).epoch, 1);

  // Without these the acceptance above proves nothing: a verifier that accepts
  // everything would pass the positive case just as well.
  assert.throws(() => check(signed.text, "someone-else"), "a wrong signer was accepted");
  assert.throws(() => check(signed.text, signer, keyIdFrom(other.publicKey)), "a wrong key was accepted");

  const tampered = JSON.parse(signed.text);
  tampered.provider_bindings.model.model = "gpt-evil";
  assert.throws(() => check(JSON.stringify(tampered)), "a tampered policy was accepted");

  // A v1 attestation does not cover the epoch, and the hosted path must refuse
  // it rather than read an epoch the signature never bound.
  const downgraded = JSON.parse(signed.text);
  delete downgraded.attestation.epoch;
  assert.throws(() => check(JSON.stringify(downgraded)), "a v1 downgrade was accepted");

  const halfStated = JSON.parse(signed.text);
  delete halfStated.attestation.authority;
  assert.throws(() => check(JSON.stringify(halfStated)), "a half-stated v2 was accepted");
});
