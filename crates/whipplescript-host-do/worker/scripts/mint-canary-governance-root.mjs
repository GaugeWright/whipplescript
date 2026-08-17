#!/usr/bin/env node
//! Mint the governance root the managed wiring canary runs under, and the
//! `:v2` signed policy envelope it presents.
//!
//!   node scripts/mint-canary-governance-root.mjs --out-dir <dir>
//!   node scripts/mint-canary-governance-root.mjs --out-dir <dir> --private-key <path>
//!
//! `managed-host-lifecycle` and `placement-forwarding` present
//! `GW_SYNTHETIC_WHIP_SIGNED_POLICY` to `POST /host/policy`, and the Durable
//! Object verifies it against the governance root pinned for that placement.
//! Two things were missing, not one: the envelope had never been minted, and
//! the deployed Worker carries no `GAUGEDESK_GOVERNANCE_SIGNER` /
//! `GAUGEDESK_GOVERNANCE_KEY`, so `pinnedGovernanceRoot()` falls through to
//! `503 hosted placement has no pinned GaugeDesk governance root` whatever the
//! envelope says. This emits both halves of that pair so they cannot disagree.
//!
//! ## Why it verifies its own output
//!
//! `canonicalize` is not JSON canonicalization. It parses into an `Envelope`
//! and re-emits, so a field the emitter does not write is silently outside the
//! signature. Four arms of DR-0063 have already vanished that way. The
//! signature covers a hash of the *canonical* form, and the verifier
//! re-canonicalizes what it is given — so a document this script composes and
//! hashes by hand can hash differently there and simply not verify.
//!
//! So nothing is written until the real verifier accepts it: this loads the
//! same wasm the Worker runs and calls `verify_host_policy` with the signer and
//! key it is about to tell you to pin. If that rejects, the envelope is wrong
//! and no file is produced. That check is the point of this script; the key
//! generation around it is the easy part.
//!
//! ## What it does not do
//!
//! It does not talk to Cloudflare, Infisical or GitHub, and it does not place
//! any secret. It writes two files 0600 and prints the commands to run. The
//! private key stays on your disk and is never printed.

import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";

export const ALGORITHM = "p256-sha256";

/// Canonical JSON as the envelope emitter produces it: sorted keys, no spaces.
///
/// This has to agree with `Envelope::to_canonical_json`, and agreement is
/// proved by `verify_host_policy` rather than asserted here.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/// The `:v2` preimage (DR-0063 §5): everything `:v1` covers, plus the policy
/// epoch and the authority the envelope speaks for.
///
/// Length-prefixed under a domain tag, and the prefix is the value's length in
/// **bytes** — `Rust`'s `str::len()`. A non-ASCII signer would make a
/// UTF-16 length disagree, and the failure would look like a bad key.
export function signingBytesV2({ envelopeHash, signer, keyId, epoch, authority }) {
  let value = "whipplescript-governance-envelope:v2;";
  for (const item of [envelopeHash, signer, ALGORITHM, keyId, String(epoch), authority]) {
    value += `${Buffer.byteLength(item)}:${item};`;
  }
  return Buffer.from(value, "utf8");
}

/// The uncompressed SEC1 point, which is what the runtime pins as `key_id`.
export function keyIdFrom(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  // The SEC1 point is the trailing 65 bytes of a P-256 SPKI: 0x04 ‖ X ‖ Y.
  const point = der.subarray(der.length - 65);
  assert.equal(point[0], 0x04, "public key is not an uncompressed P-256 point");
  return point.toString("hex");
}

/// The policy the canary runs under.
///
/// Deliberately the smallest document the suite's own assertions accept: it
/// reads the first `provider_bindings` entry for a `credential_ref` and the
/// first `placements` key as the placement ceiling, and requires at least one
/// of each. Every field here is one the canonical emitter writes — which is
/// what keeps the hash stable, and is proved rather than trusted.
export function canaryPolicy() {
  return {
    bindings: { do: "placement:do", model: "provider:openai" },
    declassifications: [],
    delegations: [],
    endorsements: [],
    parties: {},
    placements: { do: { kind: "durable_object", provider_bindings: ["model"] } },
    provider_bindings: {
      model: {
        base_url: "https://api.openai.com/v1/responses",
        credential_ref: "managed-openai",
        model: "gpt-test",
        provider: "openai",
      },
    },
    resources: {
      "placement:do": { principal: true, reader: [], writer: [] },
      "provider:openai": { principal: true, reader: [], writer: [] },
    },
  };
}

/// Compose and sign, returning the envelope text and everything to pin.
///
/// `signature` is raw `r ‖ s`, not DER. `Signature::from_slice` on the
/// verifying side takes the fixed 64-byte form, and Node emits DER unless told
/// otherwise — a mismatch there verifies as a bad signature rather than as a
/// format error, which is a long way to chase.
export function composeSignedPolicy({ privateKey, signer, keyId, epoch, authority, policy }) {
  const body = canonicalJson(policy);
  const envelopeHash = createHash("sha256").update(body, "utf8").digest("hex");
  const signature = sign(
    "sha256",
    signingBytesV2({ envelopeHash, signer, keyId, epoch, authority }),
    { key: privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("hex");
  const text = canonicalJson({
    ...policy,
    attestation: {
      algorithm: ALGORITHM,
      authority,
      envelope_hash: envelopeHash,
      epoch,
      key_id: keyId,
      signature,
      signer,
    },
  });
  return { envelopeHash, signature, text };
}

/// Prove the envelope against the verifier that will actually judge it.
///
/// Loads the nodejs-target wasm the Worker is built from. Absent, this refuses
/// rather than emitting an unverified envelope: an envelope that does not
/// verify is indistinguishable from a correct one until the canary runs against
/// production and returns a 400 nobody can read.
export function verifyWithRuntime({ text, signer, keyId, pkgPath }) {
  const require = createRequire(import.meta.url);
  let bindings;
  try {
    bindings = require(pkgPath);
  } catch (error) {
    throw new Error(
      `the nodejs wasm build is missing (${error.message}).\n`
        + "Build it first, from crates/whipplescript-host-do/worker:\n"
        + "  cargo build -p whipplescript-host-do --no-default-features \\\n"
        + "    --target wasm32-unknown-unknown --release\n"
        + "  wasm-bindgen ../../../target/wasm32-unknown-unknown/release/"
        + "whipplescript_host_do.wasm \\\n    --out-dir pkg-node --target nodejs\n"
        + "  printf '{\"type\":\"commonjs\"}\\n' > pkg-node/package.json\n\n"
        + "`pkg-node`, not `pkg`: `pkg` holds the *bundler* target the Worker is "
        + "built from, and overwriting it with the nodejs target breaks the "
        + "deploy. The package.json marker is needed because this worker package "
        + "is `\"type\": \"module\"`, which would otherwise make wasm-bindgen's "
        + "CommonJS loader resolve the .wasm against the wrong directory.",
    );
  }
  assert(
    typeof bindings.verify_host_policy === "function",
    "the wasm build does not export verify_host_policy",
  );
  return JSON.parse(bindings.verify_host_policy(text, signer, keyId));
}

function flag(argv, name, fallback) {
  const hit = argv.find((entry) => entry.startsWith(`--${name}=`));
  if (hit) return hit.slice(name.length + 3);
  const index = argv.indexOf(`--${name}`);
  if (index >= 0 && argv[index + 1] && !argv[index + 1].startsWith("--")) return argv[index + 1];
  return fallback;
}

function main() {
  const argv = process.argv.slice(2);
  const outDir = flag(argv, "out-dir");
  assert(outDir, "usage: --out-dir <dir> [--signer NAME] [--authority NAME] [--epoch N] [--private-key <path>]");
  // A name distinct from GaugeDesk's own `gaugedesk-do-host`, because this root
  // signs for the synthetic canary and nothing else. Naming it after the real
  // authority would make a canary-only key read as the product's governance
  // root the first time somebody looked.
  const signer = flag(argv, "signer", "whipplescript-canary-root");
  const authority = flag(argv, "authority", "gaugedesk");
  const epoch = Number(flag(argv, "epoch", "1"));
  assert(Number.isSafeInteger(epoch) && epoch > 0, "epoch must be a positive integer");
  const existing = flag(argv, "private-key");
  const pkgPath = resolve(
    flag(argv, "pkg", resolve(import.meta.dirname, "..", "pkg-node", "whipplescript_host_do.js")),
  );

  let privateKey;
  let generated = false;
  if (existing) {
    privateKey = createPrivateKey(readFileSync(resolve(existing), "utf8"));
  } else {
    ({ privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" }));
    generated = true;
  }
  const keyId = keyIdFrom(createPublicKey(privateKey));

  const { envelopeHash, text } = composeSignedPolicy({
    privateKey,
    signer,
    keyId,
    epoch,
    authority,
    policy: canaryPolicy(),
  });

  // Before anything is written. A file on disk is a thing somebody will paste.
  const verified = verifyWithRuntime({ text, signer, keyId, pkgPath });
  assert.equal(verified?.epoch, epoch, "the runtime read a different epoch than was signed");

  mkdirSync(outDir, { recursive: true });
  const policyFile = resolve(outDir, "canary-signed-policy.json");
  writeFileSync(policyFile, text, { mode: 0o600 });
  chmodSync(policyFile, 0o600);
  let keyFile;
  if (generated) {
    keyFile = resolve(outDir, "canary-governance-root.pem");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    chmodSync(keyFile, 0o600);
  }

  console.log(`verified against the runtime's own verifier — epoch ${verified.epoch}\n`);
  console.log(`signer         ${signer}`);
  console.log(`key_id         ${keyId}`);
  console.log(`envelope_hash  ${envelopeHash}`);
  console.log(`authority      ${authority}`);
  console.log(`\nwrote ${policyFile}`);
  if (keyFile) console.log(`wrote ${keyFile}  (private — never commit, never paste)`);
  console.log(`
Pin the Worker to this root, or the policy is refused with 503 whatever it says:

  wrangler secret put GAUGEDESK_GOVERNANCE_SIGNER   # or set as a plain var
  wrangler secret put GAUGEDESK_GOVERNANCE_KEY

Store the envelope where the canary reads it:

  infisical secrets set GW_SYNTHETIC_WHIP_SIGNED_POLICY=\
"$(cat ${policyFile})" --path /synthetics/wiring --env prod

Then project it, with the other ten, into the lane's environment.`);
  if (keyFile) {
    console.log(`
Keep the private half so a later epoch can be re-signed. It belongs in
Infisical beside the rest, under a name that says which half it is:

  infisical secrets set GW_SYNTHETIC_WHIP_GOVERNANCE_PRIVATE_KEY=\
"$(cat ${keyFile})" --path /synthetics/wiring --env prod

Re-run with --private-key to re-sign without changing what the Worker pins.`);
  }
}

if (process.argv[1]?.endsWith("mint-canary-governance-root.mjs")) main();
