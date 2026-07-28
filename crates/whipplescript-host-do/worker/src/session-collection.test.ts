import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalArtifact,
  sealArtifact,
  selectWorkspace,
  selectorMatches,
  type ArtifactEnvelope,
  type CollectionPolicy,
} from "./session-collection.ts";

const ENVELOPE: ArtifactEnvelope = {
  schema_ref: "survey.v1",
  session_id: "sess_test",
  release_id: "sha256:" + "a".repeat(64),
  revision: 1,
  produced_at_unix_ms: 1_700_000_000_000,
};

function policy(paths: string[], transcript = false): CollectionPolicy {
  return {
    exportable_paths: paths,
    transcript_eligible: transcript,
    schema_ref: "survey.v1",
    recipient_class: "collection:tenant",
    max_artifact_bytes: 1_000_000,
  };
}

const FILES = new Map([
  ["responses.json", '{"q1":"yes"}'],
  ["notes/scratch.md", "# scratch"],
  ["notes/deep/secret.md", "nested"],
  ["private.key", "must-not-leave"],
]);

test("an exact selector matches only that path", () => {
  assert.ok(selectorMatches("responses.json", "responses.json"));
  assert.ok(!selectorMatches("responses.json", "responses.json.bak"));
  assert.ok(!selectorMatches("responses.json", "other/responses.json"));
});

test("a trailing /* matches one segment and does not descend", () => {
  assert.ok(selectorMatches("notes/*", "notes/scratch.md"));
  assert.ok(!selectorMatches("notes/*", "notes/deep/secret.md"));
  assert.ok(!selectorMatches("notes/*", "notesother/x.md"));
});

test("selection returns only declared paths", () => {
  const selected = selectWorkspace(FILES, policy(["responses.json"]));
  assert.deepEqual(Object.keys(selected), ["responses.json"]);
  assert.equal(selected["responses.json"], '{"q1":"yes"}');
});

test("an undeclared file never leaves, however the agent wrote it", () => {
  const selected = selectWorkspace(FILES, policy(["responses.json", "notes/*"]));
  assert.ok(!("private.key" in selected));
  assert.ok(!("notes/deep/secret.md" in selected));
});

test("selection is deterministic in path order", () => {
  const first = selectWorkspace(FILES, policy(["responses.json", "notes/*"]));
  const second = selectWorkspace(FILES, policy(["notes/*", "responses.json"]));
  assert.deepEqual(Object.keys(first), Object.keys(second));
});

test("the canonical artifact is byte-identical across retries", () => {
  const workspace = selectWorkspace(FILES, policy(["responses.json"]));
  const a = canonicalArtifact(ENVELOPE, workspace, null);
  const b = canonicalArtifact(ENVELOPE, workspace, null);
  assert.deepEqual(a, b);
});

test("the transcript is included only when independently declared", () => {
  const workspace = selectWorkspace(FILES, policy(["responses.json"]));
  const without = new TextDecoder().decode(
    canonicalArtifact(ENVELOPE, workspace, null),
  );
  assert.ok(!without.includes("transcript"));
  const with_ = new TextDecoder().decode(
    canonicalArtifact(ENVELOPE, workspace, [{ type: "text", body: "hello" }]),
  );
  assert.ok(with_.includes("transcript"));
});

test("sealing produces ciphertext that is not the plaintext", async () => {
  const keys = await generateRecipient();
  const plaintext = canonicalArtifact(ENVELOPE, { "responses.json": "secret-answer" }, null);
  const sealed = await sealArtifact(ENVELOPE, plaintext, [keys.publicHex], "scope-a");
  assert.equal(sealed.wraps.length, 1);
  assert.ok(!sealed.ciphertext.includes(Buffer.from("secret-answer").toString("hex")));
  assert.equal(sealed.byte_len, plaintext.byteLength);
  // The secret-free envelope travels in the clear for indexing and quota.
  assert.equal(sealed.envelope.session_id, "sess_test");
});

test("each recipient receives its own wrap", async () => {
  const first = await generateRecipient();
  const second = await generateRecipient();
  const plaintext = canonicalArtifact(ENVELOPE, {}, null);
  const sealed = await sealArtifact(
    ENVELOPE,
    plaintext,
    [first.publicHex, second.publicHex],
    "scope-a",
  );
  assert.equal(sealed.wraps.length, 2);
  assert.notEqual(sealed.wraps[0].wrapped_key, sealed.wraps[1].wrapped_key);
});

test("sealing a collection with no recipient is refused", async () => {
  const plaintext = canonicalArtifact(ENVELOPE, {}, null);
  await assert.rejects(() => sealArtifact(ENVELOPE, plaintext, [], "scope-a"), /no admitted recipient/);
});

test("a fresh data key is used per artifact", async () => {
  const keys = await generateRecipient();
  const plaintext = canonicalArtifact(ENVELOPE, { a: "same" }, null);
  const first = await sealArtifact(ENVELOPE, plaintext, [keys.publicHex], "scope-a");
  const second = await sealArtifact(ENVELOPE, plaintext, [keys.publicHex], "scope-a");
  assert.notEqual(first.ciphertext, second.ciphertext);
});

async function generateRecipient(): Promise<{ publicHex: string }> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return {
    publicHex: [...raw].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}
