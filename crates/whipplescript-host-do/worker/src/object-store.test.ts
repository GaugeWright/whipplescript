import assert from "node:assert/strict";
import test from "node:test";

import { declaredLength, ingestAllowlist, ingestRefusal, objectPlaneRoute } from "./object-store.ts";

// The rules both byte routes share, apart from a bucket. `declaredLength` is
// the one that cannot be exercised through either route under workerd — it
// gives every body it constructs a content-length — so it is pinned here
// instead. A stream is stored against a length known before it starts, and
// reading the body to discover its size is the one thing neither route may do.

const headersWith = (value: string | null): Headers =>
  value === null ? new Headers() : new Headers({ "content-length": value });

test("a whole non-negative length is a length", () => {
  assert.equal(declaredLength(headersWith("0")), 0);
  assert.equal(declaredLength(headersWith("4096")), 4096);
});

// The trap this exists for: `Number("")` is 0, not NaN, so an absent header
// parsed naively reads as a zero-length body — and then every byte that
// follows overruns the stream it was supposed to size.
test("an absent header is absent, never zero", () => {
  assert.equal(declaredLength(headersWith(null)), null);
  assert.equal(declaredLength(headersWith("")), null);
});

test("anything that is not a whole non-negative number is refused", () => {
  for (const bad of ["-1", "1.5", "abc", "1e3x", "Infinity", "NaN", "0x10"]) {
    assert.equal(declaredLength(headersWith(bad)), null, bad);
  }
});

test("the object plane claims only its own path shape", () => {
  assert.equal(objectPlaneRoute(`/v1/objects/${"a".repeat(32)}`), "a".repeat(32));
  for (const other of ["/v1/objects", "/v1/objects/a/b", "/host/policy", "/healthz"]) {
    assert.equal(objectPlaneRoute(other), undefined, other);
  }
});

// Which sources ingest will read from. Every check here is about the same
// fact: the URL arrives from a model provider's answer, so it is
// attacker-influencable in the ordinary case rather than the exotic one, and a
// Worker is a good network position to borrow.

const ALLOWED = new Set(["media.example", "mirror.example"]);

test("a deployment that declared no source has not enabled ingest", () => {
  assert.equal(ingestAllowlist({}).size, 0);
  assert.equal(ingestAllowlist({ WHIP_INGEST_HOSTS: "  ,, " }).size, 0);
});

test("declared hosts are read as a list, trimmed and case-folded", () => {
  const allowed = ingestAllowlist({ WHIP_INGEST_HOSTS: " Media.Example , mirror.example " });
  assert.deepEqual([...allowed].sort(), ["media.example", "mirror.example"]);
});

test("a declared https source is read", () => {
  assert.equal(ingestRefusal("https://media.example/a.png", ALLOWED), undefined);
  assert.equal(ingestRefusal("https://MEDIA.example:443/a.png", ALLOWED), undefined);
});

test("a source outside the list is refused, whatever else is right about it", () => {
  const refusal = ingestRefusal("https://elsewhere.example/a.png", ALLOWED);
  assert.match(String(refusal), /elsewhere\.example/);
});

// A declared host on an undeclared port is a scan of the services behind it;
// userinfo in the URL is a credential `fetch` would send; and http is both of
// those over the wire in the clear.
test("scheme, credentials and port are each their own refusal", () => {
  for (const bad of [
    "http://media.example/a.png",
    "ftp://media.example/a.png",
    "https://user:secret@media.example/a.png",
    "https://media.example:8080/a.png",
    "https://media.example:22/a.png",
    "not a url",
  ]) {
    assert.notEqual(ingestRefusal(bad, ALLOWED), undefined, bad);
  }
});

test("the ingest path is its own, and not an object key", () => {
  assert.equal(objectPlaneRoute("/v1/object-ingest"), undefined);
});
