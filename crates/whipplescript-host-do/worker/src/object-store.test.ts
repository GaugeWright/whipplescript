import assert from "node:assert/strict";
import test from "node:test";

import { declaredLength, objectPlaneRoute } from "./object-store.ts";

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
