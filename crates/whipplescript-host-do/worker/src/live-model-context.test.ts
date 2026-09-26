import assert from "node:assert/strict";
import { test } from "node:test";

import { LiveModelContext } from "./live-model-context.ts";

test("captures ordered model calls without retaining a mutable request object", () => {
  const captures = new LiveModelContext();
  const body = { input: [{ role: "system", content: "instructions" }] };
  captures.record("instance\0turn", body, ["source:a", "source:a", "source:b"]);
  body.input[0]!.content = "changed later";
  captures.record("instance\0turn", { input: [{ role: "tool", content: "result" }] }, []);

  assert.deepEqual(captures.read("instance\0turn"), {
    calls: [
      { ordinal: 0, body: { input: [{ role: "system", content: "instructions" }] },
        source_handles: ["source:a", "source:b"], provenance_complete: false,
        ordered_provenance: null },
      { ordinal: 1, body: { input: [{ role: "tool", content: "result" }] },
        source_handles: [], provenance_complete: false, ordered_provenance: null },
    ],
    incomplete: false,
  });
  captures.clear("instance\0turn");
  assert.equal(captures.read("instance\0turn"), null);
});

test("does not coalesce two isolated turns", () => {
  const captures = new LiveModelContext();
  captures.record("one\0turn", { input: "one" }, []);
  captures.record("two\0turn", { input: "two" }, []);
  captures.clear("one\0turn");
  assert.equal(captures.read("one\0turn"), null);
  assert.deepEqual(captures.read("two\0turn")?.calls[0]?.body, { input: "two" });
});
