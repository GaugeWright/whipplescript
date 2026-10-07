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

test("only a fully labeled model call can claim complete provenance", () => {
  const captures = new LiveModelContext();
  const known = { source_handles: ["chat:one"], complete: true };
  captures.record("one", { messages: ["first"] }, [], {
    messages: [known], tools: { source_handles: ["package:one"], complete: true },
  });
  captures.record("one", { messages: ["second"] }, [], {
    messages: [known, { source_handles: [], complete: false }], tools: known,
  });
  captures.record("one", { messages: ["third"] }, [], {
    messages: [known], tools: { source_handles: [], complete: false },
  });
  assert.deepEqual(captures.read("one")?.calls.map((call) => call.provenance_complete),
    [true, false, false]);
});

test("a sealed capture erases every turn and refuses an in-flight late record", () => {
  const captures = new LiveModelContext();
  captures.record("one\0turn", { input: "one" }, []);
  captures.record("two\0turn", { input: "two" }, []);
  captures.seal();
  assert.equal(captures.read("one\0turn"), null);
  assert.equal(captures.read("two\0turn"), null);
  // A drive that was already awaiting a provider when teardown landed.
  captures.record("one\0turn", { input: "late" }, []);
  assert.equal(captures.read("one\0turn"), null);
});
