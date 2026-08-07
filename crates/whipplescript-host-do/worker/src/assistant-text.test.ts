import assert from "node:assert/strict";
import test from "node:test";

import { selectAssistantText } from "./assistant-text.ts";

// The regression these pin: a turn streamed its answer, the runtime reported an
// empty `assistant_text`, and `??` chose the empty string — so the settle path
// recorded nothing and advanced the delta cursor past the only surviving copy.
// The reader watched an answer arrive and then vanish.

test("streamed text wins when the runtime reports no answer", () => {
  // `assistant_text` is a Rust `String`: an absent answer arrives as "", never
  // as undefined. A turn whose last assistant message carried tool calls leaves
  // it empty by construction, which is precisely a tool-using turn.
  assert.equal(selectAssistantText("", "the streamed answer"), "the streamed answer");
});

test("streamed text wins when the runtime reported nothing at all", () => {
  assert.equal(selectAssistantText(undefined, "the streamed answer"), "the streamed answer");
});

test("the runtime's answer is authoritative when it says something", () => {
  // The durable answer replaces the partial projection at settle (DR 0061) —
  // the streamed copy may be batched, truncated, or lost.
  assert.equal(selectAssistantText("settled answer", "partial strea"), "settled answer");
});

test("a turn that produced no text at all records none", () => {
  assert.equal(selectAssistantText("", ""), "");
  assert.equal(selectAssistantText(undefined, ""), "");
});
