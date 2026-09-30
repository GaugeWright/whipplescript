import assert from "node:assert/strict";
import test from "node:test";
import { transportFailureObservation } from "./transport-failure.ts";

test("third transport failure is delivered as exhausted, never thrown away", () => {
  for (const attempts of [1, 2]) {
    assert.deepEqual(JSON.parse(transportFailureObservation(attempts, "lost reply")), {
      error: "lost reply",
    });
  }
  assert.deepEqual(JSON.parse(transportFailureObservation(3, "lost reply")), {
    error: "lost reply", transport_retry_budget_exhausted: true,
  });
});
