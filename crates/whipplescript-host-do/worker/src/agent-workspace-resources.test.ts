import assert from "node:assert/strict";
import { test } from "node:test";
import { agentWorkspaceResources } from "./agent-workspace-resources.ts";

const v0 = JSON.stringify({ schema: "whipplescript.agent_package.v0" });
const v1 = JSON.stringify({ schema: "whipplescript.agent_package.v1" });
const root = { handle: "project", kind: "file_store", writable: true };

test("v1 session writes are limited to artifacts and work", () => {
  assert.deepEqual(agentWorkspaceResources(v1, [root]), [
    { ...root, writable: false },
    { ...root, selector: "artifacts", writable: true },
    { ...root, selector: "work", writable: true },
  ]);
});

test("v1 keeps narrower admitted scopes and refuses an absent scope", () => {
  const narrow = { ...root, selector: "uploads", writable: false };
  assert.deepEqual(agentWorkspaceResources(v1, [narrow]), [narrow]);
  assert.deepEqual(agentWorkspaceResources(v1, [{ ...root, selector: "agent" }]), [
    { ...root, selector: "agent", writable: false },
  ]);
  assert.deepEqual(agentWorkspaceResources(v1, [{ ...root, selector: "artifacts/reports" }]), [
    { ...root, selector: "artifacts/reports", writable: false },
    { ...root, selector: "artifacts/reports", writable: true },
  ]);
  assert.deepEqual(agentWorkspaceResources(v1, undefined), []);
});

test("v1 leaves a host's other subtrees as admitted, presentation included", () => {
  const target = {
    handle: "target:t-a",
    kind: "file_store",
    selector: "targets/t-a",
    writable: true,
    presented_as: "api",
  };
  const readOnly = { ...target, handle: "target:t-b", selector: "targets/t-b", writable: false };
  assert.deepEqual(agentWorkspaceResources(v1, [target, readOnly]), [target, readOnly]);
  // A subtree holding the definition is still narrowed.
  assert.deepEqual(agentWorkspaceResources(v1, [{ ...root, selector: "agent/skills" }]), [
    { ...root, selector: "agent/skills", writable: false },
  ]);
});

test("older pinned packages retain their workspace authority", () => {
  assert.deepEqual(agentWorkspaceResources(v0, [root]), [root]);
  assert.equal(agentWorkspaceResources(v0, undefined), undefined);
});
