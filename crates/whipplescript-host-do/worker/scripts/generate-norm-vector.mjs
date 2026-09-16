import { mkdir, readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

const root = resolve(import.meta.dirname, "../../../..");
const output = resolve(root, "target/norm-portable-vector.json");
const impactOutput = resolve(root, "target/norm-impact-vector.json");
const publicationOutput = resolve(root, "target/norm-publication-vector.json");
await mkdir(resolve(root, "target"), { recursive: true });
// A failed producer must not leave an older vector available to the consumer.
await rm(output, { force: true });
await rm(publicationOutput, { force: true });
await rm(impactOutput, { force: true });
const result = spawnSync("cargo", [
  "test", "-p", "whipplescript", "--test", "norm_commands",
  "norm_cli_",
], {
  cwd: root,
  env: { ...process.env, WHIPPLESCRIPT_NORM_VECTOR_OUT: output, WHIPPLESCRIPT_NORM_PUBLICATION_VECTOR_OUT: publicationOutput, WHIPPLESCRIPT_NORM_IMPACT_VECTOR_OUT: impactOutput },
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(`native norm vector producer failed (${result.status ?? result.signal})`);
const vector = JSON.parse(await readFile(output, "utf8"));
assert.equal(vector.protocol, "whipplescript.norm.test-vector/v1");
assert.equal(vector.events.length, 12);
const retirements = vector.events
  .filter(event => event.kind === "norm.record.retired")
  .map(event => JSON.parse(event.payload_json).statement.action);
assert.equal(retirements.length, 2);
const [prior, current] = retirements;
assert.equal(prior.record, current.record);
assert.notEqual(prior.revision, current.revision);
assert.notEqual(prior.activation, current.activation);
assert.equal(vector.events.find(event => event.event_id === prior.previous)?.kind, "norm.record.edited");
assert.equal(current.previous, current.activation);
const retired = vector.snapshot.result.snapshot.records.find(named => named.record.id === current.record);
assert.equal(retired.record.content_head, current.revision);
assert.equal(retired.record.status, "retired");
assert.equal(retired.effectiveness.kind, "inactive");
assert.equal(vector.snapshot.result.snapshot.inventory.classification_complete, true);
assert.equal(Object.keys(vector.snapshot.result.snapshot.inventory.requirements).length, 1);
assert.equal(vector.artifacts.cuts.length, 2);
assert.equal(vector.queries.length, 5);
assert.equal(vector.queries[2].response.result.resources.binding_complete, true);
assert.equal(vector.queries[3].response.result.resources.binding_complete, false);
assert.equal(vector.queries[4].response.result.comparison.requirements.length, 2);
assert.deepEqual(vector.queries[4].response.result.comparison.changes, {
  "src/auth.py": "deleted", "src/new.py": "created", "src/parser.py": "modified",
});
console.log("Generated native custody history and stored-cut queries for the WASM command-door test.");

const publication = JSON.parse(await readFile(publicationOutput, "utf8"));
assert.equal(publication.protocol, "whipplescript.norm.publication-test-vector/v1");
assert.equal(publication.cases.length, 2);
for (const value of publication.cases) {
  assert.equal(value.draft.result.kind, "unsigned");
  assert.deepEqual(value.draft.result.statement, value.event.statement);
  assert.notDeepEqual(value.forged.statement, value.event.statement);
  assert(value.runtime_rows.some(rows => rows.table === "events"));
}
console.log("Generated custody-signed publication vectors and settled runtime rows for the WASM door.");

const impact = JSON.parse(await readFile(impactOutput, "utf8"));
assert.equal(impact.protocol, "whipplescript.norm.impact-test-vector/v1");
assert.equal(impact.cases.length, 2);
console.log("Generated authenticated protected-impact vectors for the hosted query door.");
