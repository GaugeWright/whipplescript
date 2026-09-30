import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseTimingReport } from './windows-cargo-timings.mjs';
const unit = { i: 0, name: 'fixture', version: '1', mode: 'build', target: '/private/target', features: [], start: 1, duration: 3, sections: [['frontend', {start:0,end:1}], ['codegen',{start:1,end:3}]] };
const html = (units) => `const UNIT_DATA = ${JSON.stringify(units)};`;
test('synthetic Cargo 1.95 units retain elapsed sections and hash identities', () => {
  const [u] = parseTimingReport(html([unit]));
  assert.equal(u.elapsedSeconds, 3); assert.match(u.identity, /^[a-f0-9]{64}$/);
  assert.deepEqual(u.sections, [{category:'frontend',seconds:1},{category:'codegen',seconds:2}]);
  assert.doesNotMatch(JSON.stringify(u), /private|fixture/);
  assert.equal(parseTimingReport(html([{...unit,sections:null}]))[0].sections, null);
});
test('malformed, duplicate, excessive, and incompatible formats remain unknown', () => {
  for (const input of [html([unit,unit]), html([{...unit,duration:-1}]), html([{...unit,sections:[['codegen',{start:0,end:4}]]}]), html([unit])+html([unit]), 'format changed', 'x'.repeat(4*1024*1024+1)]) assert.throws(() => parseTimingReport(input));
});
test('synthetic report observation excludes stale evidence and emits only safe metadata', () => {
  const root = mkdtempSync(join(tmpdir(),'cargo-timings-'));
  const helper = new URL('./windows-cargo-timings.mjs', import.meta.url).pathname;
  const run = (...args) => spawnSync(process.execPath,[helper,...args],{cwd:root,encoding:'utf8'});
  const after = (before) => JSON.parse(run('after',before).stdout.split(': ').slice(1).join(': '));
  try {
    assert.equal(after('missing').status,'missing');
    mkdirSync(join(root,'target/cargo-timings'),{recursive:true});
    const file = join(root,'target/cargo-timings/cargo-timing.html');
    writeFileSync(file,html([unit]));
    assert.equal(after('unavailable').status, 'unavailable');
    assert.equal(after('invalid-token').status, 'unavailable');
    const before = run('before').stdout.trim();
    assert.equal(after(before).status,'stale');
    writeFileSync(file,html([{...unit,duration:4}]));
    const result=after(before); assert.equal(result.status,'recorded'); assert.match(result.reportSha256,/^[a-f0-9]{64}$/);
    writeFileSync(file,'changed format'); assert.equal(after(before).status,'invalid');
  } finally { rmSync(root,{recursive:true,force:true}); }
});

// Extracted from a real offline one-file Cargo 1.95.0 dev fixture on macOS.
// This verifies HTML compatibility, not Windows dist workload or phase costs.
test("actual pinned Cargo 1.95 unit format is accepted", () => {
  const actual = [{"i": 0, "name": "ci-timing-schema-fixture", "version": "0.0.0", "mode": "todo", "target": " ci-timing-schema-fixture \"bin\"", "features": [], "start": 0.1, "duration": 0.06, "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null}];
  const parsed = parseTimingReport(html(actual));
  assert.equal(parsed.length, 1); assert.equal(parsed[0].sections, null);
});
