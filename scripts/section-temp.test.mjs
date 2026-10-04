import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const scripts = path.dirname(fileURLToPath(import.meta.url));

test('section bootstrap uses its writable temporary root before creating the tracker', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'section-temp-'));
  try {
    const checkout = path.join(root, 'checkout');
    const fixtureScripts = path.join(checkout, 'scripts');
    const capture = path.join(root, 'capture');
    fs.mkdirSync(fixtureScripts, { recursive: true });
    for (const name of ['section.sh', 'prerequisite.sh'])
      fs.copyFileSync(path.join(scripts, name), path.join(fixtureScripts, name));
    fs.writeFileSync(path.join(fixtureScripts, 'check-actions-pinned.sh'), `#!/usr/bin/env bash
set -euo pipefail
[ -d "$TMPDIR" ] && [ -w "$TMPDIR" ]
[ -d "$(dirname "$WHIPPLESCRIPT_ITEMS_STORE")" ]
printf '%s\\n%s\\n' "$TMPDIR" "$WHIPPLESCRIPT_ITEMS_STORE" > "$SECTION_TEMP_CAPTURE"
printf synthetic > "$WHIPPLESCRIPT_ITEMS_STORE"
exit "$SECTION_TEMP_EXIT"
`, { mode: 0o755 });
    for (const status of [0, 17]) {
      const env = { ...process.env, TMPDIR: path.join(root, 'unavailable-incoming-temp'), SECTION_TEMP_CAPTURE: capture, SECTION_TEMP_EXIT: String(status) };
      delete env.WHIPPLESCRIPT_ITEMS_STORE;
      const result = spawnSync('bash', [path.join(fixtureScripts, 'section.sh'), 'workflow-action-pins'], { env, encoding: 'utf8' });
      assert.equal(result.status, status, `${result.stdout}\n${result.stderr}`);
      const [temporary, tracker] = fs.readFileSync(capture, 'utf8').trim().split('\n');
      assert.ok(tracker.startsWith(`${temporary}/`));
      assert.equal(fs.existsSync(temporary), false, 'section EXIT must remove its temporary roots');
      assert.equal(fs.existsSync(env.TMPDIR), false, 'the incoming artifact path must not be created');
    }
    const supplied = path.join(root, 'supplied.sqlite');
    const result = spawnSync('bash', [path.join(fixtureScripts, 'section.sh'), 'workflow-action-pins'], {
      env: { ...process.env, TMPDIR: path.join(root, 'unavailable-incoming-temp'), WHIPPLESCRIPT_ITEMS_STORE: supplied, SECTION_TEMP_CAPTURE: capture, SECTION_TEMP_EXIT: '0' }, encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const [temporary, tracker] = fs.readFileSync(capture, 'utf8').trim().split('\n');
    assert.equal(tracker, supplied);
    assert.equal(fs.readFileSync(supplied, 'utf8'), 'synthetic', 'caller-owned tracker is not cleaned up');
    assert.equal(fs.existsSync(temporary), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
