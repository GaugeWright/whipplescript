import { test } from 'node:test';
import assert from 'node:assert/strict';
import { binary, readiness } from './windows-buck2-readiness.mjs';

test('Windows service launch uses only the pinned binary with a hard bound and closed receipt', () => {
  let calls = 0;
  const result = readiness({ platform: 'win32', launch: (file, args, options) => {
    calls++;
    assert.equal(file, binary);
    assert.deepEqual(args, ['--version']);
    assert.equal(options.timeout, 5000);
    assert.equal(options.killSignal, 'SIGKILL');
    assert.equal(options.shell, false);
    assert.equal(options.maxBuffer, 65536);
    return { status: 0, stdout: 'buck2 2026-09-15\n', stderr: 'sensitive unrelated output' };
  } });
  assert.equal(calls, 1);
  assert.equal(result.status, 'ready');
  assert.equal(result.nativeCompileProven, false);
  assert.doesNotMatch(JSON.stringify(result), /sensitive|2026-09-15/);
});

test('launch failures, deadline and unfamiliar output remain closed and diagnostic only', () => {
  const fixtures = [
    [{ error: { code: 'ETIMEDOUT', message: 'private path' } }, 'blocked', 'deadline'],
    [{ error: { code: 'ENOENT' } }, 'blocked', 'binary-unavailable'],
    [{ error: { code: 'EPERM' } }, 'blocked', 'launch-denied'],
    [{ error: { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' } }, 'unknown', 'launch-error'],
    [{ status: 1, stderr: 'Application Control private details' }, 'blocked', 'nonzero-exit'],
    [{ status: 0, stdout: 'secret unexpected data' }, 'unknown', 'unexpected-response'],
  ];
  for (const [response, status, reason] of fixtures) {
    const result = readiness({ platform: 'win32', launch: () => response });
    assert.equal(result.status, status);
    assert.equal(result.reason, reason);
    assert.equal(result.nativeCompileProven, false);
    assert.doesNotMatch(JSON.stringify(result), /private|secret|Application Control/);
  }
  assert.equal(readiness({ platform: 'win32', launch: () => { throw Error('private'); } }).reason, 'launch-error');
});

test('other execution contexts make no launch or Windows readiness claim', () => {
  assert.equal(readiness({ platform: 'darwin', launch: () => { assert.fail('must not launch'); } }).status, 'unknown');
});
