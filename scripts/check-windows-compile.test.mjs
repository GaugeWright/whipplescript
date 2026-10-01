import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';

const source = resolve('scripts/check-windows-compile.sh');
const shells = ['/bin/bash', '/opt/homebrew/bin/bash'].filter(existsSync);
for (const shell of shells) test(`Windows cache decisions and failure exits under ${shell}`, () => {
  const root = mkdtempSync(join(tmpdir(), 'whipple-windows-cache-'));
  const git = (...args) => execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', ...args], { cwd: root, stdio: 'pipe' }).toString().trim();
  try {
    mkdirSync(join(root, 'scripts')); mkdirSync(join(root, 'bin'));
    copyFileSync(source, join(root, 'scripts/check-windows-compile.sh'));
    copyFileSync(resolve('scripts/windows-cargo-timings.mjs'), join(root, 'scripts/windows-cargo-timings.mjs'));
    copyFileSync(resolve('scripts/windows-buck2-readiness.mjs'), join(root, 'scripts/windows-buck2-readiness.mjs'));
    writeFileSync(join(root, 'Cargo.toml'), '[workspace]\n');
    writeFileSync(join(root, '.gitignore'), 'target/\nbin/\n');
    writeFileSync(join(root, 'bin/rustc'), '#!/usr/bin/env bash\nprintf "host: %s\\nrelease: %s\\n" "${FAKE_HOST:-x86_64-pc-windows-msvc}" "${FAKE_RUSTC:-test}"\n', { mode: 0o755 });
    writeFileSync(join(root, 'bin/cargo'), '#!/usr/bin/env bash\n[ "$*" = "build --workspace --profile dist --locked --timings" ] || exit 99\nprintf "called\\n" >> "$CALLS"\nmkdir -p target/cargo-timings\nprintf "const UNIT_DATA = [];\\n" > target/cargo-timings/cargo-timing.html\nexit "${FAKE_EXIT:-0}"\n', { mode: 0o755 });
    git('init', '-q');
    const calls = join(root, 'target/calls'); mkdirSync(join(root, 'target'));
    const run = (env = {}) => spawnSync(shell, ['scripts/check-windows-compile.sh', 'scripts/windows-cargo-timings.mjs'], { cwd: root, env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`, CALLS: calls, ...env }, encoding: 'utf8' });
    const result = (r) => { assert.equal(r.status, 0, r.stderr); return JSON.parse(r.stdout.split('\n').find((s) => s.startsWith('CI_WINDOWS_COMPILE: ')).slice(20)); };
    const firstRun = run();
    const timing = (r) => JSON.parse(r.stdout.split('\n').find((s) => s.startsWith('CI_WINDOWS_CARGO_TIMING: ')).slice(25));
    assert.equal(timing(firstRun).status, 'recorded');
    const noHead = result(firstRun); assert.equal(noHead.reason, 'no-head'); assert.equal(noHead.key, ''); assert.ok(!existsSync(join(root, 'target/windows-compile-passed')));
    git('add', '.'); git('commit', '-qm', 'fixture');
    const first = result(run()); assert.equal(first.reason, 'no-pass-record'); assert.equal(first.decision, 'build'); assert.ok(Number.isInteger(first.cargoSeconds) && first.cargoSeconds >= 0); assert.match(first.key, /^[a-f0-9]{40}$/);
    const legacyKey = execFileSync('git', ['hash-object', '--stdin'], { cwd: root, input: Buffer.concat([Buffer.from('host: x86_64-pc-windows-msvc\nrelease: test\n'), execFileSync('git', ['ls-tree', '-r', 'HEAD', '--', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'dist-workspace.toml', 'crates', 'std', 'examples', 'models', 'spec', 'skills', 'scripts/check-windows-compile.sh', 'scripts/windows-cargo-timings.mjs', 'scripts/windows-buck2-readiness.mjs'], { cwd: root })]) }).toString().trim();
    assert.equal(first.key, legacyKey, 'the existing pass-key algorithm is unchanged');
    const servedRun = run(); assert.doesNotMatch(servedRun.stdout, /CI_WINDOWS_CARGO_TIMING:/);
    assert.match(servedRun.stdout, /CI_WINDOWS_BUCK2_READINESS:/);
    assert.ok(servedRun.stdout.indexOf('CI_WINDOWS_BUCK2_READINESS:') < servedRun.stdout.indexOf('CI_WINDOWS_COMPILE:'));
    const served = result(servedRun); assert.equal(served.decision, 'served'); assert.equal(served.reason, 'matching-pass'); assert.equal(served.cargoSeconds, null);
    writeFileSync(join(root, 'README.md'), 'documentation\n'); git('add', '.'); git('commit', '-qm', 'docs'); assert.equal(result(run()).key, first.key);
    mkdirSync(join(root, 'crates')); writeFileSync(join(root, 'crates/untracked.rs'), '// untracked\n'); assert.equal(result(run()).reason, 'dirty-inputs'); rmSync(join(root, 'crates'), { recursive: true });
    writeFileSync(join(root, 'Cargo.toml'), '[workspace]\n# dirty\n'); const dirty = result(run()); assert.equal(dirty.reason, 'dirty-inputs'); assert.equal(dirty.key, '');
    git('add', '.'); git('commit', '-qm', 'input changes'); const changed = result(run()); assert.equal(changed.reason, 'key-miss'); assert.notEqual(changed.inputTreeKey, first.inputTreeKey);
    const before = readFileSync(join(root, 'target/windows-compile-passed'), 'utf8');
    const failure = run({ FAKE_RUSTC: 'next', FAKE_EXIT: '23' }); assert.equal(failure.status, 23); assert.equal(timing(failure).outcome, 'failed'); const failed = JSON.parse(failure.stdout.split('\n').find((s) => s.startsWith('CI_WINDOWS_COMPILE: ')).slice(20)); assert.equal(failed.outcome, 'failed'); assert.notEqual(failed.toolchainKey, first.toolchainKey); assert.equal(readFileSync(join(root, 'target/windows-compile-passed'), 'utf8'), before);
    assert.equal(result(run({ FAKE_RUSTC: 'next' })).decision, 'build'); assert.equal(result(run({ FAKE_RUSTC: 'next' })).decision, 'served');
    const skipped = run({ FAKE_HOST: 'aarch64-apple-darwin' }); assert.equal(skipped.status, 0); assert.match(skipped.stdout, /skipped:/); assert.doesNotMatch(skipped.stdout, /CI_WINDOWS_COMPILE/);
    assert.equal(readFileSync(calls, 'utf8').trim().split('\n').length, 7);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
