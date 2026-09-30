import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
// Pinned schema: rust-lang/cargo rust-1.95.0 timings/mod.rs UnitData and
// timings/report.rs write_js_data. Internal HTML changes fail diagnostically.
const hash = (value) => createHash('sha256').update(value).digest('hex');
export function parseTimingReport(html) {
  if (Buffer.byteLength(html) > 4 * 1024 * 1024) throw new Error('size');
  const matches = [...html.matchAll(/const UNIT_DATA = (\[[\s\S]*?\]);/g)];
  if (matches.length !== 1) throw new Error('format');
  const units = JSON.parse(matches[0][1]);
  if (!Array.isArray(units) || units.length > 512) throw new Error('units');
  const seen = new Set();
  const result = units.map((u) => {
    if (!u || !Number.isSafeInteger(u.i) || u.i < 0 || seen.has(u.i) ||
        typeof u.name !== 'string' || typeof u.version !== 'string' || typeof u.target !== 'string' || typeof u.mode !== 'string' ||
        !Number.isFinite(u.start) || u.start < 0 || !Number.isFinite(u.duration) || u.duration < 0) throw new Error('unit');
    seen.add(u.i);
    // Identity is hashed: Cargo target names and feature strings can carry paths.
    const identity = hash(JSON.stringify([u.name, u.version, u.target, u.mode, u.features]));
    const sections = u.sections === null ? null : (() => {
      if (!Array.isArray(u.sections) || u.sections.length > 32) throw new Error('sections');
      return u.sections.map(([name, s]) => {
        if (!s || !Number.isFinite(s.start) || !Number.isFinite(s.end) || s.start < 0 || s.end < s.start || s.end > u.duration + 0.001) throw new Error('section');
        return { category: ['frontend', 'codegen', 'other'].includes(name) ? name : 'unknown', seconds: s.end - s.start };
      });
    })();
    return { index: u.i, identity, startSeconds: u.start, elapsedSeconds: u.duration, sections };
  });
  if (Buffer.byteLength(JSON.stringify(result)) > 128 * 1024) throw new Error('output-size');
  return result;
}
function report() {
  const file = resolve(process.env.CARGO_TARGET_DIR || 'target', 'cargo-timings/cargo-timing.html');
  const stat = statSync(file);
  if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw new Error('size');
  const bytes = readFileSync(file);
  return { fingerprint: hash(JSON.stringify([stat.mtimeMs, stat.size, hash(bytes)])), digest: hash(bytes), html: bytes.toString('utf8') };
}
export function timingObservation(before) {
  if (before !== 'missing' && !/^[a-f0-9]{64}$/.test(before || '')) return { status: 'unavailable', reportSha256: null, units: null };
  try {
    const current = report();
    if (current.fingerprint === before) return { status: 'stale', reportSha256: null, units: null };
    return { status: 'recorded', reportSha256: current.digest, units: parseTimingReport(current.html) };
  } catch (error) {
    return { status: error.code === 'ENOENT' ? 'missing' : 'invalid', reportSha256: null, units: null };
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === 'before') {
    try { console.log(report().fingerprint); } catch (error) { console.log(error.code === 'ENOENT' ? 'missing' : 'unavailable'); }
  } else {
    const revision = spawnSync('git', ['rev-parse', '--verify', 'HEAD'], { encoding: 'utf8', timeout: 1000 }).stdout?.trim();
    const commit = /^[a-f0-9]{40}$/.test(revision || '') ? revision : null;
    const outcome = process.argv[4] === '0' ? 'passed' : 'failed';
    console.log('CI_WINDOWS_CARGO_TIMING: ' + JSON.stringify({ version: 1, source: 'cargo-html-1.95', commit, outcome, ...timingObservation(process.argv[3]) }));
  }
}
