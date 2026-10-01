// Diagnostic only: launching the pinned binary is not native compile or cache proof.
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const binary = 'C:\\tools\\buck2.exe';
export function readiness({ platform = process.platform, launch = spawnSync } = {}) {
  const receipt = { version: 1, scope: 'pinned-binary-launch', status: 'unknown', reason: 'unsupported-context', errorCode: null, errorNumber: null, nativeCompileProven: false };
  if (platform !== 'win32') return receipt;
  try {
    const result = launch(binary, ['--version'], {
      encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 65536,
      windowsHide: true, shell: false,
    });
    if (result.error) {
      // Native Windows launch errors can surface as UNKNOWN. Preserve stable
      // bounded metadata without the message, path, arguments or environment.
      const codes = ['ETIMEDOUT', 'ENOENT', 'EACCES', 'EPERM', 'UNKNOWN', 'ENOEXEC', 'EINVAL', 'EIO', 'E2BIG', 'ENOMEM', 'ENOBUFS', 'ENOTDIR'];
      receipt.errorCode = codes.includes(result.error.code) ? result.error.code : 'OTHER';
      receipt.errorNumber = Number.isSafeInteger(result.error.errno) && Math.abs(result.error.errno) <= 100000 ? result.error.errno : null;
      if (result.error.code === 'ETIMEDOUT') return { ...receipt, status: 'blocked', reason: 'deadline' };
      if (result.error.code === 'ENOENT') return { ...receipt, status: 'blocked', reason: 'binary-unavailable' };
      if (['EACCES', 'EPERM'].includes(result.error.code)) return { ...receipt, status: 'blocked', reason: 'launch-denied' };
      return { ...receipt, reason: 'launch-error' };
    }
    if (result.status !== 0) return { ...receipt, status: 'blocked', reason: 'nonzero-exit' };
    if (!/^buck2\s+[^\r\n]+\s*$/i.test(result.stdout ?? '')) return { ...receipt, reason: 'unexpected-response' };
    return { ...receipt, status: 'ready', reason: 'version-returned' };
  } catch {
    return { ...receipt, reason: 'launch-error' };
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log(`CI_WINDOWS_BUCK2_READINESS: ${JSON.stringify(readiness())}`);
}
