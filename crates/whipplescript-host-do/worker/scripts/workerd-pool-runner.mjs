import { spawn } from "node:child_process";

// Own a separate process group so aborting a fixture also stops its runtimes.
export function runPool({ command, args, cwd, signal, sample, onOutput, onStart, killAfterMs = 500 }) {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error("fixture aborted"));
  return new Promise((resolve, reject) => {
    const group = process.platform !== "win32";
    const child = spawn(command, args, { cwd, detached: group, stdio: ["ignore", "pipe", "pipe"] });
    let sampling;
    let escalation;
    let failure;
    const terminate = (name) => {
      if (!child.pid) return;
      try {
        if (group) process.kill(-child.pid, name);
        else child.kill(name);
      } catch (error) {
        if (error.code !== "ESRCH") failure ??= error;
      }
    };
    const stop = (error) => {
      if (failure) return;
      failure = error instanceof Error ? error : new Error("fixture failed", { cause: error });
      clearInterval(sampling);
      terminate("SIGTERM");
      escalation = setTimeout(() => terminate("SIGKILL"), killAfterMs);
    };
    const abort = () => stop(signal.reason ?? new Error("fixture aborted"));
    const cleanup = () => {
      clearInterval(sampling);
      clearTimeout(escalation);
      signal?.removeEventListener("abort", abort);
    };
    child.on("error", stop);
    child.on("close", (code, exitSignal) => {
      // Even a successful parent can leave descendants with closed pipes.
      terminate("SIGKILL");
      cleanup();
      if (failure) reject(failure);
      else resolve({ code, signal: exitSignal });
    });
    for (const stream of [child.stdout, child.stderr]) stream.on("data", chunk => {
      try { onOutput?.(chunk); } catch (error) { stop(error); }
    });
    signal?.addEventListener("abort", abort, { once: true });
    try {
      onStart?.(child.pid);
      if (!failure && sample) sampling = setInterval(() => {
        try { sample(child.pid); } catch (error) { stop(error); }
      }, 100);
      if (signal?.aborted) abort();
    } catch (error) { stop(error); }
  });
}
