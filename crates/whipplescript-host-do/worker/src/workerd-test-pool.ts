// Each file keeps its own isolated workerd runtime, but files run sequentially.
// Seven concurrent runtimes consumed 20.73 GiB RSS during the WS-578 gate OOM.
// Buck2's per-slot thread limit does not constrain Vitest's file workers.
export const WORKERD_TEST_POOL = Object.freeze({ fileParallelism: false });
