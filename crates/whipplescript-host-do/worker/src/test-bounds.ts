/**
 * Wall-clock bounds for the workerd-backed integration suites.
 *
 * Both bounds exist to separate "settles" from "never settles", and nothing
 * else. These suites assert no duration: they prove behaviour against a real
 * Durable Object, and the wall time they take is whatever time miniflare's
 * workerd processes get on a machine the gate does not have to itself.
 *
 * Vitest's 5000ms default read as a performance budget they do not have to
 * keep. On 2026-09-10, `src/authenticated-host.integration.test.ts` failed
 * inside `scripts/check.sh` with three other sessions running cargo builds: 8
 * of its 14 tests failed, every one of them with "Test timed out in 5000ms"
 * rather than an assertion, and the suite took 70.41s. The same commit run
 * standalone passed 14 of 14, and a second `scripts/check.sh` on it went green
 * once the box quietened. Nothing about the code decided which.
 *
 * The stretch is easy to see and belongs to the machine, not to this code. On
 * a quiet box the authenticated suite spends 1.83s in tests and its longest
 * single test about 130ms. With one `cargo build --workspace --tests` running
 * alongside it, that same test took 3333ms — two thirds of the old bound, for
 * identical work.
 *
 * One measurement is worth carrying because it rules something out: CPU
 * oversubscription alone does not cross the line. Forty spinning shells on
 * twenty cores, on top of that build, at load 33, still left every test under
 * 1.1s. So the failing runs are not tests spinning, and the next reader should
 * not go looking for a busy loop; what they had that this did not is several
 * concurrent Rust builds' memory and IO, which was not reproduced here.
 *
 * These numbers are therefore far larger than the work needs. An
 * implementation that hangs is still caught; a tighter number only reports the
 * machine's load as a runtime defect. The two differ so that a condition which
 * never arrives fails on its own assertion, naming what it waited for, rather
 * than on the opaque per-test timeout.
 */

/** Per-test bound for both workerd-backed vitest configs. */
export const WORKERD_TEST_TIMEOUT_MS = 60_000;

/** Bound for a `vi.waitFor` condition inside those suites. */
export const SETTLES_WITHIN_MS = 30_000;
