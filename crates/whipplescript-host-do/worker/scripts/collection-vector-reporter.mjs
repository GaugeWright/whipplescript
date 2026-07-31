// Carry the emitted collection artifact out of workerd and onto disk.
//
// The integration test runs inside workerd, which has no filesystem, so it
// cannot write the cross-language vector itself. It attaches the artifact to the
// test's `meta` instead; Vitest serialises that back to the Node side, where
// this reporter writes it out.
//
// Deliberately inert unless `COLLECTION_VECTOR_OUT` names a path: the ordinary
// `npm test` run must not rewrite a committed vector, or every test run would
// produce a diff and the vector would stop being a fixed point anyone reviewed.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export default class CollectionVectorReporter {
  #out = process.env.COLLECTION_VECTOR_OUT;
  #written = false;
  #pending = Promise.resolve();

  onTestCaseResult(testCase) {
    if (!this.#out) return;
    const vector = testCase.meta()?.collectionVector;
    if (!vector) return;
    this.#pending = this.#write(vector);
  }

  async #write(vector) {
    await mkdir(dirname(this.#out), { recursive: true });
    await writeFile(this.#out, `${JSON.stringify(vector, null, 2)}\n`);
    this.#written = true;
    console.log(`captured DO-produced collection vector -> ${this.#out}`);
  }

  async onTestRunEnd() {
    if (!this.#out) return;
    await this.#pending;
    if (!this.#written) {
      // Silence here would look like success and commit a stale vector.
      console.error(
        "COLLECTION_VECTOR_OUT was set but no test attached a collection vector",
      );
      process.exitCode = 1;
    }
  }
}
