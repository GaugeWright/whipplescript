import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.test.toml" },
    }),
  ],
  test: {
    include: ["src/session.integration.test.ts", "src/executor-broker.integration.test.ts"],
    // Restore `vi.stubGlobal` globals before every test. The suite stubs
    // `fetch` in nine tests and unstubbed it by hand in seven; the two that
    // were missed leaked a mock provider into every test that followed, which
    // is a silent dependency on declaration order rather than a visible
    // failure. Pairing each call by hand is the thing that was already
    // forgotten twice, so the restoration is made unconditional here instead.
    // The existing in-test `vi.unstubAllGlobals()` calls are now redundant and
    // harmless, and are left as the local statement of intent.
    unstubGlobals: true,
    // Inert on an ordinary run; writes only when `COLLECTION_VECTOR_OUT` is set,
    // which is what `npm run capture:collection-vector` does.
    reporters: ["default", "./scripts/collection-vector-reporter.mjs"],
  },
});
