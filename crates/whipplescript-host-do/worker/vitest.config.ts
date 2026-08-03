import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.test.toml" },
    }),
  ],
  test: {
    include: ["src/session.integration.test.ts"],
    // Inert on an ordinary run; writes only when `COLLECTION_VECTOR_OUT` is set,
    // which is what `npm run capture:collection-vector` does.
    reporters: ["default", "./scripts/collection-vector-reporter.mjs"],
  },
});
