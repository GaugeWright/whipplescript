import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { WORKERD_TEST_TIMEOUT_MS } from "./src/test-bounds.ts";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.authenticated.test.toml" },
    }),
  ],
  test: {
    include: [
      "src/authenticated-host.integration.test.ts",
      "src/private-home-objects.integration.test.ts",
    ],
    // Bounds a hang, not the machine's load. See `src/test-bounds.ts`.
    testTimeout: WORKERD_TEST_TIMEOUT_MS,
  },
});
