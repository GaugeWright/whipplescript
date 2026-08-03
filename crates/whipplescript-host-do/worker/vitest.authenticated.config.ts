import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.authenticated.test.toml" },
    }),
  ],
  test: {
    include: ["src/authenticated-host.integration.test.ts"],
  },
});
