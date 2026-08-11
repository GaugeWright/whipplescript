// `npm run deploy` used to mean `wrangler deploy`, which meant whatever
// `wrangler.toml` happened to name. One `src/index.ts` is published under five
// worker names, and the one the documented command hit was not the one serving
// public embed sessions. A live-turn fix was chased for hours past a deploy
// that had landed on the wrong worker.
//
// So `deploy` no longer deploys. It prints the map and exits non-zero. Every
// real deploy names its target.

const TARGETS = [
  {
    script: "deploy:harness",
    config: "wrangler.harness.toml",
    worker: "whipplescript-runtime",
    serves: "the GaugeDesk hosted harness (GAUGEDESK_DO_HOST_*)",
  },
  {
    script: "deploy:public",
    config: "wrangler.public.toml",
    worker: "whipplescript-public-runtime",
    serves: "PUBLIC EMBED SESSIONS — the panels on gaugewright.com",
  },
  {
    script: "deploy:private-production",
    config: "wrangler.private-production.toml",
    worker: "whipplescript-private-home-runtime",
    serves: "the managed private Home",
  },
  {
    script: "deploy:private-staging",
    config: "wrangler.private-staging.toml",
    worker: "whipplescript-private-home-runtime-staging",
    serves: "private Home staging",
  },
  {
    script: "deploy:edge-staging",
    config: "wrangler.edge-staging.toml",
    worker: "whipplescript-runtime-edge-staging",
    serves: "edge staging",
  },
];

const width = (pick) => Math.max(...TARGETS.map((target) => pick(target).length));
const scriptWidth = width((target) => target.script);
const workerWidth = width((target) => target.worker);

const lines = [
  "",
  "`npm run deploy` does not deploy: this directory has no default target.",
  "",
  "One src/index.ts is published under several worker names. Pick the one you",
  "mean — the edge chooses the public worker by script name, not by anything in",
  "this repository.",
  "",
  ...TARGETS.map(
    (target) =>
      `  npm run ${target.script.padEnd(scriptWidth)}  ->  ` +
      `${target.worker.padEnd(workerWidth)}  ${target.serves}`,
  ),
  "",
  "Take the current version id before deploying — that is the rollback target:",
  "  npx wrangler versions list -c <config>",
  "",
];

process.stderr.write(`${lines.join("\n")}\n`);
process.exit(1);
