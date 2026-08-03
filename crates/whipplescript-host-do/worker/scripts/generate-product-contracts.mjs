import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(import.meta.dirname, "..");
const contractsRoot = resolve(root, "contracts");

const publicOperations = [
  ["runtime.public.bootstrap", "POST", "/public/session/bootstrap", "http-json", "session", "critical"],
  ["runtime.public.claim", "POST", "/public/session/claim", "http-json", "mutation", "critical"],
  ["runtime.public.erase", "POST", "/public/session/erase", "http-json", "mutation", "critical"],
  ["runtime.public.state", "GET", "/public/session/state", "http-json", "none", "important"],
  ["runtime.public.files", "GET", "/public/session/files", "http-json", "none", "important"],
  ["runtime.public.socket", "GET", "/public/session/socket", "websocket", "stream", "critical"],
];

const hostOperations = [
  ["runtime.host.policy", "POST", "/host/policy", "http-json", "mutation", "critical"],
  ["runtime.host.instance.open", "POST", "/host/instances/open", "http-json", "session", "critical"],
  ["runtime.host.turn.begin", "POST", "/host/turns", "http-json", "mutation", "critical"],
  ["runtime.host.fork.import", "POST", "/host/forks/import", "http-json", "mutation", "critical"],
  ["runtime.host.turn.cancel", "POST", "/host/instances/:instance/turns/:turn/cancel", "http-json", "mutation", "critical"],
  ["runtime.host.files.sync", "POST", "/host/instances/:instance/files/sync", "http-json", "mutation", "critical"],
  ["runtime.host.checkpoint", "POST", "/host/instances/:instance/checkpoint", "http-json", "mutation", "important"],
  ["runtime.host.restore", "POST", "/host/instances/:instance/restore", "http-json", "mutation", "critical"],
  ["runtime.host.events.stream", "GET", "/host/instances/:instance/events/stream", "sse", "stream", "critical"],
  ["runtime.host.events.live", "GET", "/host/instances/:instance/events/live", "websocket", "stream", "critical"],
  ["runtime.host.turn.stream", "GET", "/host/instances/:instance/turns/:turn/stream", "sse", "stream", "critical"],
  ["runtime.host.fork.export", "GET", "/host/instances/:instance/fork-export", "http-json", "none", "important"],
  ["runtime.host.pending.compatibility", "GET", "/host/instances/:instance/pending", "http-json", "none", "internal"],
  ["runtime.host.turn.result", "GET", "/host/instances/:instance/turns/:turn/result", "http-json", "none", "important"],
  ["runtime.host.position", "GET", "/host/instances/:instance/position", "http-json", "none", "important"],
  ["runtime.host.turn.read", "GET", "/host/instances/:instance/turns/:turn", "http-json", "none", "important"],
  ["runtime.host.transcript", "GET", "/host/instances/:instance/turns/:turn/transcript", "http-json", "none", "important"],
  ["runtime.host.events", "GET", "/host/instances/:instance/events", "http-json", "none", "important"],
  ["runtime.host.evidence", "GET", "/host/instances/:instance/evidence", "http-json", "none", "important"],
  ["runtime.host.files", "GET", "/host/instances/:instance/files", "http-json", "none", "important"],
];

const gatewayOperations = [
  [
    "runtime.placement.forward.get",
    "GET",
    "/v1/tenants/:tenant/placements/:placement/host/:operation",
    "internal-callback",
    "stream",
    "critical",
  ],
  [
    "runtime.placement.forward.post",
    "POST",
    "/v1/tenants/:tenant/placements/:placement/host/:operation",
    "internal-callback",
    "mutation",
    "critical",
  ],
  [
    "runtime.private-home.forward.get",
    "GET",
    "/v1/homes/:home/tenants/:tenant/projects/:project/commands/:command/attempts/:epoch/host/:operation",
    "internal-callback",
    "stream",
    "critical",
  ],
  [
    "runtime.private-home.forward.post",
    "POST",
    "/v1/homes/:home/tenants/:tenant/projects/:project/commands/:command/attempts/:epoch/host/:operation",
    "internal-callback",
    "mutation",
    "critical",
  ],
  ["runtime.legacy.start", "POST", "/start", "http-json", "session", "internal"],
];

function samplePath(path) {
  return path
    .replace(":tenant", "tenant-canary")
    .replace(":placement", "placement-canary")
    .replace(":home", "home-canary")
    .replace(":project", "project-canary")
    .replace(":command", "command-canary")
    .replace(":epoch", "1")
    .replace(":instance", "instance-canary")
    .replace(":turn", "turn-canary")
    .replace(":operation", "policy");
}

function evidenceFor(id) {
  const publicSession = id.startsWith("runtime.public.");
  const declaredInnerRoute = id.startsWith("runtime.host.")
    || id === "runtime.legacy.start";
  const placementRoute = id.startsWith("runtime.placement.");
  const privateHomeRoute = id.startsWith("runtime.private-home.");
  const authenticatedHostJourney = id.startsWith("runtime.host.");
  const placementJourney =
    "src/authenticated-host.integration.test.ts#authenticated-placement-journey";
  const privateHomeJourney =
    "src/authenticated-host.integration.test.ts#signed-private-home-journey";
  const privateHomeDeployed =
    "contracts/deployed-evidence.json#private-home-forwarding-2026-08-03T23:13:55Z";
  return {
    contract: publicSession
      ? ["src/session.integration.test.ts#workerd-production-object"]
      : declaredInnerRoute
        ? ["src/authenticated-host.integration.test.ts#declared-route-surface"]
        : placementRoute
          ? [placementJourney]
          : privateHomeRoute
            ? [privateHomeJourney]
            : [],
    authority: publicSession
      ? ["src/session.integration.test.ts#session-control-boundary"]
      : declaredInnerRoute
        ? ["src/authenticated-host.integration.test.ts#declared-route-surface"]
        : placementRoute
          ? [placementJourney]
          : privateHomeRoute
            ? [privateHomeJourney]
            : [],
    journey: publicSession
      ? [
        "gaugewright-cloud@d7da925:edge-runtime/scripts/public-composition-test.mjs",
      ]
      : authenticatedHostJourney || placementRoute
        ? [placementJourney]
        : privateHomeRoute
          ? [privateHomeJourney]
          : [],
    deployed: privateHomeRoute ? [privateHomeDeployed] : [],
    property: publicSession || declaredInnerRoute
      ? ["src/authenticated-host.integration.test.ts#declared-route-surface"]
      : placementRoute
        ? ["src/authenticated-host.integration.test.ts#generated-placement-boundaries"]
        : privateHomeRoute
          ? [
            "src/private-home-protocol.test.ts#grant-field-mutations",
            privateHomeJourney,
          ]
          : [],
  };
}

function operation(row) {
  const [id, method, path, transport, sideEffect, risk] = row;
  const publicSession = id.startsWith("runtime.public.");
  const privateHome = id.startsWith("runtime.private-home.");
  const placement = id.startsWith("runtime.placement.");
  return {
    id,
    jurisdiction: publicSession
      ? "public-panel-session"
      : privateHome
        ? "private-home-command"
        : "managed-workflow-placement",
    transport,
    method,
    path,
    samplePath: samplePath(path),
    producer: privateHome
      ? "whipplescript-private-home-worker"
      : publicSession
        ? "whipplescript-session-durable-object"
        : "whipplescript-host-worker",
    consumer: publicSession
      ? "GaugeWright edge Deployment object"
      : privateHome
        ? "GaugeDesk Home durable workflow client"
        : placement
          ? "GaugeDesk managed workflow client"
          : "WhippleScript host protocol client",
    authentication: privateHome
      ? "signed-home-execution-grant-and-internal-control-token"
      : "runtime-control-bearer",
    scope: publicSession
      ? "deployment-session"
      : privateHome
        ? "home-tenant-project-command"
        : "tenant-placement",
    capability: publicSession ? "session-control" : "workflow-control",
    requestSchema: `typescript:whipplescript-runtime/${id}/request`,
    responseSchema: `typescript:whipplescript-runtime/${id}/response`,
    sideEffect,
    risk,
    compatibility: {
      contractVersion: 1,
      minimumConsumer: 1,
      maximumConsumer: null,
    },
    evidence: evidenceFor(id),
  };
}

export function manifests() {
  const operations = [
    ...publicOperations,
    ...hostOperations,
    ...gatewayOperations,
  ].map(operation);
  return {
    product: {
      schemaVersion: 1,
      owner: "whipplescript-src",
      contracts: operations.map(({ samplePath: _samplePath, ...contract }) => contract),
      exceptions: [],
    },
    surface: {
      schemaVersion: 1,
      owner: "whipplescript-src",
      operations: operations.map(({
        id,
        method,
        path,
        samplePath,
        transport,
        sideEffect,
        risk,
        producer,
        authentication,
      }) => ({
        id,
        method,
        path,
        samplePath,
        transport,
        sideEffect,
        risk,
        producer,
        authentication,
      })),
    },
  };
}

function serialized(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export async function generate({ check = false } = {}) {
  const { product, surface } = manifests();
  const outputs = new Map([
    [resolve(contractsRoot, "product-routes.json"), serialized(product)],
    [resolve(contractsRoot, "runtime-route-surface.json"), serialized(surface)],
  ]);
  if (check) {
    const stale = [];
    for (const [path, expected] of outputs) {
      const actual = await readFile(path, "utf8").catch(() => "");
      if (actual !== expected) stale.push(path);
    }
    if (stale.length) {
      throw new Error(
        `generated product contracts are stale: ${stale.join(", ")}`,
      );
    }
    return;
  }
  await mkdir(contractsRoot, { recursive: true });
  await Promise.all([...outputs].map(([path, contents]) =>
    writeFile(path, contents)
  ));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await generate({ check: process.argv.includes("--check") });
}
