import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { generate } from "./generate-product-contracts.mjs";

const root = resolve(import.meta.dirname, "..");
const contracts = JSON.parse(
  await readFile(resolve(root, "contracts/product-routes.json"), "utf8"),
);
const surface = JSON.parse(
  await readFile(resolve(root, "contracts/runtime-route-surface.json"), "utf8"),
);
const indexSource = await readFile(resolve(root, "src/index.ts"), "utf8");
const privateSource = await readFile(resolve(root, "src/private-home.ts"), "utf8");
const failures = [];
const evidenceSources = new Map();

await generate({ check: true }).catch((error) => failures.push(error.message));

const requiredFields = [
  "id",
  "jurisdiction",
  "transport",
  "method",
  "path",
  "producer",
  "consumer",
  "authentication",
  "scope",
  "capability",
  "requestSchema",
  "responseSchema",
  "sideEffect",
  "risk",
  "compatibility",
  "evidence",
];
const evidenceClasses = [
  "contract",
  "authority",
  "journey",
  "deployed",
  "property",
];
const validMethods = new Set(["GET", "POST"]);
const validRisks = new Set(["critical", "important", "internal"]);
const validTransports = new Set([
  "http-json",
  "sse",
  "websocket",
  "internal-callback",
]);

if (contracts.schemaVersion !== 1 || contracts.owner !== "whipplescript-src") {
  failures.push("product manifest must be version 1 and owned by whipplescript-src");
}
if (surface.schemaVersion !== 1 || surface.owner !== "whipplescript-src") {
  failures.push("runtime surface must be version 1 and owned by whipplescript-src");
}
if (!Array.isArray(contracts.contracts) || !Array.isArray(contracts.exceptions)) {
  failures.push("product manifest contracts and exceptions must be arrays");
}
if (!Array.isArray(surface.operations)) {
  failures.push("runtime surface operations must be an array");
}

const ids = new Set();
const operations = new Set();
for (const [index, contract] of (contracts.contracts ?? []).entries()) {
  const label = `contract ${index + 1}`;
  for (const field of requiredFields) {
    if (contract[field] === undefined || contract[field] === "") {
      failures.push(`${label} lacks ${field}`);
    }
  }
  if (ids.has(contract.id)) failures.push(`duplicate contract id ${contract.id}`);
  ids.add(contract.id);
  const key = `${contract.method} ${contract.path}`;
  if (operations.has(key)) failures.push(`duplicate contract operation ${key}`);
  operations.add(key);
  if (!validMethods.has(contract.method)) failures.push(`${contract.id} has invalid method`);
  if (!validRisks.has(contract.risk)) failures.push(`${contract.id} has invalid risk`);
  if (!validTransports.has(contract.transport)) failures.push(`${contract.id} has invalid transport`);
  if (!contract.path.startsWith("/")) failures.push(`${contract.id} has invalid path`);
  if (!Number.isInteger(contract.compatibility?.contractVersion)) {
    failures.push(`${contract.id} lacks an integer contract version`);
  }
  for (const evidence of evidenceClasses) {
    if (!Array.isArray(contract.evidence?.[evidence])) {
      failures.push(`${contract.id} evidence.${evidence} must be an array`);
    }
  }
}

const declaredByOperation = new Map(
  (contracts.contracts ?? []).map((contract) => [
    `${contract.method} ${contract.path}`,
    contract,
  ]),
);
for (const operation of surface.operations ?? []) {
  const key = `${operation.method} ${operation.path}`;
  const contract = declaredByOperation.get(key);
  if (!contract) {
    failures.push(`runtime operation ${key} lacks a product contract`);
    continue;
  }
  for (const field of [
    "id",
    "transport",
    "sideEffect",
    "risk",
    "producer",
    "authentication",
  ]) {
    if (operation[field] !== contract[field]) {
      failures.push(`${contract.id} disagrees with runtime surface field ${field}`);
    }
  }
}
for (const key of declaredByOperation.keys()) {
  if (!(surface.operations ?? []).some((operation) =>
    `${operation.method} ${operation.path}` === key
  )) {
    failures.push(`product contract ${key} is absent from the runtime surface`);
  }
}

function routeMatchers(source) {
  const matchers = [];
  for (const match of source.matchAll(/url\.pathname === "([^"]+)"/g)) {
    if (match[1] !== "/healthz") {
      matchers.push({ label: match[0], test: (path) => path === match[1] });
    }
  }
  for (
    const match of source.matchAll(
      /url\.pathname\.match\(\s*(\/\^.+?\$\/)\s*,?\s*\)/gs,
    )
  ) {
    const lastSlash = match[1].lastIndexOf("/");
    const regex = new RegExp(
      match[1].slice(1, lastSlash),
      match[1].slice(lastSlash + 1),
    );
    matchers.push({ label: match[0], test: (path) => regex.test(path) });
  }
  return matchers;
}

const matchers = [
  ...routeMatchers(indexSource),
  ...routeMatchers(privateSource),
];
const samplePaths = (surface.operations ?? []).map((operation) => ({
  id: operation.id,
  path: operation.samplePath,
}));
for (const operation of samplePaths) {
  if (!matchers.some((matcher) => matcher.test(operation.path))) {
    failures.push(`${operation.id} sample path is not recognized by production routing`);
  }
}
for (const matcher of matchers) {
  if (!samplePaths.some((operation) => matcher.test(operation.path))) {
    failures.push(`production route recognizer is absent from the runtime surface: ${matcher.label}`);
  }
}

const evidenceGaps = [];
for (const contract of contracts.contracts ?? []) {
  const riskRequired = contract.risk === "critical"
    ? ["contract", "authority", "journey", "deployed"]
    : contract.risk === "important"
      ? ["contract", "authority", "journey"]
      : ["contract", "authority"];
  const required = [...riskRequired, "property"];
  for (const evidence of required) {
    if (contract.evidence[evidence].length === 0) {
      evidenceGaps.push(`${contract.id}:${evidence}`);
    }
  }
}

for (const contract of contracts.contracts ?? []) {
  for (const evidenceClass of evidenceClasses) {
    for (const reference of contract.evidence[evidenceClass]) {
      if (reference.startsWith("gaugewright-cloud@")) continue;
      const [locator, marker] = reference.split("#");
      if (!locator || !marker) {
        failures.push(`${contract.id} has malformed ${evidenceClass} evidence ${reference}`);
        continue;
      }
      let source = evidenceSources.get(locator);
      if (source === undefined) {
        source = await readFile(resolve(root, locator), "utf8").catch(() => null);
        evidenceSources.set(locator, source);
      }
      if (source === null) {
        failures.push(`${contract.id} ${evidenceClass} evidence file is absent: ${locator}`);
      } else if (!source.includes(marker)) {
        failures.push(`${contract.id} ${evidenceClass} evidence marker is absent: ${reference}`);
      }
    }
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

const digest = createHash("sha256")
  .update(JSON.stringify(canonical(contracts)))
  .digest("hex");

if (failures.length) {
  console.error("WhippleScript product contract validation failed:\n");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log(
  `WhippleScript product manifest sha256:${digest}: `
  + `${contracts.contracts.length} operations, `
  + `${contracts.exceptions.length} time-bounded exceptions, `
  + `${evidenceGaps.length} evidence gaps.`,
);
if (evidenceGaps.length) console.log(`Evidence gaps: ${evidenceGaps.join(", ")}`);
if (process.argv.includes("--enforce-evidence") && evidenceGaps.length) {
  process.exit(1);
}
