/**
 * The provider contract, read from the one artifact the kernel also embeds:
 * `crates/whipplescript-kernel/src/provider_contract.json` (WhippleScript
 * DR-0205). The worker keeps no table of its own. A fact the artifact holds — a
 * request path, a credential header, an output-limit spelling, which dialects an
 * identity admits, which identities this door hosts — is looked up here, and
 * `scripts/check-provider-contract.mjs` fails a consumer that spells one itself.
 */
import contractJson from "../../../whipplescript-kernel/src/provider_contract.json" with { type: "json" };

export type WireName = keyof typeof contractJson.wires;
export type ProviderName = keyof typeof contractJson.providers;

export interface WireContract {
  path: string;
  base_url_version: "appended" | "in-base";
  auth_header: "x-api-key" | "authorization-bearer";
  fixed_headers: Record<string, string>;
  output_limit: { field: string; required: boolean };
  streamed_usage: string;
  tool_vocabulary: "native" | "coerced";
}

export interface ProviderEntry {
  wires: string[];
  surface: "fixed" | Record<string, string>;
  default_base_url: string | null;
  path: string | null;
  extra_headers: Record<string, string>;
  output_limit: Record<string, string>;
  doors: string[];
}

const contract = contractJson as unknown as {
  version: number;
  wires: Record<WireName, WireContract>;
  providers: Record<ProviderName, ProviderEntry>;
};

export const PROVIDER_CONTRACT_VERSION = contract.version;

function isWire(name: string): name is WireName {
  return Object.hasOwn(contract.wires, name);
}

export function wireContract(wire: WireName): WireContract {
  return contract.wires[wire];
}

export function providerEntry(provider: string): ProviderEntry | undefined {
  return Object.hasOwn(contract.providers, provider)
    ? contract.providers[provider as ProviderName]
    : undefined;
}

/** The identities this door admits: those whose `doors` name the Durable
 *  Object. */
export const DURABLE_OBJECT_PROVIDERS: ReadonlySet<string> = new Set(
  (Object.keys(contract.providers) as ProviderName[]).filter((name) =>
    contract.providers[name].doors.includes("durable-object")
  ),
);

/** Every header that carries a credential on some wire or identity, so
 *  sentinel authentication can be stripped whatever the dialect. */
export const CREDENTIAL_HEADERS: ReadonlySet<string> = new Set([
  ...Object.values(contract.wires).map((wire) =>
    wire.auth_header === "x-api-key" ? "x-api-key" : "authorization"
  ),
  ...Object.values(contract.providers).flatMap((entry) =>
    Object.entries(entry.extra_headers)
      .filter(([, value]) => value === "<account>")
      .map(([name]) => name.toLowerCase())
  ),
]);

/**
 * The dialect one round speaks to an admitted endpoint.
 *
 * A wire the admission declared wins when the identity admits it, as it does
 * in the kernel (`ModelWire::declared_or_provider_default`), so the path the
 * kernel built is the path checked here. Otherwise an identity fronting
 * several surfaces is read off the admitted base URL's suffix, and any other
 * identity speaks its default — the first wire it admits.
 */
export function resolveWire(
  provider: string,
  admittedPath: string,
  declared?: string,
): WireName {
  const entry = providerEntry(provider);
  if (!entry) throw new Error(`provider ${provider} has no provider contract entry`);
  const name = declared?.trim();
  if (name && isWire(name) && entry.wires.includes(name)) return name;
  if (typeof entry.surface === "object") {
    for (const [suffix, wire] of Object.entries(entry.surface)) {
      if (admittedPath.endsWith(suffix) && isWire(wire)) return wire;
    }
  }
  const fallback = entry.wires[0];
  if (!fallback || !isWire(fallback)) {
    throw new Error(`provider ${provider} admits no known wire`);
  }
  return fallback;
}

/** The request path this identity appends to its base URL on `wire`. */
export function requestPath(provider: string, wire: WireName): string {
  return providerEntry(provider)?.path ?? contract.wires[wire].path;
}

/** The credential header `[name, value]` this wire carries. */
export function credentialHeader(wire: WireName, credential: string): [string, string] {
  return contract.wires[wire].auth_header === "x-api-key"
    ? ["x-api-key", credential]
    : ["authorization", `Bearer ${credential}`];
}

/** The output-limit spelling this identity takes on `wire`. */
export function outputLimitField(provider: string, wire: WireName): string {
  return providerEntry(provider)?.output_limit[wire] ?? contract.wires[wire].output_limit.field;
}

/** Every output-limit spelling the contract names. */
export const OUTPUT_LIMIT_FIELDS: readonly string[] = [
  ...new Set([
    ...Object.values(contract.wires).map((wire) => wire.output_limit.field),
    ...Object.values(contract.providers).flatMap((entry) => Object.values(entry.output_limit)),
  ]),
];
