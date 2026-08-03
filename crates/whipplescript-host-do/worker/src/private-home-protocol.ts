export interface DurableWorkflowGrant {
  version: 1;
  key_id: string;
  governance_signer: string;
  home_id: string;
  tenant_id: string;
  project_id: string;
  work_target_basis: string;
  command_id: string;
  attempt_id: string;
  payload_digest: string;
  epoch: number;
  profile: "durable_workflow";
  package_ref: string;
  capabilities: string[];
  credential_class: string;
  max_spend_nanos_usd: number;
  retention_seconds: number;
  callback_ref: string;
  request_method: string;
  request_path: string;
  request_body_sha256: string;
  issued_at: number;
  expires_at: number;
}

export function durableWorkflowObjectName(
  grant: Pick<
    DurableWorkflowGrant,
    "home_id" | "tenant_id" | "project_id" | "command_id"
  >,
): string {
  return JSON.stringify([
    "private-home-v2",
    grant.home_id,
    grant.tenant_id,
    grant.project_id,
    grant.command_id,
  ]);
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const FORBIDDEN_CAPABILITY =
  /^(?:bash|build|command|container|docker|exec|filesystem|network|posix|process|shell|test|workspace)(?:[.:/]|$)/;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`);
  return `{${entries.join(",")}}`;
}

export async function sha256Hex(value: ArrayBuffer | Uint8Array): Promise<string> {
  const bytes =
    value instanceof Uint8Array
      ? value
      : new Uint8Array(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((part) => part.toString(16).padStart(2, "0"))
    .join("");
}

function decodeBase64(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

export function p256JwkToGovernanceHex(key: JsonWebKey): string | undefined {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) return undefined;
  try {
    const x = new Uint8Array(decodeBase64(key.x));
    const y = new Uint8Array(decodeBase64(key.y));
    if (x.byteLength !== 32 || y.byteLength !== 32) return undefined;
    return `04${[...x, ...y]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")}`;
  } catch {
    return undefined;
  }
}

export function decodeGrant(value: string): DurableWorkflowGrant | undefined {
  try {
    const decoded = new TextDecoder().decode(decodeBase64(value));
    const grant = JSON.parse(decoded) as DurableWorkflowGrant;
    return grant && typeof grant === "object" ? grant : undefined;
  } catch {
    return undefined;
  }
}

export async function verifyP256GrantSignature(
  grant: DurableWorkflowGrant,
  signatureBase64: string,
  publicKey: JsonWebKey,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      publicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      decodeBase64(signatureBase64),
      new TextEncoder().encode(canonicalJson(grant)),
    );
  } catch {
    return false;
  }
}

export function validateDurableWorkflowGrant(
  grant: DurableWorkflowGrant,
  nowSeconds: number,
): string | undefined {
  if (grant.version !== 1 || grant.profile !== "durable_workflow") {
    return "unsupported execution profile or grant version";
  }
  const identities = [
    grant.key_id,
    grant.governance_signer,
    grant.home_id,
    grant.tenant_id,
    grant.project_id,
    grant.work_target_basis,
    grant.command_id,
    grant.attempt_id,
    grant.payload_digest,
    grant.package_ref,
    grant.credential_class,
    grant.callback_ref,
  ];
  if (identities.some((identity) => !ID.test(identity))) {
    return "invalid execution identity";
  }
  try {
    const callback = new URL(grant.callback_ref);
    if (
      callback.protocol !== "https:"
      || callback.username
      || callback.password
      || callback.search
      || callback.hash
    ) {
      return "invalid execution callback";
    }
  } catch {
    return "invalid execution callback";
  }
  if (
    !Number.isSafeInteger(grant.epoch) ||
    grant.epoch < 1 ||
    !Number.isSafeInteger(grant.max_spend_nanos_usd) ||
    grant.max_spend_nanos_usd < 0 ||
    !Number.isSafeInteger(grant.retention_seconds) ||
    grant.retention_seconds < 1
  ) {
    return "invalid execution bound";
  }
  if (
    !Array.isArray(grant.capabilities) ||
    grant.capabilities.some(
      (capability) => !ID.test(capability) || FORBIDDEN_CAPABILITY.test(capability),
    )
  ) {
    return "Durable workflow grant contains a workspace capability";
  }
  if (
    !["GET", "POST"].includes(grant.request_method) ||
    !grant.request_path.startsWith("/host/") ||
    grant.request_path.includes("#") ||
    grant.request_path.includes("://") ||
    !SHA256.test(grant.request_body_sha256)
  ) {
    return "invalid bound request";
  }
  if (
    !Number.isSafeInteger(grant.issued_at) ||
    !Number.isSafeInteger(grant.expires_at) ||
    grant.issued_at > nowSeconds + 30 ||
    grant.expires_at <= nowSeconds ||
    grant.expires_at <= grant.issued_at ||
    grant.expires_at - grant.issued_at > 900
  ) {
    return "execution grant is expired or not short-lived";
  }
  return undefined;
}
