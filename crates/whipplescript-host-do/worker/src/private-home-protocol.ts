export interface DurableWorkflowGrant {
  version: 1 | 2;
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
  /** Exact original policy independently verified by the current Home. */
  original_policy?: OriginalPolicyRef;
  /** Only a Home terminal-command signer may set this for /host/private/retire. */
  retirement_authorized?: true;
  issued_at: number;
  expires_at: number;
}

export interface OriginalPolicyRef {
  epoch: number;
  envelope_hash: string;
  signer: string;
  key_id: string;
}

/** Independently configured authority for one exact project Home. */
export interface HomeAdmissionBinding {
  home_id: string;
  tenant_id: string;
  project_id: string;
  governance_signer: string;
  key_id: string;
  public_key: JsonWebKey;
}

export interface PrivateRetirementReceipt {
  version: 1;
  attempt_id: string;
  epoch: number;
  terminal_phase: "completed" | "failed" | "canceled";
  terminal_receipt_sha256: string;
}

export function parsePrivateRetirementReceipt(value: unknown): PrivateRetirementReceipt | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const receipt = value as Partial<PrivateRetirementReceipt>;
  if (
    receipt.version !== 1 ||
    typeof receipt.attempt_id !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(receipt.attempt_id) ||
    !Number.isSafeInteger(receipt.epoch) ||
    (receipt.epoch ?? 0) < 1 ||
    !["completed", "failed", "canceled"].includes(receipt.terminal_phase ?? "") ||
    typeof receipt.terminal_receipt_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(receipt.terminal_receipt_sha256)
  ) return undefined;
  return receipt as PrivateRetirementReceipt;
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

/**
 * Physical byte key for one private command's content id. The content id stays
 * the digest-derived logical handle; the private Home owns a separate copy so
 * collecting its bytes cannot delete an equal object held by another command.
 * The `s-` shape is the host's existing narrow opaque-key namespace.
 */
export async function privateObjectStorageKey(
  grant: Pick<DurableWorkflowGrant, "home_id" | "tenant_id" | "project_id" | "command_id">,
  contentId: string,
): Promise<string> {
  const basis = new TextEncoder().encode(
    JSON.stringify([durableWorkflowObjectName(grant), contentId]),
  );
  return `s-${(await sha256Hex(basis)).slice(0, 32)}`;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SEC1 = /^(?:04[0-9a-f]{128}|0[23][0-9a-f]{64})$/;
const FORBIDDEN_CAPABILITY =
  /^(?:bash|build|command|container|docker|exec|filesystem|network|posix|process|shell|test|workspace)(?:[.:/]|$)/;

export function validOriginalPolicyRef(value: unknown): value is OriginalPolicyRef {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const policy = value as Partial<OriginalPolicyRef>;
  return Number.isSafeInteger(policy.epoch) && (policy.epoch ?? 0) > 0
    && typeof policy.envelope_hash === "string" && SHA256.test(policy.envelope_hash)
    && typeof policy.signer === "string" && ID.test(policy.signer)
    && typeof policy.key_id === "string" && SEC1.test(policy.key_id)
    && Object.keys(policy).every((field) => ["epoch", "envelope_hash", "signer", "key_id"].includes(field));
}

function configuredHomeBindings(configuration: string | undefined): HomeAdmissionBinding[] {
  const bindings: unknown = JSON.parse(configuration ?? "null");
  if (!Array.isArray(bindings) || bindings.length === 0) {
    throw new Error("project Home admission bindings are unavailable");
  }
  const homes = new Set<string>();
  const projects = new Set<string>();
  const publicKeys = new Set<string>();
  for (const value of bindings) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("project Home admission binding is invalid");
    }
    const binding = value as HomeAdmissionBinding;
    if ([binding.home_id, binding.tenant_id, binding.project_id, binding.governance_signer, binding.key_id]
      .some((id) => typeof id !== "string" || !ID.test(id))) {
      throw new Error("project Home admission identity is invalid");
    }
    const key = binding.public_key;
    const point = key && p256JwkToGovernanceHex(key);
    if (!point || key.d !== undefined || homes.has(binding.home_id)
      || projects.has(binding.project_id) || publicKeys.has(point)) {
      throw new Error("project Home admission binding is ambiguous or invalid");
    }
    homes.add(binding.home_id);
    projects.add(binding.project_id);
    publicKeys.add(point);
  }
  return bindings as HomeAdmissionBinding[];
}

/** Missing or ambiguous configuration is a refusal; no unscoped-key fallback. */
export function homeAdmissionKey(
  configuration: string | undefined,
  grant: DurableWorkflowGrant,
): JsonWebKey | undefined {
  return configuredHomeBindings(configuration).find((binding) =>
    binding.home_id === grant.home_id && binding.tenant_id === grant.tenant_id
    && binding.project_id === grant.project_id && binding.governance_signer === grant.governance_signer
    && binding.key_id === grant.key_id)?.public_key;
}

/** A legacy installation signer cannot initialize or act at a registered Home. */
export function projectHomeAddress(
  configuration: string | undefined,
  grant: Pick<DurableWorkflowGrant, "home_id" | "project_id">,
): boolean {
  return configuration !== undefined && configuredHomeBindings(configuration)
    .some((binding) => binding.home_id === grant.home_id || binding.project_id === grant.project_id);
}

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

/** Verify against the SEC1 point pinned inside one private command object. */
export async function verifyPinnedP256GrantSignature(
  grant: DurableWorkflowGrant,
  signatureBase64: string,
  sec1Hex: string,
): Promise<boolean> {
  if (!/^04[0-9a-f]{128}$/.test(sec1Hex)) return false;
  try {
    const point = Uint8Array.from(sec1Hex.match(/../g)!, (part) => Number.parseInt(part, 16));
    const key = await crypto.subtle.importKey(
      "raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key, decodeBase64(signatureBase64),
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
  if (![1, 2].includes(grant.version) || grant.profile !== "durable_workflow") {
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
  if (identities.some((identity) => typeof identity !== "string" || !ID.test(identity))) {
    return "invalid execution identity";
  }
  if ((grant.original_policy !== undefined && !validOriginalPolicyRef(grant.original_policy))
    || (grant.version === 1 && grant.original_policy !== undefined)
    || (grant.version === 2 && grant.request_path !== "/host/private/retire"
      && !validOriginalPolicyRef(grant.original_policy))) {
    return "execution grant has no valid original policy reference";
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
    typeof grant.request_path !== "string" ||
    !grant.request_path.startsWith("/host/") ||
    grant.request_path.includes("#") ||
    grant.request_path.includes("://") ||
    !SHA256.test(grant.request_body_sha256)
  ) {
    return "invalid bound request";
  }
  if (grant.request_path === "/host/private/retire") {
    if (grant.request_method !== "POST" || grant.retirement_authorized !== true) {
      return "private retirement needs terminal Home authorization";
    }
  } else if (grant.retirement_authorized !== undefined) {
    return "private retirement authorization is bound to its own route";
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
