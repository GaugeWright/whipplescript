export const MODEL_EGRESS_PROTOCOL = "whipplescript.model-egress.v1";
export const MODEL_EGRESS_STREAM_PROTOCOL = "whipplescript.model-egress.stream.v1";
export const MODEL_AUTH_SENTINEL = "whipplescript-model-broker";

const MAX_BROKER_RESPONSE_BYTES = 16 * 1024 * 1024;
const STRIPPED_AUTH_HEADERS = new Set([
  "authorization",
  "chatgpt-account-id",
  "x-api-key",
]);
const FORBIDDEN_AMBIENT_AUTH_HEADERS = new Set([
  "cookie",
  "proxy-authorization",
]);

export interface ModelBrokerBinding {
  credential_id: string;
  credential_class?: string;
  provider:
    | "openai"
    | "openai-generic"
    | "anthropic"
    | "openai-codex"
    | "cloudflare-ai-gateway";
  model: string;
  base_url: string;
}

export interface ModelBrokerConfig {
  url?: string;
  token?: string;
  executionGrant?: string;
  executionSignature?: string;
}

export interface SuspendedModelRequest {
  url: string;
  headers: [string, string][];
  body: unknown;
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;
export type ModelBrokerTimingSink = (event: string, elapsedMs: number) => void;
export interface ProviderUsage {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  /** The gateway's own log id for this round, when one was returned
   *  (`cf-aig-log-id`).
   *
   *  ADR 0085 §3 calls for the broker to return "an opaque reconciliation
   *  pointer", and §Consequences requires that "managed gateway telemetry
   *  reconciles the authoritative WhippleScript meter instead of becoming a
   *  parallel billing truth". This is that pointer: it identifies the gateway
   *  log entry carrying the **actual** cost of the round, so a publisher can be
   *  billed measured cost plus margin rather than an estimated rate card. The
   *  meter here stays authoritative for token counts; the pointer only lets the
   *  money be reconciled against what Cloudflare really charged. */
  reconciliation_ref?: string;
}

export interface DirectProviderSecrets {
  resolve: (credentialRef: string) => Promise<unknown>;
}

/** The service-held gateway token for managed funding.
 *
 *  Deliberately a different type from {@link DirectProviderSecrets}: that one
 *  resolves a *customer* credential by reference and proves it matches the
 *  admitted provider and class. There is no customer credential here and
 *  nothing to match — the token is GaugeWright's, and the customer relationship
 *  is a billing one settled from metered usage. Sharing one interface would
 *  invite resolving a deployment reference against a service secret. */
export interface ManagedGatewaySecret {
  token: () => string | undefined;
}

const MANAGED_BYOK_ALIAS = "primary";
const MANAGED_GATEWAY_RETRYABLE_STATUSES = new Set([401, 403, 408, 425, 429]);

interface ManagedGatewayTarget {
  accountId: string;
  gatewayId: string;
  unifiedBillingBaseUrl: string;
}

function managedGatewayTarget(baseUrl: string): ManagedGatewayTarget {
  const admitted = new URL(baseUrl);
  const match = /^\/v1\/([0-9a-f]{32})\/([A-Za-z0-9][A-Za-z0-9_-]{0,63})\/compat\/?$/
    .exec(admitted.pathname);
  if (
    admitted.protocol !== "https:"
    || admitted.hostname !== "gateway.ai.cloudflare.com"
    || admitted.username
    || admitted.password
    || admitted.search
    || admitted.hash
    || !match
  ) {
    throw new Error("managed funding requires an exact Cloudflare AI Gateway compat endpoint");
  }
  const [, accountId, gatewayId] = match;
  return {
    accountId: accountId!,
    gatewayId: gatewayId!,
    unifiedBillingBaseUrl:
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/v1`,
  };
}

function managedGatewayStatus(result: string): number {
  const parsed = JSON.parse(result) as { status?: unknown };
  return Number.isInteger(parsed.status) ? Number(parsed.status) : 0;
}

function shouldFallbackToUnifiedBilling(status: number): boolean {
  return MANAGED_GATEWAY_RETRYABLE_STATUSES.has(status) || status >= 500;
}

interface BrokerResponse {
  protocol: typeof MODEL_EGRESS_PROTOCOL;
  status: number;
  body: unknown;
  reconciliation_ref?: string;
}

async function directProviderCredential(
  binding: ModelBrokerBinding,
  secrets: DirectProviderSecrets,
): Promise<string> {
  const value = await secrets.resolve(binding.credential_id);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`direct provider credential ${binding.credential_id} is unavailable`);
  }
  const entry = value as {
    provider?: unknown;
    credential_class?: unknown;
    api_key?: unknown;
  };
  if (
    entry.provider !== binding.provider ||
    !binding.credential_class ||
    entry.credential_class !== binding.credential_class ||
    typeof entry.api_key !== "string"
  ) {
    throw new Error(
      `direct provider credential ${binding.credential_id} does not match the admitted provider and class`,
    );
  }
  const credential = entry.api_key.trim();
  if (!credential) {
    throw new Error(`direct provider credential ${binding.credential_id} is unavailable`);
  }
  return credential;
}

function validatedBrokerUrl(raw: string | undefined): string {
  if (!raw?.trim()) throw new Error("model broker URL is unavailable");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("model broker URL is invalid");
  }
  const loopback = url.hostname === "localhost"
    || url.hostname === "127.0.0.1"
    || url.hostname === "[::1]"
    || url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("model broker URL must use HTTPS (HTTP is loopback-only)");
  }
  if (url.username || url.password || url.hash) {
    throw new Error("model broker URL may not contain credentials or a fragment");
  }
  return url.toString();
}

function sentinelValue(name: string): string {
  return name === "authorization"
    ? `Bearer ${MODEL_AUTH_SENTINEL}`
    : MODEL_AUTH_SENTINEL;
}

export function stripSentinelAuthentication(
  headers: [string, string][],
): [string, string][] {
  const sanitized: [string, string][] = [];
  let witnessedAuthentication = false;
  for (const [name, value] of headers) {
    const normalized = name.toLowerCase();
    if (FORBIDDEN_AMBIENT_AUTH_HEADERS.has(normalized)) {
      throw new Error(`model request contains forbidden ${normalized} header`);
    }
    if (STRIPPED_AUTH_HEADERS.has(normalized)) {
      if (value !== sentinelValue(normalized)) {
        throw new Error(`model request ${normalized} header is not the broker sentinel`);
      }
      witnessedAuthentication = true;
      continue;
    }
    sanitized.push([name, value]);
  }
  if (!witnessedAuthentication) {
    throw new Error("model request has no broker-sentinel authentication header");
  }
  return sanitized;
}

async function readJsonCapped(response: Response): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared && Number(declared) > MAX_BROKER_RESPONSE_BYTES) {
    throw new Error("model broker response exceeds the size cap");
  }
  if (!response.body) throw new Error("model broker response had no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_BROKER_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("model broker response exceeds the size cap");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("model broker response was not valid JSON");
  }
}

function validatedBrokerResponse(value: unknown): BrokerResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("model broker response must be an object");
  }
  const response = value as Partial<BrokerResponse>;
  if (response.protocol !== MODEL_EGRESS_PROTOCOL) {
    throw new Error("model broker response has the wrong protocol");
  }
  if (!Number.isInteger(response.status) || Number(response.status) < 100 || Number(response.status) > 599) {
    throw new Error("model broker response has an invalid provider status");
  }
  if (!("body" in response)) {
    throw new Error("model broker response has no provider body");
  }
  if (response.reconciliation_ref !== undefined && typeof response.reconciliation_ref !== "string") {
    throw new Error("model broker reconciliation ref must be a string");
  }
  return response as BrokerResponse;
}

function directProviderBody(
  body: unknown,
  provider: ModelBrokerBinding["provider"],
): unknown {
  const providerLimit = provider === "openai" || provider === "openai-codex"
    ? "max_output_tokens"
    : provider === "cloudflare-ai-gateway"
      ? "max_completion_tokens"
      : null;
  if (!providerLimit) return body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const fields = body as Record<string, unknown>;
  if (!("max_tokens" in fields)) return body;
  if (providerLimit in fields) {
    throw new Error("provider request has conflicting output token limits");
  }
  const { max_tokens, ...rest } = fields;
  return { ...rest, [providerLimit]: max_tokens };
}

export async function performModelBrokerFetch(
  request: SuspendedModelRequest,
  binding: ModelBrokerBinding,
  config: ModelBrokerConfig,
  fetcher: FetchLike = fetch,
  onTextDelta?: (delta: string) => void,
  traceId?: string,
  onTiming?: ModelBrokerTimingSink,
): Promise<string> {
  const startedAt = performance.now();
  const mark = (event: string) => onTiming?.(event, performance.now() - startedAt);
  const brokerUrl = validatedBrokerUrl(config.url);
  const token = config.token?.trim();
  const executionGrant = config.executionGrant?.trim();
  const executionSignature = config.executionSignature?.trim();
  if (!token && (!executionGrant || !executionSignature)) {
    throw new Error("model broker authorization is unavailable");
  }
  if (token && (executionGrant || executionSignature)) {
    throw new Error("model broker authorization is ambiguous");
  }
  if (!binding.credential_id.trim()) throw new Error("model broker credential ref is empty");

  const headers = stripSentinelAuthentication(request.headers);
  const idempotencyKey = headers.find(
    ([name]) => name.toLowerCase() === "idempotency-key",
  )?.[1];
  const envelope = {
    protocol: MODEL_EGRESS_PROTOCOL,
    credential_ref: binding.credential_id,
    provider: binding.provider,
    request: {
      url: request.url,
      headers,
      body: request.body,
    },
  };
  const brokerHeaders: Record<string, string> = {
    accept: "application/vnd.whipplescript.model-egress-stream",
    "content-type": "application/json",
  };
  if (token) {
    brokerHeaders.authorization = `Bearer ${token}`;
  } else {
    brokerHeaders["x-gaugewright-execution-grant"] = executionGrant!;
    brokerHeaders["x-gaugewright-execution-signature"] = executionSignature!;
  }
  if (idempotencyKey) brokerHeaders["idempotency-key"] = idempotencyKey;
  if (traceId) brokerHeaders["x-gaugewright-trace-id"] = traceId;
  mark("broker_fetch_start");
  const response = await fetcher(brokerUrl, {
    method: "POST",
    headers: brokerHeaders,
    body: JSON.stringify(envelope),
  });
  mark("broker_headers");
  if (!response.ok) {
    throw new Error(`model broker returned HTTP ${response.status}`);
  }
  if (
    response.headers.get("x-whip-model-egress-protocol")
    === MODEL_EGRESS_STREAM_PROTOCOL
  ) {
    const upstreamStatus = Number(response.headers.get("x-whip-provider-status"));
    if (!Number.isInteger(upstreamStatus) || upstreamStatus < 100 || upstreamStatus > 599) {
      throw new Error("model broker stream has an invalid provider status");
    }
    const contentType = response.headers.get("x-whip-provider-content-type") ?? "";
    if (!response.body) throw new Error("model broker stream had no body");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    let sawTextDelta = false;
    const deltas = new ResponsesSseDeltaDecoder((delta) => {
      if (!sawTextDelta) {
        sawTextDelta = true;
        mark("provider_first_text_delta");
      }
      onTextDelta?.(delta);
    }, binding.provider);
    let total = 0;
    let sawByte = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (!sawByte) {
        sawByte = true;
        mark("broker_first_body_byte");
      }
      total += value.byteLength;
      if (total > MAX_BROKER_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("model broker response exceeds the size cap");
      }
      const text = decoder.decode(value, { stream: true });
      chunks.push(text);
      if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(text);
    }
    const tail = decoder.decode();
    if (tail) {
      chunks.push(tail);
      if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(tail);
    }
    deltas.finish();
    mark("broker_body_complete");
    const raw = chunks.join("");
    let body: unknown = raw;
    if (!contentType.toLowerCase().includes("text/event-stream")) {
      try {
        body = JSON.parse(raw);
      } catch {
        throw new Error("model broker response was not valid JSON");
      }
    }
    return JSON.stringify({ status: upstreamStatus, body });
  }
  // Rolling-deploy compatibility: an old Home broker still returns the v1
  // terminal JSON envelope. It remains valid, but cannot publish deltas.
  const decoded = validatedBrokerResponse(await readJsonCapped(response));
  mark("broker_body_complete");
  return JSON.stringify({ status: decoded.status, body: decoded.body });
}

/** Public-session provider round. The request leaves the Session DO directly;
 * no Home/broker/control-plane hop receives prompt or completion bytes. */
/**
 * A managed-funded model round: the same egress as a direct one, paid by the
 * service's gateway token instead of a customer credential (ADR 0085 §3
 * "managed", §6).
 *
 * Both the stored-key primary and managed-billing fallback delegate to
 * {@link performDirectProviderFetch} with a secrets shim rather than copying its
 * body. That function owns the part that must not drift — proving the request
 * never escaped an admitted/derived provider endpoint, stripping sentinel
 * authentication, capping the response, and parsing usage.
 */
export async function performManagedGatewayFetch(
  request: SuspendedModelRequest,
  binding: ModelBrokerBinding,
  secret: ManagedGatewaySecret,
  fetcher: FetchLike = fetch,
  onTextDelta?: (delta: string) => void,
  onTiming?: ModelBrokerTimingSink,
  onUsage?: (usage: ProviderUsage) => void,
  onGatewayLog?: (gatewayLogId: string) => void,
): Promise<string> {
  if (binding.provider !== "cloudflare-ai-gateway") {
    throw new Error(
      `managed funding requires the metered gateway, not ${binding.provider}`,
    );
  }
  const token = secret.token()?.trim();
  if (!token) {
    // Never fall back to another credential: that would silently bill the wrong
    // party, which is the failure managed funding exists to prevent.
    throw new Error("managed funding has no gateway token on this runtime");
  }
  const target = managedGatewayTarget(binding.base_url);
  const gatewaySecret = {
    // The shim answers with the shape `directProviderCredential` proves, so
    // the checks there still run — the token simply is not a per-deployment
    // reference and never came from the credential registry.
    resolve: async () => ({
      provider: binding.provider,
      credential_class: binding.credential_class,
      api_key: token,
    }),
  };

  let primaryReachedEgress = false;
  let primaryEmittedText = false;
  let primaryResult: string;
  try {
    primaryResult = await performDirectProviderFetch(
      request,
      binding,
      gatewaySecret,
      async (url, init) => {
        primaryReachedEgress = true;
        const headers = new Headers(init.headers);
        // A non-default alias is deliberate. Leaving `default` empty is what
        // lets the REST retry below use Cloudflare Unified Billing instead of
        // selecting the same broken provider key again.
        headers.set("cf-aig-byok-alias", MANAGED_BYOK_ALIAS);
        return fetcher(url, { ...init, headers });
      },
      (delta) => {
        primaryEmittedText = true;
        onTextDelta?.(delta);
      },
      onTiming,
      onUsage,
      onGatewayLog,
    );
  } catch (error) {
    // Admission/endpoint/auth-sentinel failures occur before egress and remain
    // fail-closed. Once the admitted request reached Cloudflare, a transport
    // failure may use the same account and gateway's managed billing path, but
    // never after text was exposed (which would duplicate a partial answer).
    if (!primaryReachedEgress || primaryEmittedText) throw error;
    primaryResult = JSON.stringify({ status: 599, body: null });
  }

  const primaryStatus = managedGatewayStatus(primaryResult);
  if (!shouldFallbackToUnifiedBilling(primaryStatus) || primaryEmittedText) {
    return primaryResult;
  }

  console.log(JSON.stringify({
    event: "gaugewright_managed_gateway_fallback",
    primary_status: primaryStatus,
    fallback: "cloudflare_unified_billing",
  }));

  const fallbackBinding: ModelBrokerBinding = {
    ...binding,
    base_url: target.unifiedBillingBaseUrl,
  };
  const fallbackRequest: SuspendedModelRequest = {
    ...request,
    url: `${target.unifiedBillingBaseUrl}/chat/completions`,
  };
  return performDirectProviderFetch(
    fallbackRequest,
    fallbackBinding,
    gatewaySecret,
    async (url, init) => {
      const headers = new Headers(init.headers);
      headers.set("cf-aig-gateway-id", target.gatewayId);
      // No BYOK alias is sent here and the gateway must have no `default` key;
      // Cloudflare's credential precedence therefore reaches Unified Billing.
      headers.delete("cf-aig-byok-alias");
      return fetcher(url, { ...init, headers });
    },
    onTextDelta,
    onTiming,
    onUsage,
    onGatewayLog,
  );
}

export async function performDirectProviderFetch(
  request: SuspendedModelRequest,
  binding: ModelBrokerBinding,
  secrets: DirectProviderSecrets,
  fetcher: FetchLike = fetch,
  onTextDelta?: (delta: string) => void,
  onTiming?: ModelBrokerTimingSink,
  onUsage?: (usage: ProviderUsage) => void,
  /** Each metered round's gateway log id, reported as soon as it is seen. */
  onGatewayLog?: (gatewayLogId: string) => void,
): Promise<string> {
  const startedAt = performance.now();
  const mark = (event: string) => onTiming?.(event, performance.now() - startedAt);
  const requested = new URL(request.url);
  const admitted = new URL(binding.base_url);
  const admittedPath = admitted.pathname.replace(/\/$/, "");
  const expectedPath = binding.provider === "anthropic"
    ? `${admittedPath}/v1/messages`
    : binding.provider === "openai-generic"
        || binding.provider === "cloudflare-ai-gateway"
      // The gateway's `/compat` surface is OpenAI-compatible, so the admitted
      // base URL already ends at `/compat` and the request appends
      // `/chat/completions` — the same shape as a generic endpoint.
      ? `${admittedPath}/chat/completions`
      : `${admittedPath}/v1/responses`;
  if (
    requested.origin !== admitted.origin ||
    requested.pathname !== expectedPath ||
    requested.username ||
    requested.password ||
    requested.hash
  ) {
    throw new Error("direct provider request escaped the signed provider endpoint");
  }
  const headers = new Headers(stripSentinelAuthentication(request.headers));
  const credential = await directProviderCredential(binding, secrets);
  if (binding.provider === "anthropic") {
    headers.set("x-api-key", credential);
  } else {
    headers.set("authorization", `Bearer ${credential}`);
  }
  mark("direct_provider_fetch_start");
  const response = await fetcher(request.url, {
    method: "POST",
    headers,
    body: JSON.stringify(directProviderBody(request.body, binding.provider)),
  });
  mark("direct_provider_headers");
  if (!response.body) throw new Error("direct provider response had no body");
  const contentType = response.headers.get("content-type") ?? "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let total = 0;
  let sawByte = false;
  let sawText = false;
  const deltas = new ResponsesSseDeltaDecoder((delta) => {
    if (!sawText) {
      sawText = true;
      mark("direct_provider_first_text_delta");
    }
    onTextDelta?.(delta);
  }, binding.provider);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    if (!sawByte) {
      sawByte = true;
      mark("direct_provider_first_body_byte");
    }
    total += value.byteLength;
    if (total > MAX_BROKER_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("direct provider response exceeds the size cap");
    }
    const text = decoder.decode(value, { stream: true });
    chunks.push(text);
    if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(text);
  }
  const tail = decoder.decode();
  if (tail) {
    chunks.push(tail);
    if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(tail);
  }
  deltas.finish();
  mark("direct_provider_body_complete");
  const raw = chunks.join("");
  // The gateway's log id is a fact about the *round*, not about token counts, so
  // it is reported independently of whether usage parses. Riding it on
  // `ProviderUsage` meant a response whose usage this parser does not understand
  // — the gateway's `/compat` surface returns chat-completions, not the
  // Responses shape — silently produced no pointer, and every metered turn fell
  // back to the rate card. Found only by watching a real turn get billed.
  const gatewayLogId = response.headers.get("cf-aig-log-id")?.trim();
  if (gatewayLogId) onGatewayLog?.(gatewayLogId);
  const usage = extractResponsesUsage(raw);
  if (usage) onUsage?.(usage);
  let body: unknown = raw;
  if (!contentType.toLowerCase().includes("text/event-stream")) {
    try {
      body = JSON.parse(raw);
    } catch {
      throw new Error("direct provider response was not valid JSON");
    }
    const completion =
      body && typeof body === "object" && !Array.isArray(body)
        ? (body as {
            choices?: { message?: { content?: unknown } }[];
          }).choices?.[0]?.message?.content
        : undefined;
    if (typeof completion === "string" && completion) {
      if (!sawText) {
        sawText = true;
        mark("direct_provider_first_text_delta");
      }
      onTextDelta?.(completion);
    }
  }
  if (!response.ok) {
    const providerError =
      body && typeof body === "object" && !Array.isArray(body)
        ? (body as { error?: unknown }).error
        : undefined;
    const fields =
      providerError && typeof providerError === "object" && !Array.isArray(providerError)
        ? providerError as Record<string, unknown>
        : {};
    const safeField = (name: string): string | null => {
      const value = fields[name];
      return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value)
        ? value
        : null;
    };
    console.log(JSON.stringify({
      event: "gaugewright_direct_provider_rejected",
      status: response.status,
      type: safeField("type"),
      code: safeField("code"),
      param: safeField("param"),
    }));
  }
  return JSON.stringify({ status: response.status, body });
}

function extractResponsesUsage(raw: string): ProviderUsage | null {
  let found: ProviderUsage | null = null;
  for (const line of raw.replaceAll("\r\n", "\n").split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice("data:".length).trim();
    if (!payload || payload === "[DONE]") continue;
    try {
      const event = JSON.parse(payload) as {
        response?: {
          usage?: {
            input_tokens?: unknown;
            input_tokens_details?: { cached_tokens?: unknown };
            output_tokens?: unknown;
          };
        };
        usage?: {
          input_tokens?: unknown;
          input_tokens_details?: { cached_tokens?: unknown };
          output_tokens?: unknown;
        };
      };
      const usage = event.response?.usage ?? event.usage;
      if (
        usage &&
        Number.isSafeInteger(usage.input_tokens) &&
        Number(usage.input_tokens) >= 0 &&
        Number.isSafeInteger(usage.output_tokens) &&
        Number(usage.output_tokens) >= 0 &&
        (
          usage.input_tokens_details?.cached_tokens === undefined ||
          (
            Number.isSafeInteger(usage.input_tokens_details.cached_tokens) &&
            Number(usage.input_tokens_details.cached_tokens) >= 0 &&
            Number(usage.input_tokens_details.cached_tokens) <=
              Number(usage.input_tokens)
          )
        )
      ) {
        found = {
          input_tokens: Number(usage.input_tokens),
          cached_input_tokens:
            Number.isSafeInteger(usage.input_tokens_details?.cached_tokens) &&
            Number(usage.input_tokens_details?.cached_tokens) >= 0
              ? Number(usage.input_tokens_details?.cached_tokens)
              : 0,
          output_tokens: Number(usage.output_tokens),
        };
      }
    } catch {
      // Provider decoding remains fail-closed in WhippleScript. Usage is an
      // additional terminal observation and malformed non-terminal SSE lines
      // cannot invent metering evidence.
    }
  }
  return found;
}

/** Incrementally extracts OpenAI Responses text deltas across arbitrary HTTP
 * chunk boundaries. Provider semantics remain in WhippleScript; the Home
 * broker is only an authenticated byte relay. */
export class ResponsesSseDeltaDecoder {
  private buffer = "";
  private readonly emit?: (delta: string) => void;
  private readonly provider?: ModelBrokerBinding["provider"];

  constructor(
    emit?: (delta: string) => void,
    provider?: ModelBrokerBinding["provider"],
  ) {
    this.emit = emit;
    this.provider = provider;
  }

  feed(chunk: string): void {
    this.buffer = `${this.buffer}${chunk}`.replaceAll("\r\n", "\n");
    for (;;) {
      const boundary = this.buffer.indexOf("\n\n");
      if (boundary < 0) break;
      const event = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 2);
      this.decodeEvent(event);
    }
  }

  finish(): void {
    if (this.buffer.trim()) this.decodeEvent(this.buffer);
    this.buffer = "";
  }

  private decodeEvent(block: string): void {
    for (const line of block.split("\n")) {
      const payload = line.trim().startsWith("data:")
        ? line.trim().slice("data:".length).trim()
        : "";
      if (!payload || payload === "[DONE]") continue;
      try {
        const event = JSON.parse(payload) as {
          type?: unknown;
          delta?: unknown;
          choices?: { delta?: { content?: unknown } }[];
        };
        if (this.provider === "anthropic" && event.type === "content_block_delta") {
          const anthropicDelta = event.delta as { type?: unknown; text?: unknown } | undefined;
          // `thinking_delta` is intentionally excluded: live observation may
          // project answer text, never hidden model reasoning.
          if (
            anthropicDelta?.type === "text_delta"
            && typeof anthropicDelta.text === "string"
            && anthropicDelta.text
          ) {
            this.emit?.(anthropicDelta.text);
          }
          continue;
        }
        if (
          event.type === "response.output_text.delta"
          && typeof event.delta === "string"
          && event.delta
        ) {
          this.emit?.(event.delta);
          continue;
        }
        // Cloudflare AI Gateway's `/compat/chat/completions` endpoint streams
        // OpenAI chat-completion chunks rather than Responses API events. Both
        // are admitted public-provider protocols, so project their text through
        // the same callback instead of completing a successful turn invisibly.
        const chatDelta = event.choices?.[0]?.delta?.content;
        if (typeof chatDelta === "string" && chatDelta) {
          this.emit?.(chatDelta);
        }
      } catch {
        // A malformed provider event is ignored for live projection. The
        // terminal parser remains authoritative and will reject an unusable
        // response when the stream ends.
      }
    }
  }
}
