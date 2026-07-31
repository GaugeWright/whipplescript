import { WorkflowInstance, type Env as RuntimeEnv } from "./index";
import {
  decodeGrant,
  p256JwkToGovernanceHex,
  sha256Hex,
  validateDurableWorkflowGrant,
  verifyP256GrantSignature,
  type DurableWorkflowGrant,
} from "./private-home-protocol";

interface PrivateHomeEnv extends RuntimeEnv {
  HOME_ADMISSION_KEYS?: string;
}

const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function jsonError(error: string, status: number): Response {
  return Response.json({ error }, { status });
}

function packageBindingError(
  grant: DurableWorkflowGrant,
  route: NonNullable<ReturnType<typeof routeIdentity>>,
  body: ArrayBuffer,
): string | undefined {
  if (body.byteLength === 0) return undefined;
  if (
    !["/host/instances/open", "/host/turns", "/host/forks/import"].includes(
      route.innerPath,
    )
  ) {
    return undefined;
  }
  let request: {
    command?: {
      command_id?: unknown;
      package_version_ref?: unknown;
    };
  };
  try {
    request = JSON.parse(new TextDecoder().decode(body)) as typeof request;
  } catch {
    return "private host request is not valid JSON";
  }
  if (request.command?.package_version_ref !== grant.package_ref) {
    return "private host package does not match the execution grant";
  }
  if (
    route.innerPath === "/host/turns" &&
    request.command.command_id !== grant.command_id
  ) {
    return "private host turn does not match the execution command";
  }
  return undefined;
}

function routeIdentity(url: URL): {
  homeId: string;
  tenantId: string;
  projectId: string;
  commandId: string;
  epoch: number;
  innerPath: string;
} | undefined {
  const match = url.pathname.match(
    /^\/v1\/homes\/([^/]+)\/tenants\/([^/]+)\/projects\/([^/]+)\/commands\/([^/]+)\/attempts\/([1-9][0-9]*)(\/host\/.*)$/,
  );
  if (!match) return undefined;
  const epoch = Number(match[5]);
  if (!Number.isSafeInteger(epoch)) return undefined;
  return {
    homeId: decodeURIComponent(match[1]),
    tenantId: decodeURIComponent(match[2]),
    projectId: decodeURIComponent(match[3]),
    commandId: decodeURIComponent(match[4]),
    epoch,
    innerPath: match[6],
  };
}

async function admittedGrant(
  request: Request,
  env: PrivateHomeEnv,
  route: NonNullable<ReturnType<typeof routeIdentity>>,
  body: ArrayBuffer,
): Promise<
  { grant: DurableWorkflowGrant; governanceKeyHex: string } | Response
> {
  const encodedGrant = request.headers.get("x-gaugewright-execution-grant") ?? "";
  const signature = request.headers.get("x-gaugewright-execution-signature") ?? "";
  const grant = decodeGrant(encodedGrant);
  if (!grant || !signature) return jsonError("Home execution grant is required", 401);

  const invalid = validateDurableWorkflowGrant(grant, Math.floor(Date.now() / 1000));
  if (invalid) return jsonError(invalid, 403);
  if (
    grant.home_id !== route.homeId ||
    grant.tenant_id !== route.tenantId ||
    grant.project_id !== route.projectId ||
    grant.command_id !== route.commandId ||
    grant.epoch !== route.epoch ||
    grant.request_method !== request.method ||
    grant.request_path !== `${route.innerPath}${new URL(request.url).search}`
  ) {
    return jsonError("execution grant does not match the addressed command", 403);
  }
  const bodyDigest = body.byteLength === 0 ? EMPTY_SHA256 : await sha256Hex(body);
  if (bodyDigest !== grant.request_body_sha256) {
    return jsonError("execution grant does not match the request body", 403);
  }
  const packageError = packageBindingError(grant, route, body);
  if (packageError) return jsonError(packageError, 403);

  let keys: Record<string, JsonWebKey>;
  try {
    keys = JSON.parse(env.HOME_ADMISSION_KEYS ?? "{}") as Record<string, JsonWebKey>;
  } catch {
    return jsonError("Home admission keys are unavailable", 503);
  }
  const key = keys[grant.key_id];
  if (!key || !(await verifyP256GrantSignature(grant, signature, key))) {
    return jsonError("Home execution signature is invalid", 403);
  }
  // Preserve GaugeDesk's exact SEC1-uncompressed governance key identity.
  const governanceKeyHex = p256JwkToGovernanceHex(key);
  if (!governanceKeyHex) {
    return jsonError("Home governance key is invalid", 503);
  }
  return { grant, governanceKeyHex };
}

export default {
  async fetch(
    request: Request,
    env: PrivateHomeEnv,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({ ok: true, surface: "private-durable-workflow" });
    }
    if (!env.WHIP_CONTROL_TOKEN?.trim()) {
      return jsonError("private runtime control boundary is unavailable", 503);
    }
    if (!["GET", "POST"].includes(request.method)) {
      return jsonError("method not allowed", 405);
    }
    const route = routeIdentity(url);
    if (!route) return jsonError("not found", 404);

    const body = request.method === "POST" ? await request.arrayBuffer() : new ArrayBuffer(0);
    const admission = await admittedGrant(request, env, route, body);
    if (admission instanceof Response) return admission;
    const { grant, governanceKeyHex } = admission;

    const inner = new URL(request.url);
    inner.pathname = route.innerPath;
    inner.search = url.search;
    const headers = new Headers(request.headers);
    headers.delete("x-gaugewright-execution-grant");
    headers.delete("x-gaugewright-execution-signature");
    headers.set(
      "x-gaugewright-private-governance-signer",
      grant.governance_signer,
    );
    headers.set("x-gaugewright-private-governance-key", governanceKeyHex);
    headers.set(
      "x-gaugewright-private-callback",
      grant.callback_ref,
    );
    headers.set(
      "x-gaugewright-private-execution-grant",
      request.headers.get("x-gaugewright-execution-grant") ?? "",
    );
    headers.set(
      "x-gaugewright-private-execution-signature",
      request.headers.get("x-gaugewright-execution-signature") ?? "",
    );
    headers.set("authorization", `Bearer ${env.WHIP_CONTROL_TOKEN}`);
    const forwarded = new Request(inner, {
      method: request.method,
      headers,
      body: request.method === "POST" ? body : undefined,
    });
    const objectName = [
      "home",
      grant.home_id,
      "tenant",
      grant.tenant_id,
      "project",
      grant.project_id,
      "command",
      grant.command_id,
    ].join(":");
    const stub = env.WORKFLOW_INSTANCE.get(
      env.WORKFLOW_INSTANCE.idFromName(objectName),
    );
    return stub.fetch(forwarded);
  },
} satisfies ExportedHandler<PrivateHomeEnv>;

export { WorkflowInstance };
