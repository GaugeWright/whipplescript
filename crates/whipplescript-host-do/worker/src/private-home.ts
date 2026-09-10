import { WorkflowInstance, type Env as RuntimeEnv } from "./index";
import { declaredLength } from "./object-store";
import {
  decodeGrant,
  durableWorkflowObjectName,
  p256JwkToGovernanceHex,
  sha256Hex,
  validateDurableWorkflowGrant,
  verifyP256GrantSignature,
  type DurableWorkflowGrant,
} from "./private-home-protocol";

interface PrivateHomeEnv extends RuntimeEnv {
  HOME_ADMISSION_KEYS?: string;
  /** The external byte tier (DR-0113). Absent is a refusal, not a crash. */
  WHIP_OBJECTS?: R2Bucket;
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
  try {
    return {
      homeId: decodeURIComponent(match[1]),
      tenantId: decodeURIComponent(match[2]),
      projectId: decodeURIComponent(match[3]),
      commandId: decodeURIComponent(match[4]),
      epoch,
      innerPath: match[6],
    };
  } catch {
    return undefined;
  }
}

/**
 * Everything a grant asserts EXCEPT what the body is.
 *
 * Split out because the streaming byte route must decide whether to accept a
 * body before it has one: the signature, the expiry and the route binding are
 * all header-sized and settle authorization on their own, while "are these the
 * bytes the grant names" is an integrity question the object store answers as
 * they land. A caller that has the body in hand still owes that check —
 * `admittedGrant` below is the one that does it.
 */
async function verifyGrantEnvelope(
  request: Request,
  env: PrivateHomeEnv,
  route: NonNullable<ReturnType<typeof routeIdentity>>,
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

/**
 * A grant admitted against a body already in hand.
 *
 * The digest binding is what ties this signed grant to these exact bytes, and
 * the package binding reads the body as JSON — which is precisely why the
 * streaming route cannot come through here, and takes the envelope alone.
 */
async function admittedGrant(
  request: Request,
  env: PrivateHomeEnv,
  route: NonNullable<ReturnType<typeof routeIdentity>>,
  body: ArrayBuffer,
): Promise<
  { grant: DurableWorkflowGrant; governanceKeyHex: string } | Response
> {
  const envelope = await verifyGrantEnvelope(request, env, route);
  if (envelope instanceof Response) return envelope;
  const bodyDigest = body.byteLength === 0 ? EMPTY_SHA256 : await sha256Hex(body);
  if (bodyDigest !== envelope.grant.request_body_sha256) {
    return jsonError("execution grant does not match the request body", 403);
  }
  const packageError = packageBindingError(envelope.grant, route, body);
  if (packageError) return jsonError(packageError, 403);
  return envelope;
}

/** `/host/objects/:id` — the Home's byte route, addressed by content id. */
const OBJECT_INNER_PATH = /^\/host\/objects\/([0-9a-f]{32})$/;

/**
 * Place or serve one object's bytes on a private Home, mediated by a grant.
 *
 * This is the mediated half of DR-0112: the Home decides, then the bytes move.
 * The grant is verified from headers alone — signature, expiry and route
 * binding are all header-sized, so authorization is settled **before a single
 * body byte is accepted**. What the envelope cannot settle is whether the bytes
 * are the ones it names, and that is delegated to the object store, which
 * verifies the digest server-side as they land and refuses the write otherwise.
 *
 * The id in the path must be the first sixteen bytes of the grant's body
 * digest. So a grant does not authorize "a write": it authorizes this exact
 * content at its own address, and a holder cannot redirect it to another key or
 * put different bytes under this one.
 *
 * Bytes never enter the durable object. They stream from here to the bucket,
 * and only the handle — id and length — is forwarded to the instance, which is
 * the split DR-0033 Decision 4 asks for and the only one available: the durable
 * object's Rust is synchronous throughout and cannot reach an object store at
 * any size.
 */
async function homeObjectRoute(
  request: Request,
  env: PrivateHomeEnv,
  route: NonNullable<ReturnType<typeof routeIdentity>>,
  id: string,
): Promise<Response> {
  const bucket = env.WHIP_OBJECTS;
  if (!bucket) {
    return jsonError("this Home has no external byte tier bound", 503);
  }
  const envelope = await verifyGrantEnvelope(request, env, route);
  if (envelope instanceof Response) return envelope;
  const { grant } = envelope;

  // The grant names one content id, and the path must address that one.
  if (grant.request_body_sha256.slice(0, 32) !== id) {
    return jsonError(
      "this grant authorizes different content than the object addressed",
      403,
    );
  }

  if (request.method === "GET") {
    const object = await bucket.get(id);
    if (!object) return jsonError("no such object", 404);
    return new Response(object.body, {
      status: 200,
      headers: {
        "content-type": "application/octet-stream",
        "content-length": String(object.size),
        "x-whip-content-id": id,
      },
    });
  }

  if (!request.body) return jsonError("a body is required", 400);
  // A stream is stored against a length declared before it starts, and reading
  // the body to discover its size is the one thing this route must not do.
  const declared = declaredLength(request.headers);
  if (declared === null) {
    return jsonError("content-length is required to stream an object", 411);
  }

  const measured = new FixedLengthStream(declared);
  const pumped = request.body.pipeTo(measured.writable);
  let stored: R2Object;
  try {
    stored = await bucket.put(id, measured.readable, {
      sha256: grant.request_body_sha256,
    });
    await pumped;
  } catch (error) {
    void pumped.catch(() => undefined);
    const message = error instanceof Error ? error.message : String(error);
    if (/checksum|sha-?256|digest/i.test(message)) {
      // The bytes are not the ones the grant named. That is the content
      // binding doing its job, not a transport fault.
      return jsonError("content does not match the digest this grant names", 409);
    }
    return jsonError(`object write failed: ${message}`, 502);
  }

  // The bytes are placed and verified; now the instance learns the handle, so
  // erasure can reach them. Registering only after a verified write is what
  // keeps `status` from ever claiming Live over bytes that never arrived.
  // `durableWorkflowObjectName` and not a concatenation of the same fields:
  // the structured tuple stays injective even when an admitted identity
  // contains the delimiter, and two distinct grants must never address one
  // instance. The internal hop carries the control token the same way the
  // ordinary forward below does.
  const instance = env.WORKFLOW_INSTANCE.get(
    env.WORKFLOW_INSTANCE.idFromName(durableWorkflowObjectName(grant)),
  );
  const registered = await instance.fetch(
    new Request("https://instance/host/objects/register", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${env.WHIP_CONTROL_TOKEN}`,
      },
      body: JSON.stringify({ id, byte_len: stored.size }),
    }),
  );
  if (!registered.ok) {
    // The bytes are in the bucket but nothing durable names them. Say so
    // rather than reporting a placement the Home cannot later erase.
    return jsonError(
      `object stored but its handle was not recorded: ${await registered.text()}`,
      502,
    );
  }
  return Response.json({ id, byte_len: stored.size }, { status: 201 });
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

    // Before the buffer: this route's whole point is bytes too large to hold,
    // and `arrayBuffer()` below would read them into the isolate to compute a
    // digest the object store verifies for us anyway.
    const object = route.innerPath.match(OBJECT_INNER_PATH);
    if (object) return homeObjectRoute(request, env, route, object[1]);

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
    // A structured tuple is injective even when an admitted identity itself
    // contains the old delimiter words (for example `:tenant:`). Concatenating
    // these fields could map two distinct signed grants to one object.
    const objectName = durableWorkflowObjectName(grant);
    const stub = env.WORKFLOW_INSTANCE.get(
      env.WORKFLOW_INSTANCE.idFromName(objectName),
    );
    return stub.fetch(forwarded);
  },
} satisfies ExportedHandler<PrivateHomeEnv>;

export { WorkflowInstance };
