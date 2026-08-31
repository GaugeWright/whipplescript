// The Durable Object test doubles both test workers stand up: the embedder's
// session-admission stand-in and the public-credential resolver stand-in.
// wrangler.test.toml and wrangler.authenticated.test.toml both bind these two
// class names, so each entry module re-exports them from here.

export class TestDeployment implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    if (
      request.headers.get("authorization") !==
        "Bearer public-control-secret"
    ) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const match = new URL(request.url).pathname.match(
      /^\/internal\/sessions\/([^/]+)\/(admit|settle|release|expire|deposit)$/,
    );
    if (!match || request.method !== "POST") {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    const body = await request.json<Record<string, unknown>>();
    const sessionId = decodeURIComponent(match[1]);
    const operationKey = `operation:${sessionId}:${match[2]}`;
    const operationCount =
      (await this.state.storage.get<number>(operationKey)) ?? 0;
    await this.state.storage.put(operationKey, operationCount + 1);
    if (match[2] === "deposit") {
      // Stand-in for the embedder's custody: hold what was handed over so the
      // test can assert what actually left the session.
      await this.state.storage.put(`collection:${sessionId}`, body);
      return Response.json({ deposited: true }, { status: 201 });
    }
    if (match[2] === "admit") {
      const requestId = String(body.request_id ?? "");
      const key = `reservation:${sessionId}:${requestId}`;
      const existing = await this.state.storage.get<string>(key);
      const reservationRef =
        existing ?? `reservation:${sessionId}:${requestId}`;
      if (!existing) await this.state.storage.put(key, reservationRef);
      return Response.json(
        { reservation_ref: reservationRef },
        { status: existing ? 200 : 201 },
      );
    }
    return Response.json({
      reservation_ref: body.reservation_ref,
      operation: match[2],
    });
  }
}

export class TestCredentialRegistry implements DurableObject {
  async fetch(request: Request): Promise<Response> {
    if (
      request.headers.get("authorization") !==
        "Bearer public-control-secret"
    ) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const body = await request.json<{ credential_ref?: string }>();
    if (
      request.method !== "POST" ||
      new URL(request.url).pathname !== "/resolve" ||
      body.credential_ref !==
        `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`
    ) {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    return Response.json({
      credential_ref: body.credential_ref,
      provider: "openai",
      credential_class: "managed-openai",
      api_key: "canary-provider-secret-must-not-persist",
    });
  }
}
