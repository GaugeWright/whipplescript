// A local HTTP model provider for the workerd suites (vitest globalSetup).
//
// Most session tests replace `fetch` with a stub, which proves what the Session
// object does with a response but never sends one over a socket: a stubbed
// stream can only fail the way the stub chooses to fail. This server is the
// other kind of fixture. The Durable Object's real `fetch` reaches it over
// loopback, so a fault it injects — headers sent and the connection dropped
// mid-body, a 5xx — arrives the way a provider's would.
//
// Behaviour is scripted per scenario, named by the first path segment. A test
// signs `http://127.0.0.1:<port>/<scenario>` as its provider base URL, so the
// governed request path is `/<scenario>/v1/responses`. Every request a scenario
// receives is recorded (method, path, the headers that matter, body) and read
// back from `GET /<scenario>/__requests`, which is how a test asserts on what
// actually crossed the wire — the idempotency key and the injected credential
// included. Nothing here is reachable off the host: it binds 127.0.0.1 on an
// ephemeral port and is closed in teardown.
//
// Scenarios:
//   disconnect-then-5xx   attempt 1 streams one text delta, then the socket is
//                         destroyed; attempt 2 answers 503; attempt 3 streams
//                         the same delta and a completion carrying usage.
import { createServer } from "node:http";

const DELTA = 'data: {"type":"response.output_text.delta","delta":"once"}\n\n';
const COMPLETED =
  'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens":1}}}\n\n';

const SCENARIOS = {
  "disconnect-then-5xx": (attempt, response) => {
    if (attempt === 1) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(DELTA, () => {
        // Give the delta time to reach the reader before the connection goes,
        // so the fault is a mid-stream disconnect rather than an empty body.
        setTimeout(() => response.socket?.destroy(), 50);
      });
      return;
    }
    if (attempt === 2) {
      response.writeHead(503, { "content-type": "application/json" });
      response.end(JSON.stringify({
        error: { type: "server_error", code: "overloaded", message: "503 injected overload" },
      }));
      return;
    }
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.end(DELTA + COMPLETED);
  },
};

const RECORDED_HEADERS = ["authorization", "idempotency-key", "content-type", "x-api-key"];

export function startProviderFaultFixture() {
  const requests = new Map();
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://fixture.invalid");
    const [, scenario, ...rest] = url.pathname.split("/");
    const recorded = requests.get(scenario) ?? [];
    if (request.method === "GET" && rest.join("/") === "__requests") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(recorded));
      return;
    }
    const script = SCENARIOS[scenario];
    if (!script || request.method !== "POST") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { message: "no such provider scenario" } }));
      return;
    }
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const headers = {};
      for (const name of RECORDED_HEADERS) {
        const value = request.headers[name];
        if (typeof value === "string") headers[name] = value;
      }
      recorded.push({
        method: request.method,
        path: url.pathname,
        headers,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      requests.set(scenario, recorded);
      script(recorded.length, response);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({
        origin: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done) => {
          server.closeAllConnections?.();
          server.close(() => done());
        }),
      });
    });
  });
}

export default async function setup({ provide }) {
  const fixture = await startProviderFaultFixture();
  provide("providerFaultFixtureOrigin", fixture.origin);
  return fixture.close;
}
