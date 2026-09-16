import { env, SELF } from "cloudflare:test";
import type { DurableObjectNamespace } from "@cloudflare/workers-types";
import { handleObjectPlane } from "./object-store";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The external byte tier's data plane, against a real bucket.
 *
 * The workers pool runs workerd with a simulated R2, so these exercise the
 * actual `bucket.put(key, stream)` path rather than a double — which matters,
 * because the whole claim of this route is about how bytes move through it.
 */

const TOKEN = "control-token";

/** The content id contract: SHA-256 truncated to 16 bytes, hex. Computed here
 *  independently of the Worker, so a change to either side shows up as a
 *  disagreement rather than as two copies of the same mistake. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function contentId(bytes: Uint8Array): Promise<string> {
    return (await sha256Hex(bytes)).slice(0, 32);
}

function authed(init: RequestInit = {}): RequestInit {
    return { ...init, headers: { ...(init.headers ?? {}), authorization: `Bearer ${TOKEN}` } };
}

/** A writer always knows the body's digest — it derived the id from it. */
async function put(id: string, body: Uint8Array): Promise<Response> {
    return SELF.fetch(
        `https://host/v1/objects/${id}`,
        authed({ method: "PUT", body, headers: { "x-whip-content-sha256": await sha256Hex(body) } }),
    );
}

describe("the object plane", () => {
    beforeEach(async () => {
        for (const { key } of (await env.WHIP_OBJECTS.list()).objects) {
            await env.WHIP_OBJECTS.delete(key);
        }
    });

    it("round-trips bytes that no text pipe could carry", async () => {
        // A PNG header, a NUL, and a sequence no UTF-8 decoder accepts.
        const picture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0xff, 0xfe, 0x0d]);
        const id = await contentId(picture);

        const written = await put(id, picture);
        expect(written.status, await written.clone().text()).toBe(201);
        expect(await written.json()).toMatchObject({ id, byte_len: 12 });

        const read = await SELF.fetch(`https://host/v1/objects/${id}`, authed());
        expect(read.status).toBe(200);
        expect(read.headers.get("content-type")).toBe("application/octet-stream");
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(picture);
    });

    /** The point of a content-addressed tier. An id that does not describe its
     *  bytes is worse than a failed upload: every later reader checks the id,
     *  finds it matches what it asked for, and trusts the wrong bytes. */
    it("refuses content that does not hash to the id it was sent under", async () => {
        const honest = new Uint8Array([1, 2, 3, 4]);
        const id = await contentId(honest);

        // The digest belongs to `honest`, the bytes do not. R2 is what
        // notices, as the bytes land.
        const lie = await SELF.fetch(
            `https://host/v1/objects/${id}`,
            authed({
                method: "PUT",
                body: new Uint8Array([9, 9, 9, 9]),
                headers: { "x-whip-content-sha256": await sha256Hex(honest) },
            }),
        );
        expect(lie.status, await lie.clone().text()).toBe(409);

        // And it is not left behind for a later reader to find.
        expect(await env.WHIP_OBJECTS.head(id)).toBeNull();
    });

    /** A body far past the Worker's control-body cap must go through, because
     *  bytes too large for a SQLite value are precisely this tier's job. The
     *  cap sits after this route for that reason. */
    it("carries a body larger than the control-plane body cap", async () => {
        // MAX_BOOTSTRAP_BYTES is 1 MiB; this is comfortably past it. The
        // simulated bucket is slower than a real one, and the size is the
        // point of the test, so it stays; the suite-wide bound in
        // `src/test-bounds.ts` is what gives it room.
        const big = new Uint8Array(3 * 1024 * 1024);
        crypto.getRandomValues(big.subarray(0, 65536));
        for (let at = 65536; at < big.length; at += 65536) {
            big.copyWithin(at, 0, Math.min(65536, big.length - at));
        }
        const id = await contentId(big);

        const written = await put(id, big);
        expect(written.status, await written.clone().text()).toBe(201);
        expect(await written.json()).toMatchObject({ byte_len: big.length });

        const read = await SELF.fetch(`https://host/v1/objects/${id}`, authed());
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(big);
    });

    /** A streamed body is carried when its length is declared, and refused
     *  when it is not. R2 can only store a stream against a length known
     *  before the transfer starts, so a chunked upload with no content-length
     *  has nowhere to go — and saying 411 is the honest answer rather than
     *  buffering the body to discover its size, which is the one thing this
     *  route must never do. */
    it("carries a streamed body whose length is declared", async () => {
        const pieces = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]), new Uint8Array([7])];
        const whole = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
        const id = await contentId(whole);

        const body = new ReadableStream<Uint8Array>({
            async pull(controller) {
                const next = pieces.shift();
                if (!next) return controller.close();
                controller.enqueue(next);
            },
        });
        const written = await SELF.fetch(`https://host/v1/objects/${id}`, {
            method: "PUT",
            body,
            duplex: "half",
            headers: {
                authorization: `Bearer ${TOKEN}`,
                "x-whip-content-sha256": await sha256Hex(whole),
                "content-length": String(whole.length),
            },
        } as RequestInit);
        expect(written.status, await written.clone().text()).toBe(201);

        const read = await SELF.fetch(`https://host/v1/objects/${id}`, authed());
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(whole);
    });

    /** The guard for a body whose size is unknowable before it is stored.
     *
     *  Not reachable through `SELF.fetch`: workerd gives every body it builds
     *  a content-length, so the handler is called directly with a request that
     *  has none. Buffering the body to discover its size is the one thing this
     *  route must never do, which is why the answer is 411 and not a read. */
    it("refuses a body whose length it cannot know before storing it", async () => {
        const whole = new Uint8Array([1, 2, 3]);
        const id = await contentId(whole);
        const request = new Request(`https://host/v1/objects/${id}`, {
            method: "PUT",
            body: new Blob([whole]).stream(),
            duplex: "half",
        } as RequestInit);
        request.headers.delete("content-length");
        request.headers.set("x-whip-content-sha256", await sha256Hex(whole));

        const response = await handleObjectPlane(request, env);
        expect(response?.status).toBe(411);
        expect(await response?.json()).toMatchObject({
            error: expect.stringContaining("content-length is required"),
        });
    });

    it("serves a range so a reader can take a slice", async () => {
        const body = new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17]);
        const id = await contentId(body);
        expect((await put(id, body)).status).toBe(201);

        const sliced = await SELF.fetch(
            `https://host/v1/objects/${id}`,
            authed({ headers: { range: "bytes=2-4" } }),
        );
        expect(sliced.status).toBe(206);
        expect(new Uint8Array(await sliced.arrayBuffer())).toEqual(new Uint8Array([12, 13, 14]));
    });

    it("answers metadata without the bytes", async () => {
        const body = new Uint8Array([1, 2, 3, 4, 5]);
        const id = await contentId(body);
        await put(id, body);

        const head = await SELF.fetch(`https://host/v1/objects/${id}`, authed({ method: "HEAD" }));
        expect(head.status).toBe(200);
        expect(head.headers.get("content-length")).toBe("5");
        expect(head.headers.get("x-whip-content-id")).toBe(id);
    });

    /** Erasure's other half. Idempotent, because a caller retrying an erasure
     *  it already completed must not be told something went wrong. */
    it("deletes, and says the same thing the second time", async () => {
        const body = new Uint8Array([42]);
        const id = await contentId(body);
        await put(id, body);

        expect((await SELF.fetch(`https://host/v1/objects/${id}`, authed({ method: "DELETE" }))).status).toBe(204);
        expect((await SELF.fetch(`https://host/v1/objects/${id}`, authed())).status).toBe(404);
        expect((await SELF.fetch(`https://host/v1/objects/${id}`, authed({ method: "DELETE" }))).status).toBe(204);
    });

    /** The id is the key, so anything that is not a content id stays out of
     *  the bucket's namespace entirely. */
    it("refuses a key that is not a content id", async () => {
        for (const bad of ["not-a-hash", "../escape", "0".repeat(31), "0".repeat(33), "ZZZ"]) {
            const response = await put(encodeURIComponent(bad), new Uint8Array([1]));
            expect([400, 404], bad).toContain(response.status);
        }
    });

    it("requires the control credential like every other route", async () => {
        const id = await contentId(new Uint8Array([1]));
        const bare = await SELF.fetch(`https://host/v1/objects/${id}`, { method: "GET" });
        expect(bare.status).toBe(401);
    });

    /** The two halves together: bytes over the plane, handle on the placement.
     *
     *  They are separate on purpose. The plane is placement-agnostic because
     *  content-addressed bytes serve every placement naming the same id, and
     *  the isolate cannot move bytes at all — it is synchronous and R2 is not.
     *  So this is the whole write: stream to the bucket, then tell the
     *  placement the handle exists. */
    it("registers a handle on a placement for bytes the plane already holds", async () => {
        const picture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0x0d]);
        const id = await contentId(picture);
        expect((await put(id, picture)).status).toBe(201);

        const namespace = (env as unknown as { WORKFLOW_INSTANCE: DurableObjectNamespace })
            .WORKFLOW_INSTANCE;
        const stub = namespace.get(namespace.idFromName("object-handle-registration"));
        const registered = await stub.fetch("https://placement/host/objects/register", {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
            body: JSON.stringify({ id, byte_len: picture.length }),
        });
        expect(registered.status, await registered.clone().text()).toBe(200);
        expect(await registered.json()).toMatchObject({ registered: id, byte_len: 8 });

        // An id that is not a content id would be a row no object could answer.
        const bogus = await stub.fetch("https://placement/host/objects/register", {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
            body: JSON.stringify({ id: "not-a-content-id", byte_len: 8 }),
        });
        expect(bogus.status).toBe(400);
    });
});

/**
 * Ingest: bytes the plane pulls rather than bytes a writer pushes.
 *
 * The two directions differ in exactly one fact — whether anybody knows the
 * digest before the transfer — and everything else about this route follows
 * from not knowing it.
 */
describe("the ingest direction", () => {
    /** Each stubbed source answers one URL. Anything else throws rather than
     *  reaching the network, so a check that stopped working shows up as a
     *  failure rather than as a real request to a `.invalid` host. */
    function stubSources(sources: Record<string, () => Response>): string[] {
        const asked: string[] = [];
        vi.stubGlobal("fetch", async (input: RequestInfo | URL): Promise<Response> => {
            const target = input instanceof Request ? input.url : String(input);
            asked.push(target);
            const make = sources[target];
            if (!make) throw new Error(`unexpected fetch: ${target}`);
            return make();
        });
        return asked;
    }

    function sized(bytes: Uint8Array): Response {
        return new Response(bytes, { headers: { "content-length": String(bytes.length) } });
    }

    async function ingest(url: string): Promise<Response> {
        return SELF.fetch(
            "https://host/v1/object-ingest",
            authed({
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ url }),
            }),
        );
    }

    beforeEach(async () => {
        for (const { key } of (await env.WHIP_OBJECTS.list()).objects) {
            await env.WHIP_OBJECTS.delete(key);
        }
    });

    /** The whole claim in one test: one pass over bytes nobody had read, and
     *  an id computed from them rather than asserted about them. */
    it("pulls bytes from a declared source and says what they turned out to be", async () => {
        const picture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0xff, 0xfe]);
        stubSources({ "https://media.test.invalid/a.png": () => sized(picture) });

        const pulled = await ingest("https://media.test.invalid/a.png");
        expect(pulled.status, await pulled.clone().text()).toBe(201);
        const answer = (await pulled.json()) as {
            id: string;
            byte_len: number;
            storage_key: string;
        };
        expect(answer.id).toBe(await contentId(picture));
        expect(answer.byte_len).toBe(picture.length);
        expect(answer.storage_key).toMatch(/^s-[0-9a-f]{32}$/);
        // Not under its id: the key had to be named before the digest existed.
        expect(await env.WHIP_OBJECTS.head(answer.id)).toBeNull();

        const read = await SELF.fetch(`https://host/v1/objects/${answer.storage_key}`, authed());
        expect(read.status).toBe(200);
        // A staging token is a key and not a hash, so it is not answered under
        // a header every reader takes for a content id.
        expect(read.headers.get("x-whip-object-key")).toBe(answer.storage_key);
        expect(read.headers.get("x-whip-content-id")).toBeNull();
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(picture);
    });

    /** The URL arrives from a model's answer, so it is attacker-influencable in
     *  the ordinary case. A route that fetched it unchecked would be a request
     *  forger with this Worker's network position. */
    it("refuses a source no deployment declared, without fetching it", async () => {
        const asked = stubSources({});
        const refused = await ingest("https://elsewhere.example/secret");
        expect(refused.status).toBe(403);
        expect(await refused.text()).toContain("elsewhere.example");
        expect(asked, "the refusal happens before the request, not after").toEqual([]);
    });

    /** An allowlist checked only at the first URL is not an allowlist: one open
     *  redirector on a declared host forwards the fetch anywhere. */
    it("re-checks the allowlist at every redirect", async () => {
        const asked = stubSources({
            "https://media.test.invalid/open": () =>
                new Response(null, { status: 302, headers: { location: "https://elsewhere.example/x" } }),
        });
        const refused = await ingest("https://media.test.invalid/open");
        expect(refused.status).toBe(403);
        expect(await refused.text()).toContain("elsewhere.example");
        expect(asked).toEqual(["https://media.test.invalid/open"]);
        expect((await env.WHIP_OBJECTS.list()).objects, "and nothing was written").toEqual([]);
    });

    /** Real sources redirect — a provider handing off to its CDN. A hop inside
     *  the list is followed, or the check would be a ban. */
    it("follows a redirect that stays inside the list", async () => {
        const bytes = new Uint8Array([1, 2, 3, 4, 5]);
        stubSources({
            "https://media.test.invalid/a": () =>
                new Response(null, { status: 302, headers: { location: "https://mirror.test.invalid/b" } }),
            "https://mirror.test.invalid/b": () => sized(bytes),
        });
        const pulled = await ingest("https://media.test.invalid/a");
        expect(pulled.status, await pulled.clone().text()).toBe(201);
        expect(await pulled.json()).toMatchObject({ id: await contentId(bytes), byte_len: 5 });
    });

    /** The same requirement a push has, owed by the source instead of the
     *  caller. Reading the body to discover its size is the one way out, and it
     *  is the thing this route may not do. */
    it("refuses a source that will not say how long it is", async () => {
        stubSources({
            "https://media.test.invalid/chunked": () => new Response(new Uint8Array([1, 2, 3])),
        });
        const refused = await ingest("https://media.test.invalid/chunked");
        expect(refused.status).toBe(411);
        expect((await env.WHIP_OBJECTS.list()).objects).toEqual([]);
    });

    /** A key nothing is told about is a key nothing can collect, so a failed
     *  ingest takes its own object with it rather than leaving unreachable
     *  bytes in the bucket.
     *
     *  This is the only test that errors a `put` mid-stream, and the workers
     *  pool logs "Can't read from request stream because client disconnected"
     *  twice while unwinding it — its R2 simulation proxies the body over an
     *  internal request, and aborting the transfer disconnects that request's
     *  client. It is the simulator describing itself: the lines appear with the
     *  route's own cleanup removed, and vitest reports no error. */
    it("leaves nothing behind when the source overruns the length it declared", async () => {
        stubSources({
            "https://media.test.invalid/liar": () =>
                new Response(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), {
                    headers: { "content-length": "3" },
                }),
        });
        const failed = await ingest("https://media.test.invalid/liar");
        expect(failed.status, await failed.clone().text()).toBe(502);
        expect((await env.WHIP_OBJECTS.list()).objects).toEqual([]);
    });

    /** The object plane is routed ahead of the Worker's control-body cap,
     *  because that cap exists for JSON the isolate parses and the byte routes
     *  carry bodies too large to hold. Ingest sits on both sides of that: its
     *  own request is JSON the isolate parses, and only its source is large, so
     *  it may not inherit an exemption written for a different kind of body. */
    it("caps its own request body, which names a source rather than carrying one", async () => {
        const asked = await SELF.fetch(
            "https://host/v1/object-ingest",
            authed({
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ url: `https://media.test.invalid/${"a".repeat(16 * 1024)}` }),
            }),
        );
        expect(asked.status).toBe(413);
    });

    /** Only this route mints staging keys. A writer holding the digest has
     *  every reason to key on the id — that is what makes its claim checkable —
     *  so accepting a staging key on a PUT would be a way to write bytes no
     *  check applies to. */
    it("refuses a written object keyed on a staging token", async () => {
        const staged = `s-${"ab".repeat(16)}`;
        const written = await SELF.fetch(
            `https://host/v1/objects/${staged}`,
            authed({
                method: "PUT",
                body: new Uint8Array([1]),
                headers: {
                    "x-whip-content-sha256": await sha256Hex(new Uint8Array([1])),
                },
            }),
        );
        expect(written.status).toBe(400);
        expect(await written.text()).toContain("keyed on its content id");
    });

    /** Both halves of an ingest: the plane holds bytes under a minted key, and
     *  the placement is what pairs that key with the id they turned out to
     *  have. Until it does, the object is bytes nothing can name. */
    it("registers an ingested handle, and tells a loser what it orphaned", async () => {
        const bytes = new Uint8Array([9, 8, 7, 6]);
        stubSources({ "https://media.test.invalid/one": () => sized(bytes) });

        const first = (await (await ingest("https://media.test.invalid/one")).json()) as {
            id: string;
            byte_len: number;
            storage_key: string;
        };
        const second = (await (await ingest("https://media.test.invalid/one")).json()) as {
            storage_key: string;
        };
        expect(second.storage_key).not.toBe(first.storage_key);

        const namespace = (env as unknown as { WORKFLOW_INSTANCE: DurableObjectNamespace })
            .WORKFLOW_INSTANCE;
        const stub = namespace.get(namespace.idFromName("ingested-handle-registration"));
        async function register(storage_key: string): Promise<Response> {
            return stub.fetch("https://placement/host/objects/register", {
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
                body: JSON.stringify({ id: first.id, byte_len: first.byte_len, storage_key }),
            });
        }

        const won = await register(first.storage_key);
        expect(won.status, await won.clone().text()).toBe(200);
        expect(await won.json()).toMatchObject({
            registered: first.id,
            storage_key: first.storage_key,
        });

        // Same bytes, second object. The id already means the first one, and
        // moving it is the substitution content addressing exists to prevent.
        const lost = await register(second.storage_key);
        expect(await lost.json()).toMatchObject({
            storage_key: first.storage_key,
            orphaned: second.storage_key,
        });
    });

    /** A key the plane did not mint is a caller-chosen name in the bucket, and
     *  keying on the hash is what kept those out. */
    it("refuses a handle registered under a key the plane never minted", async () => {
        const namespace = (env as unknown as { WORKFLOW_INSTANCE: DurableObjectNamespace })
            .WORKFLOW_INSTANCE;
        const stub = namespace.get(namespace.idFromName("ingested-handle-refusal"));
        const bogus = await stub.fetch("https://placement/host/objects/register", {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
            body: JSON.stringify({
                id: await contentId(new Uint8Array([1])),
                byte_len: 1,
                storage_key: "../../somewhere-else",
            }),
        });
        expect(bogus.status).toBe(400);
    });
});
