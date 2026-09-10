/**
 * The external byte tier's data plane (DR-0113, DR-0033 Decision 4).
 *
 * Content that cannot live in a DO SQLite value — anything that is not text,
 * and text past the value ceiling — is held in an object store under its own
 * content id. This module is how those bytes move.
 *
 * **It is a Worker route, deliberately not a Durable Object one.** A durable
 * object serialises its work, so streaming a large body through one would block
 * that instance for the length of the transfer, and every other request to the
 * same placement behind it. DR-0033 Decision 4 says the bytes travel
 * out-of-band and "the isolate touches only handle + metadata, never the
 * bytes"; that is what a Worker route piping a stream into R2 does, and what a
 * DO route could not do at any size.
 *
 * Nothing here buffers. `request.body` is handed to the bucket as-is, so the
 * bytes cross the isolate as a pipe rather than as a value and a 2 GB upload
 * costs the same memory as a 2 KB one.
 *
 * The first attempt teed the body — one branch to the bucket, one to a
 * `crypto.DigestStream` — to verify the content id while streaming. R2 refuses
 * that: a `put` needs a stream of known length ("request/response body or
 * readable half of FixedLengthStream"), and a tee branch has lost it. Verifying
 * through R2's own `sha256` option is better than working around that, because
 * the check then happens where the bytes land instead of beside them.
 */

/** The bucket binding a deployment supplies.
 *
 *  Absent is a refusal, not a crash — and absent on purpose in some places.
 *  `wrangler.public.toml` runs this same Worker for public sessions and is
 *  deliberately left unbound: the route authenticates with the host control
 *  token rather than the session token, so binding a bucket there would widen
 *  what a public surface can reach for no use it has. The private Home configs
 *  run `private-home.ts`, which serves no object route at all and buffers its
 *  bodies inside grant admission; giving that surface a streaming byte route is
 *  its own change, not a binding. */
export interface ObjectPlaneEnv {
    WHIP_OBJECTS?: R2Bucket;
}

/**
 * A content id is the first 16 bytes of the body's SHA-256, hex.
 *
 * This must match `whipplescript_store::stable_hash_bytes_hex` exactly: the id
 * a caller presents is checked against the bytes it sends, so a mismatch here
 * would either reject every honest upload or accept content under an id that
 * does not describe it.
 */
const CONTENT_ID_BYTES = 16;
const CONTENT_ID_PATTERN = /^[0-9a-f]{32}$/;

function contentIdOf(digest: ArrayBuffer): string {
    return [...new Uint8Array(digest).slice(0, CONTENT_ID_BYTES)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}

/** `/v1/objects/:id`, or undefined for a path this plane does not own. */
export function objectPlaneRoute(pathname: string): string | undefined {
    const match = pathname.match(/^\/v1\/objects\/([^/]+)$/);
    return match ? match[1] : undefined;
}

/**
 * Serve one object-plane request.
 *
 * Returns `undefined` for paths this plane does not own, so the caller falls
 * through to the rest of the Worker.
 */
export async function handleObjectPlane(
    request: Request,
    env: ObjectPlaneEnv,
): Promise<Response | undefined> {
    const id = objectPlaneRoute(new URL(request.url).pathname);
    if (id === undefined) return undefined;

    // The id is the key. Validating its shape first keeps anything that is not
    // a content id — a traversal, a wildcard, an arbitrary caller-chosen name —
    // out of the bucket's namespace entirely.
    if (!CONTENT_ID_PATTERN.test(id)) {
        return Response.json({ error: "not a content id" }, { status: 400 });
    }
    const bucket = env.WHIP_OBJECTS;
    if (!bucket) {
        // The same honesty the Rust seam keeps: a host with nowhere to put
        // bytes says so rather than pretending to have stored them.
        return Response.json(
            { error: "this deployment has no external byte tier bound" },
            { status: 503 },
        );
    }

    switch (request.method) {
        case "PUT":
            return putObject(request, bucket, id);
        case "GET":
            return getObject(request, bucket, id);
        case "HEAD":
            return headObject(bucket, id);
        case "DELETE":
            return deleteObject(bucket, id);
        default:
            return Response.json({ error: "method not allowed" }, { status: 405 });
    }
}

/**
 * Stream a body into the bucket, and refuse it if it is not what its id claims.
 *
 * The verification is the point of a content-addressed tier: an id that does
 * not describe its bytes is worse than a failed upload, because every later
 * reader checks the id, finds it matches what it asked for, and trusts the
 * wrong bytes.
 *
 * The caller sends the body's full SHA-256, and two checks compose into that
 * guarantee. This route checks that the id is the digest's first 16 bytes —
 * pure string work, no bytes read. R2 checks that the bytes actually hash to
 * that digest, server-side and streaming, and fails the `put` otherwise. So
 * `id === first16(sha256(bytes))` holds without this isolate ever seeing a
 * byte, which is the property DR-0033 Decision 4 asks for.
 *
 * Requiring the digest costs the caller nothing: it computed the id from that
 * same hash.
 */
async function putObject(request: Request, bucket: R2Bucket, id: string): Promise<Response> {
    if (!request.body) {
        return Response.json({ error: "a body is required" }, { status: 400 });
    }
    const claimed = (request.headers.get("x-whip-content-sha256") ?? "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(claimed)) {
        return Response.json(
            {
                error:
                    "x-whip-content-sha256 must carry the body's full SHA-256 as 64 hex " +
                    "characters; the content id is its first 16 bytes",
            },
            { status: 400 },
        );
    }
    if (claimed.slice(0, CONTENT_ID_BYTES * 2) !== id) {
        return Response.json(
            { error: "the content id is not the first 16 bytes of the digest sent with it" },
            { status: 400 },
        );
    }

    // R2 stores a stream only when its length is known ahead of the transfer,
    // and `request.body` does not carry one — it reports that only after the
    // checksum passes, so a mismatched upload fails on the digest and a correct
    // one fails on the length, which reads as the digest check working. The
    // documented way through is the readable half of a `FixedLengthStream`,
    // which is still a pipe: the length is declared, the bytes are not held.
    // `Number("")` is 0, not NaN, so an absent header must be rejected before
    // it is parsed — otherwise a missing length reads as a zero-length body and
    // every byte that follows overruns the stream.
    const lengthHeader = request.headers.get("content-length");
    const declared = lengthHeader === null ? Number.NaN : Number(lengthHeader);
    if (!Number.isInteger(declared) || declared < 0) {
        return Response.json(
            {
                error:
                    "content-length is required: the object tier streams to storage, and a " +
                    "stream can only be stored against a length declared before it starts",
            },
            { status: 411 },
        );
    }
    const measured = new FixedLengthStream(declared);
    // Deliberately not awaited: this is the pump. Awaiting it here would want
    // the whole body to pass before the put that consumes the other end
    // starts, which is the buffering this route exists to avoid.
    const pumped = request.body.pipeTo(measured.writable);

    let stored: R2Object;
    try {
        stored = await bucket.put(id, measured.readable, { sha256: claimed });
        await pumped;
    } catch (error) {
        // The pump fails alongside a refused put; its rejection is the same
        // event and must not surface as an unhandled one.
        void pumped.catch(() => undefined);
        const message = error instanceof Error ? error.message : String(error);
        // R2 reports a checksum mismatch as a failed put. That is the
        // content-addressing violation, not a transport fault, so it is the
        // caller's error and says which.
        if (/checksum|sha-?256|digest/i.test(message)) {
            return Response.json(
                { error: "content does not hash to the id it was sent under", id },
                { status: 409 },
            );
        }
        return Response.json({ error: `object write failed: ${message}` }, { status: 502 });
    }
    return Response.json({ id, byte_len: stored.size }, { status: 201 });
}

/** Stream an object out, honouring Range so a reader can take a slice. */
async function getObject(request: Request, bucket: R2Bucket, id: string): Promise<Response> {
    // Whether this is a range read is the REQUEST's business, not the stored
    // object's: R2 populates `range` on an ordinary get too, so keying the 206
    // off that answered every plain read as partial content.
    const ranged = request.headers.get("range") !== null;
    const object = await bucket.get(id, ranged ? { range: request.headers } : undefined);
    if (!object) {
        return Response.json({ error: "no such object" }, { status: 404 });
    }
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    // Bytes, never text: this tier exists for content a text pipe would ruin.
    headers.set("content-type", "application/octet-stream");
    headers.set("x-whip-content-id", id);
    if (ranged && object.range && "offset" in object.range) {
        const offset = object.range.offset ?? 0;
        const length = object.range.length ?? object.size - offset;
        headers.set("content-range", `bytes ${offset}-${offset + length - 1}/${object.size}`);
        return new Response(object.body, { status: 206, headers });
    }
    headers.set("content-length", String(object.size));
    return new Response(object.body, { status: 200, headers });
}

/** Metadata alone — the handle-and-size read the runtime does most often. */
async function headObject(bucket: R2Bucket, id: string): Promise<Response> {
    const object = await bucket.head(id);
    if (!object) {
        return Response.json({ error: "no such object" }, { status: 404 });
    }
    return new Response(null, {
        status: 200,
        headers: {
            "content-length": String(object.size),
            etag: object.httpEtag,
            "x-whip-content-id": id,
        },
    });
}

/** Erasure's other half: the index row is dropped in SQLite, the bytes here. */
async function deleteObject(bucket: R2Bucket, id: string): Promise<Response> {
    await bucket.delete(id);
    // Idempotent by construction — R2 does not distinguish, and neither should
    // a caller retrying an erasure it already completed.
    return new Response(null, { status: 204 });
}
