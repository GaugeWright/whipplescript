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
 *
 * That reasoning is about a PUSH, and it still holds for one: a writer already
 * knows the digest, so there is nothing to compute and only a claim to check.
 * It does not reach the other direction. On INGEST the bytes come from a URL
 * nobody has read yet, so no digest exists to hand R2, and this route has to
 * maintain one across the transfer itself.
 *
 * It does that without a tee. The pump reads the upstream body and writes each
 * chunk to two writers — a `FixedLengthStream` whose readable half the bucket
 * takes, and a `crypto.DigestStream` — so the length is declared rather than
 * lost, and back-pressure still reaches upstream because both writes are
 * awaited. Nothing here buffers in either direction.
 *
 * What that costs is the key. `put` has to name one before the last chunk
 * decides what the digest is, so an ingested object cannot be keyed on its id
 * and is keyed on a minted `s-`-prefixed token instead, which the durable
 * object records against the id. R2's Workers binding has no copy or rename,
 * so the alternative to a mapping is a second full transfer of the same bytes.
 * The invariant that mattered survives either way: an id is still the hash of
 * the bytes it names — computed from them here, rather than asserted about them
 * and checked, which is the honest difference between the two directions.
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
    /** Hosts this deployment will ingest bytes from, comma-separated.
     *
     *  Ingest fetches a URL, and the URL arrives from a model provider's
     *  response — which is to say from somewhere a prompt can influence.
     *  Without a declared list that is a request forger with this Worker's
     *  network position, so an unset binding refuses the route outright rather
     *  than defaulting to "anywhere". Authority here is declared by a
     *  deployment, never inferred from the value that wants to use it. */
    WHIP_INGEST_HOSTS?: string;
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

/**
 * Where ingested bytes sit: `s-` and sixteen random bytes, hex.
 *
 * A key is chosen before the digest exists, so it cannot be the id. It can
 * still be as narrow in shape as one, and has to be: keying on the hash is what
 * kept traversals, wildcards and arbitrary caller-chosen names out of the
 * bucket's namespace, and a second key form is a second door into it. The `s-`
 * prefix cannot collide with an id, which is hex throughout.
 *
 * Only this route mints them. A PUT still demands a content id, because a
 * writer that holds the digest has no reason not to key on it — and every
 * reason to, since that is what makes its claim checkable.
 */
const STAGED_KEY_PATTERN = /^s-[0-9a-f]{32}$/;

function mintStagedKey(): string {
    const token = crypto.getRandomValues(new Uint8Array(16));
    return `s-${[...token].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function contentIdOf(digest: ArrayBuffer): string {
    return [...new Uint8Array(digest).slice(0, CONTENT_ID_BYTES)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * The declared body length, or `null` when there is not one to trust.
 *
 * Shared by both byte routes because both owe the same promise: a stream is
 * stored against a length known before it starts, and reading the body to
 * discover its size is the one thing neither may do.
 *
 * `Number("")` is 0, not NaN, so an absent header must be rejected before it is
 * parsed — otherwise a missing length reads as a zero-length body and every
 * byte that follows overruns the stream.
 */
export function declaredLength(headers: Headers): number | null {
    const raw = headers.get("content-length");
    if (raw === null) return null;
    // Decimal digits only, matched before parsing. `Number` is far more
    // generous than HTTP is — it reads "0x10" as 16, and " 12 " as 12 — and a
    // length that disagrees with the bytes it describes is exactly what this
    // function exists to refuse.
    if (!/^[0-9]+$/.test(raw.trim())) return null;
    const value = Number(raw.trim());
    return Number.isSafeInteger(value) ? value : null;
}

/** `/v1/objects/:key`, or undefined for a path this plane does not own. */
export function objectPlaneRoute(pathname: string): string | undefined {
    const match = pathname.match(/^\/v1\/objects\/([^/]+)$/);
    return match ? match[1] : undefined;
}

/** Pull bytes from a declared source, rather than taking a pushed body. */
export const INGEST_PATH = "/v1/object-ingest";

/** How many hops an ingest will follow before it calls the source broken. */
const MAX_INGEST_REDIRECTS = 4;

/**
 * How large an ingest's own request body may be.
 *
 * The object plane is routed ahead of the Worker's control-body cap, because
 * that cap exists for JSON the isolate parses and the byte routes carry
 * precisely the bodies too large to hold. Ingest is the exception inside the
 * exception: its request is JSON the isolate parses, and only its *source* is
 * large. So it carries a cap of its own rather than inheriting an exemption
 * written for a different kind of body. A URL and its wrapper fit easily.
 */
const MAX_INGEST_REQUEST_BYTES = 8 * 1024;

/**
 * The hosts this deployment declared it will ingest from.
 *
 * Empty is a refusal, like an unbound bucket is: a deployment that named no
 * source has not enabled ingest, and the honest answer is that rather than
 * fetching whatever it was handed.
 */
export function ingestAllowlist(env: ObjectPlaneEnv): Set<string> {
    return new Set(
        (env.WHIP_INGEST_HOSTS ?? "")
            .split(",")
            .map((host) => host.trim().toLowerCase())
            .filter((host) => host.length > 0),
    );
}

/**
 * Why this URL will not be fetched, or undefined if it will.
 *
 * The URL reaches here from a model provider's answer, so it is attacker-
 * influencable in the ordinary case rather than the exotic one, and this Worker
 * has a network position worth borrowing. Every check below is about that: the
 * scheme, so bytes and any credential on the way to them cross the wire
 * encrypted; the userinfo, because `fetch` would send it; the port, so a
 * declared host cannot be turned into a scan of the services behind it; and the
 * host itself, against a list a deployment wrote.
 */
export function ingestRefusal(raw: string, allowed: Set<string>): string | undefined {
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        return "the ingest source is not a URL";
    }
    if (url.protocol !== "https:") {
        return `ingest reads over https; \`${url.protocol}\` is not it`;
    }
    if (url.username !== "" || url.password !== "") {
        return "an ingest source may not carry credentials in its URL";
    }
    if (url.port !== "" && url.port !== "443") {
        return `ingest reads https on its own port; \`${url.port}\` is not it`;
    }
    if (!allowed.has(url.hostname.toLowerCase())) {
        return `\`${url.hostname}\` is not a host this deployment ingests from`;
    }
    return undefined;
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
    const pathname = new URL(request.url).pathname;
    const ingesting = pathname === INGEST_PATH;
    const key = ingesting ? undefined : objectPlaneRoute(pathname);
    if (!ingesting && key === undefined) return undefined;

    // Validating the key's shape first keeps anything that is neither a content
    // id nor a minted staging token — a traversal, a wildcard, an arbitrary
    // caller-chosen name — out of the bucket's namespace entirely.
    if (key !== undefined && !CONTENT_ID_PATTERN.test(key) && !STAGED_KEY_PATTERN.test(key)) {
        return Response.json({ error: "not an object key" }, { status: 400 });
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

    if (key === undefined) {
        if (request.method !== "POST") {
            return Response.json({ error: "method not allowed" }, { status: 405 });
        }
        return ingestObject(request, bucket, env);
    }

    switch (request.method) {
        case "PUT":
            // A writer holding the digest has no reason to key on anything but
            // the id, and every reason to: keying on it is what makes the
            // claim it sends checkable. A staging key carries no such claim, so
            // accepting one here would be a way to write unverified bytes.
            if (!CONTENT_ID_PATTERN.test(key)) {
                return Response.json(
                    { error: "a written object is keyed on its content id" },
                    { status: 400 },
                );
            }
            return putObject(request, bucket, key);
        case "GET":
            return getObject(request, bucket, key);
        case "HEAD":
            return headObject(bucket, key);
        case "DELETE":
            return deleteObject(bucket, key);
        default:
            return Response.json({ error: "method not allowed" }, { status: 405 });
    }
}

/**
 * Follow the source to its bytes, checking every hop against the allowlist.
 *
 * Redirects are followed by hand rather than by `fetch`, because a list checked
 * only at the first URL is not a list: one open redirector on a declared host
 * would forward the fetch anywhere, which is the thing being refused. So each
 * `Location` re-enters `ingestRefusal` exactly as the original did.
 */
async function fetchIngestSource(
    raw: string,
    allowed: Set<string>,
): Promise<{ response: Response } | { error: string; status: number }> {
    let target = raw;
    for (let hop = 0; hop <= MAX_INGEST_REDIRECTS; hop += 1) {
        const refusal = ingestRefusal(target, allowed);
        if (refusal) return { error: refusal, status: 403 };
        let response: Response;
        try {
            response = await fetch(target, { redirect: "manual" });
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { error: `ingest source unreachable: ${message}`, status: 502 };
        }
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location");
            // Nothing was read from a redirect, but something was opened.
            await response.body?.cancel().catch(() => undefined);
            if (!location) {
                return { error: "the ingest source redirected without a location", status: 502 };
            }
            try {
                target = new URL(location, target).toString();
            } catch {
                return { error: "the ingest source redirected to a non-URL", status: 502 };
            }
            continue;
        }
        if (!response.ok) {
            await response.body?.cancel().catch(() => undefined);
            return { error: `the ingest source answered ${response.status}`, status: 502 };
        }
        return { response };
    }
    return { error: "the ingest source redirected too many times", status: 502 };
}

/**
 * Pull bytes from a declared source into the bucket, and learn what they are.
 *
 * The digest is maintained across the transfer rather than known before it, so
 * the answer carries the id the bytes turned out to have. A caller cannot ask
 * for an id here — that is the difference from `putObject`, and it is why there
 * is nothing for this route to refuse about identity: an id produced from the
 * bytes cannot disagree with them the way a claim about them can.
 *
 * What the caller does owe is the registration. Until the durable object
 * records `id -> storage_key`, the object in the bucket is bytes nothing can
 * name, and the answer below is the only place that pairing exists.
 */
async function ingestObject(
    request: Request,
    bucket: R2Bucket,
    env: ObjectPlaneEnv,
): Promise<Response> {
    const allowed = ingestAllowlist(env);
    if (allowed.size === 0) {
        return Response.json(
            { error: "this deployment declares no ingest sources" },
            { status: 503 },
        );
    }
    const requestBytes = declaredLength(request.headers);
    if (requestBytes === null || requestBytes > MAX_INGEST_REQUEST_BYTES) {
        return Response.json(
            {
                error:
                    `an ingest request declares a content-length no larger than ` +
                    `${MAX_INGEST_REQUEST_BYTES} bytes; it names a source, it does not carry one`,
            },
            { status: requestBytes === null ? 411 : 413 },
        );
    }
    const asked = (await request.json().catch(() => null)) as { url?: unknown } | null;
    if (typeof asked?.url !== "string") {
        return Response.json({ error: "`url` must name the bytes to ingest" }, { status: 400 });
    }
    const fetched = await fetchIngestSource(asked.url, allowed);
    if ("error" in fetched) {
        return Response.json({ error: fetched.error }, { status: fetched.status });
    }
    const upstream = fetched.response;
    if (!upstream.body) {
        return Response.json({ error: "the ingest source sent no body" }, { status: 502 });
    }
    // Same requirement as a push, for the same reason, and satisfied by a
    // different party: R2 stores a stream only against a length declared before
    // it starts, and here that is the source's `content-length` rather than the
    // caller's. A source that will not say how much it is sending cannot be
    // streamed to storage, and buffering it to find out is the one thing this
    // route may not do.
    const declared = declaredLength(upstream.headers);
    if (declared === null) {
        await upstream.body.cancel().catch(() => undefined);
        return Response.json(
            {
                error:
                    "the ingest source declared no content-length: the object tier streams to " +
                    "storage, and a stream can only be stored against a length known first",
            },
            { status: 411 },
        );
    }

    const storageKey = mintStagedKey();
    const digest = new crypto.DigestStream("SHA-256");
    const digestWriter = digest.getWriter();
    const measured = new FixedLengthStream(declared);
    const bodyWriter = measured.writable.getWriter();
    // A writer's `closed` settles alongside the write that failed, and so does
    // the digest, and nothing below observes either on the failure path. Left
    // alone they surface as unhandled rejections — a refusal this route handles
    // correctly, reported as a crash somewhere else. Observing them here does
    // not consume them: the failure still reaches the `put`, which is where it
    // is answered. A source that overruns the length it declared is the case.
    void bodyWriter.closed.catch(() => undefined);
    void digestWriter.closed.catch(() => undefined);
    void digest.digest.catch(() => undefined);
    // One read, two writers, no tee. Both writes are awaited, so back-pressure
    // from the bucket reaches the source and neither side runs ahead of the
    // other into memory. Deliberately not awaited here: this is the pump, and
    // the `put` that drains the other end has not started yet.
    const pumped = (async () => {
        const reader = upstream.body!.getReader();
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                await bodyWriter.write(value);
                await digestWriter.write(value);
            }
            await bodyWriter.close();
            await digestWriter.close();
        } catch (error) {
            // Everything this pump opened is closed on the way out: the two
            // writers, and the read of a source that is still sending. Leaving
            // the source's reader alive keeps a transfer running for a response
            // that has already been refused.
            await reader.cancel(error).catch(() => undefined);
            await bodyWriter.abort(error).catch(() => undefined);
            await digestWriter.abort(error).catch(() => undefined);
            throw error;
        }
    })();

    let stored: R2Object;
    try {
        const written = await bucket.put(storageKey, measured.readable);
        // Only a conditional put declines to write, and this one is not; a null
        // here would mean the bucket said nothing happened, which must not read
        // as a stored object.
        if (!written) throw new Error("the bucket declined the write");
        stored = written;
        await pumped;
    } catch (error) {
        // The pump fails alongside a refused put; its rejection is the same
        // event and must not surface as an unhandled one.
        void pumped.catch(() => undefined);
        // A key nothing will ever be told about is a key nothing can collect,
        // so a failed ingest takes its own object with it. A source whose bytes
        // disagree with its declared length lands here, through the length the
        // stream was opened against.
        await bucket.delete(storageKey).catch(() => undefined);
        const message = error instanceof Error ? error.message : String(error);
        return Response.json({ error: `ingest failed: ${message}` }, { status: 502 });
    }
    return Response.json(
        { id: contentIdOf(await digest.digest), byte_len: stored.size, storage_key: storageKey },
        { status: 201 },
    );
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
    const declared = declaredLength(request.headers);
    if (declared === null) {
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
    // The key, and the id only when the key is one. An ingested object's key is
    // a staging token, and naming it a content id would put a string that is
    // not a hash where every reader expects one.
    headers.set("x-whip-object-key", id);
    if (CONTENT_ID_PATTERN.test(id)) {
        headers.set("x-whip-content-id", id);
    }
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
            "x-whip-object-key": id,
            ...(CONTENT_ID_PATTERN.test(id) ? { "x-whip-content-id": id } : {}),
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
