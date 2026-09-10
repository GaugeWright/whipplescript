import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

/**
 * The private Home's mediated byte route (DR-0112), against a real bucket.
 *
 * The claim under test is an ordering one: the Home settles authorization from
 * the grant's headers **before** it accepts a body, and delegates "are these
 * the bytes the grant names" to the object store, which answers as they land.
 * So these exercise both halves — what a valid grant may place, and what every
 * other shape of request is refused for.
 */

const HOME = "home-objects";
const TENANT = "tenant-objects";
const PROJECT = "project-objects";
const COMMAND = "command-objects";
const EPOCH = 1;

const base =
  `/v1/homes/${HOME}/tenants/${TENANT}/projects/${PROJECT}` +
  `/commands/${COMMAND}/attempts/${EPOCH}`;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A grant naming exactly this body, signed by the test Home authority. */
/** The test Home's key identity, from the worker's own policy fixture. */
async function homeFixture(): Promise<{ key_id: string; signer: string }> {
    const response = await SELF.fetch("https://runtime.test/__test/private-home/policy");
    expect(response.status, await response.clone().text()).toBe(200);
    return response.json<{ key_id: string; signer: string }>();
}

async function grantFor(
    innerPath: string,
    method: "GET" | "POST",
    bodyDigest: string,
): Promise<Record<string, string>> {
    const fixture = await homeFixture();
    const now = Math.floor(Date.now() / 1000);
    const grant = {
        version: 1,
        key_id: fixture.key_id,
        governance_signer: fixture.signer,
        home_id: HOME,
        tenant_id: TENANT,
        project_id: PROJECT,
        work_target_basis: "whipple:cut:private-objects",
        command_id: COMMAND,
        attempt_id: `attempt:${COMMAND}:${EPOCH}`,
        payload_digest: `sha256:${"1".repeat(64)}`,
        epoch: EPOCH,
        profile: "durable_workflow",
        package_ref: "package:test@1",
        capabilities: ["chat"],
        credential_class: "private-home",
        max_spend_nanos_usd: 1_000_000,
        retention_seconds: 3600,
        callback_ref: "https://private-home-broker.test/v1/model-egress",
        request_method: method,
        request_path: innerPath,
        request_body_sha256: bodyDigest,
        issued_at: now,
        expires_at: now + 300,
    };
    const signed = await SELF.fetch("https://runtime.test/__test/private-home/sign", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(grant),
    });
    expect(signed.status, await signed.clone().text()).toBe(200);
    const proof = await signed.json<{ grant: string; signature: string }>();
    return {
        "x-gaugewright-execution-grant": proof.grant,
        "x-gaugewright-execution-signature": proof.signature,
    };
}

/** Place bytes the way an authorized writer would. */
async function place(body: Uint8Array): Promise<{ id: string; response: Response }> {
    const digest = await sha256Hex(body);
    const id = digest.slice(0, 32);
    const inner = `/host/objects/${id}`;
    const response = await SELF.fetch(`https://runtime.test${base}${inner}`, {
        method: "POST",
        body,
        headers: {
            ...(await grantFor(inner, "POST", digest)),
            "content-length": String(body.length),
        },
    });
    return { id, response };
}

describe("the private Home's byte route", () => {
    beforeEach(async () => {
        for (const { key } of (await env.WHIP_OBJECTS.list()).objects) {
            await env.WHIP_OBJECTS.delete(key);
        }
    });

    it("places bytes a grant authorizes, and serves them back", async () => {
        const picture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0, 0xff, 0xfe]);
        const { id, response } = await place(picture);
        expect(response.status, await response.clone().text()).toBe(201);
        expect(await response.json()).toMatchObject({ id, byte_len: picture.length });

        // In the bucket, byte-identical.
        const stored = await env.WHIP_OBJECTS.get(id);
        expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(picture);

        // And readable back through the Home, which needs its own grant.
        const inner = `/host/objects/${id}`;
        const read = await SELF.fetch(`https://runtime.test${base}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(picture)),
        });
        expect(read.status).toBe(200);
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(picture);
    });

    /** The grant names one content id. It authorizes that content at its own
     *  address — not "a write", which a holder could redirect elsewhere. */
    it("refuses a grant that names different content than the object addressed", async () => {
        const authorized = new Uint8Array([1, 2, 3, 4]);
        const other = new Uint8Array([5, 6, 7, 8]);
        const otherId = (await sha256Hex(other)).slice(0, 32);
        const inner = `/host/objects/${otherId}`;

        // A grant for `authorized`, aimed at `other`'s address.
        const response = await SELF.fetch(`https://runtime.test${base}${inner}`, {
            method: "POST",
            body: other,
            headers: {
                ...(await grantFor(inner, "POST", await sha256Hex(authorized))),
                "content-length": String(other.length),
            },
        });
        expect(response.status).toBe(403);
        expect(await response.json()).toMatchObject({
            error: expect.stringContaining("authorizes different content"),
        });
        expect(await env.WHIP_OBJECTS.head(otherId)).toBeNull();
    });

    /** Authorization is settled before the body; integrity is settled by the
     *  store as it lands. This is the second half failing. */
    it("refuses bytes that are not the ones the grant names", async () => {
        const named = new Uint8Array([1, 1, 1, 1]);
        const digest = await sha256Hex(named);
        const id = digest.slice(0, 32);
        const inner = `/host/objects/${id}`;

        const response = await SELF.fetch(`https://runtime.test${base}${inner}`, {
            method: "POST",
            body: new Uint8Array([9, 9, 9, 9]),
            headers: {
                ...(await grantFor(inner, "POST", digest)),
                "content-length": "4",
            },
        });
        expect(response.status, await response.clone().text()).toBe(409);
        expect(await env.WHIP_OBJECTS.head(id)).toBeNull();
    });

    it("refuses a request carrying no grant at all", async () => {
        const body = new Uint8Array([1]);
        const id = (await sha256Hex(body)).slice(0, 32);
        const response = await SELF.fetch(`https://runtime.test${base}/host/objects/${id}`, {
            method: "POST",
            body,
            headers: { "content-length": "1" },
        });
        expect(response.status).toBe(401);
    });

    /** The Home's door is a grant, never the host control token. A credential
     *  that opens the object plane on the shared Worker must not open a Home. */
    it("refuses the host control token in place of a grant", async () => {
        const body = new Uint8Array([1]);
        const id = (await sha256Hex(body)).slice(0, 32);
        const response = await SELF.fetch(`https://runtime.test${base}/host/objects/${id}`, {
            method: "POST",
            body,
            headers: { authorization: "Bearer control-token", "content-length": "1" },
        });
        expect(response.status).toBe(401);
    });

    /** The length rule itself is unit-tested in `object-store.test.ts`: the
     *  condition cannot be built through this surface, because workerd gives
     *  every body it constructs a content-length. Both byte routes call the
     *  same `declaredLength`, so pinning it once pins it for both. */

    /** A body far past the control-plane cap goes through, because bytes too
     *  large to hold are the whole reason this route exists. */
    it("carries a body larger than the control-plane body cap", async () => {
        const big = new Uint8Array(2 * 1024 * 1024);
        crypto.getRandomValues(big.subarray(0, 65536));
        for (let at = 65536; at < big.length; at += 65536) {
            big.copyWithin(at, 0, Math.min(65536, big.length - at));
        }
        const { id, response } = await place(big);
        expect(response.status, await response.clone().text()).toBe(201);
        const stored = await env.WHIP_OBJECTS.head(id);
        expect(stored?.size).toBe(big.length);
    });
});
