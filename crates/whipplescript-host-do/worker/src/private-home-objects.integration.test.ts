import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { durableWorkflowObjectName, privateObjectStorageKey } from "./private-home-protocol";

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
const AGENT = "agent-objects";
const TARGET = "authoring-target-objects";
const COMMAND = "command-objects";
const EPOCH = 1;

const baseFor = (command = COMMAND, epoch = EPOCH) =>
  `/v1/homes/${HOME}/tenants/${TENANT}/projects/${PROJECT}` +
  `/commands/${command}/attempts/${epoch}`;

const agentBaseFor = (command: string, epoch = EPOCH) =>
  `/v1/homes/${HOME}/tenants/${TENANT}/agents/${AGENT}/authoring-targets/${TARGET}` +
  `/commands/${command}/attempts/${epoch}`;

const storageKeyFor = (id: string, command = COMMAND) => privateObjectStorageKey({
    home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: command,
}, id);

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A grant naming exactly this body, signed by the test Home authority. */
/** The test Home's key identity, from the worker's own policy fixture. */
async function homeFixture(): Promise<{ key_id: string; signer: string; governance_key_id: string }> {
    const response = await SELF.fetch("https://runtime.test/__test/private-home/policy");
    expect(response.status, await response.clone().text()).toBe(200);
    return response.json<{ key_id: string; signer: string; governance_key_id: string }>();
}

async function privateHeadersForObject(id: string, digest: string): Promise<Record<string, string>> {
    const fixture = await homeFixture();
    const signed = await grantFor(`/host/objects/${id}`, "GET", digest);
    return {
        authorization: "Bearer control-token",
        "x-gaugewright-private-governance-signer": fixture.signer,
        "x-gaugewright-private-governance-key": fixture.governance_key_id,
        "x-gaugewright-private-callback": "https://private-home-broker.test/v1/model-egress",
        "x-gaugewright-private-execution-grant": signed["x-gaugewright-execution-grant"],
        "x-gaugewright-private-execution-signature": signed["x-gaugewright-execution-signature"],
    };
}

async function grantFor(
    innerPath: string,
    method: "GET" | "POST",
    bodyDigest: string,
    command = COMMAND,
    epoch = EPOCH,
    packageRef = "package:test@1",
    retirementAuthorized = false,
    agentAuthoring = false,
): Promise<Record<string, string>> {
    const fixture = await homeFixture();
    const now = Math.floor(Date.now() / 1000);
    const grant = {
        version: 1,
        key_id: fixture.key_id,
        governance_signer: fixture.signer,
        home_id: HOME,
        tenant_id: TENANT,
        project_id: agentAuthoring ? "" : PROJECT,
        work_target_basis: agentAuthoring ? "" : "whipple:cut:private-objects",
        ...(agentAuthoring ? { agent_authoring: {
            agent_id: AGENT,
            target_id: TARGET,
            target_main_basis: "cut:agent-objects",
        } } : {}),
        command_id: command,
        attempt_id: `attempt:${command}:${epoch}`,
        payload_digest: `sha256:${"1".repeat(64)}`,
        epoch,
        profile: "durable_workflow",
        package_ref: packageRef,
        capabilities: ["chat"],
        credential_class: "private-home",
        max_spend_nanos_usd: 1_000_000,
        retention_seconds: 3600,
        callback_ref: "https://private-home-broker.test/v1/model-egress",
        request_method: method,
        request_path: innerPath,
        request_body_sha256: bodyDigest,
        ...(retirementAuthorized ? { retirement_authorized: true } : {}),
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
async function place(body: Uint8Array, command = COMMAND, epoch = EPOCH): Promise<{ id: string; response: Response }> {
    const digest = await sha256Hex(body);
    const id = digest.slice(0, 32);
    const inner = `/host/objects/${id}`;
    const response = await SELF.fetch(`https://runtime.test${baseFor(command, epoch)}${inner}`, {
        method: "POST",
        body,
        headers: {
            ...(await grantFor(inner, "POST", digest, command, epoch)),
            "content-length": String(body.length),
        },
    });
    return { id, response };
}

async function retire(command: string, epoch = EPOCH): Promise<Response> {
    const inner = "/host/private/retire";
    const body = JSON.stringify({
        version: 1,
        attempt_id: `attempt:${command}:${epoch}`,
        epoch,
        terminal_phase: "completed",
        terminal_receipt_sha256: "a".repeat(64),
    });
    return SELF.fetch(`https://runtime.test${baseFor(command, epoch)}${inner}`, {
        method: "POST",
        headers: {
            ...(await grantFor(inner, "POST", await sha256Hex(new TextEncoder().encode(body)), command, epoch, "package:test@1", true)),
            "content-type": "application/json",
        },
        body,
    });
}

async function retirementRequest(command: string, authorized: boolean, failDelete = false): Promise<Response> {
    const inner = "/host/private/retire";
    const body = JSON.stringify({
        version: 1,
        attempt_id: `attempt:${command}:${EPOCH}`,
        epoch: EPOCH,
        terminal_phase: "completed",
        terminal_receipt_sha256: "a".repeat(64),
    });
    return SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
        method: "POST",
        headers: {
            ...(await grantFor(inner, "POST", await sha256Hex(new TextEncoder().encode(body)), command, EPOCH,
                "package:test@1", authorized)),
            "content-type": "application/json",
            ...(failDelete ? { "x-test-private-r2-delete-fail": "1" } : {}),
        },
        body,
    });
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
        const stored = await env.WHIP_OBJECTS.get(await storageKeyFor(id));
        expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(picture);
        expect(await env.WHIP_OBJECTS.head(id)).toBeNull();

        // And readable back through the Home, which needs its own grant.
        const inner = `/host/objects/${id}`;
        const read = await SELF.fetch(`https://runtime.test${baseFor()}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(picture)),
        });
        expect(read.status).toBe(200);
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(picture);
    });

    // command-bound-byte-keys
    it("keeps equal content in independently collectible command copies", async () => {
        const bytes = new Uint8Array([31, 41, 59, 26]);
        const first = await place(bytes, "private-copy-first");
        const second = await place(bytes, "private-copy-second");
        expect(first.response.status, await first.response.clone().text()).toBe(201);
        expect(second.response.status, await second.response.clone().text()).toBe(201);
        expect(first.id).toBe(second.id);
        const firstKey = await storageKeyFor(first.id, "private-copy-first");
        const secondKey = await storageKeyFor(first.id, "private-copy-second");
        expect(firstKey).not.toBe(secondKey);
        expect(await env.WHIP_OBJECTS.head(firstKey)).not.toBeNull();
        expect(await env.WHIP_OBJECTS.head(secondKey)).not.toBeNull();
        await env.WHIP_OBJECTS.delete(firstKey);
        // Even a legacy/global copy with equal bytes cannot substitute for
        // the first command's registered key after that key is collected.
        await env.WHIP_OBJECTS.put(first.id, bytes);
        const inner = `/host/objects/${first.id}`;
        const firstRead = await SELF.fetch(`https://runtime.test${baseFor("private-copy-first")}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), "private-copy-first"),
        });
        expect(firstRead.status).toBe(404);
        const read = await SELF.fetch(`https://runtime.test${baseFor("private-copy-second")}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), "private-copy-second"),
        });
        expect(read.status).toBe(200);
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(bytes);
    });

    it("fences and collects one command without deleting another's equal bytes", async () => {
        const bytes = new Uint8Array([4, 2, 4, 2]);
        const firstCommand = "retiring-copy";
        const secondCommand = "retained-copy";
        const first = await place(bytes, firstCommand);
        const second = await place(bytes, secondCommand);
        expect(first.response.status, await first.response.clone().text()).toBe(201);
        expect(second.response.status, await second.response.clone().text()).toBe(201);
        const firstKey = await storageKeyFor(first.id, firstCommand);
        const secondKey = await storageKeyFor(second.id, secondCommand);
        const retired = await retire(firstCommand);
        expect(retired.status, await retired.clone().text()).toBe(200);
        expect(await retired.json()).toMatchObject({ phase: "collected" });
        const object = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: firstCommand,
            }),
        ));
        const storage = await runInDurableObject(object, async (_instance, state) => ({
            bindings: state.storage.sql.exec("SELECT COUNT(*) AS n FROM content_external_blobs").one().n,
            execution: state.storage.sql.exec("SELECT COUNT(*) AS n FROM private_execution_context").one().n,
            debt: state.storage.sql.exec("SELECT COUNT(*) AS n FROM private_retirement_debt WHERE collected = 0").one().n,
            kv: (await state.storage.list()).size,
            alarm: await state.storage.getAlarm(),
        }));
        expect(storage).toMatchObject({ bindings: 0, execution: 0, debt: 0, kv: 0, alarm: null });
        expect(await env.WHIP_OBJECTS.head(firstKey)).toBeNull();
        expect(await env.WHIP_OBJECTS.head(secondKey)).not.toBeNull();
        const retry = await retire(firstCommand);
        expect(retry.status, await retry.clone().text()).toBe(200);
        const inner = `/host/objects/${first.id}`;
        const denied = await SELF.fetch(`https://runtime.test${baseFor(firstCommand)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), firstCommand),
        });
        expect(denied.status).toBe(410);
        const retained = await SELF.fetch(`https://runtime.test${baseFor(secondCommand)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), secondCommand),
        });
        expect(retained.status).toBe(200);
        expect(new Uint8Array(await retained.arrayBuffer())).toEqual(bytes);
    });

    // signed-agent-authoring-route
    it("keeps Agent-authoring bytes and retirement in their non-project command", async () => {
        const command = "agent-authoring-object";
        const bytes = new Uint8Array([6, 1, 2, 6]);
        const digest = await sha256Hex(bytes);
        const id = digest.slice(0, 32);
        const inner = `/host/objects/${id}`;
        const placed = await SELF.fetch(`https://runtime.test${agentBaseFor(command)}${inner}`, {
            method: "POST",
            body: bytes,
            headers: {
                ...(await grantFor(inner, "POST", digest, command, EPOCH, "package:test@1", false, true)),
                "content-length": String(bytes.length),
            },
        });
        expect(placed.status, await placed.clone().text()).toBe(201);
        const storageKey = await privateObjectStorageKey({
            home_id: HOME, tenant_id: TENANT, project_id: "", command_id: command,
            agent_authoring: { agent_id: AGENT, target_id: TARGET, target_main_basis: "cut:agent-objects" },
        }, id);
        expect(await env.WHIP_OBJECTS.head(storageKey)).not.toBeNull();
        const readGrant = await grantFor(inner, "GET", digest, command, EPOCH, "package:test@1", false, true);
        const read = await SELF.fetch(`https://runtime.test${agentBaseFor(command)}${inner}`, {
            method: "GET", headers: readGrant,
        });
        expect(read.status).toBe(200);
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(bytes);
        const replay = await SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
            method: "GET", headers: readGrant,
        });
        expect(replay.status).toBe(403);
        const retirement = "/host/private/retire";
        const receipt = JSON.stringify({
            version: 1, attempt_id: `attempt:${command}:${EPOCH}`, epoch: EPOCH,
            terminal_phase: "completed", terminal_receipt_sha256: "a".repeat(64),
        });
        const retired = await SELF.fetch(`https://runtime.test${agentBaseFor(command)}${retirement}`, {
            method: "POST",
            headers: {
                ...(await grantFor(retirement, "POST", await sha256Hex(new TextEncoder().encode(receipt)),
                    command, EPOCH, "package:test@1", true, true)),
                "content-type": "application/json",
            },
            body: receipt,
        });
        expect(retired.status, await retired.clone().text()).toBe(200);
        expect(await env.WHIP_OBJECTS.head(storageKey)).toBeNull();
        const late = await SELF.fetch(`https://runtime.test${agentBaseFor(command)}${inner}`, {
            method: "GET", headers: readGrant,
        });
        expect(late.status).toBe(410);
    });

    // private-command-retirement
    it("requires explicit terminal Home authority before fencing a command", async () => {
        const command = "retire-authority";
        const bytes = new Uint8Array([9, 7, 9, 7]);
        const placed = await place(bytes, command);
        expect(placed.response.status).toBe(201);
        const ordinary = await retirementRequest(command, false);
        expect(ordinary.status).toBe(403);
        expect(await env.WHIP_OBJECTS.head(await storageKeyFor(placed.id, command))).not.toBeNull();
        const terminal = await retirementRequest(command, true);
        expect(terminal.status, await terminal.clone().text()).toBe(200);
    });

    it("refuses a forged terminal grant at the command object itself", async () => {
        const command = "retire-forged-grant";
        const bytes = new Uint8Array([8, 8, 1, 3]);
        const placed = await place(bytes, command);
        expect(placed.response.status).toBe(201);
        const body = JSON.stringify({
            version: 1, attempt_id: `attempt:${command}:${EPOCH}`, epoch: EPOCH,
            terminal_phase: "completed", terminal_receipt_sha256: "a".repeat(64),
        });
        const grant = await grantFor("/host/private/retire", "POST",
            await sha256Hex(new TextEncoder().encode(body)), command, EPOCH, "package:test@1", true);
        const fixture = await homeFixture();
        const object = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: command,
            }),
        ));
        const forged = await object.fetch("https://instance/host/private/retire", {
            method: "POST",
            headers: {
                authorization: "Bearer control-token",
                "x-gaugewright-private-governance-signer": fixture.signer,
                "x-gaugewright-private-governance-key": fixture.governance_key_id,
                "x-gaugewright-private-execution-grant": grant["x-gaugewright-execution-grant"],
                "x-gaugewright-private-execution-signature": "invalid",
            },
            body,
        });
        expect(forged.status, await forged.clone().text()).toBe(403);
        expect(await env.WHIP_OBJECTS.head(await storageKeyFor(placed.id, command))).not.toBeNull();
    });

    it("keeps the command fenced and collection debt retryable when R2 deletion fails", async () => {
        const command = "retire-delete-retry";
        const bytes = new Uint8Array([3, 1, 4, 1]);
        const placed = await place(bytes, command);
        expect(placed.response.status).toBe(201);
        const key = await storageKeyFor(placed.id, command);
        const failed = await retirementRequest(command, true, true);
        expect(failed.status, await failed.clone().text()).toBe(503);
        expect(await env.WHIP_OBJECTS.head(key)).not.toBeNull();
        const late = await place(new Uint8Array([3, 1, 4, 2]), command);
        expect(late.response.status).toBe(410);
        const retry = await retirementRequest(command, true);
        expect(retry.status, await retry.clone().text()).toBe(200);
        expect(await env.WHIP_OBJECTS.head(key)).toBeNull();
    });

    it("reports legacy shared-key debt without deleting the global copy", async () => {
        const command = "retire-legacy-key";
        const bytes = new Uint8Array([5, 3, 5, 8]);
        const digest = await sha256Hex(bytes);
        const id = digest.slice(0, 32);
        await env.WHIP_OBJECTS.put(id, bytes);
        const inner = `/host/objects/${id}`;
        const unbound = await SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
            method: "GET", headers: await grantFor(inner, "GET", digest, command),
        });
        expect(unbound.status).toBe(404);
        const object = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: command,
            }),
        ));
        const registered = await object.fetch("https://instance/host/objects/register", {
            method: "POST",
            headers: { authorization: "Bearer control-token", "content-type": "application/json" },
            body: JSON.stringify({ id, byte_len: bytes.length }),
        });
        expect(registered.status, await registered.clone().text()).toBe(200);
        const retired = await retirementRequest(command, true);
        expect(retired.status, await retired.clone().text()).toBe(202);
        expect(await retired.json()).toMatchObject({ phase: "legacy-key-debt", legacy_pending: 1 });
        expect(await env.WHIP_OBJECTS.head(id)).not.toBeNull();
        const read = await SELF.fetch(`https://runtime.test${baseFor(command)}/host/objects/${id}`, {
            method: "GET", headers: await grantFor(`/host/objects/${id}`, "GET", digest, command),
        });
        expect(read.status).toBe(410);
    });

    it("refuses a late grant from an attempt superseded on the same command object", async () => {
        const bytes = new Uint8Array([9, 2, 6, 5]);
        const command = "attempt-supersession";
        const first = await place(bytes, command);
        expect(first.response.status, await first.response.clone().text()).toBe(201);
        const next = await place(bytes, command, EPOCH + 1);
        expect(next.response.status, await next.response.clone().text()).toBe(201);
        const inner = `/host/objects/${first.id}`;
        const digest = await sha256Hex(bytes);
        const oldRead = await SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", digest, command),
        });
        expect(oldRead.status).toBe(409);
        const oldWrite = await place(bytes, command);
        expect(oldWrite.response.status).toBe(409);
        const currentRead = await SELF.fetch(`https://runtime.test${baseFor(command, EPOCH + 1)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", digest, command, EPOCH + 1),
        });
        expect(currentRead.status).toBe(200);
        expect(new Uint8Array(await currentRead.arrayBuffer())).toEqual(bytes);
    });

    it("pins the package snapshot across grants for one attempt", async () => {
        const bytes = new Uint8Array([1, 6, 1, 8]);
        const command = "package-snapshot";
        const { id, response } = await place(bytes, command);
        expect(response.status, await response.clone().text()).toBe(201);
        const inner = `/host/objects/${id}`;
        const changed = await SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), command, EPOCH, "package:other@1"),
        });
        expect(changed.status).toBe(409);
        const original = await SELF.fetch(`https://runtime.test${baseFor(command)}${inner}`, {
            method: "GET",
            headers: await grantFor(inner, "GET", await sha256Hex(bytes), command),
        });
        expect(original.status).toBe(200);
    });

    it("keeps older private command bytes under their global key readable", async () => {
        const bytes = new Uint8Array([7, 7, 7, 3]);
        const digest = await sha256Hex(bytes);
        const id = digest.slice(0, 32);
        await env.WHIP_OBJECTS.put(id, bytes);
        const inner = `/host/objects/${id}`;
        const headers = await grantFor(inner, "GET", digest);
        const unbound = await SELF.fetch(`https://runtime.test${baseFor()}${inner}`, {
            method: "GET", headers,
        });
        expect(unbound.status).toBe(404);
        const legacyObject = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: COMMAND,
            }),
        ));
        const registered = await legacyObject.fetch("https://instance/host/objects/register", {
            method: "POST",
            headers: {
                authorization: "Bearer control-token",
                "content-type": "application/json",
            },
            body: JSON.stringify({ id, byte_len: bytes.length }),
        });
        expect(registered.status, await registered.clone().text()).toBe(200);
        const read = await SELF.fetch(`https://runtime.test${baseFor()}${inner}`, {
            method: "GET",
            headers,
        });
        expect(read.status).toBe(200);
        expect(new Uint8Array(await read.arrayBuffer())).toEqual(bytes);
        const repeated = await place(bytes);
        expect(repeated.response.status, await repeated.response.clone().text()).toBe(201);
        expect(await env.WHIP_OBJECTS.head(await storageKeyFor(id))).toBeNull();
        expect(await env.WHIP_OBJECTS.head(id)).not.toBeNull();
    });

    it("does not expose a command's physical byte key to a bare control bearer", async () => {
        const bytes = new Uint8Array([2, 7, 1, 8]);
        const { id, response } = await place(bytes);
        expect(response.status, await response.clone().text()).toBe(201);
        const commandObject = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: COMMAND,
            }),
        ));
        const bare = await commandObject.fetch(`https://instance/__private/object-binding/${id}`, {
            headers: { authorization: "Bearer control-token" },
        });
        expect(bare.status).toBe(403);
        const bareIntent = await commandObject.fetch(`https://instance/__private/object-intent/${id}`, {
            headers: { authorization: "Bearer control-token" },
        });
        expect(bareIntent.status).toBe(403);
    });

    /** The grant names one content id. It authorizes that content at its own
     *  address — not "a write", which a holder could redirect elsewhere. */
    it("refuses a grant that names different content than the object addressed", async () => {
        const authorized = new Uint8Array([1, 2, 3, 4]);
        const other = new Uint8Array([5, 6, 7, 8]);
        const otherId = (await sha256Hex(other)).slice(0, 32);
        const inner = `/host/objects/${otherId}`;

        // A grant for `authorized`, aimed at `other`'s address.
        const response = await SELF.fetch(`https://runtime.test${baseFor()}${inner}`, {
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
    // write-intent-survives-refusal
    it("refuses bytes that are not the ones the grant names", async () => {
        const named = new Uint8Array([1, 1, 1, 1]);
        const digest = await sha256Hex(named);
        const id = digest.slice(0, 32);
        const inner = `/host/objects/${id}`;

        const response = await SELF.fetch(`https://runtime.test${baseFor()}${inner}`, {
            method: "POST",
            body: new Uint8Array([9, 9, 9, 9]),
            headers: {
                ...(await grantFor(inner, "POST", digest)),
                "content-length": "4",
            },
        });
        expect(response.status, await response.clone().text()).toBe(409);
        expect(await env.WHIP_OBJECTS.head(await storageKeyFor(id))).toBeNull();
        const commandObject = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(
            durableWorkflowObjectName({
                home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: COMMAND,
            }),
        ));
        const intent = await commandObject.fetch(`https://instance/__private/object-intent/${id}`, {
            headers: await privateHeadersForObject(id, digest),
        });
        expect(intent.status, await intent.clone().text()).toBe(200);
        expect(await intent.json()).toEqual({ id, storage_key: await storageKeyFor(id) });
    });

    it("refuses a request carrying no grant at all", async () => {
        const body = new Uint8Array([1]);
        const id = (await sha256Hex(body)).slice(0, 32);
        const response = await SELF.fetch(`https://runtime.test${baseFor()}/host/objects/${id}`, {
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
        const response = await SELF.fetch(`https://runtime.test${baseFor()}/host/objects/${id}`, {
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
        const stored = await env.WHIP_OBJECTS.head(await storageKeyFor(id));
        expect(stored?.size).toBe(big.length);
    });
});
