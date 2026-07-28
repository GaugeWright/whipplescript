// Terminal artifact selection and sealing (DR-0049 §5, §6).
//
// Selection is driven entirely by the signed release's declaration. Nothing
// here is reachable from the agent's ability set, so an agent a visitor has
// induced to misbehave can neither widen what leaves nor suppress the emission.
//
// Sealing happens outside the runtime proper: this module receives recipient
// PUBLIC keys only, and produces ciphertext plus per-recipient wrapped data
// keys. Private recipient material stays with the tenant, exactly as the
// provider-credential contract keeps API keys out of the runtime.

export interface CollectionPolicy {
  exportable_paths: string[];
  transcript_eligible: boolean;
  schema_ref: string;
  recipient_class: string;
  max_artifact_bytes: number;
}

export interface ArtifactEnvelope {
  schema_ref: string;
  session_id: string;
  release_id: string;
  revision: number;
  produced_at_unix_ms: number;
}

export interface SealedArtifact {
  envelope: ArtifactEnvelope;
  /** Hex `nonce(12) || AES-256-GCM(ciphertext||tag)`, matching the Rust AEAD. */
  ciphertext: string;
  /** One wrap per recipient; the tenant holds the private halves. */
  wraps: {
    recipient_public_key: string;
    /** Hex uncompressed SEC1 point, as the Rust keyring encodes it. */
    ephemeral_public_key: string;
    /** Hex `nonce(12) || AES-256-GCM(wrapped data key)`. */
    wrapped_key: string;
  }[];
  byte_len: number;
}

/**
 * Domain separation from backup recovery (ADR 0102). A backup recipient key
 * must not silently double as a collection recipient.
 *
 * The derivation deliberately mirrors `backup_keyring.rs` byte for byte —
 * SHA-256 over the domain, each context component length-prefixed as a big-endian
 * u64, then the raw ECDH secret — so the Rust side can open what this seals. It
 * is not HKDF; matching the existing construction matters more than preferring a
 * different one, because a mismatch seals artifacts that never decrypt.
 */
const COLLECTION_KDF_DOMAIN = "gaugewright/collection/ecies/v1";

const NONCE_LEN = 12;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function lengthPrefixed(value: string): Uint8Array {
  const body = new TextEncoder().encode(value);
  const out = new Uint8Array(8 + body.length);
  new DataView(out.buffer).setBigUint64(0, BigInt(body.length), false);
  out.set(body, 8);
  return out;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** SHA-256(domain || lenpfx(component)* || shared) — exactly the Rust KDF. */
async function deriveWrappingKey(
  shared: Uint8Array,
  components: string[],
): Promise<Uint8Array> {
  const preimage = concatBytes([
    new TextEncoder().encode(COLLECTION_KDF_DOMAIN),
    ...components.map(lengthPrefixed),
    shared,
  ]);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
}

/** `nonce || AES-256-GCM(plaintext)`, the shape the Rust AEAD emits. */
async function aeadSeal(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const aesKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plaintext),
  );
  return concatBytes([nonce, sealed]);
}

/**
 * A selector is an exact relative path, or a `dir/*` prefix matching exactly one
 * further segment. `**` is refused at release validation, so it never arrives.
 */
export function selectorMatches(selector: string, path: string): boolean {
  if (selector.endsWith("/*")) {
    const prefix = selector.slice(0, -1);
    if (!path.startsWith(prefix)) return false;
    return !path.slice(prefix.length).includes("/");
  }
  return selector === path;
}

export function selectWorkspace(
  files: Map<string, string>,
  policy: CollectionPolicy,
): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const [path, content] of [...files.entries()].sort()) {
    if (policy.exportable_paths.some((selector) => selectorMatches(selector, path))) {
      selected[path] = content;
    }
  }
  return selected;
}

/** Deterministic bytes so a retried emission is byte-identical. */
export function canonicalArtifact(
  envelope: ArtifactEnvelope,
  workspace: Record<string, string>,
  transcript: unknown[] | null,
): Uint8Array {
  const body: Record<string, unknown> = { envelope, workspace };
  if (transcript) body.transcript = transcript;
  return new TextEncoder().encode(JSON.stringify(body));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("recipient key is not hex");
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Fresh data key per artifact, wrapped independently to each recipient. The
 * runtime never sees a private key and retains no key material after this
 * returns.
 */
export async function sealArtifact(
  envelope: ArtifactEnvelope,
  plaintext: Uint8Array,
  recipientPublicKeysHex: string[],
  admissionScope: string,
): Promise<SealedArtifact> {
  if (recipientPublicKeysHex.length === 0) {
    throw new Error("collection has no admitted recipient");
  }
  const subtle = crypto.subtle;
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = await aeadSeal(dataKey, plaintext);

  // Bound exactly as the Rust keyring binds a wrap: a scope, the specific point,
  // and the specific recipient. A wrap cannot be replayed to another deployment,
  // another session revision, or another recipient.
  const pointId = `${envelope.session_id}:${envelope.revision}`;
  const wraps: SealedArtifact["wraps"] = [];
  for (const recipientHex of recipientPublicKeysHex) {
    const recipient = await subtle.importKey(
      "raw",
      fromHex(recipientHex),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const ephemeral = (await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const shared = new Uint8Array(
      await subtle.deriveBits(
        { name: "ECDH", public: recipient } as unknown as Parameters<
          typeof subtle.deriveBits
        >[0],
        ephemeral.privateKey,
        256,
      ),
    );
    const wrappingKey = await deriveWrappingKey(shared, [
      admissionScope,
      pointId,
      recipientHex,
    ]);
    wraps.push({
      recipient_public_key: recipientHex,
      ephemeral_public_key: toHex(
        new Uint8Array(
          (await subtle.exportKey("raw", ephemeral.publicKey)) as ArrayBuffer,
        ),
      ),
      wrapped_key: toHex(await aeadSeal(wrappingKey, dataKey)),
    });
    wrappingKey.fill(0);
    shared.fill(0);
  }
  dataKey.fill(0);

  return {
    envelope,
    ciphertext: toHex(ciphertext),
    wraps,
    byte_len: plaintext.byteLength,
  };
}
