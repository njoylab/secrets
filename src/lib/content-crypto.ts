/**
 * Content layer: AES-256-GCM over the secret text, with a key that never leaves
 * the browser.
 *
 * The browser generates a 32 byte key, seals the secret with it before the POST
 * and keeps the key in the `#` fragment of the share link, which browsers never
 * send to a server. The server only ever stores the resulting `payload`, and
 * `decryptSecret` in `src/lib/crypto.ts` seals that payload a second time with
 * the deployment key, so a database dump is still not the text.
 *
 * Only Web Crypto and `atob`/`btoa` are used: the same code runs in the browser
 * and under Node 20, which is what lets the test suite prove the round trip.
 *
 * Wire format: `base64url(nonce || ciphertext || tag)`, which is the same
 * envelope `encryptSecret` uses, so the two layers are indistinguishable.
 */

/** Content key size, in bytes. */
export const CONTENT_KEY_BYTES = 32;

/** AES-GCM nonce and tag sizes, in bytes. */
export const CONTENT_NONCE_BYTES = 12;
export const CONTENT_TAG_BYTES = 16;

/** base64url text length of a fragment key: 32 bytes encode to exactly 43 characters. */
export const CONTENT_KEY_LENGTH = 43;

const BASE64URL_SHAPE = /^[A-Za-z0-9_-]*$/;

/** Chunked so a 50 KiB payload never lands in a single spread argument list. */
const BINARY_CHUNK_BYTES = 0x2000;

/**
 * Bytes as Web Crypto wants them.
 *
 * The `ArrayBuffer` type argument is what separates these from a `Uint8Array`
 * that could be backed by a `SharedArrayBuffer`, which `BufferSource` excludes.
 */
export type ContentBytes = Uint8Array<ArrayBuffer>;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += BINARY_CHUNK_BYTES) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + BINARY_CHUNK_BYTES));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/**
 * Decode unpadded base64url, or return `null` for anything that is not canonical.
 *
 * `atob` tolerates a final character whose unused low bits are set, so two texts
 * can decode to the same bytes. Re-encoding and comparing rejects those, which
 * keeps exactly one text per key: without it, a single character flipped in a
 * link fragment would still open the secret.
 */
export function decodeBase64Url(text: string): ContentBytes | null {
  if (!BASE64URL_SHAPE.test(text)) return null;
  const base64 = text.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return encodeBase64Url(bytes) === text ? bytes : null;
  } catch {
    return null;
  }
}

/** A fresh content key from the platform CSPRNG. */
export function generateContentKey(): ContentBytes {
  const key = new Uint8Array(CONTENT_KEY_BYTES);
  crypto.getRandomValues(key);
  return key;
}

/** The text form that travels in the share link fragment. */
export function encodeContentKey(key: Uint8Array): string {
  return encodeBase64Url(key);
}

/**
 * Parse a fragment key, or return `null` when it is absent or malformed.
 *
 * The length is pinned: a fragment that decodes to any other number of bytes
 * cannot have produced a payload this build can read, so it is refused before
 * any request is sent.
 */
export function decodeContentKey(text: string | null | undefined): ContentBytes | null {
  if (typeof text !== 'string' || text.length !== CONTENT_KEY_LENGTH) return null;
  const key = decodeBase64Url(text);
  if (!key || key.byteLength !== CONTENT_KEY_BYTES) return null;
  return key;
}

async function importContentKey(key: ContentBytes, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [usage]);
}

/** Seal plaintext as `base64url(nonce || ciphertext || tag)`. */
export async function encryptPayload(plaintext: string, key: ContentBytes): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(CONTENT_NONCE_BYTES));
  const cryptoKey = await importContentKey(key, 'encrypt');
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: CONTENT_TAG_BYTES * 8 },
      cryptoKey,
      new TextEncoder().encode(plaintext),
    ),
  );
  const out = new Uint8Array(CONTENT_NONCE_BYTES + sealed.byteLength);
  out.set(nonce, 0);
  out.set(sealed, CONTENT_NONCE_BYTES);
  return encodeBase64Url(out);
}

/** Open a payload. Throws when the key, the nonce or the tag does not hold. */
export async function decryptPayload(payload: string, key: ContentBytes): Promise<string> {
  const raw = decodeBase64Url(payload);
  if (!raw || raw.byteLength < CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES) {
    throw new Error('Payload is not a well formed sealed body');
  }
  const cryptoKey = await importContentKey(key, 'decrypt');
  const opened = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, CONTENT_NONCE_BYTES), tagLength: CONTENT_TAG_BYTES * 8 },
    cryptoKey,
    raw.subarray(CONTENT_NONCE_BYTES),
  );
  // `ignoreBOM` keeps a leading U+FEFF as ordinary text: the secret must come back
  // exactly as it was typed, and a BOM is content, not an encoding instruction.
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(opened);
}
