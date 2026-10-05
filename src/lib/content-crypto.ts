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
 * and under Node, which is what lets the test suite prove the round trip.
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

/**
 * Share-token shape. Mirrors `TOKEN_LENGTH` in `crypto.ts` without importing it:
 * that module is Node-only, and this one also runs in the browser.
 */
export const SHARE_TOKEN_LENGTH = 43;

/** Random salt mixed into a password-derived content key. 16 bytes encode to 22 characters. */
export const PASSWORD_SALT_BYTES = 16;
export const PASSWORD_SALT_LENGTH = 22;

/** Client-side password KDF. Web Crypto has PBKDF2, not scrypt. */
export const PASSWORD_KDF_ITERATIONS = 600_000;
export const PASSWORD_MAX_LENGTH = 512;

/**
 * Legacy verifier plaintext, retained so existing v1 links remain readable.
 */
export const PASSWORD_VERIFIER_TEXT = 'echovalue-secrets-verifier-v1';
const PASSWORD_PROOF_PREFIX = 'echovalue-secrets-verifier-v2:';

/** The proof is independent of the content key; its hash cannot authorize reveal. */
export async function createPasswordVerifier(key: ContentBytes): Promise<{
  verifier: string;
  revealProofHash: string;
}> {
  const proof = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(proof)));
  return {
    verifier: await encryptPayload(PASSWORD_PROOF_PREFIX + proof, key),
    revealProofHash: Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(''),
  };
}

/** Only a decrypted v2 verifier releases a proof. v1 links remain readable. */
export async function openPasswordVerifier(verifier: string, key: ContentBytes): Promise<string | undefined> {
  const opened = await decryptPayload(verifier, key);
  if (opened === PASSWORD_VERIFIER_TEXT) return undefined;
  if (opened.startsWith(PASSWORD_PROOF_PREFIX)) {
    const proof = opened.slice(PASSWORD_PROOF_PREFIX.length);
    if (decodeBase64Url(proof)?.byteLength === 32) return proof;
  }
  throw new Error('Invalid password verifier');
}

const PASSWORD_HKDF_INFO = new TextEncoder().encode('echovalue-secrets-v1');
const SHARE_TOKEN_SHAPE = new RegExp(`^[A-Za-z0-9_-]{${SHARE_TOKEN_LENGTH}}$`);

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

export interface ShareFragment {
  readonly key: ContentBytes;
  readonly salt: ContentBytes | null;
}

/** A fresh 16 byte salt for the password KDF. */
export function generatePasswordSalt(): ContentBytes {
  const salt = new Uint8Array(PASSWORD_SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Fragment text. Without a password it is the key alone. With a password the
 * salt follows a `.`, which is outside the base64url alphabet, so the two
 * parts cannot be confused.
 */
export function encodeShareFragment(key: Uint8Array, salt?: Uint8Array | null): string {
  const keyText = encodeContentKey(key);
  if (!salt) return keyText;
  return `${keyText}.${encodeBase64Url(salt)}`;
}

/**
 * Parse a fragment, or return `null` when the key or the salt is not canonical.
 *
 * One dot separates the key from the salt. A second dot, a short salt or a
 * non-canonical character fails closed: the caller must not reveal.
 */
export function decodeShareFragment(text: string | null | undefined): ShareFragment | null {
  if (typeof text !== 'string' || text.length === 0) return null;
  const dot = text.indexOf('.');
  if (dot === -1) {
    const key = decodeContentKey(text);
    return key ? { key, salt: null } : null;
  }
  if (text.indexOf('.', dot + 1) !== -1) return null;
  const saltText = text.slice(dot + 1);
  if (saltText.length !== PASSWORD_SALT_LENGTH) return null;
  const key = decodeContentKey(text.slice(0, dot));
  const salt = decodeBase64Url(saltText);
  if (!key || !salt || salt.byteLength !== PASSWORD_SALT_BYTES) return null;
  return { key, salt };
}

/**
 * Same-origin link to a token URL of this service.
 *
 * Both generated links are built here, from the origin the page was loaded
 * from, never from an absolute URL a response carried: behind a reverse proxy
 * the server rebuilds `request.url` from headers it may not recognise, so a link
 * assembled server-side can point at a host the user never visited. The content
 * key is appended by the caller and must never be attached to an origin the page
 * itself was not loaded from.
 */
export function tokenUrl(pageOrigin: string, section: 's' | 'c', token: string): string | null {
  if (!SHARE_TOKEN_SHAPE.test(token)) return null;
  let url: URL;
  try {
    url = new URL(pageOrigin);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  return `${url.origin}/${section}/${token}`;
}

/** Same-origin one-time share link. */
export function shareUrl(pageOrigin: string, token: string): string | null {
  return tokenUrl(pageOrigin, 's', token);
}

/** Same-origin control link: cancels the secret, so it must reach this deployment. */
export function controlUrl(pageOrigin: string, token: string): string | null {
  return tokenUrl(pageOrigin, 'c', token);
}

/**
 * Content key that requires both the fragment key and the password.
 *
 * PBKDF2-HMAC-SHA256 produces a KEK, and HKDF mixes that KEK with the fragment
 * key. Either input alone is not enough to open the payload. The password is
 * normalised to NFKC and never leaves this function.
 */
export async function derivePasswordKey(
  fragmentKey: ContentBytes,
  password: string,
  salt: ContentBytes,
): Promise<ContentBytes> {
  const normalized = password.normalize('NFKC');
  if (normalized.length === 0 || normalized.length > PASSWORD_MAX_LENGTH) {
    throw new Error('Password is empty or too long');
  }
  if (fragmentKey.byteLength !== CONTENT_KEY_BYTES || salt.byteLength !== PASSWORD_SALT_BYTES) {
    throw new Error('Password key material is the wrong size');
  }

  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(normalized),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const kek = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSWORD_KDF_ITERATIONS },
      material,
      256,
    ),
  );
  const base = await crypto.subtle.importKey('raw', fragmentKey, 'HKDF', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: kek, info: PASSWORD_HKDF_INFO },
      base,
      256,
    ),
  );
  if (derived.byteLength !== CONTENT_KEY_BYTES) {
    throw new Error('Derived content key is the wrong size');
  }
  return derived;
}

/**
 * True when `text` is a canonical sealed envelope of at most `maxDecoded` bytes.
 *
 * The server cannot check the GCM tag: it does not have the content key. It can
 * refuse strings that are not the envelope the browser produces, so a raw secret
 * is not stored under the deployment key alone.
 */
export function isSealedEnvelope(text: string, maxDecoded: number): boolean {
  const raw = decodeBase64Url(text);
  if (!raw) return false;
  return raw.byteLength >= CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES && raw.byteLength <= maxDecoded;
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
