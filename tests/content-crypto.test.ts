/**
 * The content layer: the key that never leaves the browser.
 *
 * The invariant under test is narrow and absolute. The server stores and returns
 * the sealed payload verbatim, so the only thing that can open a secret is the key
 * in the link fragment. If any of these tests fail, the whole design is void.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  CONTENT_KEY_BYTES,
  CONTENT_KEY_LENGTH,
  CONTENT_NONCE_BYTES,
  CONTENT_TAG_BYTES,
  PASSWORD_KDF_ITERATIONS,
  PASSWORD_MAX_LENGTH,
  PASSWORD_VERIFIER_TEXT,
  createPasswordVerifier,
  openPasswordVerifier,
  decodeBase64Url,
  decodeContentKey,
  decodeShareFragment,
  encodeBase64Url,
  encodeContentKey,
  encodeShareFragment,
  encryptPayload,
  generateContentKey,
  generatePasswordSalt,
  derivePasswordKey,
  decryptPayload,
  isSealedEnvelope,
  controlUrl,
  shareUrl,
} from '../src/lib/content-crypto.ts';

const SECRET = 'the quick brown fox';

describe('key text', () => {
  it('is 43 characters of unpadded base64url for 32 bytes', () => {
    const key = generateContentKey();
    const text = encodeContentKey(key);

    expect(CONTENT_KEY_BYTES).toBe(32);
    expect(CONTENT_KEY_LENGTH).toBe(43);
    expect(text).toHaveLength(43);
    expect(text).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // 32 bytes is one short of a multiple of three, so the last character carries
    // only two bits of payload and one of padding.
    expect(text.endsWith('=')).toBe(false);
  });

  it('survives a round trip through decodeContentKey', () => {
    const key = generateContentKey();
    expect(decodeContentKey(encodeContentKey(key))).toEqual(key);
  });

  it('refuses anything that is not exactly 43 characters', () => {
    const text = encodeContentKey(generateContentKey());
    expect(decodeContentKey(text.slice(0, 42))).toBeNull();
    expect(decodeContentKey(`${text}A`)).toBeNull();
    expect(decodeContentKey('')).toBeNull();
    expect(decodeContentKey(null)).toBeNull();
    expect(decodeContentKey(undefined)).toBeNull();
  });

  it('refuses a 43 character fragment that is not base64url', () => {
    expect(decodeContentKey(`${'x'.repeat(42)}+`)).toBeNull();
    expect(decodeContentKey(`${'x'.repeat(42)}/`)).toBeNull();
    expect(decodeContentKey(`${'x'.repeat(42)}=`)).toBeNull();
    expect(decodeContentKey(`${'x'.repeat(42)}.`)).toBeNull();
    expect(decodeContentKey(`${'x'.repeat(42)}€`)).toBeNull();
  });

  it('refuses a 43 character fragment that decodes to another size', () => {
    // 43 characters is 32 bytes or an error, never 31 or 33, and those two sizes
    // are not 43 characters to begin with, so the length pin already refuses them.
    expect(encodeContentKey(new Uint8Array(31))).toHaveLength(42);
    expect(decodeContentKey(encodeContentKey(new Uint8Array(31)))).toBeNull();
    expect(encodeContentKey(new Uint8Array(33))).toHaveLength(44);
    expect(decodeContentKey(encodeContentKey(new Uint8Array(33)))).toBeNull();
  });

  it('maps exactly one 43 character text to any given 32 byte key', () => {
    // 32 bytes are 256 bits and 43 characters carry 258, so the last character's
    // low two bits are unused and four texts decode to the same 32 bytes. `atob`
    // accepts all four; without a canonical re-encode check a single flipped
    // character in a fragment would still open the secret, and two links to the
    // same secret would look unrelated.
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const key = generateContentKey();
    const canonical = encodeContentKey(key);
    const last = ALPHABET.indexOf(canonical.slice(42));
    expect(last).toBeGreaterThanOrEqual(0);

    let accepted = 0;
    for (let suffix = 0; suffix < 4; suffix += 1) {
      const altered = `${canonical.slice(0, 42)}${ALPHABET[(last & ~0b11) | suffix]}`;
      const decoded = decodeContentKey(altered);
      if (suffix === 0) {
        // The canonical text is the one that opens the secret.
        expect(altered).toBe(canonical);
        expect(decoded).toEqual(key);
        accepted += 1;
        continue;
      }
      // The other three carry the same 32 bytes, so refusing them is the whole
      // point: a tampered fragment must not decrypt anything.
      expect(decoded, altered).toBeNull();
    }
    expect(accepted).toBe(1);

    // A different last character that changes the byte is simply a different key.
    const other = ALPHABET[(last & ~0b11) | ((last + 1) & 0b11)];
    const otherKey = decodeContentKey(`${canonical.slice(0, 42)}${other}`);
    if (otherKey) expect(otherKey).not.toEqual(key);
  });

  it('is a fresh random key every time', () => {
    const keys = new Set(Array.from({ length: 64 }, () => encodeContentKey(generateContentKey())));
    expect(keys.size).toBe(64);
  });
});

describe('base64url', () => {
  it('round-trips arbitrary bytes, including the whole byte range', () => {
    const all = new Uint8Array(256);
    for (let index = 0; index < 256; index += 1) all[index] = index;

    for (const length of [0, 1, 2, 3, 4, 5, 31, 32, 33, 1000, all.length]) {
      const bytes = all.slice(0, length);
      expect(decodeBase64Url(encodeBase64Url(bytes)), String(length)).toEqual(bytes);
    }
  });

  it('never produces padding, plus or slash characters', () => {
    for (let length = 0; length < 40; length += 1) {
      const text = encodeBase64Url(new Uint8Array(length).fill(0xfb));
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
    }
  });

  it('rejects a non canonical text, padding and a bad length', () => {
    expect(decodeBase64Url('A')).toBeNull();
    expect(decodeBase64Url('AAAA=')).toBeNull();
    expect(decodeBase64Url('AA+A')).toBeNull();
    expect(decodeBase64Url('AA/A')).toBeNull();
    expect(decodeBase64Url('AA A')).toBeNull();
    expect(decodeBase64Url('AA.A')).toBeNull();
  });
});

describe('payload sealing', () => {
  it('opens with the key that sealed it', async () => {
    const key = generateContentKey();
    const sealed = await encryptPayload(SECRET, key);

    expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(await decryptPayload(sealed, key)).toBe(SECRET);
  });

  it('is nonce + ciphertext + tag, so it grows by exactly 28 bytes', async () => {
    const key = generateContentKey();
    const sealed = await encryptPayload(SECRET, key);
    const raw = decodeBase64Url(sealed);

    expect(raw).not.toBeNull();
    expect(raw?.byteLength).toBe(CONTENT_NONCE_BYTES + Buffer.byteLength(SECRET, 'utf8') + CONTENT_TAG_BYTES);
  });

  it('uses a fresh nonce, so the same text never seals to the same value', async () => {
    const key = generateContentKey();
    const sealed = new Set<string>();
    for (let attempt = 0; attempt < 32; attempt += 1) {
      sealed.add(await encryptPayload(SECRET, key));
    }
    expect(sealed.size).toBe(32);
  });

  it('round-trips awkward text byte for byte', async () => {
    const key = generateContentKey();
    const cases: readonly string[] = [
      '',
      ' ',
      '\n\r\t',
      'trailing spaces    ',
      'leading BOM\uFEFF',
      '😀🎉👩‍💻',
      'e\u0301 vs é',
      'مرحبا بالعالم',
      '{"a":[1,2,3]}',
      '<script>alert(1)</script>',
      "'; DROP TABLE secrets; --",
    ];

    for (const value of cases) {
      const sealed = await encryptPayload(value, key);
      expect(await decryptPayload(sealed, key), JSON.stringify(value)).toBe(value);
    }
  });

  it('keeps a leading byte order mark, because the text is content', async () => {
    // TextDecoder strips a leading U+FEFF by default, which would silently
    // shorten the secret the reader sees.
    const key = generateContentKey();
    const opened = await decryptPayload(await encryptPayload('\uFEFFwith bom', key), key);
    expect(opened).toBe('\uFEFFwith bom');
    expect(opened.startsWith('\uFEFF')).toBe(true);
  });

  it('handles a 50 KiB secret, the largest the form allows', async () => {
    const key = generateContentKey();
    const value = '€'.repeat(Math.floor((50 * 1024) / 3));
    const sealed = await encryptPayload(value, key);
    expect(await decryptPayload(sealed, key)).toBe(value);
  });
});

describe('payload opening', () => {
  it('fails with a different key, and the tag is what fails', async () => {
    const sealed = await encryptPayload(SECRET, generateContentKey());
    const wrong = generateContentKey();

    await expect(decryptPayload(sealed, wrong)).rejects.toThrow();
  });

  it('fails when a single bit of the ciphertext is flipped', async () => {
    const key = generateContentKey();
    const sealed = await encryptPayload(SECRET, key);

    for (const index of [CONTENT_NONCE_BYTES, CONTENT_NONCE_BYTES + 1, 40]) {
      const raw = decodeBase64Url(sealed);
      if (!raw) throw new Error('sealed payload did not decode');
      const position = Math.min(index, raw.byteLength - 1);
      raw[position] = (raw[position] ?? 0) ^ 0x01;
      const tampered = encodeBase64Url(raw);
      expect(tampered).not.toBe(sealed);
      await expect(decryptPayload(tampered, key), String(index)).rejects.toThrow();
    }
  });

  it('fails when the nonce is swapped for another payload nonce', async () => {
    const key = generateContentKey();
    const first = decodeBase64Url(await encryptPayload(SECRET, key));
    const second = decodeBase64Url(await encryptPayload('a different secret', key));
    if (!first || !second) throw new Error('sealed payload did not decode');

    const spliced = new Uint8Array(first.byteLength);
    spliced.set(second.subarray(0, CONTENT_NONCE_BYTES), 0);
    spliced.set(first.subarray(CONTENT_NONCE_BYTES), CONTENT_NONCE_BYTES);
    await expect(decryptPayload(encodeBase64Url(spliced), key)).rejects.toThrow();
  });

  it('rejects a payload too short to hold a nonce and a tag', async () => {
    const key = generateContentKey();
    const raw = decodeBase64Url(await encryptPayload(SECRET, key));
    if (!raw) throw new Error('sealed payload did not decode');

    // Exactly the envelope with no ciphertext at all, and progressively less.
    for (const length of [0, 1, CONTENT_NONCE_BYTES, CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES - 1]) {
      await expect(decryptPayload(encodeBase64Url(raw.slice(0, length)), key), String(length)).rejects.toThrow();
    }
  });

  it('rejects a payload that is not base64url at all', async () => {
    const key = generateContentKey();
    for (const payload of ['', 'not base64!', 'AAAA=']) {
      await expect(decryptPayload(payload, key), JSON.stringify(payload)).rejects.toThrow();
    }
  });

  it('recognises a sealed envelope and refuses raw text', async () => {
    const key = generateContentKey();
    const sealed = await encryptPayload('hello', key);
    expect(isSealedEnvelope(sealed, 1024)).toBe(true);
    expect(isSealedEnvelope('hello', 1024)).toBe(false);
    expect(isSealedEnvelope(sealed, 10)).toBe(false);
  });

  it('accepts the empty string as a valid, empty secret', async () => {
    // The form refuses an empty secret, but a payload that decrypts to nothing is
    // still a payload: refusing here would be a second, different validation rule.
    const key = generateContentKey();
    expect(await decryptPayload(await encryptPayload('', key), key)).toBe('');
  });
});

describe('share links', () => {
  const token = encodeContentKey(generateContentKey());

  it('builds the share URL from the page origin and a well formed token', () => {
    expect(shareUrl('https://secrets.example/anything', token)).toBe(`https://secrets.example/s/${token}`);
    expect(shareUrl('http://127.0.0.1:4321/create', token)).toBe(`http://127.0.0.1:4321/s/${token}`);
  });

  it('builds the control URL the same way, so both links share one origin', () => {
    expect(controlUrl('https://secrets.example/anything', token)).toBe(`https://secrets.example/c/${token}`);
    expect(controlUrl('http://127.0.0.1:4321/create', token)).toBe(`http://127.0.0.1:4321/c/${token}`);
  });

  it('refuses a token or an origin that cannot carry the key', () => {
    expect(shareUrl('https://secrets.example', 'short')).toBeNull();
    expect(shareUrl('https://secrets.example', `${token}x`)).toBeNull();
    expect(shareUrl('not a url', token)).toBeNull();
    expect(shareUrl('javascript:alert(1)', token)).toBeNull();
    expect(controlUrl('https://secrets.example', 'short')).toBeNull();
    expect(controlUrl('not a url', token)).toBeNull();
    expect(controlUrl('javascript:alert(1)', token)).toBeNull();
  });

  it('round-trips a fragment that also carries a password salt', () => {
    const key = generateContentKey();
    const salt = generatePasswordSalt();
    const text = encodeShareFragment(key, salt);
    expect(text.startsWith(`${encodeContentKey(key)}.`)).toBe(true);
    expect(decodeShareFragment(text)).toEqual({ key, salt });
    expect(decodeShareFragment(encodeShareFragment(key))).toEqual({ key, salt: null });
    expect(decodeShareFragment(`${text}.extra`)).toBeNull();
    expect(decodeShareFragment(`${encodeContentKey(key)}.short`)).toBeNull();
  });
});

describe('password-derived content key', () => {
  it('releases an independent authorization proof only after decrypting the password verifier', async () => {
    const key = generateContentKey();
    const salt = generatePasswordSalt();
    const derived = await derivePasswordKey(key, 'correct horse', salt);
    const { verifier, revealProofHash } = await createPasswordVerifier(derived);
    const proof = await openPasswordVerifier(verifier, derived);
    expect(proof).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createHash('sha256').update(proof!).digest('hex')).toBe(revealProofHash);
    expect(proof).not.toBe(encodeContentKey(key));
    expect(proof).not.toBe(encodeContentKey(derived));
    await expect(openPasswordVerifier(verifier, key)).rejects.toThrow();
    await expect(openPasswordVerifier(verifier, await derivePasswordKey(key, 'wrong horse', salt))).rejects.toThrow();
    const legacy = await encryptPayload(PASSWORD_VERIFIER_TEXT, derived);
    expect(await openPasswordVerifier(legacy, derived)).toBeUndefined();
    for (const text of ['unexpected', 'echovalue-secrets-verifier-v2:short']) {
      await expect(openPasswordVerifier(await encryptPayload(text, derived), derived)).rejects.toThrow();
    }
  });
  it('uses the OWASP PBKDF2 iteration floor', () => {
    expect(PASSWORD_KDF_ITERATIONS).toBeGreaterThanOrEqual(600_000);
    expect(PASSWORD_MAX_LENGTH).toBe(512);
  });

  it('rejects an empty or oversized password before deriving', async () => {
    const key = generateContentKey();
    const salt = generatePasswordSalt();
    await expect(derivePasswordKey(key, '', salt)).rejects.toThrow();
    await expect(derivePasswordKey(key, 'p'.repeat(PASSWORD_MAX_LENGTH + 1), salt)).rejects.toThrow();
  });

  it('requires both the fragment key and the password', async () => {
    const key = generateContentKey();
    const salt = generatePasswordSalt();
    const derived = await derivePasswordKey(key, 'correct horse', salt);
    const payload = await encryptPayload('sealed', derived);
    const verifier = await encryptPayload(PASSWORD_VERIFIER_TEXT, derived);

    expect(await decryptPayload(payload, derived)).toBe('sealed');
    expect(await decryptPayload(verifier, derived)).toBe(PASSWORD_VERIFIER_TEXT);
    await expect(decryptPayload(payload, key)).rejects.toThrow();

    const other = await derivePasswordKey(key, 'wrong horse', salt);
    await expect(decryptPayload(verifier, other)).rejects.toThrow();

    const equivalent = await derivePasswordKey(key, 'e\u0301', salt);
    const composed = await derivePasswordKey(key, '\u00E9', salt);
    expect(equivalent).toEqual(composed);
  });
});
