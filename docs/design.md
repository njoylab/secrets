# Design notes

Why the protocol looks the way it does, and the parts that turned out to be
harder than the cryptography. The normative description, trust boundaries and
limits live in the [security model](security.md); this document explains the
reasoning behind them.

**This is client-side encryption, not audited end-to-end encryption.** The
operator can change the JavaScript served to users. That limit is documented
everywhere instead of hidden.

## The flow

Create:

1. The browser generates a random 32-byte fragment key.
2. HKDF-SHA256 derives two independent keys from it: a content key
   (`echovalue-secrets-v3:content-key`) and an auth key
   (`echovalue-secrets-v3:auth-key`). With a password, a PBKDF2 output becomes
   the HKDF salt (see below).
3. The browser seals the text with AES-256-GCM under the content key.
4. POST `{ payload, expiresIn, authHash, passwordProtected }`, where `authHash`
   is the SHA-256 of the auth key.
5. The server wraps the payload in a *second* AES-256-GCM layer under the
   deployment key, stores an HMAC of `authHash` under a subkey of that same
   deployment key, and returns two tokens.
6. The page builds `https://host/s/<token>#<fragmentKey>` (plus `.<salt>` when a
   password is set) from its own origin, and a separate control link.

Reveal:

1. The browser derives the auth key again and POSTs `{ token, authKey }` to
   `/api/secrets/reveal`. Never a GET.
2. The server checks the auth key against the stored HMAC, opens the outer
   layer, deletes the row, commits, and only then serializes the payload.
3. The browser opens the inner layer with the content key.

The server stores ciphertext it cannot read, a hash of the share token, a hash
of the control token, and a keyed hash of the auth key. A `pg_dump` gives you
ciphertext, not secrets.

```ts
export async function encryptPayload(plaintext: string, key: ContentBytes): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(CONTENT_NONCE_BYTES));
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
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
```

The content layer uses only Web Crypto and `atob`/`btoa`. That is deliberate:
the *same module* runs in the browser and under Node, which lets the test suite
prove the round trip instead of mocking crypto.

## Decisions

### base64url decoding is not canonical

`atob` tolerates a final character whose unused low bits are set, so two
different strings can decode to identical bytes: flipping one character in a
link fragment could still open the secret. The fix is to re-encode and compare:

```ts
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
```

Exactly one text per key.

### Every reveal proves the key before anything is deleted

A one-time secret has an awkward failure mode: if the reveal deletes the row and
the browser then fails to decrypt, because the fragment was damaged or the
password is wrong, the secret is gone and nobody read it.

So every secret, with or without a password, has an auth key derived alongside
the content key. The reveal must present it, and the server checks it before the
delete. A wrong password or a damaged fragment returns `403` and leaves the row
in place; the original link still works.

The two keys come from separate HKDF `info` labels, so neither can be derived
from the other, and the server never sees anything that opens the payload.

### A password needs two inputs, not one

The obvious design is "derive the content key from the password". Then the
fragment has nothing left to carry, and anyone holding the ciphertext can guess
the password. Instead, PBKDF2-HMAC-SHA256 (600k iterations, NFKC-normalized
password, 16-byte salt from the fragment) produces 32 bytes that become the HKDF
salt, and HKDF expands the *fragment* key. Both keys therefore need both inputs,
and the password never leaves the browser.

```ts
hkdfSalt = new Uint8Array(await crypto.subtle.deriveBits(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSWORD_KDF_ITERATIONS }, material, 256,
));
const base = await crypto.subtle.importKey('raw', fragmentKey, 'HKDF', false, ['deriveBits']);
const expand = async (info: ContentBytes): Promise<ContentBytes> =>
  new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info }, base, 256),
  );
return { contentKey: await expand(CONTENT_KEY_INFO), authKey: await expand(AUTH_KEY_INFO) };
```

### Password guesses must be online

An earlier version stored a sealed "verifier" that the browser fetched and
opened locally to check the password before revealing. It worked, but anyone
holding the full link could download the verifier once and brute-force the
password offline, with no rate limit at all.

Now the only way to test a password is a reveal request. Each guess is charged
to the reveal rate-limit bucket, keyed per IPv4 address or IPv6 /64.

The stored value is not a plain SHA-256 either: it is an HMAC under a subkey
derived with HKDF (`echovalue-secrets-v3:auth-hmac`) from the deployment key.
A database dump plus a full link is not enough to guess offline; an attacker
would also need `SECRET_ENCRYPTION_KEY`.

The switch was a clean cut. Migration `0005_auth_key.sql` closes every secret
created with the old format and writes a receipt for its control link.

### Consumption is one statement, not a read-then-delete

The naive shape (SELECT, decrypt, DELETE) has two races: two concurrent
readers can both SELECT and both return the payload.

Reading and checking happen without a lock. Consumption is a single conditional
`DELETE ... RETURNING` inside a transaction, which also writes the close
receipt. The payload is serialized only after the commit:

```sql
DELETE FROM secrets
 WHERE token_hash = $1
   AND expires_at > now()
   AND auth_hash = $2
 RETURNING control_hash, expires_at
```

Because the row is gone, `RETURNING` produces at most one row per token: at
most one concurrent retrieval can succeed. A test fires parallel reveals at one
token, mixing right and wrong keys, and asserts exactly one success.

The outer layer is opened *before* the delete. If it fails (wrong or rotated
deployment key, corrupted ciphertext), the row is **left in place** and the
response is a 500, whatever auth key was presented. A 404 would be a lie that
outlives the outage, and a password error would send the user after a problem
they cannot fix. Restore the key and the link works again.

### Status codes are security decisions

| Situation | Status | Why |
|---|---|---|
| Wrong password | `403` | The secret exists, the credential does not match |
| Wrong fragment key (no password) | `403` | Same, and the secret is not consumed |
| Missing / expired / consumed | `404` | One answer for all three, so no oracle |
| Deployment key unavailable | `500` | The link works again once the key is back |
| Rate limited | `429` | With `Retry-After` set to what is left of the window |

### GET must not consume

There is no `GET` handler on the reveal path. If rendering a page, browser
prefetching or a link-preview bot could burn a secret, the "one-time" promise
would be an illusion.

The reveal page also strips the fragment from the address bar on load, so a
copied URL, synced history or shared screen does not carry the key. The
trade-off: a reload loses the key. The page then says so explicitly. The secret
was not consumed, and the original link still works.

### Headers are part of the protocol

- A strict Content-Security-Policy (`default-src 'self'`, hashed inline
  scripts and styles) protects the page that holds the key in memory.
- `no-store` and `noindex` are set on every response.
- Cross-origin POSTs are rejected before the body is read.
- Forwarded client addresses are trusted only from configured proxies.
- The locale redirect accepts only same-origin paths. Tab characters and dot
  segments were both real bypasses of the first version.

## Lessons

- **Delete before you send.** It is the only reliable way to make "read once"
  mean read once.
- **Prove before you delete.** A failure after the delete is a lost secret.
- **Failures are states too.** Most of the design work was in the error
  branches, not the happy path.
- **Concurrency is a schema question.** If the invariant is "exactly one", push
  it into a single statement.
- **Count what an attacker can do offline.** Anything the server hands out
  without consuming is a potential offline oracle.
- **Document what you can't do.** WAL, backups and the operator's ability to
  change JavaScript are real limits. See [security.md](security.md).

## Running it

Source (MIT, Astro + TypeScript + `pg`, no Docker, no Redis, no accounts):
`github.com/njoylab/secrets`.

Self-hosting needs a PostgreSQL URL, one 32-byte key and `npm run migrate`. See
the [operations guide](operations.md).
