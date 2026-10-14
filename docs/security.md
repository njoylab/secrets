# Security model

## How a secret travels

1. The browser generates a random 32-byte fragment key. It derives two
   independent 32-byte keys from it with HKDF-SHA256: the content key
   (`info = "echovalue-secrets-v3:content-key"`) and the auth key
   (`info = "echovalue-secrets-v3:auth-key"`). Without a password the HKDF salt
   is empty. With a password, the browser first runs PBKDF2-HMAC-SHA256
   (600,000 iterations, random 16-byte salt, NFKC-normalised password) and uses
   its 32-byte output as the HKDF salt, so both keys need the fragment key and
   the password. Distinct labels make each key useless for computing the other.
   The browser seals the secret as `base64url(nonce || ciphertext || tag)` with
   AES-256-GCM under the content key.
2. The browser POSTs only that sealed payload, an `expiresIn` preset, the hex
   SHA-256 of the auth key (`authHash`) and a `passwordProtected` flag that only
   tells the open page whether to ask for a password. The server stores the
   hash only as `auth_hash = HMAC-SHA256(k_auth, authHash)`, where `k_auth` is
   derived from `SECRET_ENCRYPTION_KEY` with HKDF-SHA256
   (`info = "echovalue-secrets-v3:auth-hmac"`), never the AES key itself.
   **The fragment key, the
   content key, the auth key and the password are never sent at creation.** A
   database dump and the deployment key provide neither the fragment key nor the
   password.
3. The server wraps the sealed payload in a second AES-256-GCM layer under
   `SECRET_ENCRYPTION_KEY` and stores the result. This is at-rest protection
   against a dump; it is not what protects the reader.
4. The reply contains only the share token, the control token and metadata.
   The browser builds both links from its own origin and appends the fragment
   from memory: `#<key>` without a password, or `#<key>.<salt>` with a password.
   The key appears in no request, header, server log line or database row.
5. The recipient opens `/s/<token>#<key>`. The page reads the fragment and
   removes it from the address bar. A GET never consumes anything. On a
   deliberate POST to `/api/secrets/reveal` the browser sends the token and the
   auth key it derived (from the fragment key, plus the password when set). The
   server recomputes the keyed hash of its SHA-256 and compares it with the
   stored value in constant time, outside any transaction. It also opens the
   at-rest layer first: if that fails (wrong or rotated deployment key, damaged
   ciphertext) the answer is a server error and the row is kept, because a wrong
   deployment key would otherwise look like a wrong password. A mismatch answers `badPassword` (or `badKey` without a password)
   and leaves the row untouched. A match runs the single conditional
   `DELETE ... RETURNING`, guarded on the same hash, and returns the sealed
   payload, which the browser opens with the content key.

The server never receives the fragment, so a request log and a `Referer` header
do not carry the key (`Referrer-Policy` is `no-referrer`, and browsers omit the
fragment from `Referer` anyway). The open page removes the fragment from the
current history entry after reading it. Language-switch links carry the key only
in their fragment, which browsers preserve through the locale redirect without
sending it to the server. Reloading a bare share URL loses the in-memory key; the
page then says that nothing was consumed and asks for the original share link.
The key is deliberately not persisted in browser storage. The link the creator copies still
contains the key, so a paste into chat includes it. That link opens a secret
once. With a password, the link alone is not enough.

## Security invariants

- Sensitive inputs have no HTML names, and create/reveal buttons stay disabled
  until their JavaScript handlers and Web Crypto are ready. Native submission
  cannot serialize the secret or password if a bundle fails to load.
- **The server cannot read the secrets it stores, as long as it serves this
  client.** The content key lives only in the link fragment and is never
  included in a request body, a header, a log or a row. A password, when set,
  is mixed into that key and is not stored. A database dump, the deployment key
  and the process memory are not enough to read the text; with a password, the
  link alone is not enough either. This is client-side encryption, not audited
  end-to-end encryption. An operator who replaces the page can read secrets
  created or opened after that change. A compromised device can read them too.
- Tokens and control tokens carry 256 bits of randomness each and are independent
  of each other. Only their SHA-256 hashes are stored, so a database dump does not
  yield usable links, and a leaked control token cannot be used to read anything.
- Stored content is wrapped with AES-256-GCM under a random per-secret nonce.
  Revealing returns the sealed payload, never text, and only after the deleting
  statement has committed.
- Optional passwords never reach the server. Every reveal must present the auth
  key whose keyed hash is stored as `auth_hash` (NOT NULL), so token-only requests,
  wrong passwords and damaged fragment keys cannot consume a secret.
- **Password guessing is online only.** No endpoint returns anything derived from
  the password before a successful reveal, so the holder of a complete link can
  test a password only by sending a reveal request, which counts against the
  reveal rate limit (`RATE_LIMIT_REVEAL_*`, per client IP or IPv6 /64). Each guess
  also costs the guesser 600,000 PBKDF2 iterations. The stored hash is of a key
  that also depends on the 256-bit fragment key, and it is keyed with an HMAC
  subkey of the deployment key, so a database dump cannot be used to guess the
  password offline, not even together with a complete link. **Residual limit:**
  someone holding a complete link, a database dump and `SECRET_ENCRYPTION_KEY`
  can still test passwords offline. Choose passwords that survive that
  combination when it matters, and keep the deployment key out of database
  backups.
- Only this protocol is supported. Migration `0005_auth_key.sql` closed every row
  created by earlier versions and dropped their columns. Do not roll back to
  code that skips the auth key check: it would reopen consumption without proof.
- Consumption is a single conditional `DELETE ... RETURNING` inside the same
  transaction that writes the `read` receipt, so at most one concurrent request
  can ever obtain the content and the state reported afterwards always matches it.
- A cancel that races a read deletes nothing and reports `read`, so the control
  link can never claim a secret was cancelled after somebody took it.
- **Residual limit:** the payload is consumed before the browser decrypts it. If
  the delete commits and the response never reaches the browser, the content is
  unrecoverable and the control link will correctly report `read`. A truncated
  or altered fragment no longer reaches the delete: its auth key does not match. There is no second read and no recovery. This is
  deliberate, and it is the one failure mode users should know about before they
  rely on a link they cannot re-open.
- **Residual limit:** deleting a row removes it from the heap but not from the
  WAL, from free space maps, or from base backups already taken. Erasure from
  backups is a matter of backup retention policy, not of application logic. The
  same applies to receipts, which record only the fact and the time of a read, not
  the content.

## Limitations

These are the honest limits of the current implementation, not a roadmap:

- A control link reports state only. If you lose the share link, the content is
  not recoverable by anyone, including the operator.
- Consumption happens before the browser decrypts. A lost response leaves the
  secret marked read with no way to re-read it.
- Deletion does not reach the WAL, free space maps or backups already taken.
  Erasure from backups depends on retention policy outside this repository.
- There are no accounts, no key escrow and no audit log of who read a secret:
  receipts record that a read happened and when, not who did it.
