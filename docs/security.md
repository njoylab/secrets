# Security model

## How a secret travels

1. The browser generates a 32-byte content key and seals the secret as
   `base64url(nonce || ciphertext || tag)` with AES-256-GCM under that key.
2. The browser POSTs only that sealed payload, an `expiresIn` preset and, when
   a password was set, a short sealed verifier and a random reveal proof's SHA-256
   hash. The proof is sealed inside that verifier. **The key and the password are
   never sent.** The password is mixed into the content key in the browser
   (PBKDF2-HMAC-SHA256, 600,000 iterations, then HKDF with the fragment key).
   Reading a password-protected payload requires both the fragment key and
   the password. A database dump and deployment key provide neither input.
3. The server wraps the sealed payload in a second AES-256-GCM layer under
   `SECRET_ENCRYPTION_KEY` and stores the result. This is at-rest protection
   against a dump; it is not what protects the reader.
4. The reply contains only the share token, the control token and metadata.
   The browser builds both links from its own origin and appends the fragment
   from memory: `#<key>` without a password, or `#<key>.<salt>` with a password.
   The key appears in no request, header, server log line or database row.
5. The recipient opens `/s/<token>#<key>`. The page reads the fragment and
   removes it from the address bar. A GET never consumes anything. With a
   password, the browser first asks for the verifier and checks it locally; a
   wrong password does not reveal. Decrypting the verifier releases the random
   proof, which the server requires in the `revealProof` field before consuming
   a password-protected link. A deliberate POST to `/api/secrets/reveal`
   performs the single `DELETE ... RETURNING` and returns the sealed payload.
   The browser opens it with the fragment key, or with the password-derived key.

The server never receives the fragment, so a request log and a `Referer` header
do not carry the key (`Referrer-Policy` is `no-referrer`, and browsers omit the
fragment from `Referer` anyway). The open page removes the fragment from the
current history entry after reading it. Language-switch links carry the key only
in their fragment, which browsers preserve through the locale redirect without
sending it to the server. Reloading a bare share URL loses the in-memory key;
reopen the original share link in that case. The link the creator copies still
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
- Optional passwords never reach the server. The browser derives a key with
  PBKDF2-HMAC-SHA256 (600,000 iterations) and HKDF over the fragment key, and
  seals an independent 256-bit reveal proof inside the verifier. Only the proof's
  SHA-256 hash is stored for server authorization; the password, fragment key and
  derived key remain in the browser. Password links require a valid proof
  before deletion, so token-only API requests cannot consume them.
  A verifier and its proof hash must always be supplied together. Only this
  password protocol is supported; incomplete or unsupported stored records are
  unavailable and cannot be consumed. Historical migrations remain versioned;
  the unused `password_hash` column is never populated or verified by the app.
  Do not roll back to code that
  ignores reveal proofs: it would reopen the consumption bypass.
- Consumption is a single conditional `DELETE ... RETURNING` inside the same
  transaction that writes the `read` receipt, so at most one concurrent request
  can ever obtain the content and the state reported afterwards always matches it.
- A cancel that races a read deletes nothing and reports `read`, so the control
  link can never claim a secret was cancelled after somebody took it.
- **Residual limit:** the payload is consumed before the browser decrypts it. If
  the delete commits and the response never reaches the browser, or the fragment
  is truncated in transit, the content is unrecoverable and the control link will
  correctly report `read`. There is no second read and no recovery. This is
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
