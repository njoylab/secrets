# secrets

A one-time secret sharing service. Text is encrypted **in the browser** with a
random AES-256-GCM key that stays in the link fragment, so the content key never
reaches the server, and the request body carries an opaque sealed payload. The
server stores that payload and wraps it in a second AES-256-GCM layer of its own
to keep the at-rest ciphertext unreadable from a database dump alone.

Each secret gets two links: the **share link** `/s/<token>#<key>`, and a
**control link** `/c/<control token>` that only ever reports the state of the
secret (`pending`, `read`, `expired`, `cancelled`) and can cancel it. The share
link is redeemed at most once: consumption is a conditional
`DELETE ... RETURNING` executed by the database, so concurrent readers cannot
both obtain the content. Secrets expire after 1 hour to 30 days (default 7) and
an optional password can gate the read. The app is an Astro 5 SSR project served
by the Node adapter, backed by an external PostgreSQL. No Docker, no Redis, no
separate backend.

## Requirements

- Node.js >= 20.11 (`engines.node`). The lockfile and the current toolchain are on Node 24.
- A reachable PostgreSQL instance (any supported version; only core features are used: `make_interval`, `ON CONFLICT`, `timestamptz`).

## Setup

```sh
npm install
cp .env.example .env
```

Create the database and role:

```sql
CREATE ROLE secrets LOGIN PASSWORD 'choose-a-password';
CREATE DATABASE secrets OWNER secrets;
```

Generate the encryption key:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

The value must decode to exactly 32 bytes in base64url (43 characters). Store it
in `SECRET_ENCRYPTION_KEY` in `.env`. The key must be kept out of the database
and out of version control: it is the only thing standing between a database dump
and the plaintext of every secret, and there is no recovery path if it is lost.
Rotating it makes all existing secrets permanently unreadable.

Apply the schema and start the app:

```sh
npm run migrate
npm run dev
```

For production:

```sh
npm run build
npm start
```

## How a secret travels

1. The browser generates a 32-byte content key and seals the secret as
   `base64url(nonce || ciphertext || tag)` with AES-256-GCM under that key.
2. The browser POSTs only that sealed payload, an `expiresIn` preset and, when
   a password was set, a short sealed verifier. **The key and the password are
   never sent.** The password is mixed into the content key in the browser
   (PBKDF2-HMAC-SHA256, 600,000 iterations, then HKDF with the fragment key).
   The server never sees the plaintext or the password, so a database dump plus
   the deployment key still cannot read a password-protected secret unless the
   attacker also has the password.
3. The server wraps the sealed payload in a second AES-256-GCM layer under
   `SECRET_ENCRYPTION_KEY` and stores the result. This is at-rest protection
   against a dump; it is not what protects the reader.
4. The reply contains the share link **without** the fragment plus the control
   link. The browser appends `#<key>` from memory, so the key appears in no
   request, no header, no log line and no database row.
5. The recipient opens `/s/<token>#<key>`. The page reads the fragment and
   removes it from the address bar. A GET never consumes anything. With a
   password, the browser first asks for the verifier and checks it locally; a
   wrong password does not reveal. A deliberate POST to `/api/secrets/reveal`
   performs the single `DELETE ... RETURNING` and returns the sealed payload.
   The browser opens it with the fragment key, or with the password-derived key.

The server never receives the fragment, so a request log and a `Referer` header
do not carry the key (`Referrer-Policy` is `no-referrer`, and browsers omit the
fragment from `Referer` anyway). The open page removes the fragment from the
current history entry after reading it. The link the creator copies still
contains the key, so a paste into chat includes it. That link opens a secret
once. With a password, the link alone is not enough.

## Environment variables

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | yes | — | PostgreSQL connection string, e.g. `postgres://user:password@host:5432/database`. |
| `SECRET_ENCRYPTION_KEY` | yes | — | AES-256-GCM key, 32 random bytes encoded base64url, used for the at-rest wrapper around the sealed payload. Held outside the database. Losing it makes every stored payload permanently unreadable. |
| `TRUSTED_PROXIES` | no | empty (trust nobody) | Comma-separated addresses of the proxies you control, which are then allowed to supply `X-Forwarded-For`. |
| `HOST` | no | `127.0.0.1` | Interface the Node adapter listens on; the process is meant to sit behind a reverse proxy on the loopback. |
| `SERVER_CERT_PATH` | no | — | Path to the PEM certificate when running with TLS in-process. |
| `SERVER_KEY_PATH` | no | — | Path to the PEM private key when running with TLS in-process. |
| `ALLOWED_HOSTS` | no | `localhost,127.0.0.1` | Hostnames this deployment answers to. Read at **build** time by `astro.config.mjs`. |
| `ALLOWED_ORIGINS` | no | empty | Extra origins accepted for same-origin POSTs. |
| `RATE_LIMIT_CREATE_MAX` | no | `20` | Secret creations allowed per window, per client IP. |
| `RATE_LIMIT_CREATE_WINDOW_SECONDS` | no | `3600` | Creation window length. |
| `RATE_LIMIT_REVEAL_MAX` | no | `30` | Reveal attempts allowed per window, per client IP. Cancel uses the same maximum, counted in its own bucket, so the two budgets are independent. |
| `RATE_LIMIT_REVEAL_WINDOW_SECONDS` | no | `300` | Window length for the reveal counter and, separately, for the cancel counter. |
| `COOKIE_SECURE` | no | `true` when `NODE_ENV=production`, otherwise `false` | `Secure` attribute on the locale cookie. |
| `CLEANUP_KEEP_COUNTER_SECONDS` | no | `3600` | Read only by `npm run cleanup`: age after which idle rate limit counters are deleted. |

### Hostnames and client addresses

Two separate mechanisms, easy to confuse:

`ALLOWED_HOSTS` feeds `security.allowedDomains` in `astro.config.mjs` and is read
at **build** time, so rebuild after changing it. With an empty list Astro
rebuilds every `request.url` as `http://localhost`, which would break generated
links and make legitimate browser POSTs look cross-origin. The default covers
local development only: set your real hostname in production.

`TRUSTED_PROXIES` controls who may supply `X-Forwarded-For`, and must list the
addresses of proxies you actually control. `server.mjs` strips every
`x-forwarded-*` header from untrusted peers before Astro sees the request, so a
client cannot claim someone else's address to reset its own rate limit budget.
If the list is empty, or the peer is not in it, the header is discarded and all
clients collapse into the peer's single bucket — behind a reverse proxy that is
one shared quota for everyone. `npm run dev` bypasses `server.mjs` entirely, so
in development every request shares one bucket.

## Migrations

SQL files in `migrations/` are applied in filename order by `npm run migrate`.
Each file runs in its own transaction and is recorded in `schema_migrations`
together with its application time, so a failure rolls back without leaving a
partial version marker. Re-running the command applies nothing and reports
`database already up to date`.

`0001_init.sql` creates `secrets` and `rate_limits`. `0002_control_link.sql`
adds the `control_hash` column and its unique index, plus the `secret_receipts`
table that remembers how a secret closed. There is no down migration: rolling
back would mean discarding secrets or state that no longer has meaning.

## Cleanup

`npm run cleanup` does three things in one transaction each and prints the counts:

- deletes expired rows from `secrets` and writes an `expired` receipt for each, so
  a control link keeps answering "expired" instead of "unavailable" after the row
  is gone;
- deletes receipts whose retention has elapsed;
- deletes rate limit counters older than the counter retention.

Receipts are kept for seven days past the later of the secret's expiry and the
moment it was closed, so a control link is informative for a bounded time after
the fact and then stops existing at all. The counter retention is the largest of
`CLEANUP_KEEP_COUNTER_SECONDS`, `RATE_LIMIT_CREATE_WINDOW_SECONDS` and
`RATE_LIMIT_REVEAL_WINDOW_SECONDS`: a counter is keyed by the start of its
window, so removing one whose window is still open would hand that client a fresh
budget. When the effective retention is longer than the configured value, the
script prints both so the mismatch is visible. Run it from cron or a systemd
timer, for example every hour:

```
17 * * * * cd /srv/secrets && npm run cleanup
```

## Deployment on Node

- `npm run build` emits the server bundle at `dist/server/entry.mjs`; `npm start` runs `server.mjs`, which imports that bundle.
- `server.mjs` is required in production, not just a convenience: it is what makes forwarding headers and the client IP trustworthy (see above).
- Run it behind a TLS-terminating reverse proxy, set `COOKIE_SECURE=true`, and
  send `Strict-Transport-Security` from that proxy. The app also sets HSTS on
  HTTPS responses whose host is not localhost, so a first visit over HTTP cannot
  be rewritten into a page that reads the fragment.
- Set the environment variables in the process manager (systemd `Environment=`,
  PM2, container env) rather than in a file, and keep `.env` out of the deployment.
- Run `npm run migrate` as a deploy step before switching traffic.
- Schedule `npm run cleanup`.
- The adapter listens on `HOST`/`PORT` (default port `8080`). `HOST` defaults to
  `127.0.0.1`, so the process is reachable only through a proxy on the same
  machine; set it explicitly only when a proxy has to reach it on another
  interface. Keep it on a private interface and let the proxy be the only public
  entry point.
- TLS in-process is optional and off by default: set both `SERVER_KEY_PATH` and
  `SERVER_CERT_PATH` to make `server.mjs` serve HTTPS directly. The expected
  deployment is still a proxy terminating TLS, and with both variables unset the
  server stays plain HTTP.

## Security notes

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
  stores only a sealed verifier. A wrong password fails that check locally and
  does not consume the secret. A caller that skips the check can still burn the
  row and take the ciphertext, which remains unreadable without the password.
  Rows created before this change keep a scrypt hash (N=32768, r=8, p=1) and
  still reject a wrong password on the server, outside any database lock.
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

## Local test database

The integration suite requires a real PostgreSQL; there is no in-memory
substitute. Point it at a dedicated database (default URL used by the tests:
`postgres://postgres:postgres@localhost:5433/secrets_test`), e.g. in
`.env.test`:

```
DATABASE_URL=postgres://postgres:postgres@localhost:5433/secrets_test
```

```sh
npm test
```

`npm test` loads `.env` and, when present, `.env.test` (the latter wins). Never
point it at a production database. The suite lives in `tests/`, uses
`tests/setup.ts` as its setup file, and runs serially against a single database.

`tests/content-crypto.test.ts` and `tests/api.test.ts` need no database, and are
the fastest way to check a change to the encryption or the JSON contract.
