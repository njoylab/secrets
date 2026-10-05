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
an optional password can gate the read. The app is an Astro 7 SSR project served
by the Node adapter, backed by an external PostgreSQL. No Docker, no Redis, no
separate backend.

## Requirements

- Node.js >= 22.12 (`engines.node`). CI and the current toolchain use Node 24.
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
   a password was set, a short sealed verifier and a random reveal proof's SHA-256
   hash. The proof is sealed inside that verifier. **The key and the password are
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
   wrong password does not reveal. Decrypting the verifier releases the random
   proof, which the server requires in the `revealProof` field before consuming
   a new password-protected link. A deliberate POST to `/api/secrets/reveal`
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
| `REQUEST_METRICS` | no | `false` | Set to `true` for JSON route/status/duration metrics. Never includes request URLs, bodies, tokens, IPs or raw errors. |

### Hostnames and client addresses

Two separate mechanisms, easy to confuse:

`ALLOWED_HOSTS` feeds `security.allowedDomains` in `astro.config.mjs` and is read
at **build** time, so rebuild after changing it. With an empty list Astro rebuilds
every `request.url` as `http://localhost`. That no longer reaches the generated
links — the page composes both of them from the origin it was served from, see
below — but it does still affect Astro's own CSRF check on form-like POSTs, so set
your real hostname in production anyway. The default covers local development
only. Note that `npm run build` does not load `.env`: export the variable in the
build environment, or the manifest silently keeps the development default.

**Links are composed by the page, never by the server.** `POST /api/secrets`
returns the two tokens and no absolute URL. The browser joins them to
`window.location.origin`, so a control link cannot be handed to a host the user
never visited, and the content key still never travels in a response body. A
reverse proxy that this process does not recognise therefore cannot corrupt the
links it produces.

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

- `npm run build` emits the server bundle at `dist/server/entry.mjs`; `npm start` applies migrations and then runs `server.mjs`, which imports that bundle. Migration failure prevents the listener from starting.
- `server.mjs` is required in production, not just a convenience: it is what makes forwarding headers and the client IP trustworthy (see above).
- Run it behind a TLS-terminating reverse proxy, set `COOKIE_SECURE=true`, and
  send `Strict-Transport-Security` from that proxy. The app also sets HSTS on
  HTTPS responses whose host is not localhost, so a first visit over HTTP cannot
  be rewritten into a page that reads the fragment.
- Set the environment variables in the process manager (systemd `Environment=`,
  PM2, container env) rather than in a file, and keep `.env` out of the deployment.
- Start with `npm start` so migrations complete before switching traffic. `npm run migrate` remains available for an explicit migration step.
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
  seals an independent 256-bit reveal proof inside the verifier. Only the proof's
  SHA-256 hash is stored for server authorization; the password, fragment key and
  derived key remain in the browser. New password links require a valid proof
  before deletion, so token-only API requests cannot consume them.
  Migration `0004_reveal_proof.sql` is additive. Existing v1 links retain their
  original contract until expiration (at most 30 days): a caller bypassing the
  browser check can consume their unreadable ciphertext. Existing pages must be
  refreshed before creating password links with the new protocol. Do not roll
  back to code that ignores reveal proofs: it would reopen the consumption bypass
  for new links. Older rows keep a scrypt hash (N=32768, r=8, p=1) and
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

## Legal documents

`/privacy` and `/terms` are the privacy policy and the terms of use, in both
languages like everything else. The prose lives in `src/lib/legal.ts`, one string
per language; `src/layouts/LegalLayout.astro` only renders it. A revision is a
diff in one place, and nothing legal is written inside an `.astro` file.

Inline links are written `[[token]]` and resolved by `resolveLegalText`, which
returns text and links as separate parts so the page renders prose as text. The
allowed tokens and their labels are in `LEGAL_LINKS`; `tests/legal.test.ts` fails on
an unknown or unused token. The operator identity — name, VAT number, contact
address and the umbrella documents on the operator's main site — is the `OPERATOR`
constant at the top of the same file.

The documents describe what the code does: hashed tokens, the browser-side
ciphertext, the retention of `scripts/cleanup.mjs`, and the two residual limits
below. Where the implementation cannot back a promise they say so, so a revision
must keep matching the code rather than the intention.

### Infrastructure retention policy

The chosen target is a maximum of **7 days** for technical logs and any database
backups controlled by Example Operator S.r.l.. This is a policy to configure and verify, not a
retention guarantee enforced by the application. No infrastructure setting has
been changed or verified in this repository.

- Configure log rotation and deletion by age; redact share and control tokens
  from request paths, and never log request bodies or link fragments.
- If backups are enabled, expire backup copies, snapshots and archived WAL
  within the same 7-day recovery window, including exported copies.
- Record the effective settings and deletion checks before describing the limit
  as active in the privacy policy. Retention of provider-controlled data must be
  checked separately in the applicable contracts and policies.

Turnstile is documented as a possible future addition and is not integrated.
Before activation, verify the deployed cookie settings (including pre-clearance),
provider transfer safeguards and retention, then update the notice to describe
actual use. The support mailbox provider and message retention remain unverified.

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

The API tests require this database too: they execute real route handlers and
persist real fixtures. Even pure crypto files currently run the shared database
setup. Use the isolated database for every invocation of this Vitest config.

## Release checks and the platform operations

the platform manages the deployment on the hosting provider. CI verifies typecheck,
PostgreSQL tests, build, browser flows and the production dependency audit.
The first GitHub attempt could not acquire a hosted runner; local checks are not
proof of a CI-gated release. The current Git webhook can deploy a push before CI finishes. Deploy
only a verified revision, or configure a CI gate before relying on automatic releases.

Browser tests use the built Node server on loopback with Chromium, Firefox and
WebKit, on desktop and mobile. They truncate fixtures and refuse targets other
than a local `*_test` database. Apply migrations to that isolated database first:

```sh
ALLOWED_HOSTS=localhost,127.0.0.1 npm run build
npx playwright install chromium firefox webkit
TEST_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/secrets_test npm run test:browser
```

The Node entry point rejects declared bodies above 72 KiB. The adapter and JSON
reader also bound streamed bodies. Header timeout is 15 seconds; request/socket
timeouts are 30 seconds. Application SQL statements time out after 10 seconds,
lock waits after 5 seconds, and cleanup statements after 60 seconds. Migrations
serialize with an advisory lock. `npm start` migrates before accepting traffic.

Configure these settings together during the approved the platform release:

- Build with `NODE_VERSION=24` and `ALLOWED_HOSTS=secrets.example.com`.
  Use `npm start`, replacing `node server.mjs` and the post-deploy migration hook.
  Ensure build dependencies are installed. Bind to the private network for the
  the platform proxy; do not expose the app port publicly. Verify `TRUSTED_PROXIES`
  against the actual controlled addresses and the full Cloudflare forwarding chain.
- Health check: HTTP GET `/api/health`, port 3000 for this resource, expected 200,
  interval 60s, timeout 15s, three retries, start period 30s. The endpoint checks
  the database/schema without consuming secrets and returns only `ok`; failure
  returns 503. Bound public polling at the proxy to protect the connection pool.
- Schedule `node scripts/cleanup.mjs` hourly in the app working directory with
  its runtime environment. Monitor failures and missed runs, deployment errors,
  unhealthy resources and failed/missing backups through the existing the platform
  notification channel. Verify delivery; use a two-day missing-backup alert for
  a daily schedule.
- Preserve `no-store`, `no-referrer`, `DENY` and the app CSP through the proxy
  and Cloudflare. Set HSTS at the HTTPS edge and bound bodies before forwarding.
  Add measured edge rate limits: PostgreSQL quotas do not stop volumetric attacks.
- Redact share/control path tokens from proxy/CDN logs; never log request bodies.
  Verify age-based log deletion within seven days. `REQUEST_METRICS=true` emits
  only route templates, method, status and duration, without raw errors or IPs.
- Verify backup scope, successful execution and recovery. The seven-day target
  requires checking local/S3 copies, exported files, VM snapshots and provider
  retention separately. Job-based retention does not prove deletion when jobs
  stop. Preserve the runtime encryption key outside the database and its backups.

`npm run check:live` checks the public homepage headers and readiness through
Cloudflare, visiting no secret URLs and performing no writes. Set
`MONITOR_ORIGIN` only to another HTTPS origin if needed. Failures produce check
names and a nonzero exit status. Correct local headers are not public proof.

**Recovery:** an old database backup can resurrect consumed secrets. Restore
only offline. Without a complete, independently verified record of subsequent
consumptions/cancellations, discard restored pending payloads before reopening
traffic. This also invalidates unread links. Require explicit operator approval
for that destructive recovery step. Never restore the database just to roll back
code; retain the previous artifact/config and use forward-compatible migrations.
Changing `SECRET_ENCRYPTION_KEY` invalidates stored payloads.

Inspection on 5 October 2026 found no application health check or scheduled
cleanup, unrestricted CPU/memory, and migrations configured after deploy. The
shared PostgreSQL resource found in the platform has daily all-databases backups with
successful executions, local retention 3 days, S3 enabled with retention 14 days,
and missing-backup alerts disabled. Confirm it hosts this app before changing
scope; its shared retention affects other databases and exceeds the seven-day
policy target. The subsequent approved release enabled the health check and
hourly cleanup, and moved migrations into `npm start` before accepting traffic.
The observed runtime was Node 22.23.3, which meets the minimum of 22.12.
Cleanup execution and backup ownership still require verification.

Public HTTP redirected to HTTPS and cache was disabled, but response headers
were `Referrer-Policy: same-origin`, `X-Frame-Options: SAMEORIGIN`, with no HSTS
or CSP. The approved release now passes public readiness and header checks,
including the application CSP. A Cloudflare response-header rule scoped to
`secrets.example.com` sets `no-referrer`, `DENY` and HSTS (`max-age=15552000`).

Local proof: 428 PostgreSQL/unit tests and 40 browser cases passed, with clean
build/typecheck and no known npm vulnerabilities. An isolated restore drill
reproduced resurrection and verified offline payload removal prevents it. Outage
checks returned safe 503 responses and recovered without losing a pending fixture;
chunked body limits, malformed-host rejection and token-free metrics/errors
passed. A 100-request local readiness burst had p95 about 40 ms, not a production
capacity estimate. Actual the platform restore, notification delivery, log retention
and edge rate limits remain unverified. The v2 password protocol rejects direct
API consumption without the proof released by the password verifier. Existing
v1 links retain the consumption limitation described above until expiration.

References: [the platform backups](https://example.com/docs/databases/backups),
[proxy middleware](https://example.com/docs/core/networking/proxy/traefik/custom-middlewares),
[Node](https://railpack.com/languages/node/).
