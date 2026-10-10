# secrets

A one-time secret sharing service. Text is encrypted **in the browser** with a
random AES-256-GCM key that stays in the link fragment, so the content key never
reaches the server, and the request body carries an opaque sealed payload. The
server stores that payload and wraps it in a second AES-256-GCM layer of its own
to keep the at-rest ciphertext unreadable from a database dump alone.

Each secret gets two links: the **share link** `/s/<token>#<key>`, and a
**control link** `/c/<control token>` that only ever reports the state of the
secret (`pending`, `read`, `expired`, `cancelled`), when it was created and
closed, and can cancel it. The share link is redeemed at most once: consumption
is a conditional
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
   a password-protected link. A deliberate POST to `/api/secrets/reveal`
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
| `MONITOR_ORIGIN` | no | — | Required by `npm run check:live` only: the HTTPS origin of the deployment to verify. |

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

## QR code and control link instants

Two additions on top of the MVP, both of which only touch what a link already
exposes.

**The QR code** of the share link is drawn by `src/lib/qr.ts`, a byte-mode
encoder written for this project: Reed-Solomon over GF(256), block interleaving,
the eight data masks with the four penalty rules, and the BCH format and version
information. It runs in the browser on a `<canvas>` and draws runs of dark
modules, so no image request, data URL or third-party script is involved and no
asset reaches the page from anywhere but this origin.

The encoder is deliberately narrow: byte mode only, no ECI, no kanji, no Micro
QR. It exists to render one short ASCII link, and everything else is left out
rather than half implemented. Because a silent bug here produces a code no
scanner can read, `tests/qr.test.ts` verifies it by decoding its own output back
(format information, unmask, zigzag walk, de-interleave, then a Reed-Solomon
syndrome check per block) and cross-checks the resulting codewords against
`qrcode-generator`, pinned as a **dev** dependency for that purpose only. It is
never imported by `src/` and never reaches the bundle. The one thing the two
implementations are allowed to disagree on is which mask they pick, since the
reference library scores masks with a non-standard penalty function.

The code encodes the full share link including the key in its fragment, so it is
drawn only once the link exists and the canvas is cleared when the result panel
is reset, rather than left holding key material behind a hidden element.

**The control link instants** come from columns that already existed:
`secrets.created_at` and `secret_receipts.closed_at`. No migration was needed.
A pending secret shows when it was created and when it expires; once it closes,
the row is gone, so the creation instant disappears and the closing instant takes
its place. The cancel endpoint returns the instants alongside the new state so
the page repaints in place instead of waiting for a reload. These are instants
and nothing else: `tests/secrets.test.ts` enumerates the fields a control link
may return and fails if anything else appears.

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
- The adapter listens on `HOST`/`PORT` (default port `4321`). `HOST` defaults to
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
  derived key remain in the browser. Password links require a valid proof
  before deletion, so token-only API requests cannot consume them.
  A verifier and its proof hash must always be supplied together. Only this
  password protocol is supported; incomplete or unsupported stored records are
  unavailable and cannot be consumed. Historical migrations remain versioned;
  the unused `password_hash` column is never populated or verified by the app.
  No existing data is deleted by this code change. Do not roll back to code that
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

## Legal documents

`/privacy` and `/terms` are the privacy policy and the terms of use, in both
languages like everything else. The prose lives in `src/lib/legal.ts`, one string
per language; `src/layouts/LegalLayout.astro` only renders it. A revision is a
diff in one place, and nothing legal is written inside an `.astro` file.

Inline links are written `[[token]]` and resolved by `resolveLegalText`, which
returns text and links as separate parts so the page renders prose as text. The
allowed tokens and their labels are in `LEGAL_LINKS`; `tests/legal.test.ts` fails on
an unknown or unused token. The operator identity — name, contact address and the
umbrella documents of the main site — is the `OPERATOR` constant at the top of the
same file. It ships as a placeholder and the operator name is also written into the
prose, so replace both before deploying under your own identity: the published
documents state the controller, and they must name whoever actually runs the
service. `tests/legal.test.ts` fails when the prose and the constant disagree.

No VAT number is published. Articles 13-14 GDPR require the controller's identity
and contact details, not a registration number, and the test asserts that none
appears in the prose.

The documents describe what the code does: hashed tokens, the browser-side
ciphertext, the retention of `scripts/cleanup.mjs`, and the two residual limits
below. Where the implementation cannot back a promise they say so, so a revision
must keep matching the code rather than the intention. The bundled text also
describes the deployment it was written against — its host, its proxy and its
providers. A deployment on a different stack must revise those paragraphs before
the documents describe anything true.

### Infrastructure retention policy

Retention of technical logs and backups is a property of the infrastructure, not
of this application: nothing here enforces it. If you publish a limit, such as a
maximum of 7 days, then verify the settings that produce it.

- Configure log rotation and deletion by age; redact share and control tokens
  from request paths, and never log request bodies or link fragments.
- If backups are enabled, expire backup copies, snapshots and archived WAL
  within the same recovery window, including exported copies.
- Record the effective settings and deletion checks before describing the limit
  as active in the privacy policy. Retention of provider-controlled data must be
  checked separately in the applicable contracts and policies.

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

## Release checks

CI verifies typecheck, PostgreSQL tests, build, browser flows and the production
dependency audit. Browser tests use the built Node server on loopback with Chromium, Firefox and
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

## Operating the deployment

The items below are the checks to configure for your own platform. Nothing here
is specific to one host: a reverse proxy, a process manager and a scheduler are
enough.

- Build with a Node version matching `engines.node`, and export
  `ALLOWED_HOSTS=<your hostname>` in the build environment, since
  `npm run build` does not load `.env`. Use `npm start`, not `node server.mjs`
  and not a post-deploy migration hook, so migrations finish before traffic
  arrives. Bind `HOST` to the private interface the proxy reaches and never
  expose the app port publicly. Verify `TRUSTED_PROXIES` against the addresses
  you actually control, including every hop of the forwarding chain.
- Health check: HTTP GET `/api/health`, expected 200, with an interval of about
  60s, a timeout of 15s, three retries and a start period long enough for the
  first migration. The endpoint checks the database and schema without consuming
  secrets and returns only `ok`; failure returns 503. Bound public polling at
  the proxy so health checks cannot exhaust the connection pool.
- Schedule `npm run cleanup` (hourly is a reasonable default) in the app working
  directory with its runtime environment. Monitor cleanup failures, missed runs,
  deployment errors, unhealthy resources and failed or missing backups, and
  verify that notifications are actually delivered. Alert on a missed backup
  after roughly two days for a daily schedule.
- Preserve `no-store`, `no-referrer`, `DENY` and the application CSP through the
  proxy and any CDN in front of it. Send HSTS from the HTTPS edge and bound
  request bodies before forwarding. Add measured edge rate limits: the
  PostgreSQL quotas do not stop volumetric attacks.
- Redact share and control path tokens from proxy and CDN logs; never log
  request bodies. Verify age-based log deletion. `REQUEST_METRICS=true` emits
  only route templates, method, status and duration, without raw errors or IPs.
- Bound CPU and memory for the service. Verify that backups cover the right
  scope, actually run, and can be restored. A job-based retention setting does
  not prove deletion when the job stops. Keep `SECRET_ENCRYPTION_KEY` outside
  the database and outside its backups.

`npm run check:live` verifies the public homepage headers and readiness of a
deployed instance, visiting no share or control URLs and performing no writes.
It requires `MONITOR_ORIGIN` to be set to the HTTPS origin under test. Failures
produce check names and a nonzero exit status. Correct local headers are not
public proof: run it against the deployed origin.

**Recovery:** an old database backup can resurrect consumed secrets. Restore
only offline. Without a complete, independently verified record of subsequent
consumptions and cancellations, discard restored pending payloads before
reopening traffic; this also invalidates unread links. Require explicit operator
approval for that destructive step. Never restore the database just to roll
back code: retain the previous artifact and configuration and use
forward-compatible migrations. Changing `SECRET_ENCRYPTION_KEY` invalidates
every stored payload.

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

## Security reporting

Report a suspected vulnerability privately as described in `.github/SECURITY.md`
rather than in a public issue, and include reproduction steps. Never include
real secrets, passwords or complete share links in a report.

## Contributing

Small, reviewable pull requests against `main`. Match the existing style: TypeScript
strict, English code comments, no runtime dependency added without a stated need,
and no change that breaks an invariant listed in "Security notes" — in particular
never let a `GET` consume a secret and never send the fragment key to the server.
Update `README.md` and the legal documents in `src/lib/legal.ts` when behaviour
changes; `npm run typecheck`, `npm test`, `npm run build` and `npm run test:browser`
must pass, and all of them run in CI.

## License

MIT. See `LICENSE`.
