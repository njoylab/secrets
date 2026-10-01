# secrets

A one-time secret sharing service. A secret is submitted over POST, encrypted
at rest, and exposed behind a single-use link. The link is redeemed at most
once: consumption is a conditional `DELETE ... RETURNING` executed by the
database, so concurrent readers cannot both obtain the content. Secrets expire
after 1–30 days (default 7) and an optional password can gate the read. The app
is an Astro 5 SSR project served by the Node adapter, backed by an external
PostgreSQL. No Docker, no Redis, no separate backend.

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

## Environment variables

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | yes | — | PostgreSQL connection string, e.g. `postgres://user:password@host:5432/database`. |
| `SECRET_ENCRYPTION_KEY` | yes | — | AES-256-GCM key, 32 random bytes encoded base64url. Held outside the database. |
| `TRUSTED_PROXIES` | no | empty (trust nobody) | Comma-separated addresses of the proxies you control, which are then allowed to supply `X-Forwarded-For`. |
| `ALLOWED_HOSTS` | no | `localhost,127.0.0.1` | Hostnames this deployment answers to. Read at **build** time by `astro.config.mjs`. |
| `ALLOWED_ORIGINS` | no | empty | Extra origins accepted for same-origin POSTs. |
| `RATE_LIMIT_CREATE_MAX` | no | `20` | Secret creations allowed per window, per client IP. |
| `RATE_LIMIT_CREATE_WINDOW_SECONDS` | no | `3600` | Creation window length. |
| `RATE_LIMIT_REVEAL_MAX` | no | `30` | Reveal attempts allowed per window, per client IP. |
| `RATE_LIMIT_REVEAL_WINDOW_SECONDS` | no | `300` | Reveal window length. |
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

## Cleanup

`npm run cleanup` deletes expired rows from `secrets` and rate limit counters
older than `CLEANUP_KEEP_COUNTER_SECONDS`, printing the counts. Run it from cron
or a systemd timer, for example every hour:

```
17 * * * * cd /srv/secrets && npm run cleanup
```

## Deployment on Node

- `npm run build` emits the server bundle at `dist/server/entry.mjs`; `npm start` runs `server.mjs`, which imports that bundle.
- `server.mjs` is required in production, not just a convenience: it is what makes forwarding headers and the client IP trustworthy (see above).
- Run it behind a TLS-terminating reverse proxy and set `COOKIE_SECURE=true`.
- Set the environment variables in the process manager (systemd `Environment=`,
  PM2, container env) rather than in a file, and keep `.env` out of the deployment.
- Run `npm run migrate` as a deploy step before switching traffic.
- Schedule `npm run cleanup`.
- The adapter listens on `HOST`/`PORT` (default port `8080`). Keep it on the loopback or a private interface and let the proxy be the only public entry point.

## Security notes

- Tokens carry 256 bits of randomness. Only their SHA-256 hash is stored, so a
  database dump does not yield usable links.
- Content is encrypted at rest with AES-256-GCM under a random per-secret nonce.
  This is **encryption at rest, not end-to-end encryption**: the server holds
  the key and can read any secret.
- Passwords use scrypt (N=32768, r=8, p=1) with a random 16-byte salt per
  secret. A wrong password is rejected before any delete runs and never consumes
  the secret.
- Consumption is a single conditional `DELETE ... RETURNING`, so at most one
  concurrent request can ever obtain the content.
- If the delete commits but the response never reaches the browser, the secret
  is gone. There is no second read and no recovery. This is deliberate.
- **Residual limit:** deleting a row removes it from the heap but not from the
  WAL, from free space maps, or from base backups already taken. Erasure from
  backups is a matter of backup retention policy, not of application logic.

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
point it at a production database. The test files are not part of the tree yet;
`vitest.config.ts` expects them under `tests/` with a `tests/setup.ts` setup file
and runs them serially against a single database.
