# secrets

A minimal service for sharing text through one-time links, with expiration,
optional passwords, and a separate control link to check status or cancel.

The browser encrypts the text with AES-256-GCM before sending it. The key stays in
the share-link fragment; the server stores only a sealed payload, wrapped in a
second encryption layer under a deployment key, and the hash of a separate auth
key derived from the fragment key and the optional password. Passwords stay in the
browser, and a wrong one never consumes the secret.
This is client-side encryption, **not audited end-to-end encryption**: the service
operator can change the JavaScript delivered to users.

Built with Astro, TypeScript, the Node adapter and PostgreSQL. No accounts,
attachments, Docker, Redis or separate backend.

## Features

- Text up to 50 KiB in UTF-8, preserving whitespace and markup as inert text.
- Expiration presets: 1 hour, 1 day, 7 days (default), or 30 days.
- Explicit reveal action; GET requests, previews and prefetches never consume.
- Atomic database consumption: at most one concurrent retrieval succeeds.
- Optional password, local QR code, and independent control/cancellation link.
- Minimal dark interface in Italian and English.

## Requirements

- Node.js >= 22.12; CI uses Node 24.
- A reachable, supported PostgreSQL instance.
- A modern browser with JavaScript and Web Crypto. HTTPS is required outside
  localhost development.

## Quick start

```sh
git clone https://github.com/njoylab/secrets.git
cd secrets
npm ci
cp .env.example .env
```

Create an application role and database with your PostgreSQL administrator:

```sql
CREATE ROLE secrets LOGIN PASSWORD 'choose-a-password';
CREATE DATABASE secrets OWNER secrets;
```

Set `DATABASE_URL` in `.env` to that database. Generate the deployment encryption
key and put it in `SECRET_ENCRYPTION_KEY`:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Keep the key outside version control, the database and its backups. It protects
the outer storage layer; the separate browser key is still needed to read the
text. Losing or replacing the deployment key makes stored payloads unreadable.

```sh
npm run migrate
npm run dev
```

Open [localhost:4321](http://localhost:4321). Development uses a shared rate-limit
bucket because it bypasses the production proxy wrapper.

## Production

Export your hostname at **build time**; `npm run build` does not load `.env`:

```sh
ALLOWED_HOSTS=secrets.example.com npm run build
npm start
```

Configure runtime secrets in your process manager. `npm start` applies migrations
before accepting traffic and runs the required `server.mjs` wrapper. Put a TLS
reverse proxy in front, configure `TRUSTED_PROXIES` to match its actual addresses,
keep the app port private, and schedule `npm run cleanup` hourly. Migration
`0005_auth_key.sql` closes every live link created before it; see the operations
guide before upgrading. Without trusted
proxy configuration, users behind that proxy share one rate-limit quota. IPv6
clients are counted per /64, so a whole IPv6 subnet shares one quota.

Before public use, replace the operator placeholders and deployment-specific
statements in `src/lib/legal.ts`. Check log redaction, backup retention, recovery,
and the proxy configuration in the [operations guide](docs/operations.md).

## Security and limits

The share link contains the decryption key after `#`; treat the complete link as
sensitive and send any password separately. A control link cannot read content.

- Consumption commits before delivery. A lost response or failed client
  decryption cannot be retried; the control link reports `read`.
- A wrong password or a damaged key is refused before deletion, so it consumes
  nothing. Each password guess is a reveal request and counts against the reveal
  rate limit. The stored auth hash is keyed with the deployment key, so a
  database dump, even together with the link, does not allow offline guessing;
  someone who also holds `SECRET_ENCRYPTION_KEY` can still guess offline.
- Reloading after the fragment is removed loses the in-memory key, but consumes
  nothing: reopen the original share link. Changing language preserves the key in
  client-side fragments and never sends it to the server.
- Expiration blocks reads immediately; periodic cleanup removes expired rows.
- Close receipts persist until `max(original expiry, closure + 7 days)`, then
  cleanup removes them.
- Database deletion does not immediately erase WAL or existing backups. Backup
  restoration can resurrect consumed records; recovery must happen offline.
- HSTS protects subsequent visits once the browser knows the policy. It does not
  protect an initial HTTP visit; share HTTPS links only.

See the [security model](docs/security.md) for the protocol, trust boundaries,
password authorization, and remaining limits. Report vulnerabilities privately
through [GitHub Security Advisories](https://github.com/njoylab/secrets/security/advisories/new);
see [SECURITY.md](.github/SECURITY.md). Use synthetic reproduction data only.

## Development and tests

Tests delete fixtures. Use an **isolated local database** whose name ends in
`_test`, with a connection URL without query parameters. Never use the application
or production database. The suite validates the target before cleanup, including
teardown after a failed setup.

Create a separate database and role with your PostgreSQL administrator:

```sql
CREATE ROLE secrets_test LOGIN PASSWORD 'choose-a-test-password';
CREATE DATABASE secrets_test OWNER secrets_test;
```

Set the URL for that local instance:

```sh
export TEST_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/secrets_test
DATABASE_URL="$TEST_DATABASE_URL" npm run migrate
npm run typecheck
DATABASE_URL="$TEST_DATABASE_URL" npm test
ALLOWED_HOSTS=localhost,127.0.0.1 npm run build
npx playwright install chromium firefox webkit
npm run test:browser
npm audit --omit=dev --audit-level=high
```

Run Vitest and browser tests sequentially: they reset the same fixtures.
Vitest loads `.env` and then `.env.test` when present; existing shell environment
variables take precedence. Browser tests require `TEST_DATABASE_URL` and use the
built Node server. Even pure Vitest files currently use the shared database setup.

CI runs typecheck, PostgreSQL tests, build, browser flows on Chromium/Firefox/WebKit
and desktop/mobile profiles, and the production dependency audit. Coverage includes
password failures, expiry, concurrency, non-consuming GETs, limits, XSS, rate limits,
cross-origin protection, failed JavaScript loading, and locale changes before reveal.

## Contributing

Small, reviewable pull requests against `main`. Use strict TypeScript and English
code comments, preserve the security invariants, and explain any new runtime
dependency. Run the checks above and update documentation and IT/EN dictionaries
when behavior changes. Update `src/lib/legal.ts` when stored data or retention changes.

## Documentation

- [Security model and limitations](docs/security.md)
- [Design notes](docs/design.md)
- [Environment, migrations, cleanup, deployment and recovery](docs/operations.md)
- [QR implementation and control timestamps](docs/qr.md)
- [Security reporting policy](.github/SECURITY.md)

## License

[MIT](LICENSE).
