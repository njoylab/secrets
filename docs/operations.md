# Operations

Runtime and deployment reference. See the [README](../README.md) for setup and
the [security model](security.md) for cryptographic guarantees and limits.

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
| `SOURCE_URL` | no | empty (no link) | Absolute HTTPS URL of the public repository, linked from the footer. Invalid values are rejected at startup rather than rendered. |
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
table that remembers how a secret closed. `0003_password_verifier.sql` adds the
browser-side password verifier; `0004_reveal_proof.sql` adds its authorization
proof hash. The current app rejects legacy password records without a reveal
proof; keep the historical migrations, but do not roll back to an implementation
that ignores proofs. There is no down migration: rolling back would mean
discarding secrets or state that no longer has meaning.

## Cleanup

`npm run cleanup` does three things in one transaction each and prints the counts:

- deletes expired rows from `secrets` and writes an `expired` receipt for each, so
  a control link keeps answering "expired" instead of "unavailable" after the row
  is gone;
- deletes receipts whose retention has elapsed;
- deletes rate limit counters older than the counter retention.

Receipts are kept until `max(original expiry, closure + 7 days)`, so a control
link is informative for a bounded time after closure and then becomes unavailable. The counter retention is the largest of
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
  HTTPS responses whose host is not localhost. HSTS protects future HTTP visits
  after the browser learns the policy; it does not protect an initial HTTP
  visit. Share HTTPS links only. HSTS preload requires a separate, deliberate
  deployment decision covering the domain and its subdomains.
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

The bundled policy omits a VAT number. Treat the legal text as a template for
your own deployment, and review the identity, contact details, providers and
retention statements before publishing it.

The documents describe what the code does: hashed tokens, the browser-side
ciphertext, the retention of `scripts/cleanup.mjs`, and the residual limits in the [security model](security.md). Where the implementation cannot back a promise they say so, so a revision
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
