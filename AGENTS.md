# Agent Guidelines

Instructions for coding agents and contributors working on this repository.
Personal or machine-specific preferences belong in an ignored local file
(`AGENTS.local.md`), not here.

## Project scope

- A minimal application for sharing text secrets through one-time links, with expiration and an optional password.
- Stack: Astro, TypeScript, the Node adapter, and external PostgreSQL through `pg` with a connection pool.
- Do not introduce Docker, Redis, a separate backend, or additional frontend frameworks.
- Keep SQL migrations versioned. Avoid new dependencies unless necessary.
- `docs/security.md` describes the security model in detail; keep it consistent with any change to the crypto or reveal flow.

## Working approach

- If `AGENTS.local.md` exists, read it and follow it as well.
- Read the README, package manifest, and relevant configuration before changing code.
- Make small, local, maintainable changes and preserve existing patterns.
- Keep the product minimal: do not add features beyond the current scope or perform broad refactors without discussion.

## Language

- **All code comments must be in English**, including inline comments, block comments, JSDoc, SQL comments, and TODO notes.
- Use English identifiers for variables, functions, types, database objects, and configuration keys.
- Add comments only to explain non-obvious decisions or invariants; avoid narrating the code.
- Keep user-facing text in centralized Italian and English dictionaries, including errors and accessibility labels.
- Never translate or modify the secret content.

## UI

- The chrome follows the echoValue shell: skip link, navbar, theme toggle, hamburger, footer, and `src/styles/dev-theme.css`, imported by the layout so Astro can hash it into the page CSP. Dark is the default.
- Keep page copy in the Italian and English dictionaries. Secret content is never translated.
- Prefer Astro components and the classes already in the theme. Do not add a second palette, a remote font, or a remote icon stylesheet: the Content-Security-Policy is `default-src 'self'`.
- The create, reveal, and control flows stay a form inside the shell. Do not turn them into a marketing landing.
- Preserve responsive layout, keyboard navigation, accessible labels, and visible focus states.

## Security and data invariants

- Never consume a secret through GET requests, page rendering, previews, or prefetching.
- Reveal secrets only after an explicit POST and successful password verification, when required.
- Enforce expiration in SQL and consume the record atomically. Send the content only after the deletion commits.
- Concurrent reveal requests must allow at most one successful retrieval.
- Incorrect passwords must not consume the secret. Do not hold database locks while deriving password keys or verifying authorization.
- Seal secret content in the browser with AES-256-GCM. The fragment key stays in the share-link fragment and never reaches the server. Wrap the resulting payload at rest with AES-256-GCM under a key kept outside the database.
- In the browser, derive two independent keys with HKDF-SHA256 from the fragment key, using distinct `info` labels: the content key that seals the payload and an auth key. With a password, PBKDF2-HMAC-SHA256 output is the HKDF salt, so both keys need the fragment key and the password. Never send the content key, the fragment key, or the password, and never store anything from which they can be tested offline.
- Store only token hashes, control-token hashes, and a keyed hash of the auth key: HMAC-SHA256 of the client-sent SHA-256 under an HKDF subkey of the deployment key (never the AES key bytes directly). A wrong deployment key must report a server error without consuming, never a password error. Every reveal must present the auth key, checked timing-safely before the conditional delete, so a wrong password or fragment key never consumes and each guess is one rate-limited reveal request. No verifier endpoint and no legacy formats are supported. The at-rest wrapper uses Node cryptographic primitives. The content seal and key derivation use Web Crypto so the same code runs in the browser.
- Validate inputs on the server, use parameterized queries, and render secrets as text rather than HTML.
- Never expose credentials or log secret content, passwords, tokens, request bodies, or complete secret URLs.
- Disable caching and indexing for sensitive responses. Enforce cross-origin POST protection and configurable rate limits.
- Trust forwarded client IP headers only through explicitly configured trusted proxies.
- Keep real credentials out of version control; provide placeholders in `.env.example`.
- Document persistence and backup limits. Do not claim end-to-end encryption or immediate erasure from WAL and backups.

## Verification

- Run the closest useful checks after changes: targeted tests, typecheck, and build where relevant.
- Test password failures, expiration, concurrent consumption, GET requests without consumption, input limits, XSS handling, rate limits, and cross-origin protection.
- Verify Italian and English text, accessibility basics, and desktop/mobile layouts for UI changes.
- Use an isolated test database. Never run destructive tests against production.
- Keep the README concise and document setup, environment variables, migrations, cleanup, and Node deployment.
- Do not claim a check passed unless it was executed successfully.
