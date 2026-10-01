# Project Working Agreement

## Project scope

- Read `PIANO_SVILUPPO.md` before implementing features. It defines the MVP requirements and acceptance checks.
- Build a minimal application for sharing text secrets through one-time links, with expiration and an optional password.
- Use Astro, TypeScript, the Node adapter, and external PostgreSQL through `pg` with a connection pool.
- Do not introduce Docker, Redis, a separate backend, or additional frontend frameworks.
- Keep SQL migrations versioned. Avoid new dependencies unless necessary.

## Working approach

- Read repository instructions, README, package manifest, and relevant configuration before changing code, when present.
- Make small, local, maintainable changes and preserve existing patterns.
- Preserve user changes. If unexpected concurrent changes affect the work, stop and report the conflict.
- Proceed directly on low-risk implementation choices. Ask one precise question for destructive actions or material product, data, deployment, or security ambiguity.
- Do not add features outside the MVP scope or perform broad refactors.
- Do not create branches, commit, push, deploy, or modify production data unless explicitly requested.

## Language and communication

- **All code comments must be in English**, including inline comments, block comments, JSDoc, SQL comments, and TODO notes.
- Use English identifiers for variables, functions, types, database objects, and configuration keys.
- Add comments only to explain non-obvious decisions or invariants; avoid narrating the code.
- Keep user-facing text in centralized Italian and English dictionaries, including errors and accessibility labels.
- Never translate or modify the secret content.
- Communicate with the user in Italian unless requested otherwise. Keep updates and final reports concise.

## UI

- Keep the interface minimal, dark, and oriented toward developers.
- Use system fonts, monospace for secrets and links, subtle borders, and one accent color.
- Prefer Astro components, plain CSS, and minimal browser JavaScript.
- Avoid marketing sections, verbose explanations, decorative animations, and third-party assets.
- Preserve responsive layout, keyboard navigation, accessible labels, and visible focus states.

## Security and data invariants

- Never consume a secret through GET requests, page rendering, previews, or prefetching.
- Reveal secrets only after an explicit POST and successful password verification, when required.
- Enforce expiration in SQL and consume the record atomically. Send the content only after the deletion commits.
- Concurrent reveal requests must allow at most one successful retrieval.
- Incorrect passwords must not consume the secret. Do not hold database locks while computing password hashes.
- Encrypt secret content with AES-256-GCM using a random nonce per secret and a key kept outside the database.
- Store only token hashes and salted scrypt password hashes. Use Node cryptographic primitives.
- Validate inputs on the server, use parameterized queries, and render secrets as text rather than HTML.
- Never expose credentials or log secret content, passwords, tokens, request bodies, or complete secret URLs.
- Disable caching and indexing for sensitive responses. Enforce cross-origin POST protection and configurable rate limits.
- Trust forwarded client IP headers only through explicitly configured trusted proxies.
- Keep real credentials out of version control; provide placeholders in `.env.example`.
- Document persistence and backup limits. Do not claim end-to-end encryption or immediate erasure from WAL and backups.

## Verification and delivery

- Run the closest useful checks after changes: targeted tests, typecheck, and build where relevant.
- Test password failures, expiration, concurrent consumption, GET requests without consumption, input limits, XSS handling, rate limits, and cross-origin protection.
- Verify Italian and English text, accessibility basics, and desktop/mobile layouts for UI changes.
- Use an isolated test database. Never run destructive tests against production.
- Keep the README concise and document setup, environment variables, migrations, cleanup, and Node deployment.
- Finish with the result, files touched, checks actually run, and remaining risks or unverified behavior.
- Do not claim a check passed unless it was executed successfully.
