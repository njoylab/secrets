# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately, through GitHub's
["Report a vulnerability"](https://github.com/njoylab/secrets/security/advisories/new)
on this repository, rather than in a public issue.

Please include the affected version or commit, reproduction steps and the impact
you observed. Do not include real secrets, passwords, tokens or complete share
links. Reports are private, but reproduction data must still be synthetic.

Expect an acknowledgement within a few days. Fixes land as a normal commit; the
repository has no separate embargo policy, so please do not disclose publicly
before a fix and a release note exist.

## Scope

In scope: the code in this repository, the migrations, the browser-side
cryptography, the API endpoints and the server configuration defaults.

Out of scope: the deployment of a fork. Whoever operates a copy owns its TLS,
proxy, logging, backups, rate limits and `SECRET_ENCRYPTION_KEY`, and the
application cannot enforce any of those.

## Known limits

These are documented behaviours, not vulnerabilities, and are listed so they are
not reported again:

- The content key lives in the link fragment, so anyone holding the complete
  link and the optional password can read the secret. This is client-side
  encryption, not audited end-to-end encryption, and an operator who changes the page can read secrets
  created or opened afterwards.
- Consumption is a `DELETE ... RETURNING` that commits before the response is
  sent. If the response is lost, the secret is marked read and cannot be read
  again. See the [security model](../docs/security.md).
- Deleted rows remain in the WAL, in free space maps and in backups already
  taken. Erasure depends on retention policy outside this repository.
