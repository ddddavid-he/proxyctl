# Security Policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that may expose credentials,
private keys, hostnames, or network access. Use the repository host's private
security-reporting channel.

Include the affected version or commit, impact, and reproduction steps. Avoid
including live secrets in the report.

## Security invariants

- Real secrets never enter the repository, release artifacts, command lines, or
  logs.
- Example configurations use placeholders and reserved documentation values
  only; they contain no live hostname, operator topology, or private scenario.
- Unsafe or incomplete configuration fails closed.
- CI builds and verifies artifacts but does not deploy them.
- Third-party actions and upstream binaries are pinned and verified.
