# Runtime credential rendering

Status: accepted.

## Context

Committed configuration contains placeholders only. Runtime rendering must load
credentials without allowing callers to choose arbitrary secret paths, and it
must publish configuration and key material without following symlinks or
overwriting existing files.

## Decision

`render` loads a role-specific bundle from systemd's fixed credential directory.
The CLI exposes no flag for a credential root, credential filename, environment
variable, URL, or standard-input source. Tests inject synthetic bundles through
an in-process loader interface.

Credential metadata accepts either private `0700`/`0600`-style material or the
root-owned systemd credential mount used by Debian 13 / systemd 257 (`0550`
directory and `0440` files). The latter exception requires `root:root`, forbids
group write/execute on files, forbids group write on the directory, and always
forbids world access. Non-root group-readable material still fails closed.

The rendered configuration and allowlisted certificate assets are validated in
memory before the first write. Output names are fixed per role, paths are checked
component by component, existing targets are never replaced, and files are
published with restrictive permissions.

The bundle and all mutable copies owned by the renderer are zeroed on success
and failure. Immutable Go strings cannot be reliably overwritten and are
released normally. Backends must consume byte slices synchronously and retain no
references.

Typed-nil loader and probe implementations are rejected explicitly. Missing,
malformed, wrong-role, duplicate, oversized, or unexpected credential material
fails closed and is never included in diagnostics.

## Network evidence

Preflight defines a closed set of role-specific DNS and certificate facts. The
default implementation performs no live lookup and reports evidence as
unavailable. A future probe can be injected without allowing caller-supplied
targets or changing the evaluation rules.

For the Guangzhou gateway, the public HTTPS CONNECT edge is OpenResty
TCP/8444. OpenResty terminates TLS with an allowlisted SNI/certificate mapping
and forwards decrypted bytes to the authenticated Mihomo HTTP listener on the
fixed loopback address `127.0.0.1:18444`. Proxyctl reserves and validates the
loopback backend, while the external edge remains an independently reviewed
configuration transaction. Ordinary HTTP `proxy_pass` is not equivalent to
this stream contract and is not supported.

The HTTPS listener has two fixed, independently provisioned identities.
`HTTPS_USER_1`/`HTTPS_PASSWORD_1` remains the interactive client identity;
`HTTPS_USER_2`/`HTTPS_PASSWORD_2` is reserved for the HomeServer build-egress
machine adapter. Both pairs are required systemd credentials. A release that
contains the second identity must not be activated until its root-only files
exist; the renderer otherwise fails closed before replacing the running
process. The two identities must never reuse a password.

## Consequences

- The `gateway` role renders a Mihomo configuration and may publish gateway
  certificate material.
- The `egress` role renders a Hysteria2 server configuration and may publish
  egress certificate material.
- Rendering without provisioned credentials fails closed and publishes nothing.
- A partial multi-file write is retained for explicit inspection; the renderer
  never deletes a path by name after a failure.
