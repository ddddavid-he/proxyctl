# proxyctl CLI

`proxyctl` is a local validation and rendering tool. It performs no remote
execution, deployment, or proxy data-plane work.

## Commands

```
proxyctl preflight --role gateway|egress [--offline] [--config PATH]
proxyctl render --role gateway|egress --template-dir DIR --config PATH --out-dir DIR
proxyctl verify --profile loopback|canary
proxyctl status [--json] [--state-dir DIR]
proxyctl version
```

All output is JSON (except `status` without `--json` and `version`).
Errors on stderr are safe JSON: `{"error": {"code": "...", "message": "..."}}`.

## Exit codes (stable contract)

| Code | Constant | Meaning |
|---|---|---|
| 0 | OK | success |
| 2 | USAGE | missing/invalid argument combination |
| 3 | UNKNOWN_COMMAND | unknown subcommand |
| 4 | UNKNOWN_FLAG | unknown or malformed flag |
| 5 | INVALID_ENUM | invalid --role or --profile value |
| 6 | NOT_FOUND | template/config/state file missing |
| 7 | PERMISSION | permission denied |
| 8 | CONFIG_REJECTED / TEMPLATE_REJECTED / RENDER_UNSAFE | allowlist or safety rejection |
| 9 | IO | filesystem error |
| 10 | INTERNAL | internal error (details never printed) |

## preflight

Read-only checks; **no DNS resolution or network access is performed**
in any mode (`--offline` additionally marks the run and skips all
probing). Checks: architecture expectation (arm64 for gateway, amd64 for egress),
reserved port documentation, credential placeholder posture (when
`--config` is given; the config path must be a regular file — symlinks,
directories and raw `..` traversal components are refused), fail-closed
marker, and — when online — the `dns-evidence` / `certificate-evidence`
checks described below.

## render

Validates then renders the role template into `--out-dir` (an explicit,
caller-isolated, pre-existing directory with mode `0700`; proxyctl never
creates it, never walks above it, and never replaces an existing file).

### Runtime credentials

`render` resolves the credential placeholders from the role's **systemd
credential bundle**, loaded through `credential.LoadSystemd`: the fixed
`/run/credentials` root (`$CREDENTIALS_DIRECTORY`) and a fixed per-role
name allowlist.

- **Nothing caller-controlled can supply a credential.** There is no
  flag for a credential root, directory, file name, environment variable
  name, stdin stream, URL or arbitrary path. Every such flag is an
  unknown flag (`UNKNOWN_FLAG`, exit 4).
- A missing, duplicate, malformed, oversized, multiline,
  control-bearing, wrong-role or inaccessible credential **fails
  closed**: nothing is published.
- Credential inode permissions accept private `0700`/`0600` material and the
  root-owned `0550`/`0440` mount produced by Debian 13's systemd 257. The
  root-group exception is read-only and never permits world access; equivalent
  modes owned by a non-root user or group are rejected.
- A bundle whose role differs from the requested role is refused, and
  render independently enforces the per-role asset allowlist, so a `gateway`
  render can never publish `egress.crt`/`egress.key`.
- The bundle is **closed as soon as the render finishes** (success or
  failure): the bundle's own asset bytes are zeroed in place and later
  lookups on it fail closed.
- The buffers render itself owns are wiped too, on **every** path out of
  the command — writer success, writer failure, and every early return
  including a rejected asset name, an empty asset or a duplicate name.
  Closing the bundle alone is not sufficient, because `Materialize` hands
  out deep copies the bundle never sees again. Two cleanups therefore
  run: one over the publication set, and one over the **entire batch**
  `Materialize` returned, registered the moment that batch exists so an
  asset rejected mid-loop (and every asset after it) is still zeroed.
  The two overlap deliberately; zeroing twice is idempotent.
  Documented limit: the rendered config also exists as an immutable Go
  string, which cannot be zeroed without `unsafe` aliasing of memory
  render does not own; it is left to the collector.
- A **typed-nil** bundle (a non-nil interface wrapping a nil
  `*credential.Bundle`) is detected and refused explicitly rather than
  panicking, since `== nil` is false for it.
- No secret value, source path, auth header, private-key byte or full
  credential content ever appears in `render` stdout, stderr or JSON.

### Published output

The rendered config **and** the role's allowlisted certificate/key assets
are published together in **one** safe transaction, under their fixed
names:

| Role | Published files |
|---|---|
| `gateway` | `gateway-rendered.yaml`, `gateway.crt`, `gateway.key` (+ `gateway-client.crt`, `gateway-client.key` when present) |
| `egress` | `egress-rendered.yaml`, `egress.crt`, `egress.key` (+ `gateway-client-ca.crt` when present) |

`Result.files` lists exactly these fixed names in publication order.
Scalar secrets and asset bytes stay strictly distinct: asset bytes are
written to their own files and are never inlined into the rendered
config.

The published YAML is the locked engine's native runtime configuration,
not the `private-proxy/v1` input document. The `gateway` template is accepted by
Mihomo and routes every request through the configured Hysteria2 upstream;
the `egress` template is accepted by Hysteria2 server mode. The input document
must provide `egress-server`, fixed `egress-port: 443`, and `egress-sni` for `gateway`; the
`egress` listener port is likewise fixed at `443`. Runtime syntax validation is
part of release acceptance, while proxyctl remains the renderer rather than
an embedded proxy implementation. For Hysteria2 `userpass`, render derives
the client authentication value as `gateway-egress-user:GATEWAY_EGRESS_PASSWORD_1`; machine
usernames are restricted so the delimiter cannot be ambiguous.

Safety matrix (all rejected before any write):

- templates are governed by a **double allowlist**: the exact file name
  per role (`templates/mihomo/mihomo-gateway.yaml.tmpl` for gateway,
  `templates/hysteria/hysteria-egress.yaml.tmpl` for egress) **and** a SHA-256
  digest of the repository-controlled template bytes pinned in
  `internal/render`; a same-named file with arbitrary or tampered
  content is rejected (`TEMPLATE_REJECTED`) with no output created.
  Changing a template requires updating its pinned digest in the same
  reviewed change;
- the template dir itself must be a real directory (not a symlink);
- the config path final component must be a regular file (symlinks and
  directories are refused before reading);
- unknown top-level fields, unknown sections, unknown listener fields rejected (schema allowlist `private-proxy/v1`);
- `DIRECT` fallback, `skip-cert-verify`, `insecure: true` rejected;
- `mixed-port 7890` must bind `127.0.0.1`; public 7890 rejected;
- controller must not bind `0.0.0.0`/`::` (including `:port` forms);
- empty credentials and non-placeholder (real) credential values rejected — Git only ever carries `${VAR}` placeholders;
- path traversal (`..` components, checked on raw strings before any
  Clean/Join) rejected in template dir, config path and output dir;
- template engine directives (`{{`, `}}`, `{%`) rejected (no includes, no arbitrary template features);
- the **publication set is name-validated before the first write**: every
  output name is checked against the fixed allowlist, so a rejected name
  performs zero filesystem operations and publishes nothing;
- published per file atomically with **no replace** (a pre-existing
  target is never overwritten or truncated); the output directory and
  every path component are verified on a held descriptor, so no symlink
  at any depth is followed;
- output files are `0600` inside a `0700` directory, each fsynced before
  publication.
- **validation-before-write, without exception**: the config document,
  the template identity, the placeholder schema, the whole credential
  bundle and the output name allowlist are validated and fully
  substituted/assembled in memory first, so a rejection never leaves a
  partial artifact and never touches the filesystem.

**Partial-bundle behavior.** A set of files is *not* atomic. If a
mid-transaction publish fails, the run returns the fixed
`output bundle state undefined; published files retained, manual cleanup
required` error (exit 9) and **already-published files are left on
disk** — published files are never deleted, because a delete-by-name
could be re-pointed at a file proxyctl does not own. Treat any error as
"bundle state undefined", never as "nothing was written"; inspect and
remove residue manually.

## preflight DNS and certificate evidence

Preflight reports two **independent** evidence checks, `dns-evidence`
and `certificate-evidence`, over a **closed** set of targets declared in
code (`mihomo-gateway` 8443/tcp and `native-gateway` 8444/tcp for `gateway`;
`proxy-egress` 443/udp for `egress`).

- **No live name or certificate access is implemented.** No DNS
  resolution, no ACME or provider call, no certificate issuance or
  renewal, and no read of any real host certificate. The production
  default probe reports both fact kinds as unavailable, so **both checks
  fail closed** — they never pass on absent evidence and never emit a
  `skip` that could be mistaken for a pass.
- **Targets are never caller-supplied.** No flag can name a hostname,
  URL, path, command or resolver; targets come from the validated role
  only.
- **Evidence, not proof.** A passing `dns-evidence` check is *not*
  certificate proof, and neither check claims that a host or a domain is
  configured — the passing details say so explicitly.
- All probe output is untrusted: names/SANs are structurally validated,
  first-label matching is exact (no prefix, suffix or wildcard match),
  addresses must be numeric literals, and **no hostname, certificate
  byte, SAN or probe error text is ever echoed** into a check detail.
- A **typed-nil** `NetProbe` (a non-nil interface wrapping a nil
  pointer) is detected and falls back to the fail-closed default, so it
  can neither panic on a nil receiver nor be mistaken for a live probe.
- `--offline` makes **zero** DNS and certificate probe calls and emits
  neither check.

## verify

Runs the named profile's invariants and prints stable JSON. Never runs
external commands, never opens sockets, never includes passwords, auth
headers, or full target URLs (URLs are reduced to scheme+host via
`RedactTargetURL`).

## status

Prints version, restricted-mode state and the most recent verification
summary (read from `--state-dir/last-verify.json`). The state dir must
be a real directory (not a symlink, no raw `..` traversal components)
and the state file itself must not be a symlink. Never displays
secrets.

## Version injection

Build-time metadata is injected via `-ldflags`:

```sh
go build -trimpath \
  -ldflags "-X main.version=v0.1.0 \
            -X main.commit=$(git rev-parse --short HEAD) \
            -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o proxyctl ./cmd/proxyctl
```

Cross compilation:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o proxyctl-linux-arm64 ./cmd/proxyctl
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o proxyctl-linux-amd64 ./cmd/proxyctl
```

Release packaging and CI policy live in `scripts/release/release.py`,
`.github/workflows/ci.yml`, and `.github/workflows/release.yml`. These create
and verify candidate bundles only; they do not activate services or provide
remote deployment automation (see `docs/prx02-release.md`).

## Out of scope (by design)

No embedded Mihomo/Hysteria2/Trojan/CONNECT/QUIC implementation, no shell
or systemctl passthrough, no remote execution, no secret storage — proxyctl
is a local validation and rendering control plane only. The release bundle
contains separately locked upstream engine binaries.
