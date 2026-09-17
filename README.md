# proxyctl

`proxyctl` is a local, security-focused CLI for validating and rendering a
two-role proxy configuration. It prepares configuration for a Mihomo gateway
and a Hysteria2 egress service without implementing proxy traffic itself.

## Features

- strict allowlist-based configuration parsing;
- runtime credential loading from systemd credentials;
- fail-closed validation for unsafe listeners, direct fallbacks, insecure TLS,
  path traversal, symlinks, and unexpected fields;
- transactional, no-replace output with restrictive file permissions;
- read-only preflight and status commands with stable JSON errors;
- deterministic release bundles with checksums, SBOM, and provenance metadata;
- offline secret scanning with a synthetic self-test corpus.

## Non-goals

`proxyctl` is not a proxy engine, secret store, installer, remote executor, or
deployment system. It does not open network listeners, run `systemctl`, or
connect to remote hosts. Mihomo and Hysteria2 remain separate upstream tools.

## Build and test

```sh
go build ./cmd/proxyctl
go test ./...
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/secret_scan.py --self-test
python3 tools/secret_scan.py
```

## Commands

```text
proxyctl preflight --role gateway|egress [--offline] [--config PATH]
proxyctl render --role gateway|egress --template-dir DIR --config PATH --out-dir DIR
proxyctl verify --profile loopback|canary
proxyctl status [--json] [--state-dir DIR]
proxyctl version
```

See [CLI reference](docs/proxyctl-cli.md),
[credential-rendering design](docs/adr-prx01-render-runtime-credentials.md), and
[release format](docs/prx02-release.md) for details.

## Project status

The CLI and its local validation paths are implemented and tested. Network
probing and host activation are intentionally outside the current scope.

## License

MIT. See [LICENSE](LICENSE).
