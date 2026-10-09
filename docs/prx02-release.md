# Release bundles

`scripts/release/release.py` builds deterministic Linux bundles for the
`gateway` and `egress` roles. A bundle contains `proxyctl`, the pinned upstream
engine, the role template, deployment assets, checksums, an SPDX SBOM, license
inventory, and in-toto provenance metadata. Gateway releases also contain the
matching-architecture Hysteria2 ingress binary and the consolidated Compose definition. CI
publishes separately attested `private-proxy-runtime-linux-amd64.tar.gz` and
`private-proxy-runtime-linux-arm64.tar.gz` image archives so production can use `docker load` without building or pulling
an image.

## Build

```sh
python3 scripts/release/release.py validate-lock
python3 scripts/release/release.py fetch --cache-dir /tmp/proxyctl-upstreams
python3 scripts/release/release.py build \
  --role gateway \
  --arch arm64 \
  --version v0.1.0 \
  --commit <FULL_SOURCE_COMMIT> \
  --source-repository https://example.org/owner/proxyctl.git \
  --builder-environment local \
  --builder-identity <BUILDER_ID> \
  --host-label <HOST_LABEL> \
  --cache-dir /tmp/proxyctl-upstreams \
  --output-dir dist
```

Repeat with `--role egress` and `--arch amd64|arm64` for the other Linux bundles.
Both roles support both architectures; omitted `--arch` preserves the legacy
role default (gateway arm64, egress amd64). No other release targets are built.

## Verify

```sh
python3 scripts/release/release.py verify \
  dist/proxyctl-gateway-linux-arm64.tar.gz \
  --role gateway
```

Verification rejects unsafe archive members, checksum mismatches, unexpected
files, unpinned upstream metadata, invalid provenance, and inconsistent role or
architecture metadata.

## Trust boundary

The release workflow creates and attests artifacts only. It contains no remote
host credentials and performs no installation, activation, service restart, or
deployment.


## GitHub Actions builds

`candidate-release` builds all four role/architecture combinations on native
Ubuntu runners (`ubuntu-24.04` for amd64, `ubuntu-24.04-arm` for arm64), plus the
two matching runtime image archives. Gateway bundles build the customized
Mihomo from pinned source and include its complete modified source and build
manifest. Each native gateway binary runs the TCP/UDP forwarding and SQLite
integration check before upload. CI also runs engine race tests on both targets.

Pushes to `main`/`master` build development candidates; `workflow_dispatch`
allows an explicit candidate version. Download artifacts from the workflow run:

- `candidate-gateway-linux-amd64` and `candidate-gateway-linux-arm64`
- `candidate-egress-linux-amd64` and `candidate-egress-linux-arm64`
- `candidate-runtime-linux-amd64` and `candidate-runtime-linux-arm64`

All archives receive build attestations. Only a `proxy-vMAJOR.MINOR.PATCH` tag
publishes a GitHub Release and its combined SHA256SUMS. Branch/manual runs keep
artifacts for 14 days and do not create a Release or activate services.
