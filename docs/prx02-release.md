# Release bundles

`scripts/release/release.py` builds deterministic Linux bundles for the
`gateway` and `egress` roles. A bundle contains `proxyctl`, the pinned upstream
engine, the role template, deployment assets, checksums, an SPDX SBOM, license
inventory, and in-toto provenance metadata. Gateway releases also contain the
ARM64 Hysteria2 ingress binary and the consolidated Compose definition. CI
publishes a separately attested `private-proxy-runtime-linux-arm64.tar.gz`
image archive so production can use `docker load` without building or pulling
an image.

## Build

```sh
python3 scripts/release/release.py validate-lock
python3 scripts/release/release.py fetch --cache-dir /tmp/proxyctl-upstreams
python3 scripts/release/release.py build \
  --role gateway \
  --version v0.1.0 \
  --commit <FULL_SOURCE_COMMIT> \
  --source-repository https://example.org/owner/proxyctl.git \
  --builder-environment local \
  --builder-identity <BUILDER_ID> \
  --host-label <HOST_LABEL> \
  --cache-dir /tmp/proxyctl-upstreams \
  --output-dir dist
```

Repeat with `--role egress` for the egress bundle.

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
