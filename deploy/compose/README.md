# Gateway Compose stack

This stack replaces the gateway's separate Mihomo, Hysteria2, strongSwan, and
IKEv2 policy systemd services with one versioned Compose project. OpenResty is
intentionally left on the host because it is the shared ingress for unrelated
services; its existing loopback TCP/18444 and UDP/18445 upstreams do not
change.

## Host layout

Keep all non-image inputs below one configuration root:

```text
/etc/private-proxy/stack/
  config/gateway.yaml
  secrets/
    GATEWAY_EGRESS_PASSWORD_1
    TROJAN_USER_1
    TROJAN_PASSWORD_1
    HTTPS_USER_1
    HTTPS_PASSWORD_1
    HTTPS_USER_2
    HTTPS_PASSWORD_2
    gateway.crt
    gateway.key
    IKEV2_USER_1
    IKEV2_PASSWORD_1
    IKEV2_REMOTE_ID
    ikev2.crt
    ikev2.key
  runtime.env
```

The `_1` HTTPS pair is the interactive identity. The `_2` pair is a separate
machine identity for the HomeServer build-egress adapter and must not reuse the
interactive password.

The configuration directory is root-owned `0750`; `gateway.yaml` is `0640`.
The secrets directory and each secret are root-owned `0700`/`0600`. Compose
bind-mounts only the files required by each service. Each launcher copies its
scoped inputs into a private `/run/credentials/<service>` tmpfs tree, so
rendered credentials never enter an image layer or persistent container
filesystem.

`runtime.env` contains paths and an image name only, never credentials:

```dotenv
PRIVATE_PROXY_RUNTIME_IMAGE=private-proxy-runtime:v0.3.0
PRIVATE_PROXY_RELEASE_DIR=/opt/private-proxy/releases/v0.3.0
PRIVATE_PROXY_CONFIG_DIR=/etc/private-proxy/stack/config
PRIVATE_PROXY_SECRETS_DIR=/etc/private-proxy/stack/secrets
```

## Immutable inputs

The candidate release contains the Compose file, all launchers, proxyctl,
Mihomo, Hysteria2, the strongSwan helpers, hashes, SBOM, and provenance. CI
also publishes `private-proxy-runtime-linux-arm64.tar.gz`, built from the
digest-pinned Debian ARM64 base with exact strongSwan package versions.
Production imports it with `docker load`; `pull_policy: never` prevents an
implicit registry fallback.

## Cutover and rollback

Before cutover, verify both release artifacts, import the image, run `docker
compose config`, and confirm the existing systemd services are healthy. The
exclusive-port cutover then stops and disables the three proxy systemd units
and starts this Compose project. Acceptance requires every Compose healthcheck,
the original HTTPS and Hysteria2 paths, IKEv2 UDP/500 and UDP/4500, the
loopback-only TCP/UDP 17894 listener, and a HomeCloud IKEv2 data-path check.

Rollback is `docker compose down`, removal of the stack-owned nftables policy
if still present, and re-enabling the previous systemd units. Do not delete the
previous release, runtime image, or `/etc/private-proxy/stack` until the
acceptance window closes.
