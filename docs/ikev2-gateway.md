# IKEv2 gateway ingress

This optional ingress lets operating-system IKEv2 clients join the existing
gateway route without creating another egress path:

```text
IKEv2 client
  -> strongSwan UDP/500 or UDP/4500
  -> virtual pool 10.89.0.0/24
  -> nftables TPROXY policy
  -> primary Mihomo TPROXY 127.0.0.1:17894
  -> existing controlled-egress
```

There is deliberately no source NAT or `DIRECT` fallback. TCP and UDP from the
VPN pool are intercepted by Mihomo. Other forwarded protocols from the pool
are dropped. If the policy, Mihomo, or the configured upstream is unavailable,
the client loses external connectivity instead of using an uncontrolled host
route.

## Host dependencies

The release bundle does not embed or install strongSwan, nftables, or iproute2.
On the Debian arm64 gateway, install the exact versions in
`deploy/ikev2/packages.lock` through the normal reviewed host-management path.
The supported service is `charon-systemd` with `strongswan-swanctl`; the legacy
starter configuration is not used.

The primary Mihomo unit receives only `CAP_NET_ADMIN`, which is required to
create its loopback transparent proxy socket. The root policy unit receives the
same bounded capability to manage its dedicated nftables table and policy
route. No other capabilities are added and no second Mihomo process is used.

## Runtime credentials

Provide these root-owned regular files with mode `0600` under
`/etc/private-proxy/secrets/`:

| File | Meaning |
|---|---|
| `IKEV2_USER_1` | EAP identity |
| `IKEV2_PASSWORD_1` | EAP-MSCHAPv2 secret |
| `IKEV2_REMOTE_ID` | Server identity used by clients |
| `ikev2.crt` | Server certificate chain |
| `ikev2.key` | Matching private key |

The certificate must be valid for `IKEV2_REMOTE_ID` and chain to a CA trusted
by the client. The renderer reads the files through systemd credentials and
writes the generated swanctl tree only under `/run/private-proxy-ikev2` with
mode `0600`. Values must never be placed in the Git input document, unit files,
release manifest, or command line.

## Activation boundary

Installing packages, copying credentials, changing the host firewall, and
starting units are production changes. They are intentionally not performed by
`proxyctl` or the release workflow. After a fresh read-only host check, an
authorized deployment installs the packaged units and enables them in this
order:

1. `private-proxy-mihomo.service`
2. `private-proxy-ikev2-policy.service`
3. `strongswan.service`
4. `private-proxy-ikev2.service`

Acceptance requires a native IKEv2 client to authenticate, receive an address
from the fixed pool, resolve DNS through the tunnel, and observe the controlled
remote egress. It must also verify that direct connections to TCP or UDP/17894
are rejected and that stopping Mihomo or the upstream does not produce direct
Internet access.

## Rollback

Stop and disable `private-proxy-ikev2.service`, then stop
`private-proxy-ikev2-policy.service`. The policy unit removes its dedicated
nftables table before deleting the mark route. Remove the five IKEv2 credential
files only after the service is stopped. Rolling back the gateway release
removes the loopback TPROXY listener and its capability; HTTPS, Trojan, and
Hysteria2 configuration otherwise remains unchanged.
