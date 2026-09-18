# Hysteria2 gateway ingress

The optional Guangzhou user ingress terminates Hysteria2 with the official
Hysteria server, then sends every accepted connection through the production
Mihomo SOCKS listener:

```text
client -> UDP/19444 edge -> 127.0.0.1:18445 Hysteria2 server
       -> 127.0.0.1:7890 Mihomo SOCKS -> controlled Hysteria2 egress
```

The public UDP edge is owned by OpenResty/Nginx stream configuration in the
infrastructure repository. The Hysteria process remains loopback-only. The
server uses the first SOCKS5 outbound as its default, so there is no direct
fallback.

The deployed binary is pinned separately under
`/opt/private-proxy/hysteria-gateway/<version>/`; `current` selects the active
version. Install the renderer beside that binary and install
`deploy/systemd/private-proxy-hysteria-gateway.service` as a system unit.
Do not build or download the binary on the Guangzhou host.

The unit loads an existing terminal HTTPS user and password plus the gateway
certificate and key through systemd credentials. The renderer writes the only
credential-bearing configuration to
`/run/private-proxy-hy2-gateway/server.json` with mode `0600`. No credential,
certificate, private key, or authenticated URL belongs in Git.

For the official Hysteria client, `userpass` authentication is expressed as
one `username:password` auth string. Mihomo's Hysteria2 proxy schema exposes
only a `password` field; place the same `username:password` string in that
field. A production client uses:

- server `ladder.ddddavid.cn`;
- UDP port `19444`;
- SNI `ladder.ddddavid.cn`;
- strict certificate verification (`skip-cert-verify: false`).

The public endpoint is a Guangzhou relay to the controlled US egress. Do not
describe it as a direct US address or as IPv4-only. DNS has A and AAAA records,
but external IPv6 Hysteria2 reachability must remain marked unverified until a
client with a working IPv6 route completes an end-to-end test.
