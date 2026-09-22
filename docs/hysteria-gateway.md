# Hysteria2 gateway ingress

This optional reference ingress terminates Hysteria2 with the official server
and sends every accepted connection through a loopback-only Mihomo SOCKS
listener:

```text
client -> public UDP edge -> loopback Hysteria2 server
       -> loopback Mihomo SOCKS -> controlled Hysteria2 egress
```

The public UDP edge may be owned by a separately reviewed stream proxy. The
Hysteria process remains loopback-only. Its first SOCKS5 outbound is the
default, so the reference configuration has no direct fallback.

Pin the Hysteria binary in a versioned installation directory and select the
active version with an administrator-controlled link. Install the renderer
beside that binary and install
`deploy/systemd/private-proxy-hysteria-gateway.service` as a system unit. Build
and download steps should occur in a separate, verified release workflow rather
than on the target host.

The unit loads a dedicated ingress username and password plus the gateway
certificate and key through systemd credentials. The renderer writes the only
credential-bearing configuration to a private runtime directory with mode
`0600`. No credential, certificate, private key, authenticated URL, live host,
or deployment-specific address belongs in Git.

For the official Hysteria client, `userpass` authentication is expressed as one
`username:password` auth string. Mihomo's Hysteria2 proxy schema exposes only a
`password` field; place the same `username:password` string in that field. A
generic client configuration should use reserved documentation values, for
example:

- server `proxy.example.com`;
- an operator-selected UDP port;
- SNI `proxy.example.com`;
- strict certificate verification (`skip-cert-verify: false`).

Replace all example values outside version control during deployment. Endpoint
reachability, address-family support, DNS, and certificate validity require
independent end-to-end verification and are not implied by rendering success.
