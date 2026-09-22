#!/usr/bin/env python3
"""Apply or remove the fail-closed IKEv2-to-Mihomo TPROXY policy."""

from __future__ import annotations

import argparse
import subprocess


TABLE = "private_proxy_ikev2"
POOL = "10.89.0.0/24"
TPROXY_PORT = 17894
MARK = "0x51"
ROUTE_TABLE = "151"


def nft_rules() -> str:
    return f"""table inet {TABLE} {{
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    ip saddr {POOL} tcp dport != {TPROXY_PORT} tproxy ip to 127.0.0.1:{TPROXY_PORT} meta mark set {MARK} accept
    ip saddr {POOL} udp dport != {TPROXY_PORT} tproxy ip to 127.0.0.1:{TPROXY_PORT} meta mark set {MARK} accept
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname != "lo" tcp dport {TPROXY_PORT} drop
    iifname != "lo" udp dport {TPROXY_PORT} drop
  }}
  chain forward {{
    type filter hook forward priority filter - 5; policy accept;
    ip saddr {POOL} drop
  }}
}}
"""


def _run(argv: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, check=check, capture_output=True)


def table_exists() -> bool:
    result = _run(["/usr/sbin/nft", "list", "table", "inet", TABLE], check=False)
    return result.returncode == 0


def apply() -> None:
    if table_exists():
        raise RuntimeError(f"nftables table {TABLE} already exists; remove it before applying")
    # Install the local policy route before rules can mark any packet. This
    # ordering prevents a transient direct route during service startup.
    _run(["/usr/sbin/ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", ROUTE_TABLE])
    remove_rules()
    _run(["/usr/sbin/ip", "rule", "add", "fwmark", MARK, "lookup", ROUTE_TABLE])
    try:
        _run(["/usr/sbin/nft", "-f", "-"], input_text=nft_rules())
    except Exception:
        remove_route()
        raise


def remove_rules() -> None:
    # iproute2 permits duplicate policy rules. Remove every exact rule owned by
    # this service so restarts cannot accumulate stale entries.
    for _ in range(32):
        result = _run(["/usr/sbin/ip", "rule", "del", "fwmark", MARK, "lookup", ROUTE_TABLE], check=False)
        if result.returncode != 0:
            return
    raise RuntimeError("too many duplicate IKEv2 policy rules")


def remove_route() -> None:
    remove_rules()
    _run(["/usr/sbin/ip", "route", "flush", "table", ROUTE_TABLE], check=False)


def remove() -> None:
    # Remove packet marking first; only then remove the route for marked
    # packets. Existing VPN traffic fails closed during shutdown.
    _run(["/usr/sbin/nft", "delete", "table", "inet", TABLE], check=False)
    remove_route()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "remove"))
    args = parser.parse_args()
    if args.action == "apply":
        apply()
    else:
        remove()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
