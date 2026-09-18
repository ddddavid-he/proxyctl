#!/usr/bin/env python3
"""Small health probes for the Compose data-plane services."""

from __future__ import annotations

import socket
import subprocess
import sys


def tcp(host: str, port: str) -> None:
    with socket.create_connection((host, int(port)), timeout=1):
        return


def policy() -> None:
    subprocess.run(["/usr/sbin/nft", "list", "table", "inet", "private_proxy_ikev2"], check=True, stdout=subprocess.DEVNULL)
    rules = subprocess.run(["/usr/sbin/ip", "rule", "show"], check=True, text=True, capture_output=True).stdout
    if "fwmark 0x51 lookup 151" not in rules:
        raise RuntimeError("IKEv2 policy rule is missing")


def ikev2() -> None:
    result = subprocess.run(["/usr/sbin/swanctl", "--list-conns"], check=True, text=True, capture_output=True)
    if not any(line.startswith("private-proxy-ikev2:") for line in result.stdout.splitlines()):
        raise RuntimeError("IKEv2 connection is missing")


def main(arguments: list[str]) -> int:
    if len(arguments) == 4 and arguments[1] == "tcp":
        tcp(arguments[2], arguments[3])
    elif arguments == [arguments[0], "policy"]:
        policy()
    elif arguments == [arguments[0], "ikev2"]:
        ikev2()
    else:
        raise SystemExit("invalid healthcheck")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
