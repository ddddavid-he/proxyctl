#!/usr/bin/env python3
"""Render and exec the primary Mihomo process inside the Compose service."""

from __future__ import annotations

import os
import pathlib
import subprocess

from credential_stage import stage


APP = pathlib.Path("/app")
CONFIG = pathlib.Path(os.environ.get("GATEWAY_CONFIG", "/config/gateway.yaml"))
RUNTIME = pathlib.Path("/run/private-proxy")


def checked(arguments: list[str]) -> None:
    subprocess.run(arguments, check=True)


def main() -> int:
    stage("mihomo", (
        "GATEWAY_EGRESS_PASSWORD_1", "TROJAN_USER_1", "TROJAN_PASSWORD_1",
        "HTTPS_USER_1", "HTTPS_PASSWORD_1", "gateway.crt", "gateway.key",
        "HTTPS_USER_2", "HTTPS_PASSWORD_2",
    ))
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    checked([str(APP / "proxyctl"), "preflight", "--role", "gateway", "--offline", "--config", str(CONFIG)])
    checked([
        str(APP / "proxyctl"), "render", "--role", "gateway",
        "--template-dir", str(APP / "templates/mihomo"),
        "--config", str(CONFIG), "--out-dir", str(RUNTIME),
    ])
    os.execv(str(APP / "mihomo"), [str(APP / "mihomo"), "-f", str(RUNTIME / "gateway-rendered.yaml")])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
