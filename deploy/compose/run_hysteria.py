#!/usr/bin/env python3
"""Render and exec the loopback Hysteria2 gateway ingress."""

from __future__ import annotations

import os
import pathlib
import subprocess

from credential_stage import stage


APP = pathlib.Path("/app")
RUNTIME_CONFIG = "/run/private-proxy-hy2-gateway/server.json"


def main() -> int:
    stage("hysteria", ("HY2_USER_1", "HY2_PASSWORD_1", "gateway.crt", "gateway.key"))
    subprocess.run(["python3", str(APP / "deploy/hysteria-gateway/render_hysteria_gateway.py")], check=True)
    os.execv(str(APP / "hysteria"), [str(APP / "hysteria"), "server", "-c", RUNTIME_CONFIG])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
