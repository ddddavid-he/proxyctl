#!/usr/bin/env python3
"""Render the credential-bearing Guangzhou Hysteria2 ingress config at runtime."""

import json
import os
from pathlib import Path


credential_dir = Path(os.environ["CREDENTIALS_DIRECTORY"])
runtime_dir = Path("/run/private-proxy-hy2-gateway")

if not credential_dir.is_absolute() or not str(credential_dir).startswith(
    "/run/credentials/"
):
    raise SystemExit("credential directory rejected")


def read_scalar(name: str) -> str:
    value = (credential_dir / name).read_text(encoding="utf-8").strip()
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SystemExit("credential rejected")
    return value


user = read_scalar("HY2_USER_1")
password = read_scalar("HY2_PASSWORD_1")
certificate = credential_dir / "gateway.crt"
private_key = credential_dir / "gateway.key"

config = {
    "listen": "127.0.0.1:18445",
    "tls": {"cert": str(certificate), "key": str(private_key)},
    "auth": {"type": "userpass", "userpass": {user: password}},
    "outbounds": [
        {
            "name": "mihomo",
            "type": "socks5",
            "socks5": {"addr": "127.0.0.1:7890"},
        }
    ],
}

runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
target = runtime_dir / "server.json"
temporary = runtime_dir / ".server.json.tmp"
file_descriptor = os.open(
    temporary,
    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
    0o600,
)
with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, target)
