#!/usr/bin/env python3
"""Render a strongSwan swanctl tree from systemd credentials.

The production unit supplies credentials through $CREDENTIALS_DIRECTORY. The
renderer deliberately has no command-line options so service configuration
cannot redirect secret reads or runtime writes to arbitrary paths.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import stat
import tempfile


RUNTIME_DIR = pathlib.Path("/run/private-proxy-ikev2")
POOL = "10.89.0.0/24"
DNS = "1.1.1.1"
REQUIRED = ("IKEV2_USER_1", "IKEV2_PASSWORD_1", "IKEV2_REMOTE_ID", "ikev2.crt", "ikev2.key")
PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


class RenderError(RuntimeError):
    """Safe operational error that never includes credential contents."""


def _regular_file(path: pathlib.Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise RenderError(f"required credential is unavailable: {path.name}") from exc
    if not stat.S_ISREG(mode):
        raise RenderError(f"credential must be a regular file: {path.name}")


def _read_scalar(directory: pathlib.Path, name: str) -> str:
    path = directory / name
    _regular_file(path)
    try:
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as exc:
        raise RenderError(f"cannot read credential: {name}") from exc
    if not value or len(value) > 255 or any(char in value for char in "\r\n\x00{};"):
        raise RenderError(f"credential has an invalid format: {name}")
    return value


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _install_certificate_chain(source: pathlib.Path, runtime: pathlib.Path) -> None:
    try:
        certificates = PEM_CERTIFICATE.findall(source.read_bytes())
    except OSError as exc:
        raise RenderError("cannot read credential: ikev2.crt") from exc
    if not certificates:
        raise RenderError("credential has an invalid PEM certificate chain: ikev2.crt")

    leaf = runtime / "x509" / "ikev2.crt"
    leaf.write_bytes(certificates[0])
    os.chmod(leaf, 0o600)

    for stale in (runtime / "x509ca").glob("ikev2-chain-*.crt"):
        stale.unlink()
    for index, certificate in enumerate(certificates[1:], start=1):
        intermediate = runtime / "x509ca" / f"ikev2-chain-{index}.crt"
        intermediate.write_bytes(certificate)
        os.chmod(intermediate, 0o600)


def render(credentials: pathlib.Path, runtime: pathlib.Path) -> pathlib.Path:
    for name in REQUIRED:
        _regular_file(credentials / name)
    user = _read_scalar(credentials, "IKEV2_USER_1")
    password = _read_scalar(credentials, "IKEV2_PASSWORD_1")
    remote_id = _read_scalar(credentials, "IKEV2_REMOTE_ID")

    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    for relative in ("x509", "x509ca", "private"):
        target = runtime / relative
        target.mkdir(mode=0o700, exist_ok=True)
        os.chmod(target, 0o700)

    _install_certificate_chain(credentials / "ikev2.crt", runtime)
    shutil.copyfile(credentials / "ikev2.key", runtime / "private" / "ikev2.key")
    os.chmod(runtime / "private" / "ikev2.key", 0o600)

    config = f"""connections {{
  private-proxy-ikev2 {{
    version = 2
    send_cert = always
    pools = private-proxy-pool
    proposals = aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048
    local {{
      auth = pubkey
      certs = ikev2.crt
      id = {_quote(remote_id)}
    }}
    remote {{
      auth = eap-mschapv2
      eap_id = %any
    }}
    children {{
      private-proxy-full-tunnel {{
        local_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-ecp256,aes256-sha256
        dpd_action = clear
        close_action = none
        start_action = none
      }}
    }}
  }}
}}

pools {{
  private-proxy-pool {{
    addrs = {POOL}
    dns = {DNS}
  }}
}}

secrets {{
  eap-user-1 {{
    id = {_quote(user)}
    secret = {_quote(password)}
  }}
}}
"""
    fd, temporary = tempfile.mkstemp(prefix=".swanctl.", dir=runtime)
    output = runtime / "swanctl.conf"
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(config)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return output


def main() -> int:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise RenderError("CREDENTIALS_DIRECTORY is required")
    render(pathlib.Path(directory), RUNTIME_DIR)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RenderError as exc:
        raise SystemExit(f"IKEv2 render failed: {exc}") from None
