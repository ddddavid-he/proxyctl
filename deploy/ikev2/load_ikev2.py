#!/usr/bin/env python3
"""Load the rendered IKEv2 configuration and require its connection to exist."""

from __future__ import annotations

import re
import subprocess


SWANCTL = "/usr/sbin/swanctl"
CONFIG = "/run/private-proxy-ikev2/swanctl.conf"
CONNECTION = "private-proxy-ikev2"


class LoadError(RuntimeError):
    """Operational error that never includes rendered configuration data."""


def _run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, check=False)


def load() -> None:
    loaded = _run([SWANCTL, "--load-all", "--noprompt", "--file", CONFIG])
    if loaded.returncode != 0:
        raise LoadError("swanctl failed to load the IKEv2 configuration")
    listed = _run([SWANCTL, "--list-conns"])
    if listed.returncode != 0:
        raise LoadError("swanctl failed to list loaded connections")
    if re.search(rf"(?m)^{re.escape(CONNECTION)}\s*:", listed.stdout) is None:
        raise LoadError("required IKEv2 connection was not loaded")


def main() -> int:
    load()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LoadError as exc:
        raise SystemExit(f"IKEv2 load failed: {exc}") from None
