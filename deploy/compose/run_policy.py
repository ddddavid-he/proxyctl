#!/usr/bin/env python3
"""Own the host IKEv2 TPROXY policy for the lifetime of this container."""

from __future__ import annotations

import importlib.util
import pathlib
import signal
import threading


POLICY_PATH = pathlib.Path("/app/deploy/ikev2/configure_policy.py")


def load_policy():
    spec = importlib.util.spec_from_file_location("private_proxy_ikev2_policy", POLICY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    policy = load_policy()
    stopped = threading.Event()

    def stop(_signum, _frame):
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # A prior SIGKILL may leave the dedicated fail-closed table behind.
    # Remove only this stack's named state before applying one clean copy.
    policy.remove()
    policy.apply()
    try:
        stopped.wait()
    finally:
        policy.remove()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
