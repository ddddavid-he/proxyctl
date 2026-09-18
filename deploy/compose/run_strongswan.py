#!/usr/bin/env python3
"""Run charon-systemd in the foreground and load the rendered IKEv2 config."""

from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import time

from credential_stage import stage


APP = pathlib.Path("/app")
VICI = pathlib.Path("/run/charon.vici")


def main() -> int:
    stage("ikev2", ("IKEV2_USER_1", "IKEV2_PASSWORD_1", "IKEV2_REMOTE_ID", "ikev2.crt", "ikev2.key"))
    subprocess.run(["python3", str(APP / "deploy/ikev2/render_ikev2.py")], check=True)
    child = subprocess.Popen(["/usr/sbin/charon-systemd"])

    def stop(signum, _frame):
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for _ in range(100):
            if child.poll() is not None:
                return child.returncode or 1
            if VICI.exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("charon VICI socket did not become ready")
        subprocess.run(["python3", str(APP / "deploy/ikev2/load_ikev2.py")], check=True)
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
