#!/usr/bin/env python3
"""Stage service-scoped bind-mounted secrets into a private tmpfs directory."""

from __future__ import annotations

import os
import pathlib
import shutil
import stat


SOURCE = pathlib.Path("/run/input-secrets")
TARGET_ROOT = pathlib.Path("/run/credentials")


def stage(service: str, names: tuple[str, ...]) -> pathlib.Path:
    target = TARGET_ROOT / service
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target, 0o700)
    for name in names:
        source = SOURCE / name
        mode = source.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise RuntimeError(f"credential input is not a regular file: {name}")
        destination = target / name
        shutil.copyfile(source, destination, follow_symlinks=False)
        os.chmod(destination, 0o600)
    return target
