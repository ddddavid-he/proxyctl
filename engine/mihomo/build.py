#!/usr/bin/env python3
"""Reproducibly apply the GPL extension to the exact upstream source commit."""
import argparse
import gzip
import io
import tarfile
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = "ac017cdd246ce8bd547653d927e7bf77d7ee73d5"
REPOSITORY = "https://github.com/MetaCubeX/mihomo.git"

def prepare(source):
    if not source.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--branch", "v1.19.30", REPOSITORY, str(source)], check=True)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != BASE:
        raise RuntimeError("Mihomo source commit mismatch")
    patch = ROOT / "engine/mihomo/accounting.patch"
    applied = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)], cwd=source, capture_output=True).returncode == 0
    if not applied:
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=source, check=True)
    for path in (ROOT / "engine/mihomo/overlay/tunnel/statistic").glob("*.go"):
        shutil.copyfile(path, source / "tunnel/statistic" / path.name)
    # Refuse unexpected source modifications, not just a matching HEAD.
    allowed = {"main.go", "tunnel/statistic/tracker.go"}
    allowed.update("tunnel/statistic/" + p.name for p in (ROOT / "engine/mihomo/overlay/tunnel/statistic").glob("*.go"))
    changed = subprocess.check_output(["git", "diff", "--name-only", "HEAD"], cwd=source, text=True).splitlines()
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=source, text=True).splitlines()
    if set(changed + untracked) - allowed:
        raise RuntimeError("unexpected changes in engine checkout")
    actual = subprocess.check_output(["git", "diff", "--", "main.go", "tunnel/statistic/tracker.go"], cwd=source)
    if actual != patch.read_bytes():
        raise RuntimeError("engine patch mismatch")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--goos", default="linux", choices=("linux",))
    parser.add_argument("--goarch", default="arm64", choices=("arm64", "amd64"))
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()
    lock = json.loads((ROOT / "upstream-lock.json").read_text())
    if ("go" + lock["goToolchain"]) not in subprocess.check_output(["go", "version"], text=True).split():
        raise RuntimeError("locked Go toolchain required")
    source, output = args.source.resolve(), args.output.resolve()
    prepare(source)
    if args.test:
        subprocess.run(["go", "test", "-race", "-count=1", "./tunnel/statistic"], cwd=source, check=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="0", GOOS=args.goos, GOARCH=args.goarch)
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-tags", "with_gvisor", "-ldflags", "-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version=v1.19.30-proxyctl.1 -X github.com/metacubex/mihomo/constant.BuildTime=source-pinned", "-o", str(output), "."], cwd=source, env=env, check=True)
    records = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "engine/mihomo").rglob("*")) if p.is_file() and '__pycache__' not in str(p)}
    manifest = dict(base_commit=BASE, repository=REPOSITORY, extension=records, go=lock["goToolchain"], goos=args.goos, goarch=args.goarch, binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    archive_path = output.with_suffix(".source.tar.gz")
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=source, text=True))
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=source, text=True).splitlines()
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name in sorted(set(paths)):
                    path = source / name
                    info = archive.gettarinfo(str(path), arcname=name)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = epoch
                    if info.isfile():
                        with path.open("rb") as stream:
                            archive.addfile(info, stream)
                    else:
                        archive.addfile(info)
    manifest["source_sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    output.with_suffix(".build.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
