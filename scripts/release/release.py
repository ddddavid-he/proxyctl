#!/usr/bin/env python3
"""Build and independently verify deterministic proxyctl release bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.error
import urllib.request


SCRIPT_PATH = pathlib.Path(__file__).resolve()
# In the source tree this file lives at scripts/release/release.py. A copy is
# also embedded at the release root as verify-release.py so a source checkout
# is not required for independent verification.
ROOT = SCRIPT_PATH.parent if (SCRIPT_PATH.parent / "upstream-lock.json").is_file() else SCRIPT_PATH.parents[2]
ALLOWED_BUILDERS = {"github", "local", "self-hosted"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
ACTION_PIN_RE = re.compile(r"^\s*-?\s*uses:\s*[^\s@]+@([0-9a-f]{40})(?:\s*#.*)?$")

ROLE_SPECS = {
    "gateway": {
        "goarch": "arm64",
        "upstream": "mihomo-linux-arm64",
        "bundle": "proxyctl-gateway-linux-arm64.tar.gz",
        "engine": "mihomo",
        "template": "templates/mihomo/mihomo-gateway.yaml.tmpl",
        "units": ["private-proxy-mihomo.service", "private-proxy-verify.service", "private-proxy-verify.timer"],
    },
    "egress": {
        "goarch": "amd64",
        "upstream": "hysteria-linux-amd64",
        "bundle": "proxyctl-egress-linux-amd64.tar.gz",
        "engine": "hysteria",
        "template": "templates/hysteria/hysteria-egress.yaml.tmpl",
        "units": ["private-proxy-hysteria.service", "private-proxy-verify.service", "private-proxy-verify.timer"],
    },
}


class ReleaseError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def load_lock(path: pathlib.Path) -> dict:
    try:
        lock = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read upstream lock: {exc}") from exc
    if set(lock) != {"schemaVersion", "goToolchain", "upstreams"} or lock["schemaVersion"] != 1:
        raise ReleaseError("upstream lock has an unsupported schema")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", lock["goToolchain"]):
        raise ReleaseError("Go toolchain must be an exact patch version")
    if set(lock["upstreams"]) != {spec["upstream"] for spec in ROLE_SPECS.values()}:
        raise ReleaseError("upstream lock must contain exactly the closed target set")
    for name, item in lock["upstreams"].items():
        required = {"version", "sourceRepository", "sourceTagOid", "url", "sha256", "format", "outputName", "goos", "goarch", "license"}
        if set(item) != required:
            raise ReleaseError(f"{name}: unexpected or missing lock fields")
        if not VERSION_RE.fullmatch(item["version"]) or "latest" in item["url"].lower():
            raise ReleaseError(f"{name}: floating or invalid version")
        if not SHA256_RE.fullmatch(item["sha256"]):
            raise ReleaseError(f"{name}: invalid SHA-256")
        if not OID_RE.fullmatch(item["sourceTagOid"]):
            raise ReleaseError(f"{name}: source tag OID must be a full commit SHA")
        parsed = urllib.parse.urlparse(item["url"])
        if parsed.scheme != "https" or parsed.netloc != "github.com" or "/releases/download/" not in parsed.path:
            raise ReleaseError(f"{name}: download must be an official GitHub release URL")
        source = urllib.parse.urlparse(item["sourceRepository"])
        if source.scheme != "https" or source.netloc != "github.com":
            raise ReleaseError(f"{name}: source repository must be on GitHub HTTPS")
        if item["format"] not in {"raw", "gzip"} or item["goos"] != "linux":
            raise ReleaseError(f"{name}: unsupported format or OS")
        if item["goarch"] not in {"arm64", "amd64"} or not item["license"]:
            raise ReleaseError(f"{name}: unsupported architecture or missing license")
    for spec in ROLE_SPECS.values():
        if lock["upstreams"][spec["upstream"]]["goarch"] != spec["goarch"]:
            raise ReleaseError("role architecture and upstream lock disagree")
    return lock


def validate_license_inventory(lock: dict, path: pathlib.Path) -> None:
    try:
        inventory = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read license inventory: {exc}") from exc
    components = inventory.get("components") if inventory.get("schemaVersion") == 1 else None
    if not isinstance(components, list):
        raise ReleaseError("license inventory has an unsupported schema")
    licenses = {item.get("name"): item.get("license") for item in components if isinstance(item, dict)}
    if licenses.get("proxyctl") != "MIT":
        raise ReleaseError("license inventory must explicitly record proxyctl as MIT")
    for item in lock["upstreams"].values():
        if licenses.get(item["outputName"]) != item["license"]:
            raise ReleaseError(f"license inventory mismatch for {item['outputName']}")


def validate_builder(environment: str, identity: str, host_label: str) -> None:
    if environment not in ALLOWED_BUILDERS:
        raise ReleaseError(f"builder environment {environment!r} is not allowed")
    for label, value in (("identity", identity), ("host label", host_label)):
        if not value or len(value) > 160 or any(ord(ch) < 0x20 for ch in value):
            raise ReleaseError(f"builder {label} is invalid")


def validate_source_repository(value: str) -> None:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ReleaseError("source repository must be a credential-free HTTPS URL")


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(command, cwd=ROOT, env=env, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseError(f"command failed: {command[0]}") from exc


def write_file(root: pathlib.Path, relative: str, data: bytes, mode: int = 0o644) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(mode)


def copy_file(root: pathlib.Path, source: pathlib.Path, relative: str, mode: int = 0o644) -> None:
    write_file(root, relative, source.read_bytes(), mode)


def checked_upstream(lock_item: dict, cache_dir: pathlib.Path) -> bytes:
    filename = pathlib.PurePosixPath(urllib.parse.unquote(urllib.parse.urlparse(lock_item["url"]).path)).name
    source = cache_dir / filename
    if not source.is_file() or source.is_symlink():
        raise ReleaseError(f"upstream cache is missing regular file {filename}")
    if sha256_file(source) != lock_item["sha256"]:
        raise ReleaseError(f"upstream hash mismatch for {filename}")
    data = source.read_bytes()
    if lock_item["format"] == "gzip":
        try:
            data = gzip.decompress(data)
        except OSError as exc:
            raise ReleaseError(f"invalid gzip upstream {filename}") from exc
    if not data:
        raise ReleaseError(f"empty upstream payload {filename}")
    return data


def fetch_upstreams(lock_path: pathlib.Path, cache_dir: pathlib.Path) -> None:
    lock = load_lock(lock_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    for name, item in sorted(lock["upstreams"].items()):
        filename = pathlib.PurePosixPath(urllib.parse.unquote(urllib.parse.urlparse(item["url"]).path)).name
        target = cache_dir / filename
        if target.is_file() and not target.is_symlink() and sha256_file(target) == item["sha256"]:
            print(f"cached {name}")
            continue
        temporary = cache_dir / (filename + ".partial")
        try:
            request = urllib.request.Request(item["url"], headers={"User-Agent": "proxyctl-prx02/1"})
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
                final_host = urllib.parse.urlparse(response.geturl()).hostname or ""
                if final_host != "github.com" and not final_host.endswith(".githubusercontent.com"):
                    raise ReleaseError(f"{name}: redirect left GitHub-controlled hosts")
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 256 * 1024 * 1024:
                        raise ReleaseError(f"{name}: upstream asset exceeds size limit")
                    output.write(chunk)
            if sha256_file(temporary) != item["sha256"]:
                raise ReleaseError(f"{name}: downloaded SHA-256 does not match lock")
            os.replace(temporary, target)
            print(f"fetched {name}")
        except (OSError, urllib.error.URLError) as exc:
            raise ReleaseError(f"{name}: upstream download failed") from exc
        finally:
            if temporary.exists():
                temporary.unlink()


def source_epoch(explicit: int | None) -> int:
    if explicit is not None:
        if explicit < 1:
            raise ReleaseError("SOURCE_DATE_EPOCH must be positive")
        return explicit
    try:
        raw = subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True).strip()
        return int(raw)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise ReleaseError("cannot determine source commit timestamp") from exc


def current_source() -> tuple[str, str]:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        repository = subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseError("cannot resolve current source repository and commit") from exc
    if dirty:
        raise ReleaseError("source checkout is not clean")
    validate_source_repository(repository)
    return commit, repository.rstrip("/")


def build_proxyctl(stage: pathlib.Path, role: str, version: str, commit: str, epoch: int, go_binary: str) -> None:
    build_time = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    ldflags = f"-s -w -X main.version={version} -X main.commit={commit} -X main.buildTime={build_time} -buildid="
    env = dict(os.environ)
    env.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": ROLE_SPECS[role]["goarch"], "SOURCE_DATE_EPOCH": str(epoch)})
    run([go_binary, "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", str(stage / "proxyctl"), "./cmd/proxyctl"], env=env)
    (stage / "proxyctl").chmod(0o755)


def file_records(stage: pathlib.Path, excluded: set[str] | None = None) -> list[dict]:
    excluded = excluded or set()
    records = []
    for path in sorted(p for p in stage.rglob("*") if p.is_file() and not p.is_symlink()):
        relative = path.relative_to(stage).as_posix()
        if relative in excluded:
            continue
        records.append({"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size, "mode": format(stat.S_IMODE(path.stat().st_mode), "04o")})
    return records


def make_sbom(stage: pathlib.Path, role: str, version: str, commit: str, lock_item: dict) -> dict:
    files = []
    for record in file_records(stage):
        files.append({"SPDXID": "SPDXRef-File-" + hashlib.sha256(record["path"].encode()).hexdigest()[:16], "fileName": "./" + record["path"], "checksums": [{"algorithm": "SHA256", "checksumValue": record["sha256"]}]})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": ROLE_SPECS[role]["bundle"],
        "documentNamespace": f"https://pushpop.invalid/spdx/proxyctl/{commit}/{role}/{version}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: scripts/release/release.py"]},
        "packages": [
            {"name": "proxyctl", "SPDXID": "SPDXRef-Package-proxyctl", "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "MIT", "licenseDeclared": "MIT", "copyrightText": "Copyright (c) 2026 proxyctl contributors", "externalRefs": [{"referenceCategory": "OTHER", "referenceType": "source-commit", "referenceLocator": commit}]},
            {"name": lock_item["outputName"], "SPDXID": "SPDXRef-Package-upstream", "versionInfo": lock_item["version"], "downloadLocation": lock_item["url"], "filesAnalyzed": False, "licenseConcluded": lock_item["license"], "licenseDeclared": lock_item["license"], "copyrightText": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": lock_item["sha256"]}]},
        ],
        "files": files,
    }


def deterministic_tar(stage: pathlib.Path, output: pathlib.Path, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(stage.rglob("*")):
                    relative = path.relative_to(stage).as_posix()
                    info = archive.gettarinfo(str(path), arcname=relative)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = epoch
                    info.pax_headers = {}
                    if path.is_file():
                        with path.open("rb") as stream:
                            archive.addfile(info, stream)
                    else:
                        archive.addfile(info)


def build_bundle(args: argparse.Namespace) -> pathlib.Path:
    lock = load_lock(args.lock)
    validate_license_inventory(lock, ROOT / "release/licenses.json")
    validate_builder(args.builder_environment, args.builder_identity, args.host_label)
    if args.role not in ROLE_SPECS or not VERSION_RE.fullmatch(args.version):
        raise ReleaseError("invalid role or release version")
    if not OID_RE.fullmatch(args.commit):
        raise ReleaseError("source commit must be a full 40-character SHA")
    validate_source_repository(args.source_repository)
    actual_commit, actual_repository = current_source()
    if args.commit != actual_commit or args.source_repository.rstrip("/") != actual_repository:
        raise ReleaseError("declared source repository or commit does not match checkout")
    try:
        go_version = subprocess.check_output([args.go_binary, "version"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseError("cannot execute locked Go toolchain") from exc
    if f"go{lock['goToolchain']}" not in go_version.split():
        raise ReleaseError(f"Go toolchain mismatch: expected {lock['goToolchain']}")
    epoch = source_epoch(args.source_date_epoch)
    spec = ROLE_SPECS[args.role]
    lock_item = lock["upstreams"][spec["upstream"]]
    with tempfile.TemporaryDirectory(prefix="prx02-stage-") as temp:
        stage = pathlib.Path(temp)
        build_proxyctl(stage, args.role, args.version, args.commit, epoch, args.go_binary)
        write_file(stage, spec["engine"], checked_upstream(lock_item, args.cache_dir), 0o755)
        copy_file(stage, ROOT / spec["template"], spec["template"])
        example = "tests/fixtures/render/gateway-valid.yaml" if args.role == "gateway" else "tests/fixtures/render/egress-valid.yaml"
        copy_file(stage, ROOT / example, f"examples/{args.role}.yaml")
        for unit in spec["units"]:
            copy_file(stage, ROOT / "deploy/systemd" / unit, f"systemd/{unit}")
        copy_file(stage, ROOT / "deploy/tmpfiles.d/private-proxy.conf", "tmpfiles.d/private-proxy.conf")
        copy_file(stage, ROOT / "release/licenses.json", "licenses.json")
        copy_file(stage, args.lock, "upstream-lock.json")
        copy_file(stage, ROOT / "scripts/release/release.py", "verify-release.py", 0o755)
        sbom = make_sbom(stage, args.role, args.version, args.commit, lock_item)
        write_file(stage, "sbom.spdx.json", json_bytes(sbom))
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "proxyctl", "digest": {"sha256": sha256_file(stage / "proxyctl")}},
                {"name": spec["engine"], "digest": {"sha256": sha256_file(stage / spec["engine"])}},
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {"buildType": "https://pushpop.invalid/buildtypes/prx02/v1", "externalParameters": {"role": args.role, "version": args.version, "sourceCommit": args.commit, "upstreamLockSha256": sha256_file(args.lock)}, "resolvedDependencies": [{"uri": lock_item["sourceRepository"], "digest": {"gitCommit": lock_item["sourceTagOid"]}}, {"uri": lock_item["url"], "digest": {"sha256": lock_item["sha256"]}}]},
                "runDetails": {"builder": {"id": f"https://pushpop.invalid/builders/{args.builder_environment}/{urllib.parse.quote(args.builder_identity, safe='')}"}, "metadata": {"invocationId": f"{args.commit}:{args.role}:{epoch}"}},
            },
        }
        write_file(stage, "provenance.intoto.jsonl", json_bytes(provenance))
        manifest_files = file_records(stage)
        manifest = {
            "schemaVersion": 1,
            "releaseVersion": args.version,
            "role": args.role,
            "target": {"goos": "linux", "goarch": spec["goarch"]},
            "source": {"repository": args.source_repository, "commit": args.commit},
            "builder": {"environment": args.builder_environment, "identity": args.builder_identity, "hostLabel": args.host_label},
            "toolchain": {"go": lock["goToolchain"]},
            "sourceDateEpoch": epoch,
            "upstream": {"name": spec["upstream"], **lock_item},
            "files": manifest_files,
            "installationRoot": f"/opt/private-proxy/releases/{args.version}/",
            "activation": "manual-only: verify first; never overwrite /opt/private-proxy/current",
        }
        write_file(stage, "manifest.json", json_bytes(manifest))
        checksums = "".join(f"{record['sha256']}  {record['path']}\n" for record in file_records(stage, {"SHA256SUMS"}))
        write_file(stage, "SHA256SUMS", checksums.encode())
        output = args.output_dir / spec["bundle"]
        deterministic_tar(stage, output, epoch)
    print(f"built {output.name} sha256={sha256_file(output)}")
    return output


def verify_bundle(path: pathlib.Path, expected_role: str | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="prx02-verify-") as temp:
        root = pathlib.Path(temp)
        try:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                names: set[str] = set()
                for member in members:
                    pure = pathlib.PurePosixPath(member.name)
                    if member.name.startswith("/") or ".." in pure.parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                        raise ReleaseError("bundle contains an unsafe member")
                    if member.name in names:
                        raise ReleaseError("bundle contains a duplicate member")
                    names.add(member.name)
                # The archive is extracted into a new empty directory only
                # after every member has passed the closed type/path checks.
                # Python 3.12+ supplies an additional safe-data filter. Keep
                # the explicit closed checks above for Python 3.9-3.11.
                try:
                    archive.extractall(root, filter="data")
                except TypeError:
                    archive.extractall(root)
        except (OSError, tarfile.TarError) as exc:
            raise ReleaseError(f"cannot extract bundle: {exc}") from exc
        for required in ("manifest.json", "SHA256SUMS", "sbom.spdx.json", "licenses.json", "provenance.intoto.jsonl", "proxyctl", "upstream-lock.json"):
            if not (root / required).is_file():
                raise ReleaseError(f"bundle missing {required}")
        checksums: dict[str, str] = {}
        for line in (root / "SHA256SUMS").read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
            if not match or match.group(2) in checksums:
                raise ReleaseError("invalid or duplicate SHA256SUMS entry")
            checksums[match.group(2)] = match.group(1)
        actual = {p.relative_to(root).as_posix(): sha256_file(p) for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
        if checksums != actual:
            raise ReleaseError("SHA256SUMS does not match extracted files")
        manifest = json.loads((root / "manifest.json").read_text())
        if manifest.get("schemaVersion") != 1 or manifest.get("builder", {}).get("environment") not in ALLOWED_BUILDERS:
            raise ReleaseError("manifest schema or builder is invalid")
        if expected_role and manifest.get("role") != expected_role:
            raise ReleaseError("bundle role does not match expectation")
        validate_builder(manifest["builder"]["environment"], manifest["builder"]["identity"], manifest["builder"]["hostLabel"])
        validate_source_repository(manifest.get("source", {}).get("repository", ""))
        if not OID_RE.fullmatch(manifest.get("source", {}).get("commit", "")):
            raise ReleaseError("manifest source commit is invalid")
        embedded_lock = load_lock(root / "upstream-lock.json")
        spec = ROLE_SPECS.get(manifest.get("role"))
        if spec is None or manifest.get("upstream") != {"name": spec["upstream"], **embedded_lock["upstreams"][spec["upstream"]]}:
            raise ReleaseError("manifest upstream does not match embedded lock")
        validate_license_inventory(embedded_lock, root / "licenses.json")
        if manifest.get("toolchain", {}).get("go") != embedded_lock["goToolchain"]:
            raise ReleaseError("manifest toolchain does not match embedded lock")
        expected_manifest_files = file_records(root, {"manifest.json", "SHA256SUMS"})
        if manifest.get("files") != expected_manifest_files:
            raise ReleaseError("manifest file inventory does not match bundle")
        sbom = json.loads((root / "sbom.spdx.json").read_text())
        if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages") or not sbom.get("files"):
            raise ReleaseError("SPDX SBOM is incomplete")
        expected_sbom_records = file_records(
            root,
            {"sbom.spdx.json", "provenance.intoto.jsonl", "manifest.json", "SHA256SUMS"},
        )
        expected_sbom_files = {
            ("./" + item["path"], item["sha256"]) for item in expected_sbom_records
        }
        try:
            sbom_files = {
                (item["fileName"], item["checksums"][0]["checksumValue"])
                for item in sbom["files"]
                if item["checksums"][0]["algorithm"] == "SHA256"
            }
        except (KeyError, IndexError, TypeError):
            raise ReleaseError("SPDX SBOM file inventory is invalid") from None
        if sbom_files != expected_sbom_files or len(sbom["files"]) != len(expected_sbom_files):
            raise ReleaseError("SPDX SBOM file inventory does not match bundle")
        provenance = json.loads((root / "provenance.intoto.jsonl").read_text())
        if provenance.get("predicateType") != "https://slsa.dev/provenance/v1" or not provenance.get("subject"):
            raise ReleaseError("provenance statement is invalid")
        expected_subjects = {
            ("proxyctl", sha256_file(root / "proxyctl")),
            (spec["engine"], sha256_file(root / spec["engine"])),
        }
        try:
            subjects = {
                (item["name"], item["digest"]["sha256"])
                for item in provenance["subject"]
            }
        except (KeyError, TypeError):
            raise ReleaseError("provenance subjects are invalid") from None
        if subjects != expected_subjects or len(provenance["subject"]) != len(expected_subjects):
            raise ReleaseError("provenance subjects do not match bundle")
        return manifest


def lint_workflows(directory: pathlib.Path) -> None:
    workflow_files = sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml"))
    if not workflow_files:
        raise ReleaseError("no workflow files found")
    for path in workflow_files:
        text = path.read_text()
        if re.search(r"(?i)(ssh|scp|rsync|kubectl|systemctl|docker\s+build)", text):
            raise ReleaseError(f"{path.name}: deployment or forbidden build command in workflow")
        for number, line in enumerate(text.splitlines(), 1):
            if "uses:" in line and not ACTION_PIN_RE.match(line):
                raise ReleaseError(f"{path.name}:{number}: action is not pinned to a full commit SHA")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-lock")
    validate.add_argument("--lock", type=pathlib.Path, default=ROOT / "upstream-lock.json")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--lock", type=pathlib.Path, default=ROOT / "upstream-lock.json")
    fetch.add_argument("--cache-dir", type=pathlib.Path, required=True)
    build = sub.add_parser("build")
    build.add_argument("--role", required=True, choices=sorted(ROLE_SPECS))
    build.add_argument("--version", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--source-repository", required=True)
    build.add_argument("--builder-environment", required=True, choices=sorted(ALLOWED_BUILDERS))
    build.add_argument("--builder-identity", required=True)
    build.add_argument("--host-label", required=True)
    build.add_argument("--cache-dir", type=pathlib.Path, required=True)
    build.add_argument("--output-dir", type=pathlib.Path, required=True)
    build.add_argument("--lock", type=pathlib.Path, default=ROOT / "upstream-lock.json")
    build.add_argument("--go-binary", default="go")
    build.add_argument("--source-date-epoch", type=int)
    verify = sub.add_parser("verify")
    verify.add_argument("bundle", type=pathlib.Path)
    verify.add_argument("--role", choices=sorted(ROLE_SPECS))
    lint = sub.add_parser("lint-workflows")
    lint.add_argument("--directory", type=pathlib.Path, default=ROOT / ".github/workflows")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate-lock":
            lock = load_lock(args.lock)
            if args.lock.resolve() == (ROOT / "upstream-lock.json").resolve():
                validate_license_inventory(lock, ROOT / "release/licenses.json")
            print("upstream lock: OK")
        elif args.command == "fetch":
            fetch_upstreams(args.lock, args.cache_dir)
        elif args.command == "build":
            build_bundle(args)
        elif args.command == "verify":
            manifest = verify_bundle(args.bundle, args.role)
            print(f"bundle verified: role={manifest['role']} commit={manifest['source']['commit']}")
        elif args.command == "lint-workflows":
            lint_workflows(args.directory)
            print("workflow policy: OK")
        return 0
    except (ReleaseError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"release error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
