import copy
import importlib.util
import io
import json
import pathlib
from unittest import mock
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prx02_release", ROOT / "scripts/release/release.py")
release = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release)


class LockTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT / "upstream-lock.json").read_text())

    def write_lock(self, directory, value):
        path = pathlib.Path(directory) / "lock.json"
        path.write_text(json.dumps(value))
        return path

    def test_repository_lock_is_valid(self):
        loaded = release.load_lock(ROOT / "upstream-lock.json")
        self.assertEqual(loaded["schemaVersion"], 1)

    def test_legacy_lock_remains_verifiable(self):
        with tempfile.TemporaryDirectory() as temp:
            value = copy.deepcopy(self.lock)
            del value["upstreams"]["mihomo-linux-amd64"]
            loaded = release.load_lock(self.write_lock(temp, value))
            self.assertEqual(len(loaded["upstreams"]), 3)

    def test_floating_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            value = copy.deepcopy(self.lock)
            value["upstreams"]["mihomo-linux-arm64"]["url"] = "https://github.com/MetaCubeX/mihomo/releases/download/latest/mihomo.gz"
            with self.assertRaisesRegex(release.ReleaseError, "floating"):
                release.load_lock(self.write_lock(temp, value))

    def test_unknown_architecture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            value = copy.deepcopy(self.lock)
            value["upstreams"]["mihomo-linux-arm64"]["goarch"] = "mips64"
            with self.assertRaisesRegex(release.ReleaseError, "architecture"):
                release.load_lock(self.write_lock(temp, value))

    def test_missing_license_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            value = copy.deepcopy(self.lock)
            value["upstreams"]["hysteria-linux-amd64"]["license"] = ""
            with self.assertRaisesRegex(release.ReleaseError, "license"):
                release.load_lock(self.write_lock(temp, value))

    def test_hash_mismatch_is_rejected_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            item = copy.deepcopy(self.lock["upstreams"]["hysteria-linux-amd64"])
            item["url"] = "https://github.com/apernet/hysteria/releases/download/app%2Fv2.9.2/asset"
            pathlib.Path(temp, "asset").write_bytes(b"tampered")
            with self.assertRaisesRegex(release.ReleaseError, "hash mismatch"):
                release.checked_upstream(item, pathlib.Path(temp))


class BuilderPolicyTests(unittest.TestCase):
    def test_allowed_builders(self):
        for environment in sorted(release.ALLOWED_BUILDERS):
            release.validate_builder(environment, "builder-01", "runner-01")

    def test_unknown_environment_is_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "not allowed"):
            release.validate_builder("unknown", "builder-01", "runner-01")

    def test_invalid_builder_metadata_is_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "invalid"):
            release.validate_builder("local", "", "runner-01")

    def test_credentialed_source_repository_is_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "credential-free"):
            release.validate_source_repository("https://user:password@example.invalid/repo.git")  # secret-scan:allow-line synthetic credentialed URL rejection vector

    def test_current_source_rejects_dirty_checkout(self):
        with mock.patch.object(release.subprocess, "check_output") as check:
            check.side_effect = [
                "0" * 40 + "\n",
                "https://example.org/owner/proxyctl.git\n",
                " M tracked.go\n",
            ]
            with self.assertRaisesRegex(release.ReleaseError, "not clean"):
                release.current_source()


class ArchitectureTests(unittest.TestCase):
    def test_architecture_selects_matching_engines_and_names(self):
        for role in release.ROLE_SPECS:
            for arch in release.ARCHITECTURES:
                with self.subTest(role=role, arch=arch):
                    spec = release.role_spec(role, arch)
                    self.assertEqual(spec["goarch"], arch)
                    self.assertEqual(spec["bundle"], f"proxyctl-{role}-linux-{arch}.tar.gz")
                    self.assertEqual(spec["upstream"], f"{spec['engine']}-linux-{arch}")
                    for name, _ in spec["extra_upstreams"]:
                        self.assertTrue(name.endswith("-" + arch))
        self.assertEqual(release.ROLE_SPECS["gateway"]["goarch"], "arm64")

    def test_other_architectures_are_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "architecture"):
            release.role_spec("gateway", "386")
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", new=io.StringIO()):
            release.parser().parse_args(["build", "--role", "gateway", "--arch", "386"])

    def test_proxyctl_cross_build_uses_requested_architecture(self):
        for arch in release.ARCHITECTURES:
            with tempfile.TemporaryDirectory() as temp, mock.patch.object(release, "run") as run:
                stage = pathlib.Path(temp)
                (stage / "proxyctl").touch()
                release.build_proxyctl(stage, "gateway", "v0.4.0", "a"*40, 1, "go", arch)
                env = run.call_args.kwargs["env"]
                self.assertEqual((env["GOOS"], env["GOARCH"]), ("linux", arch))


class WorkflowTests(unittest.TestCase):
    def test_repository_workflows_are_pinned_and_non_deploying(self):
        release.lint_workflows(ROOT / ".github/workflows")

    def test_floating_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp, "bad.yml")
            path.write_text("steps:\n  - uses: actions/checkout@v6\n")
            with self.assertRaisesRegex(release.ReleaseError, "not pinned"):
                release.lint_workflows(path.parent)

    def test_deployment_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp, "bad.yml")
            path.write_text("steps:\n  - run: ssh host true\n")
            with self.assertRaisesRegex(release.ReleaseError, "forbidden"):
                release.lint_workflows(path.parent)

    def test_release_checksums_are_download_directory_relative(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("(cd dist && shasum -a 256 ./*.tar.gz > SHA256SUMS)", workflow)
        self.assertNotIn("shasum -a 256 dist/*.tar.gz", workflow)

    def test_mihomo_unit_uses_writable_runtime_home(self):
        unit = (ROOT / "deploy/systemd/private-proxy-mihomo.service").read_text()
        self.assertIn("RuntimeDirectory=private-proxy\n", unit)
        self.assertIn("Environment=HOME=/run/private-proxy\n", unit)
        self.assertIn("Environment=SAFE_PATHS=/run/private-proxy\n", unit)
        self.assertIn("ProtectHome=yes\n", unit)


class BundleVerificationTests(unittest.TestCase):
    def make_bundle(self, directory, *, wrong_checksum=False, role="gateway", goarch="arm64"):
        spec = release.role_spec(role, goarch)
        root = pathlib.Path(directory, "stage")
        root.mkdir()
        release.write_file(root, "proxyctl", b"proxyctl", 0o755)
        if role == "gateway":
            release.write_file(root, "mihomo", b"mihomo", 0o755)
        release.write_file(root, "hysteria", b"hysteria", 0o755)
        release.copy_file(root, ROOT / "upstream-lock.json", "upstream-lock.json")
        release.copy_file(root, ROOT / "release/licenses.json", "licenses.json")
        lock = release.load_lock(ROOT / "upstream-lock.json")
        lock_item = lock["upstreams"][spec["upstream"]]
        extra_items = [(name, lock["upstreams"][name]) for name, _ in spec["extra_upstreams"]]
        release.write_file(root, "sbom.spdx.json", release.json_bytes(release.make_sbom(root, role, "v0.1.0", "a" * 40, [(spec["upstream"], lock_item), *extra_items], goarch)))
        release.write_file(root, "provenance.intoto.jsonl", release.json_bytes({
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": "proxyctl", "digest": {"sha256": release.sha256_file(root / "proxyctl")}},
                *([{ "name": "mihomo", "digest": {"sha256": release.sha256_file(root / "mihomo")} }] if role == "gateway" else []),
                {"name": "hysteria", "digest": {"sha256": release.sha256_file(root / "hysteria")}},
            ],
        }))
        records = release.file_records(root)
        manifest = {
            "schemaVersion": 1,
            "role": role,
            "target": {"goos": "linux", "goarch": goarch},
            "source": {"repository": "https://example.invalid/proxyctl.git", "commit": "a" * 40},
            "builder": {"environment": "local", "identity": "test", "hostLabel": "test-host"},
            "toolchain": {"go": "1.25.14"},
            "upstream": {"name": spec["upstream"], **lock_item},
            "additionalUpstreams": [{"name": name, **item} for name, item in extra_items],
            "files": records,
        }
        release.write_file(root, "manifest.json", release.json_bytes(manifest))
        checksum_records = release.file_records(root)
        lines = [f"{item['sha256']}  {item['path']}\n" for item in checksum_records]
        if wrong_checksum:
            lines[0] = "0" * 64 + lines[0][64:]
        release.write_file(root, "SHA256SUMS", "".join(lines).encode())
        bundle = pathlib.Path(directory, "bundle.tar.gz")
        release.deterministic_tar(root, bundle, 1)
        return bundle

    def test_valid_bundle_verifies(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = release.verify_bundle(self.make_bundle(temp), "gateway")
            self.assertEqual(manifest["role"], "gateway")

    def test_both_roles_verify_on_both_linux_architectures(self):
        for role in release.ROLE_SPECS:
            for arch in release.ARCHITECTURES:
                with self.subTest(role=role, arch=arch), tempfile.TemporaryDirectory() as temp:
                    manifest = release.verify_bundle(self.make_bundle(temp, role=role, goarch=arch), role)
                    self.assertEqual(manifest["target"], {"goos": "linux", "goarch": arch})
                    self.assertEqual(manifest["upstream"]["goarch"], arch)

    def test_tampered_checksum_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(release.ReleaseError, "SHA256SUMS"):
                release.verify_bundle(self.make_bundle(temp, wrong_checksum=True), "gateway")

    def test_symlink_member_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = pathlib.Path(temp, "unsafe.tar.gz")
            with tarfile.open(bundle, "w:gz") as archive:
                info = tarfile.TarInfo("unsafe")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info, io.BytesIO())
            with self.assertRaisesRegex(release.ReleaseError, "unsafe"):
                release.verify_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
