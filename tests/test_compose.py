import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


credentials = load("compose_credentials", ROOT / "deploy/compose/credential_stage.py")


class ComposeContractTests(unittest.TestCase):
    def test_stack_has_closed_runtime_and_expected_services(self):
        text = (ROOT / "deploy/compose/compose.yaml").read_text()
        for service in ("mihomo:", "hysteria-gateway:", "ikev2-policy:", "strongswan:"):
            self.assertIn(service, text)
        self.assertIn("pull_policy: never", text)
        self.assertIn("network_mode: host", text)
        self.assertIn("read_only: true", text)
        self.assertIn("no-new-privileges:true", text)
        self.assertNotIn("privileged: true", text)
        self.assertNotIn("ports:", text)
        self.assertNotIn("image: latest", text)
        self.assertIn("HOME: /run/private-proxy", text)

    def test_runtime_image_is_digest_pinned_and_strongswan_is_exact(self):
        text = (ROOT / "deploy/compose/Dockerfile.runtime").read_text()
        self.assertRegex(text.splitlines()[0], r"^FROM debian@sha256:[0-9a-f]{64}$")
        self.assertIn("ARG STRONGSWAN_VERSION=6.0.1-6+deb13u7", text)
        self.assertIn("charon-systemd=${STRONGSWAN_VERSION}", text)
        self.assertIn("       python3 \\\n", text)
        self.assertNotIn("python3-minimal", text)

    def test_credential_stage_rejects_non_regular_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "bad").mkdir()
            previous = credentials.SOURCE
            previous_target = credentials.TARGET_ROOT
            credentials.SOURCE = source
            credentials.TARGET_ROOT = root / "target"
            try:
                with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                    credentials.stage("test", ("bad",))
            finally:
                credentials.SOURCE = previous
                credentials.TARGET_ROOT = previous_target

    def test_gateway_release_includes_compose_assets(self):
        release = load("release_for_compose", ROOT / "scripts/release/release.py")
        destinations = {destination for _, destination, _ in release.ROLE_SPECS["gateway"]["extra_files"]}
        self.assertIn("compose/compose.yaml", destinations)
        self.assertIn("deploy/compose/credential_stage.py", destinations)
        self.assertIn("deploy/compose/run_strongswan.py", destinations)
        self.assertEqual(release.ROLE_SPECS["gateway"]["extra_upstreams"], [("hysteria-linux-arm64", "hysteria")])


if __name__ == "__main__":
    unittest.main()
