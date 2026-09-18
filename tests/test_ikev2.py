import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


renderer = load("ikev2_renderer", ROOT / "deploy/ikev2/render_ikev2.py")
policy = load("ikev2_policy", ROOT / "deploy/ikev2/configure_policy.py")
loader = load("ikev2_loader", ROOT / "deploy/ikev2/load_ikev2.py")


class RenderTests(unittest.TestCase):
    def credentials(self, root):
        directory = pathlib.Path(root, "credentials")
        directory.mkdir()
        values = {
            "IKEV2_USER_1": "synthetic-user",
            "IKEV2_PASSWORD_1": "synthetic-password",
            "IKEV2_REMOTE_ID": "vpn.example.invalid",
            "ikev2.crt": "synthetic-certificate",
            "ikev2.key": "synthetic-private-key",
        }
        for name, value in values.items():
            (directory / name).write_text(value)
        return directory

    def test_render_is_full_tunnel_and_uses_runtime_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            credentials = self.credentials(temp)
            runtime = pathlib.Path(temp, "runtime")
            output = renderer.render(credentials, runtime)
            text = output.read_text()
            self.assertIn("local_ts = 0.0.0.0/0", text)
            self.assertIn('id = "synthetic-user"', text)
            self.assertIn('secret = "synthetic-password"', text)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual((runtime / "private/ikev2.key").stat().st_mode & 0o777, 0o600)

    def test_invalid_secret_is_rejected_without_leaking_value(self):
        with tempfile.TemporaryDirectory() as temp:
            credentials = self.credentials(temp)
            bad = "do-not-leak\nsecond-line"
            (credentials / "IKEV2_PASSWORD_1").write_text(bad)
            with self.assertRaises(renderer.RenderError) as raised:
                renderer.render(credentials, pathlib.Path(temp, "runtime"))
            self.assertNotIn("do-not-leak", str(raised.exception))

    def test_symlinked_credential_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            credentials = self.credentials(temp)
            target = pathlib.Path(temp, "outside")
            target.write_text("synthetic-password")
            (credentials / "IKEV2_PASSWORD_1").unlink()
            (credentials / "IKEV2_PASSWORD_1").symlink_to(target)
            with self.assertRaises(renderer.RenderError):
                renderer.render(credentials, pathlib.Path(temp, "runtime"))


class PolicyTests(unittest.TestCase):
    def test_rules_intercept_tcp_udp_and_drop_other_forwarding(self):
        rules = policy.nft_rules()
        self.assertIn("tproxy ip to 127.0.0.1:17894", rules)
        self.assertIn("ip saddr 10.89.0.0/24 drop", rules)
        self.assertNotIn("masquerade", rules.lower())
        self.assertNotIn("dnat", rules.lower())

    def test_apply_installs_route_before_nft_rules(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            missing = argv[1:4] == ["list", "table", "inet"] or argv[1:3] == ["rule", "del"]
            return mock.Mock(returncode=1 if missing else 0, stdout="")

        with mock.patch.object(policy, "_run", side_effect=fake_run):
            policy.apply()
        route_index = next(i for i, argv in enumerate(calls) if argv[1:3] == ["route", "replace"])
        nft_index = next(i for i, argv in enumerate(calls) if argv[1:3] == ["-f", "-"])
        self.assertLess(route_index, nft_index)

    def test_remove_deletes_nft_before_policy_route(self):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(returncode=1 if argv[1:3] == ["rule", "del"] else 0, stdout="")

        with mock.patch.object(policy, "_run", side_effect=fake_run):
            policy.remove()
        self.assertEqual(calls[0][1:4], ["delete", "table", "inet"])
        self.assertEqual(calls[1][1:3], ["rule", "del"])


class LoadTests(unittest.TestCase):
    def test_load_requires_named_connection(self):
        responses = [
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="private-proxy-ikev2: IKEv2\n", stderr=""),
        ]
        with mock.patch.object(loader, "_run", side_effect=responses):
            loader.load()

    def test_load_rejects_swanctl_zero_with_no_connection(self):
        responses = [
            mock.Mock(returncode=0, stdout="no connections found\n", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
        ]
        with mock.patch.object(loader, "_run", side_effect=responses):
            with self.assertRaisesRegex(loader.LoadError, "was not loaded"):
                loader.load()


class UnitTests(unittest.TestCase):
    def test_ikev2_unit_uses_systemd_credentials(self):
        unit = (ROOT / "deploy/systemd/private-proxy-ikev2.service").read_text()
        self.assertIn("LoadCredential=IKEV2_PASSWORD_1:", unit)
        self.assertIn("LoadCredential=ikev2.key:", unit)
        self.assertNotIn("synthetic-password", unit)

    def test_primary_mihomo_has_required_tproxy_capability(self):
        unit = (ROOT / "deploy/systemd/private-proxy-mihomo.service").read_text()
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN\n", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN\n", unit)

    def test_tproxy_listener_is_merged_into_primary_template(self):
        config = (ROOT / "templates/mihomo/mihomo-gateway.yaml.tmpl").read_text()
        self.assertIn("name: gateway-ikev2-tproxy", config)
        self.assertIn("listen: 127.0.0.1\n    port: 17894", config)
        self.assertNotIn("DIRECT", config)

    def test_gateway_bundle_includes_ikev2_assets(self):
        spec = load("release_for_ikev2", ROOT / "scripts/release/release.py").ROLE_SPECS["gateway"]
        self.assertIn("private-proxy-ikev2.service", spec["units"])
        self.assertNotIn("private-proxy-ikev2-tproxy.service", spec["units"])
        destinations = {destination for _, destination, _ in spec["extra_files"]}
        self.assertIn("deploy/ikev2/render_ikev2.py", destinations)
        self.assertIn("deploy/ikev2/load_ikev2.py", destinations)
        self.assertIn("deploy/ikev2/configure_policy.py", destinations)
        self.assertIn("apparmor/usr.sbin.swanctl.private-proxy", destinations)

    def test_apparmor_fragment_allows_only_runtime_reads(self):
        fragment = (ROOT / "deploy/apparmor/usr.sbin.swanctl.private-proxy").read_text()
        self.assertIn("/run/private-proxy-ikev2/** r,", fragment)
        self.assertNotIn(" w,", fragment)


if __name__ == "__main__":
    unittest.main()
