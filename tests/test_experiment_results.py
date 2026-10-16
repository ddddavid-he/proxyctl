import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'experiment_results', Path(__file__).resolve().parents[1] / 'tools/verify_experiment_results.py')
results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(results)


class ExperimentResultsTests(unittest.TestCase):
    def test_failure_consumption_survives_verified_body_denominator(self):
        rows = [
            dict(file_attempted=True, success=True, file_bytes=100, gateway_tx_bytes=110),
            dict(file_attempted=True, success=False, file_bytes=100, gateway_tx_bytes=50),
            dict(file_attempted=False, success=False, file_bytes=0, gateway_tx_bytes=7),
        ]
        summary = results.summarize_transfers(rows)
        self.assertEqual(summary['gateway_tx_per_verified_body'], 1.6)
        self.assertEqual(summary['failed_transfer_tx_bytes'], 50)
        self.assertEqual(summary['setup_tx_bytes'], 7)
        self.assertEqual((summary['attempts'], summary['successful']), (2, 1))

    def test_pairing_requires_same_session_and_both_verified_directions(self):
        def row(session, direction, ok, mbps):
            return dict(case_id='case-1', session=session, direction=direction, ok=ok,
                        mbps=mbps, body=100, gateway_tx_bytes=110)
        rows = [row(1, 'download', True, 30), row(1, 'upload', False, None),
                row(2, 'download', True, 30), row(2, 'upload', True, 10),
                row(3, 'download', True, 30), row(3, 'upload', True, 25)]
        summary = results.summarize_requests(rows)
        self.assertEqual(summary['both_verified_sessions'], 2)
        self.assertEqual(summary['both_ge20_sessions'], 1)
        self.assertAlmostEqual(summary['upload']['gateway_tx_per_verified_body'], 1.65)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            results.summarize_requests(rows + [rows[0]])

    def test_privacy_check_rejects_routing_identifiers_and_exact_timestamps(self):
        # Public DNS addresses are synthetic test input, never operator endpoints.
        import ipaddress
        public_address = str(ipaddress.IPv4Address(0x08080808))
        self.assertTrue(results.privacy_findings(public_address))
        self.assertTrue(results.privacy_findings('/Users/' + 'synthetic-user/private'))
        self.assertTrue(results.privacy_findings('2000-01-01' + 'T12:00:00'))
        self.assertTrue(results.privacy_findings('https://' + 'service.invalid/path'))
        self.assertTrue(results.privacy_findings('operator.' + 'cn'))
        self.assertFalse(results.privacy_findings('gateway-A 192.0.2.1 example.com 2001:db8::1'))

    def test_published_dataset_reconciles_without_private_sources(self):
        summary = results.verify()
        self.assertEqual(summary['full_chain']['TT']['successful'], 24)
        self.assertEqual(summary['controller_primary']['controller']['both_ge20_sessions'], 4)
        self.assertEqual(summary['packet_probes']['origin']['missing'], 3186)


if __name__ == '__main__':
    unittest.main()
