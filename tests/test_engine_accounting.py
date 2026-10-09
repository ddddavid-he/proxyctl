import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("engine_traffic", ROOT / "deploy/traffic/traffic.py")
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


class EngineAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.spool = self.root / 'spool'
        self.spool.mkdir()
        self.store = traffic.Store(self.root / 'usage.sqlite3')
        self.at = int(time.time()) // 900 * 900 - 900

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def batch(self, sequence=1, **changes):
        batch = dict(version=1, epoch='a'*32, sequence=sequence, **{'from': self.at + (sequence-1)*2, 'to': self.at + sequence*2}, unclean_previous=False,
                     rows=[dict(start=self.at, domain='example.com', upload=123, download=456)])
        batch.update(changes)
        batch["emitted_ns"] = batch["to"] * 10**9 + sequence
        path = self.spool / f"{batch['epoch']}-{sequence:020d}.json"
        path.write_text(json.dumps(batch))
        return path

    def totals(self):
        return self.store.db.execute('SELECT SUM(upload),SUM(download) FROM buckets').fetchone()

    def test_short_completed_connections_survive_collector_restart_and_replay(self):
        path = self.batch()
        data = path.read_bytes()
        self.assertEqual(traffic.drain_engine(self.store, self.spool), 1)
        self.store.close()
        self.store = traffic.Store(self.root / 'usage.sqlite3')
        path.write_bytes(data)  # crash after SQLite commit, before unlink
        traffic.drain_engine(self.store, self.spool)
        self.assertEqual(self.totals(), (123, 456))
        self.assertEqual(self.store.db.execute('SELECT upload,download FROM domain_buckets').fetchone(), (123, 456))

    def test_missing_sequence_blocks_without_acknowledgement(self):
        path = self.batch(2)
        with self.assertRaisesRegex(ValueError, 'sequence gap'):
            traffic.drain_engine(self.store, self.spool)
        self.assertTrue(path.exists())
        self.assertEqual(self.totals(), (None, None))

    def test_transaction_failure_preserves_batch(self):
        path = self.batch()
        self.store.db.execute("CREATE TRIGGER fail BEFORE INSERT ON kernel_epochs BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(traffic.sqlite3.Error):
            traffic.drain_engine(self.store, self.spool)
        self.assertTrue(path.exists())
        self.assertEqual(self.totals(), (None, None))

    def test_multi_batch_backlog_and_engine_restart(self):
        for seq in range(1, 21):
            self.batch(seq)
        traffic.drain_engine(self.store, self.spool)
        self.batch(epoch='b'*32, **{'from': self.at+40, 'to': self.at+42}, unclean_previous=True)
        traffic.drain_engine(self.store, self.spool)
        self.assertEqual(self.totals(), (123*21, 456*21))
        self.assertEqual(self.store.db.execute('SELECT SUM(possible_tail_loss) FROM kernel_epochs').fetchone()[0], 1)

    def test_v2_migration_keeps_history_and_labels_mixed_period(self):
        self.store.record(self.at-2, 0, 0, 'old', 'controller', connections=[])
        self.store.record(self.at, 10, 20, 'old', 'controller', connections=[])
        self.batch()
        traffic.drain_engine(self.store, self.spool)
        self.assertEqual(self.totals(), (133, 476))
        report = traffic.domain_report(self.root/'usage.sqlite3', self.at-900, self.at+900, '15m', traffic.timezone('+00:00'), self.at+900)
        self.assertEqual(report['attribution_method'], 'mixed-sampled-and-kernel')
        report = traffic.domain_report(self.root/'usage.sqlite3', self.at, self.at+900, '15m', traffic.timezone('+00:00'), self.at+900)
        self.assertEqual(report['attribution_method'], 'kernel-byte-counters')

    def test_restart_in_same_second_orders_batches_by_emission(self):
        self.batch(epoch='f'*32)
        self.batch(2, epoch='f'*32, **{'from':self.at+2,'to':self.at+2})
        path=self.batch(epoch='a'*32, **{'from':self.at+2,'to':self.at+2})
        value=json.loads(path.read_text())
        value['emitted_ns']+=10
        path.write_text(json.dumps(value))
        traffic.drain_engine(self.store,self.spool)
        self.assertEqual(self.totals(),(123*3,456*3))

    def test_invalid_domain_and_interval_are_rejected(self):
        path = self.batch(rows=[dict(start=self.at,domain='https://example.com/private',upload=1,download=2)])
        with self.assertRaisesRegex(ValueError, 'domain'):
            traffic.drain_engine(self.store,self.spool)
        self.assertTrue(path.exists())

    def test_conflicting_replay_is_rejected(self):
        path=self.batch()
        traffic.drain_engine(self.store,self.spool)
        self.batch(rows=[])
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            traffic.drain_engine(self.store,self.spool)

    def test_bucket_boundary_and_unknown_domain_preserve_totals(self):
        self.batch(**{'from':self.at+899,'to':self.at+901}, rows=[dict(start=self.at,domain='example.com',upload=1,download=2),dict(start=self.at+900,domain='[ip-only]',upload=3,download=4)])
        traffic.drain_engine(self.store,self.spool)
        self.assertEqual(self.totals(),(4,6))
        self.assertEqual(self.store.db.execute('SELECT observed_seconds FROM buckets ORDER BY start').fetchall(),[(1,),(1,)])

if __name__ == '__main__':
    unittest.main()
