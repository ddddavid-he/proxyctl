import contextlib
import datetime as dt
import http.server
import importlib.util
import io
import json
import pathlib
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("traffic", ROOT / "deploy/traffic/traffic.py")
traffic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(traffic)
UTC = dt.timezone.utc
BASE = int(dt.datetime(2026, 9, 1, tzinfo=UTC).timestamp())


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / "usage.sqlite3"
        self.store = traffic.Store(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def sample(self, seconds, up, down, epoch="one", interval=60):
        return self.store.record(BASE + seconds, up, down, epoch, "source", interval)

    def query(self, start=0, end=3600, granularity="15m", zone=UTC, now=None):
        return traffic.report(self.path, BASE + start, BASE + end, granularity, zone, now or BASE + end)

    def test_cumulative_not_rates_and_first_sample_is_baseline(self):
        self.sample(0, 10000, 50000)
        self.sample(60, 10100, 50700)
        result = self.query()
        self.assertEqual(result["totals"]["total_bytes"], 800)
        self.assertEqual(result["buckets"][0]["observed_seconds"], 60)
        self.assertEqual(result["buckets"][1]["coverage"], "missing")

    def test_bucket_crossing_keeps_integer_totals(self):
        self.sample(870, 0, 0)
        self.sample(930, 101, 203)
        rows = self.query()["buckets"]
        self.assertEqual([row["total_bytes"] for row in rows[:2]], [151, 153])
        self.assertEqual(sum(row["observed_seconds"] for row in rows), 60)

    def test_hour_and_local_midnight_day_aggregation(self):
        # UTC 16:00 is midnight at UTC+8.
        self.sample(16 * 3600, 0, 0)
        for minute in range(1, 61):
            self.sample(16 * 3600 + minute * 60, minute, minute * 2)
        hour = self.query(16 * 3600, 17 * 3600, "hour")
        day = self.query(16 * 3600, 40 * 3600, "day", traffic.timezone("+08:00"))
        self.assertEqual(hour["totals"]["total_bytes"], 180)
        self.assertEqual(day["totals"], hour["totals"])
        self.assertIn("2026-09-02T00:00:00+08:00", day["buckets"][0]["start"])
        self.assertEqual(hour["buckets"][0]["coverage"], "complete")

    def test_collector_restart_and_duplicate_sample_do_not_double_count(self):
        self.sample(0, 0, 0)
        self.sample(60, 100, 200)
        self.store.close()
        self.store = traffic.Store(self.path)
        self.assertEqual(self.sample(60, 999, 999), "clock_not_advanced")
        self.sample(120, 200, 400)
        self.assertEqual(self.query()["totals"]["total_bytes"], 600)

    def test_process_restart_with_higher_counters_and_reset_api(self):
        self.sample(0, 100, 200)
        self.assertEqual(self.sample(60, 500, 900, "two"), "reset")
        self.assertEqual(self.sample(120, 10, 20, "two"), "reset")
        result = self.query()
        self.assertEqual(result["totals"]["total_bytes"], 1430)
        self.assertEqual(result["buckets"][0]["resets"], 2)
        self.assertEqual(result["buckets"][0]["estimated_seconds"], 120)

    def test_outage_keeps_cumulative_delta_and_flags_estimated_time(self):
        self.sample(0, 0, 0)
        self.assertEqual(self.sample(1800, 100, 300), "gap")
        result = self.query()
        self.assertEqual(result["totals"]["total_bytes"], 400)
        self.assertEqual([r["estimated_seconds"] for r in result["buckets"][:2]], [900, 900])

    def test_retention_three_calendar_months_and_outage_pruning(self):
        self.sample(0, 0, 0)
        self.sample(60, 100, 300)
        december = int(dt.datetime(2026, 12, 2, tzinfo=UTC).timestamp())
        self.store.prune(december)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM buckets").fetchone()[0], 0)
        march = int(dt.datetime(2026, 5, 31, 12, 4, tzinfo=UTC).timestamp())
        expected = int(dt.datetime(2026, 2, 28, 12, tzinfo=UTC).timestamp())
        self.assertEqual(traffic.cutoff(march), expected)

    def test_invalid_source_or_counter_rolls_back_cursor_and_usage(self):
        self.sample(0, 0, 0)
        with self.assertRaises(ValueError):
            self.store.record(BASE + 60, 100, 200, "one", "different")
        for invalid in (True, -1, "100", 2**63):
            with self.assertRaises(ValueError):
                self.sample(60, invalid, 1)
        with mock.patch.object(traffic, "cutoff", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                self.sample(60, 100, 200)
        self.sample(60, 100, 200)
        self.assertEqual(self.query()["totals"]["total_bytes"], 300)

    def test_failure_after_bucket_write_rolls_back_everything(self):
        self.sample(0, 0, 0)
        self.store.db.execute("CREATE TRIGGER reject_cursor BEFORE INSERT ON cursor WHEN NEW.upload=100 BEGIN SELECT RAISE(ABORT, 'test'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sample(60, 100, 200)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM buckets").fetchone()[0], 0)
        self.assertEqual(self.store.db.execute("SELECT upload FROM cursor").fetchone()[0], 0)
        self.sample(60, 200, 400)
        self.assertEqual(self.query()["totals"]["total_bytes"], 600)

    def test_long_outage_bounds_work_to_retention_window(self):
        self.sample(0, 0, 0)
        later = BASE + 400 * 86400
        self.store.record(later, 400000, 800000, "one", "source")
        self.assertLessEqual(self.store.db.execute("SELECT count(*) FROM buckets").fetchone()[0], 92 * 96 + 1)
        self.assertEqual(self.store.db.execute("SELECT min(start) FROM buckets").fetchone()[0], traffic.cutoff(later))

    def test_query_alignment_readonly_and_missing_database(self):
        with self.assertRaises(ValueError):
            self.query(start=1)
        missing = self.path.parent / "missing.sqlite3"
        with self.assertRaises(sqlite3.OperationalError):
            traffic.report(missing, BASE, BASE + 3600, "hour", UTC, BASE + 3600)
        self.assertFalse(missing.exists())
        self.sample(0, 0, 0)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = traffic.main(["query", "--db", str(self.path), "--from", "2026-09-01T00:00:00Z",
                                 "--to", "2026-09-01T01:00:00Z", "--granularity", "hour", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["scope"], "gateway-total")

    def test_health_uses_fresh_persisted_cursor_without_creating_database(self):
        self.assertFalse(traffic.healthy(self.path, 180, BASE))
        self.sample(0, 0, 0)
        self.assertTrue(traffic.healthy(self.path, 180, BASE + 180))
        self.assertFalse(traffic.healthy(self.path, 180, BASE + 181))
        self.assertFalse(traffic.healthy(self.path, 180, BASE - 1))
        with self.assertRaises(sqlite3.OperationalError):
            traffic.healthy(self.path.parent / "absent.sqlite3", 180, BASE)

    def test_single_writer_lock(self):
        with traffic.collector_lock(self.path):
            with self.assertRaisesRegex(ValueError, "already owns"):
                with traffic.collector_lock(self.path):
                    self.fail("second writer")

    def test_process_epoch_file_and_proc_parser(self):
        marker = self.path.parent / "epoch"
        marker.write_text("unique-start\n")
        self.assertEqual(traffic.process_epoch(None, None, marker), "file:unique-start")
        with mock.patch.object(pathlib.Path, "read_text", side_effect=["123 (miho mo)) S " + " ".join(str(i) for i in range(4, 23)), "boot"]):
            self.assertEqual(traffic.process_epoch(123, None), "boot:123:22")


class APITests(unittest.TestCase):
    def test_origin_rejects_public_hostname_credentials_and_redirect_paths(self):
        for value in ("http://example.com:9090", "http://192.0.2.1", "https://127.0.0.1", "http://localhost", "http://127.0.0.1/traffic", "http://127.0.0.1?token=x"):
            with self.assertRaises(ValueError):
                traffic.controller(value)
        self.assertEqual(traffic.controller("http://[::1]:9090"), ("::1", 9090))

    def test_http_reads_one_small_cumulative_frame_no_proxy(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.path = self.path
                self.server.auth = self.headers.get("Authorization")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"up":999,"down":999,"upTotal":100,"downTotal":200}\n')

            def log_message(self, *_):
                pass

        with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                with mock.patch.dict("os.environ", {"HTTP_PROXY": "http://192.0.2.1:1"}):
                    self.assertEqual(traffic.fetch(f"http://127.0.0.1:{server.server_port}"), (100, 200))
                self.assertEqual(server.path, "/traffic")
                self.assertIsNone(server.auth)
            finally:
                thread.join(timeout=5)

    def test_malformed_or_rejected_http_frames_fail_closed(self):
        response = mock.MagicMock()
        response.status = 200
        connection = mock.MagicMock()
        connection.getresponse.return_value = response
        with mock.patch.object(traffic.http.client, "HTTPConnection", return_value=connection):
            for body in (b'{}\n', b'{"upTotal":true,"downTotal":1}\n', b'x' * 4097, b'{"upTotal":1,"downTotal":2}'):
                response.readline.return_value = body
                with self.assertRaises((ValueError, KeyError)):
                    traffic.fetch("http://127.0.0.1:9090", "synthetic")
            response.status = 302
            with self.assertRaises(ValueError):
                traffic.fetch("http://127.0.0.1:9090")
        self.assertEqual(connection.close.call_count, 5)

    def test_restart_during_fetch_leaves_cursor_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "usage.sqlite3"
            with mock.patch.object(traffic, "fetch", return_value=(100, 200)), mock.patch.object(traffic, "process_epoch", side_effect=["one", "two"]), contextlib.redirect_stderr(io.StringIO()):
                code = traffic.main(["collect", "--db", str(path), "--once"])
            self.assertEqual(code, 1)
            db = sqlite3.connect(path)
            self.assertEqual(db.execute("SELECT count(*) FROM cursor").fetchone()[0], 0)
            db.close()

    def test_sample_failure_once_returns_failure_without_advancing_database(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "usage.sqlite3"
            with mock.patch.object(traffic, "fetch", side_effect=ValueError), contextlib.redirect_stderr(io.StringIO()):
                code = traffic.main(["collect", "--db", str(path), "--once"])
            self.assertEqual(code, 1)
            db = sqlite3.connect(path)
            self.assertEqual(db.execute("SELECT count(*) FROM cursor").fetchone()[0], 0)
            db.close()


if __name__ == "__main__":
    unittest.main()
