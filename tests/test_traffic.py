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


class DomainTests(unittest.TestCase):
    setUp = AccountingTests.setUp
    tearDown = AccountingTests.tearDown
    sample = AccountingTests.sample
    query = AccountingTests.query
    def sample_domain(self, seconds, up, down, connections, epoch="one"):
        return self.store.record(BASE+seconds, up, down, epoch, "source", 2, connections)

    def conn(self, identity="a", domain="example.com", up=0, down=0, start=1):
        return (identity, domain, up, down, BASE+start)

    def domains(self, start=0, end=3600, granularity="hour", domain=None, limit=20):
        return traffic.domain_report(self.path, BASE+start, BASE+end, granularity, UTC, BASE+end, domain, limit)

    def test_first_snapshot_baselines_existing_lifetimes(self):
        self.sample(0, 100, 200)
        self.sample_domain(2, 1000, 2000, [self.conn(up=700, down=1400, start=-100)])
        self.sample_domain(4, 1010, 2040, [self.conn(up=710, down=1440, start=-100)])
        result = self.domains()
        self.assertEqual(result["totals"]["total_bytes"], 50)
        self.assertEqual(result["domains"][0]["domain"], "example.com")
        self.assertEqual(result["tracking_started"], dt.datetime.fromtimestamp(BASE+2, UTC).isoformat())
        self.assertEqual(result["buckets"][0]["observed_seconds"], 2)

    def test_new_connections_count_and_closed_tails_are_unattributed(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 100, 300, [self.conn(up=80, down=250)])
        self.sample_domain(4, 120, 350, [])
        rows = {r["domain"]:r for r in self.domains()["domains"]}
        self.assertEqual(rows["example.com"]["total_bytes"], 330)
        self.assertEqual(rows[traffic.UNATTRIBUTED]["total_bytes"], 140)
        self.assertEqual(sum(r["total_bytes"] for r in rows.values()), 470)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domain_cursor").fetchone()[0], 0)

    def test_connection_finishes_between_snapshots_not_invented(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 123, 456, [])
        result=self.domains()
        self.assertEqual(result["unattributed_bytes"], 579)
        self.assertEqual(result["domain_attribution_ratio"], 0)

    def test_restart_preserves_checkpoint_no_double_count(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 10, 20, [self.conn(up=10, down=20)])
        self.store.close();self.store=traffic.Store(self.path)
        self.sample_domain(2, 999, 999, [self.conn(up=999, down=999)])
        self.sample_domain(4, 15, 25, [self.conn(up=15, down=25)])
        self.assertEqual(self.domains()["totals"]["total_bytes"], 40)
        self.assertEqual(self.domains()["identified_domain_bytes"], 40)

    def test_source_restart_does_not_reuse_old_connection_counters(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 10, 20, [self.conn(up=10, down=20)])
        self.sample_domain(4, 100, 200, [self.conn(up=100, down=200)], "two")
        self.sample_domain(6, 110, 220, [self.conn(up=110, down=220)], "two")
        result=self.domains()
        self.assertEqual(result["totals"]["total_bytes"], 360)
        self.assertEqual(result["identified_domain_bytes"], 60)
        self.assertEqual(result["unattributed_bytes"], 300)
        self.assertEqual(result["buckets"][0]["resets"], 1)

    def test_counter_decrease_and_domain_change_never_rebill_lifetime(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 100, 200, [self.conn(up=100, down=200)])
        self.sample_domain(4, 200, 400, [self.conn(up=1, down=1, domain="changed.example")])
        self.assertEqual(self.domains()["identified_domain_bytes"], 300)
        self.assertEqual(self.domains()["unattributed_bytes"], 300)

    def test_unknown_preexisting_connection_and_clock_future_baseline(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 100, 200, [self.conn(up=100, down=200, start=-10),self.conn("future",up=100,down=200,start=99)])
        self.assertEqual(self.domains()["unattributed_bytes"], 300)

    def test_snapshot_skew_caps_both_directions_and_exposes_clipping(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 10, 20, [self.conn(up=100, down=100),self.conn("b","b.example",up=100,down=100)])
        result=self.domains()
        self.assertEqual(result["totals"]["total_bytes"], 30)
        self.assertEqual(result["unattributed_bytes"], 0)
        self.assertEqual(result["buckets"][0]["clipped_upload_bytes"], 190)
        self.assertEqual(result["buckets"][0]["clipped_download_bytes"], 180)

    def test_boundary_integer_conservation_by_bucket(self):
        self.sample_domain(899, 0, 0, [])
        self.sample_domain(901, 101, 203, [self.conn(up=33,down=101,start=900),self.conn("b","b.example",up=68,down=102,start=900)])
        result=self.domains(granularity="15m")
        self.assertEqual([r["total_bytes"] for r in result["buckets"][:2]], [151,153])
        self.assertEqual(result["totals"],self.query()["totals"])

    def test_total_only_fallback_and_domain_recovery_preserve_independent_cursor(self):
        self.sample_domain(0, 0, 0, [])
        self.sample_domain(2, 10, 20, [self.conn(up=10,down=20)])
        self.sample(4, 20, 40)
        self.sample_domain(8, 40, 80, [self.conn(up=30,down=60)])
        result=self.domains()
        self.assertEqual(result["totals"]["total_bytes"],120)
        self.assertEqual(result["identified_domain_bytes"],90)
        self.assertEqual(result["unattributed_bytes"],30)
        self.assertEqual(result["buckets"][0]["estimated_seconds"],6)

    def test_domain_writes_roll_back_with_global_cursor_failure(self):
        self.sample_domain(0, 0, 0, [])
        self.store.db.execute("CREATE TRIGGER reject_new_cursor BEFORE INSERT ON cursor WHEN NEW.upload=10 BEGIN SELECT RAISE(ABORT, 'test'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sample_domain(2, 10, 20, [self.conn(up=10,down=20)])
        self.assertEqual(self.domains()["totals"]["total_bytes"],0)
        self.assertEqual(self.store.db.execute("SELECT at FROM domain_state").fetchone()[0],BASE)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domain_cursor").fetchone()[0],0)

    def test_ranking_limit_filter_and_local_day(self):
        self.sample_domain(0,0,0,[])
        self.sample_domain(2,10,20,[self.conn(up=2,down=3),self.conn("b","b.example",up=8,down=17)])
        result=self.domains(limit=1)
        self.assertEqual(result["domains"][0]["domain"],"b.example")
        self.assertEqual(result["other_domains_bytes"],5)
        filtered=self.domains(domain="example.com")
        self.assertEqual(filtered["totals"]["total_bytes"],5)
        self.assertEqual(filtered["buckets"][0]["total_bytes"],5)
        day=traffic.domain_report(self.path,BASE-8*3600,BASE+16*3600,"day",traffic.timezone("+08:00"),BASE+16*3600)
        self.assertEqual(day["totals"]["total_bytes"],30)
        self.assertEqual(day["buckets"][0]["total_bytes"],30)

    def test_retention_and_domain_health(self):
        self.sample_domain(0,0,0,[])
        self.sample_domain(2,10,20,[self.conn(up=10,down=20)])
        self.assertTrue(traffic.healthy(self.path,10,BASE+10,True))
        self.sample(20,20,40)
        self.assertFalse(traffic.healthy(self.path,10,BASE+20,True))
        self.assertTrue(traffic.healthy(self.path,10,BASE+20))
        self.store.prune(BASE+100*86400)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domain_buckets").fetchone()[0],0)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domain_sampling").fetchone()[0],0)

    def test_v1_upgrade_preserves_total_data_and_query_does_not_migrate(self):
        self.sample(0,0,0);self.sample(60,10,20)
        self.store.close()
        db=sqlite3.connect(self.path)
        for table in ("domain_buckets","domain_sampling","domain_cursor","domain_state"):
            db.execute("DROP TABLE "+table)
        db.execute("PRAGMA user_version=1");db.commit();db.close()
        self.assertIsNone(self.domains()["tracking_started"])
        self.store=traffic.Store(self.path)
        self.assertEqual(self.query()["totals"]["total_bytes"],30)
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0],2)


class DomainAPITests(unittest.TestCase):
    def payload(self):
        return {"uploadTotal":10,"downloadTotal":20,"connections":[{"id":"synthetic-id","start":"2026-09-01T00:00:01Z","upload":10,"download":20,"metadata":{"host":"EXAMPLE.COM.","sourceIP":"192.0.2.99","process":"private-process","inboundUser":"synthetic-user"}}]}

    def test_domain_canonicalization_and_minimal_checkpoint(self):
        result=traffic.connection_samples(self.payload())
        self.assertEqual(result[0][1:4],("example.com",10,20))
        for private in ("192.0.2.99","private-process","synthetic-user","synthetic-id"):
            self.assertNotIn(private,json.dumps(result))
        self.assertEqual(traffic.domain_name("bücher.example"),"xn--bcher-kva.example")
        for invalid in ("https://example.com/path","user@example.com","example.com:443","x\n.example", "-bad.example"):
            self.assertEqual(traffic.domain_name(invalid),traffic.UNKNOWN_DOMAIN)
        self.assertEqual(traffic.domain_name("192.0.2.1"),traffic.IP_ONLY)

    def test_ip_and_sniffed_domain_no_address_persistence(self):
        p=self.payload();p["connections"][0]["metadata"]={"host":"192.0.2.1","sniffHost":"actual.example"}
        self.assertEqual(traffic.connection_samples(p)[0][1],"actual.example")
        p["connections"][0]["metadata"]={"destinationIP":"192.0.2.1"}
        self.assertEqual(traffic.connection_samples(p)[0][1],traffic.IP_ONLY)
        p["connections"][0]["metadata"]={}
        self.assertEqual(traffic.connection_samples(p)[0][1],traffic.UNKNOWN_DOMAIN)

    def test_connections_http_and_null_list(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.seen=(self.path,self.headers.get("Authorization"))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps(self.server.payload).encode())
            def log_message(self,*_): pass
        with http.server.HTTPServer(("127.0.0.1",0),Handler) as server:
            server.payload=self.payload()
            thread=threading.Thread(target=server.handle_request);thread.start()
            try:
                up,down,items=traffic.fetch_connections(f"http://127.0.0.1:{server.server_port}","synthetic")
                self.assertEqual((up,down),(10,20));self.assertEqual(items[0][1],"example.com")
                self.assertEqual(server.seen,("/connections","Bearer synthetic"))
            finally: thread.join(timeout=5)
        p=self.payload();p["connections"]=None
        self.assertEqual(traffic.connection_samples(p),[])

    def test_reject_duplicate_malformed_and_oversized_snapshot(self):
        p=self.payload();p["connections"]*=2
        with self.assertRaises(ValueError): traffic.connection_samples(p)
        for bad in (True,-1,2**63):
            p=self.payload();p["connections"][0]["upload"]=bad
            with self.assertRaises(ValueError): traffic.connection_samples(p)
        p=self.payload();p["connections"][0]["start"]="2026-09-01T00:00:00"
        with self.assertRaises(ValueError):traffic.connection_samples(p)
        response=mock.MagicMock();response.status=200;response.read.return_value=b'x'*(traffic.MAX_SNAPSHOT+1)
        connection=mock.MagicMock();connection.getresponse.return_value=response
        with mock.patch.object(traffic.http.client,"HTTPConnection",return_value=connection):
            with self.assertRaises(ValueError):traffic.fetch_connections("http://127.0.0.1")
        connection.close.assert_called_once()

    def test_cli_domains_and_failure_fallback_keep_total(self):
        with tempfile.TemporaryDirectory() as temp:
            path=pathlib.Path(temp)/"usage.sqlite3"
            with mock.patch.object(traffic,"fetch_connections",side_effect=ValueError),mock.patch.object(traffic,"fetch",return_value=(10,20)),contextlib.redirect_stderr(io.StringIO()),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(traffic.main(["collect","--db",str(path),"--domains","--once"]),1)
            self.assertTrue(traffic.healthy(path,180,int(dt.datetime.now(UTC).timestamp())))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(traffic.main(["query","--db",str(path),"--from","2026-09-01","--to","2026-09-02","--group-by","domain","--json"]),0)
            self.assertEqual(json.loads(output.getvalue())["scope"],"gateway-domains")

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
