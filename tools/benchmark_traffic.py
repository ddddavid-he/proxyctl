#!/usr/bin/env python3
"""Synthetic 90-day SQLite capacity/CPU benchmark; never accesses the proxy."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import resource
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("traffic_benchmark", ROOT / "deploy/traffic/traffic.py")
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


def main():
    with tempfile.TemporaryDirectory(prefix="proxy-traffic-benchmark-") as temporary:
        path = Path(temporary) / "usage.sqlite3"
        store = traffic.Store(path)
        begin = int(dt.datetime(2026, 7, 4, tzinfo=dt.timezone.utc).timestamp())
        samples = 90 * 24 * 60
        store.record(begin, 0, 0, "synthetic", "benchmark")
        wall = time.perf_counter()
        cpu = time.process_time()
        for index in range(1, samples + 1):
            store.record(begin + index * 60, index * 2**20, index * 4 * 2**20, "synthetic", "benchmark")
        wall = time.perf_counter() - wall
        cpu = time.process_time() - cpu
        rows = store.db.execute("SELECT count(*) FROM buckets").fetchone()[0]
        sizes = {file.name: file.stat().st_size for file in path.parent.iterdir()}
        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        store.close()
        query_start = time.perf_counter()
        report = traffic.report(path, begin, begin + 90 * 86400, "day", dt.timezone.utc, begin + 90 * 86400)
        query_ms = (time.perf_counter() - query_start) * 1000
        expected = samples * 5 * 2**20
        if report["totals"]["total_bytes"] != expected:
            raise RuntimeError("benchmark total mismatch")
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_bytes = rss if sys.platform == "darwin" else rss * 1024
        print(json.dumps({"python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version,
                          "platform": sys.platform, "simulated_days": 90, "minute_samples": samples,
                          "bucket_rows": rows, "files_before_checkpoint_bytes": sizes,
                          "database_bytes": path.stat().st_size, "peak_process_rss_bytes": rss_bytes,
                          "ingest_wall_seconds": round(wall, 3), "ingest_cpu_seconds": round(cpu, 3),
                          "average_commit_ms": round(wall * 1000 / samples, 3),
                          "daily_query_ms": round(query_ms, 3), "total_bytes_verified": expected}, indent=2))


if __name__ == "__main__":
    main()
