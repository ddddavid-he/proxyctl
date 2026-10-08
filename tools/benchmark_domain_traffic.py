#!/usr/bin/env python3
"""Synthetic domain-mode SQLite benchmark; does not contact a proxy."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import resource
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("domain_benchmark", ROOT / "deploy/traffic/traffic.py")
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


def main():
    with tempfile.TemporaryDirectory(prefix="proxy-domain-benchmark-") as temporary:
        path = Path(temporary) / "usage.sqlite3"
        store = traffic.Store(path)
        begin = int(dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc).timestamp())
        # One simulated hour: 100 active connections, 50 DNS names, 2-second polls.
        count = 1800
        store.record(begin, 0, 0, "synthetic", "benchmark", 2, [])
        wall, cpu = time.perf_counter(), time.process_time()
        for sample in range(1, count + 1):
            connections = [(str(index), f"site{index % 50}.example", sample*100,
                            sample*1000, begin+1) for index in range(100)]
            store.record(begin+sample*2, sample*10000, sample*100000,
                         "synthetic", "benchmark", 2, connections)
        wall, cpu = time.perf_counter()-wall, time.process_time()-cpu
        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        store.close()
        began = time.perf_counter()
        result = traffic.domain_report(path, begin, begin+3600, "hour", dt.timezone.utc, begin+3600)
        query_ms = (time.perf_counter()-began)*1000
        if result["totals"]["total_bytes"] != count*110000 or result["unattributed_bytes"]:
            raise RuntimeError("domain benchmark conservation failed")
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(json.dumps({"python": sys.version.split()[0], "platform": sys.platform,
                          "simulated_hours": 1, "active_connections": 100, "domains": 50,
                          "samples": count, "ingest_wall_seconds": round(wall, 3),
                          "ingest_cpu_seconds": round(cpu, 3),
                          "average_commit_ms": round(wall/count*1000, 3),
                          "query_ms": round(query_ms, 3), "database_bytes": path.stat().st_size,
                          "peak_process_rss_bytes": rss if sys.platform == "darwin" else rss*1024,
                          "verified_bytes": result["totals"]["total_bytes"]}, indent=2))


if __name__ == "__main__":
    main()
