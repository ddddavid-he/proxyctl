#!/usr/bin/env python3
"""Local Mihomo usage collector and SQLite reports (Python standard library)."""
from __future__ import annotations

import argparse
import calendar
import contextlib
import datetime as dt
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import threading
import time
import urllib.parse

BUCKET = 900
MAX_COUNTER = 2**63 - 1


def cutoff(now: int) -> int:
    """Three calendar months, clamped for shorter months; keep boundary bucket."""
    value = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    month_index = value.year * 12 + value.month - 1 - 3
    year, month = divmod(month_index, 12)
    month += 1
    value = value.replace(year=year, month=month,
                          day=min(value.day, calendar.monthrange(year, month)[1]))
    return int(value.timestamp()) // BUCKET * BUCKET


def counter(value) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise ValueError("invalid cumulative counter")
    return value


class Store:
    def __init__(self, path: Path):
        if not path.parent.is_dir() or path.is_symlink():
            raise ValueError("database needs a private existing directory and a regular path")
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_size_limit=1048576")
        self.db.execute("PRAGMA wal_autocheckpoint=128")
        self.db.execute("PRAGMA cache_size=-2048")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            raise ValueError("unsupported traffic database version")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS buckets (
          start INTEGER PRIMARY KEY, upload INTEGER NOT NULL, download INTEGER NOT NULL,
          observed_seconds INTEGER NOT NULL, estimated_seconds INTEGER NOT NULL,
          resets INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cursor (
          id INTEGER PRIMARY KEY CHECK(id=1), at INTEGER NOT NULL,
          upload INTEGER NOT NULL, download INTEGER NOT NULL, epoch TEXT NOT NULL,
          source TEXT NOT NULL
        );
        PRAGMA user_version=1;
        """)

    def close(self):
        self.db.close()

    def record(self, at: int, upload: int, download: int, epoch: str,
               source: str, interval: int = 60) -> str:
        upload, download = counter(upload), counter(download)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute("SELECT at,upload,download,epoch,source FROM cursor WHERE id=1").fetchone()
            status = "baseline"
            if previous:
                old_at, old_up, old_down, old_epoch, old_source = previous
                if old_source != source:
                    raise ValueError("source changed; use a separate database")
                if at <= old_at:
                    self.db.execute("ROLLBACK")
                    return "clock_not_advanced"
                reset = epoch != old_epoch or upload < old_up or download < old_down
                up = upload if reset else upload - old_up
                down = download if reset else download - old_down
                duration = at - old_at
                estimated = reset or duration > interval * 2
                status = "reset" if reset else "gap" if estimated else "ok"
                # Allocate by overlap. Cumulative integer division preserves exact totals.
                begin = max(old_at, cutoff(at))
                position = begin
                while position < at:
                    start = position // BUCKET * BUCKET
                    end = min(at, start + BUCKET)
                    left, right = position - old_at, end - old_at
                    u = up * right // duration - up * left // duration
                    d = down * right // duration - down * left // duration
                    seconds = end - position
                    self.db.execute("""
                    INSERT INTO buckets VALUES (?,?,?,?,?,?)
                    ON CONFLICT(start) DO UPDATE SET
                      upload=upload+excluded.upload, download=download+excluded.download,
                      observed_seconds=observed_seconds+excluded.observed_seconds,
                      estimated_seconds=estimated_seconds+excluded.estimated_seconds,
                      resets=resets+excluded.resets
                    """, (start, u, d, 0 if estimated else seconds,
                          seconds if estimated else 0, int(reset and position == begin)))
                    position = end
            self.db.execute("INSERT OR REPLACE INTO cursor VALUES (1,?,?,?,?,?)",
                            (at, upload, download, epoch, source))
            self.db.execute("DELETE FROM buckets WHERE start < ?", (cutoff(at),))
            self.db.execute("COMMIT")
            return status
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def prune(self, now: int):
        self.db.execute("DELETE FROM buckets WHERE start < ?", (cutoff(now),))


def controller(value: str):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme != "http" or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("controller must be a loopback HTTP origin")
    if not parts.hostname or not ipaddress.ip_address(parts.hostname).is_loopback:
        raise ValueError("controller must use a loopback IP literal")
    return parts.hostname, parts.port or 80


def fetch(origin: str, secret: str = "") -> tuple[int, int]:
    host, port = controller(origin)
    # Direct connection: no environment proxy, redirects, or connection metadata.
    connection = http.client.HTTPConnection(host, port, timeout=4)
    try:
        headers = {"Authorization": "Bearer " + secret} if secret else {}
        connection.request("GET", "/traffic", headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("controller rejected traffic request")
        line = response.readline(4097)
        if len(line) > 4096 or not line.endswith(b"\n"):
            raise ValueError("invalid traffic response")
        payload = json.loads(line)
        return counter(payload["upTotal"]), counter(payload["downTotal"])
    finally:
        connection.close()


def process_epoch(pid: int | None, name: str | None, epoch_file: Path | None = None) -> str:
    if epoch_file:
        with epoch_file.open() as handle:
            value = handle.read(129).strip()
        if not value or len(value) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("invalid source epoch")
        return "file:" + value
    if pid is None and name is None:
        return "counter-only"
    if name:
        matches = []
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    if (entry / "comm").read_text().strip() == name:
                        matches.append(int(entry.name))
                except (OSError, UnicodeError):
                    continue
        if len(matches) != 1:
            raise ValueError("expected exactly one source process")
        pid = matches[0]
    stat = Path(f"/proc/{pid}/stat").read_text()
    # comm may contain spaces or parentheses; starttime is field 22.
    fields = stat[stat.rfind(")") + 2:].split()
    if fields[0] == "Z":
        raise ValueError("source process exited")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return f"{boot}:{pid}:{fields[19]}"


@contextlib.contextmanager
def collector_lock(path: Path):
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("a collector already owns this database") from None
        yield
    finally:
        os.close(fd)


def collect(args):
    controller(args.controller)
    source = args.controller.rstrip("/")
    secret = ""
    if args.secret_file:
        secret = args.secret_file.read_text().strip()
        if not secret or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise ValueError("invalid controller credential")
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    with collector_lock(args.db):
        store = Store(args.db)
        try:
            failed = False
            while not stopped.is_set():
                started = time.monotonic()
                try:
                    before = process_epoch(args.pid, args.process_name, args.epoch_file)
                    up, down = fetch(args.controller, secret)
                    after = process_epoch(args.pid, args.process_name, args.epoch_file)
                    if before != after:
                        raise ValueError("source restarted during sampling")
                    failed = False
                    status = store.record(int(time.time()), up, down, after, source, args.interval)
                    if status != "ok":
                        print(json.dumps({"event": status}), flush=True)
                except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
                    # Never log response bodies, credential contents or request headers.
                    failed = True
                    print('{"event":"sample_failed"}', file=sys.stderr, flush=True)
                store.prune(int(time.time()))  # retention also runs during API outages
                if args.once:
                    break
                stopped.wait(max(0, args.interval - (time.monotonic() - started)))
        finally:
            store.close()
        if args.once and failed:
            raise ValueError("sample failed")


def timezone(value: str) -> dt.timezone:
    import re
    if not re.fullmatch(r"[+-]\d\d:\d\d", value):
        raise ValueError("offset must be +HH:MM or -HH:MM")
    hours, minutes = map(int, value[1:].split(":"))
    if hours > 14 or minutes not in (0, 15, 30, 45) or (hours == 14 and minutes):
        raise ValueError("offset must be within 14 hours and aligned to 15 minutes")
    return dt.timezone(dt.timedelta(minutes=(hours * 60 + minutes) * (1 if value[0] == "+" else -1)))


def timestamp(value: str, zone: dt.timezone) -> int:
    parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return int(parsed.timestamp())


def report(path: Path, start: int, end: int, granularity: str, zone: dt.timezone, now: int):
    width = {"15m": 900, "hour": 3600, "day": 86400}[granularity]
    offset = int(zone.utcoffset(None).total_seconds())
    if end <= start or end - start > 96 * 86400:
        raise ValueError("query range must be positive and at most 96 days")
    if (start + offset) % width or (end + offset) % width:
        raise ValueError("query endpoints must align to the requested granularity")
    if path.is_symlink():
        raise ValueError("database must not be a symlink")
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        db.execute("BEGIN")
        cursor = db.execute("SELECT at,source FROM cursor WHERE id=1").fetchone()
        records = db.execute("""SELECT start,upload,download,observed_seconds,estimated_seconds,resets
            FROM buckets WHERE start>=? AND start<? ORDER BY start""",
                             (max(start, cutoff(now)), min(end, now))).fetchall()
    finally:
        db.close()
    aggregated = {}
    for at, up, down, observed, estimated, resets in records:
        group = (at + offset) // width * width - offset
        item = aggregated.setdefault(group, [0] * 5)
        for i, number in enumerate((up, down, observed, estimated, resets)):
            item[i] += number
    rows = []
    for at in range(start, end, width):
        up, down, observed, estimated, resets = aggregated.get(at, [0] * 5)
        rows.append({"start": dt.datetime.fromtimestamp(at, zone).isoformat(),
                     "upload_bytes": up, "download_bytes": down, "total_bytes": up + down,
                     "observed_seconds": observed, "estimated_seconds": estimated,
                     "missing_seconds": max(0, width - observed - estimated), "resets": resets,
                     "coverage": "missing" if observed + estimated == 0 else
                     "estimated" if estimated else "complete" if observed == width else "partial"})
    return {"scope": "gateway-total", "unit": "bytes", "granularity": granularity,
            "last_sample": dt.datetime.fromtimestamp(cursor[0], dt.timezone.utc).isoformat() if cursor else None,
            "sample_age_seconds": max(0, now - cursor[0]) if cursor else None,
            "retained_since": dt.datetime.fromtimestamp(cutoff(now), dt.timezone.utc).isoformat(),
            "totals": {key: sum(row[key] for row in rows) for key in ("upload_bytes", "download_bytes", "total_bytes")},
            "buckets": rows}


def healthy(path: Path, max_age: int, now: int) -> bool:
    if path.is_symlink():
        raise ValueError("database must not be a symlink")
    with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        row = db.execute("SELECT at FROM cursor WHERE id=1").fetchone()
    return bool(row and 0 <= now - row[0] <= max_age)


def main(argv=None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("collect")
    ingest.add_argument("--db", type=Path, required=True)
    ingest.add_argument("--controller", default="http://127.0.0.1:9090")
    ingest.add_argument("--secret-file", type=Path)
    ingest.add_argument("--interval", type=int, default=60)
    ingest.add_argument("--once", action="store_true")
    identity = ingest.add_mutually_exclusive_group()
    identity.add_argument("--pid", type=int)
    identity.add_argument("--process-name")
    identity.add_argument("--epoch-file", type=Path)
    query = commands.add_parser("query")
    query.add_argument("--db", type=Path, required=True)
    query.add_argument("--from", dest="start", required=True)
    query.add_argument("--to", dest="end", required=True)
    query.add_argument("--granularity", choices=("15m", "hour", "day"), default="15m")
    query.add_argument("--utc-offset", default="+08:00")
    query.add_argument("--json", action="store_true")
    health = commands.add_parser("health")
    health.add_argument("--db", type=Path, required=True)
    health.add_argument("--max-age", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            if not 10 <= args.interval <= 300 or (args.pid is not None and args.pid <= 0):
                raise ValueError("interval must be 10..300 seconds and PID must be positive")
            collect(args)
        elif args.command == "health":
            if args.max_age <= 0:
                raise ValueError("max age must be positive")
            return 0 if healthy(args.db, args.max_age, int(time.time())) else 1
        else:
            zone = timezone(args.utc_offset)
            result = report(args.db, timestamp(args.start, zone), timestamp(args.end, zone),
                            args.granularity, zone, int(time.time()))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"gateway-total; last sample: {result['last_sample']}; age: {result['sample_age_seconds']}s")
                print("start                     upload MiB download MiB total MiB coverage missing(s)")
                for row in result["buckets"]:
                    print(f"{row['start']} {row['upload_bytes']/2**20:10.2f} {row['download_bytes']/2**20:12.2f} "
                          f"{row['total_bytes']/2**20:9.2f} {row['coverage']:9} {row['missing_seconds']}")
                print(f"total bytes: {result['totals']['total_bytes']}")
        return 0
    except (OSError, ValueError, sqlite3.Error, OverflowError):
        print('{"error":"traffic operation failed; check arguments, database and service state"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
