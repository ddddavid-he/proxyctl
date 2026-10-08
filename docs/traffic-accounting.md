# Aggregate traffic accounting

The optional collector measures **all traffic handled by one Mihomo gateway**.
It reports upload, download and their sum at 15-minute, hour and day resolution.
SQLite stores 15-minute buckets and a single restart-safe cumulative cursor;
there is no database server or third-party Python dependency. No user identities,
connection details, destination addresses or request bodies are stored.

## Accounting contract

- Poll every 60 seconds. Upload means client-to-destination; download is the
  reverse. Store integer bytes; the terminal displays MiB (1,048,576 bytes).
- The source is the pinned Mihomo v1.19.30 HTTP `/traffic` stream. Read its first
  line's `upTotal` and `downTotal`, then close the connection. These are cumulative
  counters, including completed connections. The `up`/`down` rate fields are
  deliberately ignored. See upstream [HTTP implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/hub/route/server.go)
  and [counter implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/tunnel/statistic/manager.go).
- Count once at the gateway, including the repository's Trojan, HTTPS CONNECT,
  Hysteria-to-SOCKS and IKEv2-to-TProxy paths. Also counts local probes and other
  traffic using this Mihomo. Traffic bypassing it is outside this scope.
- These are proxy payload counters, **not cloud-provider billed interface
  bytes**: encryption, packet headers, retransmission and non-proxy host traffic
  are outside the measurement. There are no prices, quotas or automatic charges.
- First installation establishes a baseline without billing historical counters.
  Each later sample updates both buckets and cursor in one SQLite transaction.
  Restarting the collector therefore preserves its baseline and avoids duplicates.
- Compose publishes a new source epoch before each Mihomo launch, and systemd
  identifies Mihomo by boot ID, PID and process start time. These detect even a
  restart whose new counters exceed the previous sample. A counter decrease also
  detects API counter resets. A change during a request causes that sample to be
  skipped. Manual collection without an epoch flag detects only counter decreases;
  it may miss a restart with higher new counters. Use exactly one identity mode
  and controller per database; changing the controller requires a new database.
- On a detected source restart/reset, count current counters from zero. Traffic
  between the previous sample and the old process's exit cannot be recovered.
  A reset interval is marked estimated. Normal abrupt-restart loss is up to about
  one sampling interval; an extended collector outage makes that bound longer.
- Distribute deltas proportionally over overlapping buckets, conserving integer
  totals. Normally boundary-time attribution can be off by one sampling interval.
  If an API outage exceeds two intervals, recover the delta on reconnection when
  the same counters survive, but mark its distribution estimated. Unknown traffic
  from terminated processes cannot be reconstructed.
- `observed_seconds` means a normally sampled interval, not an exact billable
  measurement. `estimated_seconds` marks recovered gaps/resets; `missing_seconds`
  includes periods without a baseline, unobserved trailing time and future time
  in a currently open bucket. Coverage is `complete`, `partial`, `estimated` or
  `missing`. A missing bucket's zero bytes are not evidence of zero consumption.
  JSON also exposes `last_sample`, its age and reset counts. Check sample freshness
  before using reports; failed reads leave the cursor unchanged.
- Retain **three calendar months** in UTC, clamping short months. Delete old
  buckets on every collector cycle, including API outages. Keep the boundary
  15-minute bucket (at most 15 minutes extra); reports apply the same retention
  cutoff even if the collector stopped. This is logical retention; SQLite may
  reuse freed pages rather than reduce its file size. The cursor remains as a
  single checkpoint, and is not a raw sample history.
- Persist buckets in UTC. Report boundaries default to a fixed `+08:00` offset;
  select another offset with `--utc-offset`. No daylight-saving zone conversion
  is implied. Query endpoints must align to the selected granularity; ranges are
  half-open `[from,to)` and limited to 96 days.

## Compose

The gateway release contains the collector and documentation. Python's standard
`sqlite3` module is required in the runtime image (the existing Debian `python3`
package supplies it). Enable the optional service explicitly:

```sh
docker compose --env-file /etc/private-proxy/stack/runtime.env \
  -f /opt/private-proxy/current/compose/compose.yaml --profile traffic up -d traffic
```

Provision the host data directory before enabling collection:

```sh
install -d -m 0700 -o 10001 -g 10001 /opt/docker/private-proxy/data/traffic
```

If an existing database already has data, back it up and migrate its files with
SQLite's backup API before changing mount paths or ownership. Do not silently
start with an empty database. Inside the container the directory is `/var/lib/private-proxy-traffic`; it maps
to `/opt/docker/private-proxy/data/traffic` in the example deployment.
`usage.sqlite3`, `-wal` and `-shm` all live in the
same mapped directory. Files are mode 0600; the directory is 0700.

The existing `controller-listen` setting must match the collector's loopback
origin. The default is `http://127.0.0.1:9090`; override it in `runtime.env` with
`PRIVATE_PROXY_TRAFFIC_CONTROLLER` when using a different port. The collector
never follows redirects or uses HTTP proxy environment variables, and rejects
public addresses and hostnames. It introduces no HTTP listener. The repository's
controller is already restricted to loopback; do not expose it publicly.

Compose runs the collector as UID/GID 10001 and bind-mounts
`PRIVATE_PROXY_TRAFFIC_DATA_DIR` (default `./data/traffic`, relative to the Compose project) read/write for the database and mounts the shared
source epoch tmpfs volume read-only in the collector. Database/lock/WAL files use a
private umask. Its root filesystem remains read-only and it has no Linux
capabilities. The collector has a 64 MiB memory ceiling and a 25% CPU ceiling.
Its Docker healthcheck requires a successful sample within the last 180 seconds,
with a 5-second initial probe interval (Docker Engine 25+).
The proxy does not depend on this service, so a failed or full database does not
stop proxy traffic. Inspect collector logs and report freshness to detect failure.

The bind-mounted data directory survives container replacement and Compose
shutdown independently of the source epoch tmpfs volume. Use the same Compose
project name across release upgrades. Both new Compose assets and the new Mihomo
launcher are needed for the epoch marker; an older running Mihomo container must
be recreated during an authorized rollout. Proxy activation is separate from
local source changes.

Query in the running collector, for example:

```sh
docker compose --env-file /etc/private-proxy/stack/runtime.env \
  -f /opt/private-proxy/current/compose/compose.yaml --profile traffic exec traffic \
  python3 /app/deploy/traffic/traffic.py query \
  --db /var/lib/private-proxy-traffic/usage.sqlite3 \
  --from 2026-10-01 --to 2026-10-02 --granularity hour --json
```

Use `--granularity 15m`, `hour` or `day`; omit `--json` for a terminal table.
SQLite queries open the existing database read-only and take a consistent
snapshot while the collector writes.

## systemd or manual collection

The release also includes `private-proxy-traffic.service`. It uses the existing
`privateproxy` account and a separate persistent, mode-0700 `StateDirectory`,
with the same CPU/memory limits. Install the unit through your normal reviewed
rollout and enable it after checking the controller address. Its default
`--process-name mihomo` requires exactly one visible Mihomo process. For multiple
instances, select the corresponding source PID and use separate databases.
Changing a systemd instance's PID requires updating that selector; prefer the
process-name selector for the repository's single-instance layout.

For a manual collector, create a private data directory owned by the collector
account, then run:

```sh
python3 deploy/traffic/traffic.py collect --db /var/lib/private-proxy-traffic/usage.sqlite3 \
  --controller http://127.0.0.1:9090 --process-name mihomo
```

`health --db PATH [--max-age 180]` checks the persisted cursor without creating
a database. `--once` performs one sample and returns nonzero on failure. `--interval` supports
10–300 seconds. `--pid` and `--epoch-file` are alternate process identity sources.
If a separately configured controller requires a token, supply `--secret-file`
with an existing protected credential file, such as a systemd `LoadCredential`
path or a read-only Compose mount. Never put tokens in command arguments, URLs,
images or repository configuration. Errors log fixed event names without headers,
response bodies or credential contents.

One collector holds an exclusive lock per database. A full or unwritable disk
fails writes; the last committed cursor and buckets remain intact. Do not delete
or replace the database/lock path while collecting. For a live backup use
SQLite's backup API, or stop collection before copying; copying only the database
while WAL is active can lose committed samples. Historical totals are useful for
usage budgeting, not strict invoicing or payment settlement.

## Capacity and validation

A local macOS benchmark (Python 3.9.6, SQLite 3.54.0) produced 8,640 buckets
from 129,600 minute-sample commits. The database was **228 KiB**, the observed WAL
519 KiB and shared-memory file 32 KiB; peak Python process RSS was **19.2 MiB**.
Ingest took 9.87 seconds wall / 3.925 seconds CPU (0.076 ms per commit); a
90-day daily report took 7.8 ms. These are synthetic local measurements,
excluding a production collector's HTTP connection and container overhead.

Allow **5–10 MiB disk and 32–64 MiB RAM** for one gateway. Normal minute-level
collection should use well below 0.1% of one CPU core, but that is a planning
estimate requiring target-host measurement. The configured 64 MiB / 25% CPU
limits are ceilings, not expected consumption. Each cycle opens one small
loopback HTTP stream for about one second and commits once; WAL page writes
can be roughly 12–24 MiB/day before filesystem write amplification, even though
the retained database is tiny. The source epoch tmpfs is capped at 1 MiB
and normally holds one tiny marker. No source-rate/connection-count scaling
is needed for this total-only collector.

A single gateway produces 96 buckets/day: about 8,640 over 90 days, and up to
about 8,833 including the retention boundary bucket. Hour/day summaries reuse these rows rather
than multiplying storage. Memory and processing cost scale with the number of
buckets, not users, connections or transferred gigabytes. Queries use at most
9,216 output rows for their 96-day bound.

Run the reproducible synthetic capacity benchmark:

```sh
python3 tools/benchmark_traffic.py
python3 -m unittest discover -s tests -p 'test_traffic.py'
```

The benchmark performs 129,600 real SQLite minute-sample transactions for 90
simulated days, checks their byte totals, measures peak process RSS and a daily
report, and removes the temporary database. It does not connect to a proxy.
The tests cover counters, cross-bucket rounding, local day boundaries, source and
collector restarts, gaps, transaction rollback, retention, read-only reports,
writer exclusion and a local HTTP source. Linux/container resource usage and
production end-to-end acceptance still need to be measured on the target host.

## Adding accounting to an existing release

`deploy/traffic/compose.override.yaml` supplies a separate accounting release
mount, an updated Mihomo launcher mount and the accounting service. It preserves
the existing proxy engine release and its credentials. Stage `traffic.py` and
`deploy/compose/run_mihomo.py` as `run_mihomo.py` in a versioned accounting
release directory; set `PRIVATE_PROXY_TRAFFIC_RELEASE_DIR` to it and set the
controller origin to the actual gateway port. Merge the overlay with the
existing Compose file for all subsequent operations. Recreate only Mihomo to
activate its source epoch, then start `traffic`. Recreating Mihomo interrupts
its existing connections; it does not require replacing the proxy engines,
certificates or passwords. Check health of the unchanged ingress/policy services.
An overlay deployment uses `/accounting/traffic.py` for queries and health,
rather than the complete-release `/app/deploy/traffic/traffic.py` path.

Rollback stops/removes only the accounting service, restores the saved Compose
configuration and recreates Mihomo using the original launcher. Preserve the
host data directory; it remains independent of all release versions.
