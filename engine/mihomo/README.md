# proxyctl Mihomo extension

Base: MetaCubeX/mihomo v1.19.30, commit
`ac017cdd246ce8bd547653d927e7bf77d7ee73d5`.
The patch and overlay are GPL-3.0-or-later; the separate proxyctl control CLI
retains its MIT license. Build with `python3 engine/mihomo/build.py --help`.

Every gateway TCP/UDP tracker byte increment contributes to a hostname and
15-minute bucket, including initial buffered bytes and optimized copy paths.
Nested trackers are excluded using the upstream `pushToManager` flag.
No connection sampling, destination paths, client IDs, or raw IPs are persisted.

`PROXYCTL_ACCOUNTING_DIR` enables a private shared spool. Every two seconds the
engine writes an immutable JSON batch, fsyncs it, renames it, and fsyncs the
directory. SQLite imports and acknowledges batches transactionally, so collector
restarts do not lose or double count batches. A stalled collector accumulates
batches. A full spool or disk failure stops the engine visibly. More than 10,000
active domain/bucket keys per batch aggregate into `[domain-limit]`.

Payload counts follow the pinned upstream's byte semantics, not NIC billing.
An abrupt process/host failure can lose the unflushed interval (normally up to
2 seconds, longer if disk I/O stalls). Every subsequent process start carries a
conservative possible-tail-loss marker, including graceful restarts because
relay goroutines can race shutdown. No numeric loss estimate is invented.
