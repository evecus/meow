# Benchmark methodology

See [ADR-0006](../adr/0006-m2-benchmark-methodology.md) for the canonical protocol.
This file records the hardware spec for the M2 reference baseline.

## Reference hardware

> **TODO (engineer-b / team-lead):** fill in the fields below from the actual
> reference bench host before M2 exit tagging. The initial baseline in this
> directory was captured on a developer machine; it does **not** count toward
> the M2 exit criteria.

| Field | Value |
|-------|-------|
| CPU | _(e.g. Apple M3 Pro, 12-core)_ |
| RAM | _(e.g. 36 GB)_ |
| OS / kernel | _(e.g. macOS 15.4, Darwin 24.4.0)_ |
| CPU governor | macOS: charger plugged, Low Power Mode off |
| Rust toolchain | _(output of `rustup show active-toolchain`)_ |
| Go mihomo version | _(output of `./target/bench/mihomo-go -v`)_ |
| Run date | _(YYYY-MM-DD)_ |

## Developer baseline (2026-04-18)

Machine: Apple Silicon (arm64), macOS 25.4.0 (Darwin 25.4.0), developer laptop.
**Not the M2 reference host.** Recorded here to verify the harness runs end-to-end.

Go mihomo: not measured (no binary available on this machine).

```
Binary size : 11.0 MB (stripped, release LTO)
RSS idle    :  9.3 MB
RSS load    : 11.7 MB (peak during conn-rate test)
Throughput  :  7.02 Gbps (64 MB single transfer, loopback)
Latency p50 :  296 µs    (connect + 1 B echo, 500 iters)
Latency p99 :  488 µs
Conn rate   :  762 conns/s (10 s, concurrency=32)
```

Full JSON: `baseline-2026-04-18.json`

## Workloads (from ADR-0006 §1)

| # | Workload | Tool | Steady-state |
|---|----------|------|--------------|
| W1 | Bulk throughput | `bench_throughput` | 60 s |
| W2 | Round-trip latency | `bench_latency` | 1000 iters |
| W3 | Connection rate | `bench_connrate` | 30 s, concurrency=64 |
| W4 | DNS QPS | `bench_dns` *(pending M2.B-2)* | 60 s |
| W5 | Rule-match throughput | `cargo bench` (criterion) | criterion default |

W4 and W5 land with Task #36 (M2.B-2).

## Statistical protocol (from ADR-0006 §4)

Three runs per metric; report median and IQR. Reject any run where
IQR / median > 0.10 and re-run.

## M2 exit thresholds (from ADR-0006 §5)

| Metric | Threshold |
|--------|-----------|
| W1 throughput (64 MB, Gbps) | ≥ 1.10× Go |
| W2 latency p99 | ≤ 1.05× Go |
| W2 latency p50 | ≤ Go |
| W3 connection rate | ≥ Go |
| W3 peak RSS under load | ≤ 0.80× Go |
| W4 DNS QPS | ≥ 1.10× Go |
| W4 DNS p99 latency | ≤ Go |
| Binary size (stripped, x86_64-musl) | ≤ Go |
| W5 rule match/sec (10k rules) | ≥ 20M absolute |
| W5 allocations per match | 0 heap allocs |
