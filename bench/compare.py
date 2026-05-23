#!/usr/bin/env python3
"""
Compare a new benchmark run against a baseline and flag regressions.

Usage:
    python3 bench/compare.py <baseline.json> <current.json> [--threshold 0.05]

Exit codes:
    0  no regressions beyond threshold
    1  one or more metrics regressed beyond threshold
"""

import json
import sys
import argparse


METRICS = [
    # (path_in_rust_obj, label, higher_is_better)
    ("conn_rate.connections_per_sec", "conn_rate (conns/s)", True),
    ("latency.p50_us",                "latency p50 (µs)",    False),
    ("latency.p99_us",                "latency p99 (µs)",    False),
    ("rss_idle_bytes",                "RSS idle (bytes)",     False),
    ("rss_load_bytes",                "RSS load (bytes)",     False),
]

THROUGHPUT_LABEL = "64 MB x 1"


def get_nested(obj, path):
    for key in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def get_throughput(rust_obj, label):
    for t in rust_obj.get("throughput", []):
        if t.get("label", "").startswith(label):
            return t.get("gbps")
    return None


def compare(baseline_path, current_path, threshold):
    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(current_path) as f:
        current = json.load(f)

    base_rust = baseline.get("rust", {})
    curr_rust = current.get("rust", {})

    regressions = []
    rows = []

    for path, label, higher_is_better in METRICS:
        base_val = get_nested(base_rust, path)
        curr_val = get_nested(curr_rust, path)
        if base_val is None or curr_val is None or base_val == 0:
            continue

        delta = (curr_val - base_val) / abs(base_val)
        regressed = (delta < -threshold) if higher_is_better else (delta > threshold)
        flag = "REGRESSED" if regressed else "ok"
        rows.append((label, base_val, curr_val, delta * 100, flag))
        if regressed:
            regressions.append(label)

    # Throughput
    base_tp = get_throughput(base_rust, THROUGHPUT_LABEL)
    curr_tp = get_throughput(curr_rust, THROUGHPUT_LABEL)
    if base_tp and curr_tp and base_tp != 0:
        delta = (curr_tp - base_tp) / abs(base_tp)
        regressed = delta < -threshold
        flag = "REGRESSED" if regressed else "ok"
        rows.append((f"throughput {THROUGHPUT_LABEL} (Gbps)", base_tp, curr_tp, delta * 100, flag))
        if regressed:
            regressions.append(f"throughput {THROUGHPUT_LABEL}")

    # Print table
    print(f"\n{'Metric':<35} {'Baseline':>12} {'Current':>12} {'Delta':>8}  Status")
    print("-" * 80)
    for label, base, curr, pct, flag in rows:
        marker = " <-- REGRESSION" if flag == "REGRESSED" else ""
        print(f"{label:<35} {base:>12.2f} {curr:>12.2f} {pct:>+7.1f}%  {flag}{marker}")

    print()
    if regressions:
        print(f"FAIL: {len(regressions)} regression(s) beyond {threshold*100:.0f}% threshold:")
        for r in regressions:
            print(f"  - {r}")
        sys.exit(1)
    else:
        print(f"PASS: no regressions beyond {threshold*100:.0f}% threshold.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="Path to baseline JSON")
    parser.add_argument("current", help="Path to current run JSON")
    parser.add_argument("--threshold", type=float, default=0.05,
                        help="Regression threshold as a fraction (default: 0.05 = 5%%)")
    args = parser.parse_args()
    compare(args.baseline, args.current, args.threshold)


if __name__ == "__main__":
    main()
