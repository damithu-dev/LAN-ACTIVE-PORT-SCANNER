"""
tests/test_rate_limit.py
--------------------------
Week 9 (Damithu, Day 59): validates that the packet-per-second rate limiter
(min_interval in scanner/concurrent_scan.py) actually throttles scan speed,
so the scanner can be safely run over slow/low-bandwidth links without
flooding them.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.concurrent_scan import run_concurrent_scan  # noqa: E402
from stress.docker_lab_simulator import MockLab  # noqa: E402


def test_no_throttle_is_fast():
    lab = MockLab(count=20, base_port=49000)
    endpoints = lab.start()
    try:
        report = run_concurrent_scan(endpoints, max_workers=20, timeout=1.0, min_interval=0.0)
    finally:
        lab.stop()
    # Unthrottled local scan of 20 ports should comfortably finish under 1s.
    assert report.duration_seconds < 1.0


def test_throttled_scan_respects_pps_budget():
    lab = MockLab(count=20, base_port=49100)
    endpoints = lab.start()
    min_interval = 0.02  # simulated "low-bandwidth link" budget: 50 pps max
    try:
        start = time.monotonic()
        report = run_concurrent_scan(endpoints, max_workers=20, timeout=1.0, min_interval=min_interval)
        elapsed = time.monotonic() - start
    finally:
        lab.stop()

    expected_minimum = (len(endpoints) - 1) * min_interval
    assert elapsed >= expected_minimum * 0.8, (
        f"Throttle too weak: {len(endpoints)} probes at {min_interval}s/probe "
        f"should take >= {expected_minimum:.2f}s, took {elapsed:.2f}s"
    )
    assert len(report.results) == len(endpoints)


if __name__ == "__main__":
    test_no_throttle_is_fast()
    test_throttled_scan_respects_pps_budget()
    print("Rate-limiting validation: PASS")
