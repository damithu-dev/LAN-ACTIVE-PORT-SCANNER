"""
scanner/concurrent_scan.py
---------------------------
ThreadPoolExecutor-based worker pool for scanning many host:port pairs
in parallel. This is the module Damithu stress-tests in Week 8 (Day 53,
500-thread saturation test) and regression-tests in Week 9 (Day 57).
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Tuple

from scanner.port_probe import PortStatus, probe_port

# Simple in-process rate limiter (packets-per-second style throttle),
# audited by Damithu in Week 9 Day 59 (rate-limiting validation).
_rate_lock = threading.Lock()
_last_dispatch = [0.0]


def _throttle(min_interval: float) -> None:
    if min_interval <= 0:
        return
    with _rate_lock:
        now = time.monotonic()
        wait = _last_dispatch[0] + min_interval - now
        if wait > 0:
            time.sleep(wait)
        _last_dispatch[0] = time.monotonic()


@dataclass
class ScanResult:
    host: str
    port: int
    status: PortStatus
    error: str = ""


@dataclass
class ScanReport:
    results: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def _scan_one(host: str, port: int, timeout: float, min_interval: float) -> ScanResult:
    try:
        _throttle(min_interval)
        status = probe_port(host, port, timeout=timeout)
        return ScanResult(host=host, port=port, status=status)
    except Exception as exc:  # defensive: worker threads must never crash silently
        return ScanResult(host=host, port=port, status=PortStatus.FILTERED, error=str(exc))


def run_concurrent_scan(
    targets: List[Tuple[str, int]],
    max_workers: int = 100,
    timeout: float = 0.5,
    min_interval: float = 0.0,
) -> ScanReport:
    """Scan a list of (host, port) tuples concurrently.

    Args:
        targets: list of (host, port) pairs to probe.
        max_workers: thread pool size (default matches production config of 100;
            Week 8 Day 53 pushes this to 500 to find the saturation point).
        timeout: per-probe socket timeout in seconds.
        min_interval: minimum seconds between dispatches (0 = no throttle),
            used for the Week 9 rate-limiting / anti-flood safety feature.

    Returns:
        ScanReport with all individual results, any worker-level errors,
        and total wall-clock duration.
    """
    start = time.monotonic()
    report = ScanReport()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(_scan_one, host, port, timeout, min_interval)
            for host, port in targets
        ]
        for future in as_completed(futures):
            result = future.result()
            report.results.append(result)
            if result.error:
                report.errors.append(f"{result.host}:{result.port} -> {result.error}")
    report.duration_seconds = time.monotonic() - start
    return report
