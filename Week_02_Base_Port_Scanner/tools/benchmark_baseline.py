"""
Week 2: Baseline Single-Threaded Scan Latency Benchmark
Author: Damithu (QA & Solution Architecture Lead)
"""

import time
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.port_scanner_core import scan_host_ports_sequential
from scanner.port_parser import parse_ports


def run_baseline_benchmark(target: str = "127.0.0.1"):
    print(f"=== Single-Threaded Scan Latency Baseline Benchmark ===")
    print(f"Target Host: {target}\n")

    test_port_sets = [
        ("10 Ports Sample", parse_ports("21,22,23,25,53,80,110,143,443,3306")),
        ("Top 25 Ports", parse_ports("top100")[:25]),
        ("Top 50 Ports", parse_ports("top100")[:50]),
    ]

    for label, ports in test_port_sets:
        print(f"[*] Benchmarking: {label} ({len(ports)} ports)...")
        start = time.perf_counter()
        res = scan_host_ports_sequential(target, ports, timeout=0.2)
        duration = time.perf_counter() - start

        print(f"    Total Duration:     {duration:.3f} seconds")
        print(f"    Average Per-Port:   {(duration / len(ports)):.4f} seconds")
        print(f"    Open Ports Found:   {res['open_count']}")
        print(f"    Closed Ports:       {res['closed_count']}")
        print(f"    Filtered Ports:     {res['filtered_count']}")
        print("-" * 50)

    print("\n[!] Baseline established: Single-threaded linear scanning scales linearly O(N * timeout).")
    print("[!] Recommendation for Week 3: Transition to ThreadPoolExecutor concurrency pool.")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_baseline_benchmark(host)
