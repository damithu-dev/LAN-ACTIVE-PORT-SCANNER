"""
Week 6: TCP SYN Stealth vs TCP Full Connect Benchmark
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.advanced_probe import probe_syn_stealth, probe_tcp_connect_fallback, is_privileged


def run_syn_vs_connect_benchmark(host: str = "127.0.0.1"):
    print("=" * 70)
    print("       BENCHMARK: TCP SYN STEALTH VS TCP FULL CONNECT")
    print("=" * 70)
    print(f"Target: {host} | Execution Privileges: {'ROOT/ADMIN' if is_privileged() else 'STANDARD USER'}")
    print(f"{'Probe Technique':<25} | {'Duration (s)':<15} | {'Stealth Level':<25}")
    print("-" * 70)

    sample_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

    # Benchmark Full Connect
    t0 = time.perf_counter()
    for p in sample_ports:
        probe_tcp_connect_fallback(host, p, timeout=0.1)
    connect_time = time.perf_counter() - t0

    # Benchmark SYN Probe
    t1 = time.perf_counter()
    for p in sample_ports:
        probe_syn_stealth(host, p, timeout=0.1)
    syn_time = time.perf_counter() - t1

    print(f"{'TCP Connect (Full)':<25} | {connect_time:<15.4f} | {'Logged in Server Event Logs':<25}")
    print(f"{'TCP SYN (Half-Open)':<25} | {syn_time:<15.4f} | {'Tears Down Before Logging':<25}")
    print("=" * 70)
    print("[+] Architectural Finding:")
    print("    SYN scanning avoids completing the 3-way handshake, reducing connection")
    print("    overhead and bypassing standard application-layer connection logs.")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_syn_vs_connect_benchmark(target)
