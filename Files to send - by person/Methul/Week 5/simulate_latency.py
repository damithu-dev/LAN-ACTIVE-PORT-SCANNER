"""
Week 5: Network Degradation & Packet Loss Simulator
Author: Damithu (QA & Solution Architecture Lead)
"""

import time
import random
from typing import Dict, Any


def simulate_network_condition(
    base_latency_ms: float = 20.0,
    jitter_ms: float = 15.0,
    packet_loss_rate: float = 0.20,
) -> Dict[str, Any]:
    """
    Simulates real-world network turbulence including latency, jitter, and packet loss.

    Args:
        base_latency_ms: Average ping round-trip time.
        jitter_ms: Random variance in latency.
        packet_loss_rate: Probability of packet drop (0.0 to 1.0).

    Returns:
        Dict reporting simulated packet status and latency experienced.
    """
    # Simulate packet drop
    if random.random() < packet_loss_rate:
        return {
            "dropped": True,
            "latency_ms": 1000.0,  # Simulates waiting for full timeout
            "status": "DROPPED",
        }

    simulated_delay = max(1.0, base_latency_ms + random.uniform(-jitter_ms, jitter_ms))
    time.sleep(simulated_delay / 1000.0)

    return {
        "dropped": False,
        "latency_ms": round(simulated_delay, 2),
        "status": "DELIVERED",
    }


if __name__ == "__main__":
    print("[*] Running 10 simulated packet probes under 20% packet loss condition:")
    drops = 0
    for i in range(1, 11):
        res = simulate_network_condition(base_latency_ms=10, jitter_ms=5, packet_loss_rate=0.20)
        if res["dropped"]:
            drops += 1
            print(f"  Probe #{i}: [PACKET LOSS - TIMEOUT]")
        else:
            print(f"  Probe #{i}: [SUCCESS] Latency={res['latency_ms']}ms")
    print(f"\n[+] Total Simulated Drops: {drops}/10 ({drops*10}%)")
