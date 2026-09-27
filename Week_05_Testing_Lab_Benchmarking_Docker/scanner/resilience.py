"""
LAN Scanner - Week 5: Network Resilience & Adaptive Retry Engine
Author: Damithu (Quality Assurance & Solution Architecture Lead)

Description:
    Adaptive timeout and retry heuristics engineered to withstand artificial packet loss,
    variable network jitter, and congested wireless networks without false positives.
"""

import time
import socket
import errno
from typing import Dict, Any, Callable, Optional

STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED"


def probe_with_resilience(
    host: str,
    port: int,
    initial_timeout: float = 0.3,
    max_retries: int = 2,
    backoff_multiplier: float = 1.5,
) -> Dict[str, Any]:
    """
    Probes a TCP port with adaptive retry heuristics under unstable or lossy conditions.

    If a probe times out (suggesting packet loss or firewall filtering), the engine
    retries with an increased timeout before definitively marking it FILTERED.
    An immediate RST (connection refused) or SYN-ACK (open) bypasses retries.

    Args:
        host: Target IP or hostname.
        port: Target TCP port.
        initial_timeout: Base timeout in seconds (default: 0.3s).
        max_retries: Number of retry attempts on timeout (default: 2).
        backoff_multiplier: Factor by which timeout grows on retry (default: 1.5).

    Returns:
        Dict containing status, attempts_made, latency_ms, and reliability metric.
    """
    current_timeout = initial_timeout
    attempts = 0
    total_start = time.perf_counter()

    final_status = STATUS_FILTERED
    final_err = -1

    for attempt_idx in range(1, max_retries + 2):
        attempts = attempt_idx
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except (socket.error, OSError):
            pass
        sock.settimeout(current_timeout)

        try:
            err = sock.connect_ex((host, port))
            if err == 0:
                final_status = STATUS_OPEN
                final_err = 0
                sock.close()
                break  # Successful connection, no retry needed
            elif err in (10061, 111):
                final_status = STATUS_CLOSED
                final_err = err
                sock.close()
                break  # Host actively refused; port is closed, no retry needed
            else:
                # Potential packet drop or unreachability; retry if attempts remain
                final_status = STATUS_FILTERED
                final_err = err
        except (socket.timeout, TimeoutError):
            final_status = STATUS_FILTERED
            final_err = 10060
        except Exception:
            final_status = STATUS_FILTERED
            final_err = -1
        finally:
            sock.close()

        # If timeout occurred, apply backoff heuristic before next attempt
        current_timeout *= backoff_multiplier

    total_latency_ms = (time.perf_counter() - total_start) * 1000.0

    return {
        "host": host,
        "port": port,
        "status": final_status,
        "attempts_made": attempts,
        "latency_ms": round(total_latency_ms, 2),
        "error_code": final_err,
        "resilience_rating": "HIGH" if attempts == 1 else "RECOVERED",
    }
