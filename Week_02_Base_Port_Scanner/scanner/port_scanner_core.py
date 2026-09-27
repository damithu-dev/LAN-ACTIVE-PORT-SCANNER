"""
LAN Scanner - Week 2: Sequential Port Scanner Core
Author: Damithu (Quality Assurance & Solution Architecture Lead)
"""

import time
import socket
from typing import List, Dict, Any, Callable, Optional

# Standard Winsock / POSIX codes
WSAETIMEDOUT = 10060
WSAECONNREFUSED = 10061

STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED"


def probe_single_port(host: str, port: int, timeout: float = 0.5) -> Dict[str, Any]:
    """Single TCP probe helper."""
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except (socket.error, OSError):
        pass
    sock.settimeout(timeout)

    status = STATUS_FILTERED
    err = -1
    try:
        err = sock.connect_ex((host, port))
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if err == 0:
            status = STATUS_OPEN
        elif err in (10061, 111):
            status = STATUS_CLOSED
        else:
            status = STATUS_FILTERED
    except (socket.timeout, TimeoutError):
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        status = STATUS_FILTERED
        err = 10060
    except Exception:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        status = STATUS_FILTERED
        err = -1
    finally:
        sock.close()

    return {
        "host": host,
        "port": port,
        "status": status,
        "latency_ms": round(elapsed_ms, 2),
        "error_code": err,
    }


def scan_host_ports_sequential(
    host: str,
    ports: List[int],
    timeout: float = 0.5,
    progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Performs a sequential single-threaded port scan across a list of target ports.

    Args:
        host: Target IP or hostname.
        ports: List of integer ports to scan.
        timeout: Socket connection timeout per port (default: 0.5s).
        progress_callback: Optional callback func(scanned_count, total_count, last_result).

    Returns:
        Dict[str, Any] containing aggregated scan statistics and list of open ports.
    """
    total_ports = len(ports)
    open_ports = []
    closed_ports = []
    filtered_ports = []
    all_results = []

    start_wall_time = time.perf_counter()

    for idx, port in enumerate(ports, start=1):
        res = probe_single_port(host, port, timeout)
        all_results.append(res)

        if res["status"] == STATUS_OPEN:
            open_ports.append(res)
        elif res["status"] == STATUS_CLOSED:
            closed_ports.append(res)
        else:
            filtered_ports.append(res)

        if progress_callback:
            progress_callback(idx, total_ports, res)

    total_duration_sec = round(time.perf_counter() - start_wall_time, 3)

    return {
        "host": host,
        "total_scanned": total_ports,
        "open_count": len(open_ports),
        "closed_count": len(closed_ports),
        "filtered_count": len(filtered_ports),
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "filtered_ports": filtered_ports,
        "duration_seconds": total_duration_sec,
        "average_latency_ms": (
            round(sum(r["latency_ms"] for r in all_results) / total_ports, 2)
            if total_ports > 0
            else 0.0
        ),
    }
