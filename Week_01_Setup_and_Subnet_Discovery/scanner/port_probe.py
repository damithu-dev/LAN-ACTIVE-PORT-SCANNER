"""
LAN Scanner & Active Port Scanner - Week 1: Port Probing Engine
Author: Damithu (Quality Assurance & Solution Architecture Lead)
Team: Kevindu (Tech Lead), Methul (Solution Arch), Damithu (QA/Arch), Senura (UX), Ayami (Docs)

Description:
    Low-level TCP socket probe module utilizing socket.connect_ex() with
    configurable socket timeouts, SO_REUSEADDR handling, latency tracking,
    and cross-platform connection status classification (OPEN, CLOSED, FILTERED).
"""

import socket
import time
import errno
from typing import Dict, Any

# Standardized Port Status Enums / Constants
STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED"

# Standard Windows Winsock Error Codes for cross-platform mapping
WSAETIMEDOUT = 10060
WSAECONNREFUSED = 10061
WSAEHOSTUNREACH = 10065
WSAENETUNREACH = 10051


def probe_tcp_port(host: str, port: int, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Probes a single TCP port on a target host using socket.connect_ex().

    Args:
        host: Target IP address or hostname string (e.g. '192.168.1.1').
        port: Destination TCP port number (1-65535).
        timeout: Socket timeout duration in seconds (default 0.5s).

    Returns:
        Dict[str, Any]: Dictionary containing probe results:
            - 'host': target IP/hostname
            - 'port': target port integer
            - 'status': 'OPEN', 'CLOSED', or 'FILTERED'
            - 'latency_ms': measured connection duration in milliseconds
            - 'error_code': integer return code from connect_ex()

    Raises:
        ValueError: If port is out of range (not between 1 and 65535).
        TypeError: If host is not a string or port is not an int.
    """
    if not isinstance(host, str):
        raise TypeError(f"Host must be a string, got {type(host).__name__}")
    if not isinstance(port, int):
        raise TypeError(f"Port must be an integer, got {type(port).__name__}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is out of valid range (1-65535)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable SO_REUSEADDR to prevent local socket exhaustion during rapid test sweeps
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except (socket.error, OSError):
        pass

    sock.settimeout(timeout)
    start_time = time.perf_counter()
    status = STATUS_FILTERED
    err_code = -1

    try:
        err_code = sock.connect_ex((host, port))
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if err_code == 0:
            status = STATUS_OPEN
        elif err_code in (errno.ECONNREFUSED, WSAECONNREFUSED):
            status = STATUS_CLOSED
        elif err_code in (
            errno.ETIMEDOUT,
            WSAETIMEDOUT,
            errno.EHOSTUNREACH,
            WSAEHOSTUNREACH,
            getattr(errno, "ENETUNREACH", 101),
            WSAENETUNREACH,
        ):
            status = STATUS_FILTERED
        else:
            # Fallback for unexpected socket errors (treated as filtered/drop)
            status = STATUS_FILTERED
    except (socket.timeout, TimeoutError):
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        status = STATUS_FILTERED
        err_code = errno.ETIMEDOUT
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        status = STATUS_FILTERED
        err_code = -1
    finally:
        sock.close()

    return {
        "host": host,
        "port": port,
        "status": status,
        "latency_ms": round(elapsed_ms, 2),
        "error_code": err_code,
    }


if __name__ == "__main__":
    import sys
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    print(f"[*] Probing {target_host}:{target_port}...")
    res = probe_tcp_port(target_host, target_port)
    print(f"[*] Result: Status={res['status']}, Latency={res['latency_ms']}ms, Code={res['error_code']}")
