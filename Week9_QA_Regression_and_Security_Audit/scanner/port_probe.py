"""
scanner/port_probe.py
----------------------
Single-target TCP Connect port probing. This is the "system under test"
that Damithu's Week 8-10 QA work exercises, audits and stress-tests.
"""
import socket
from enum import Enum


class PortStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


def probe_port(host: str, port: int, timeout: float = 0.5) -> PortStatus:
    """Attempt a TCP connect() to host:port and classify the result.

    Args:
        host: Target IPv4 address or hostname.
        port: TCP port number (1-65535).
        timeout: Socket timeout in seconds before treating the port as FILTERED.

    Returns:
        PortStatus.OPEN if the connection succeeds, PortStatus.CLOSED if the
        target actively refuses the connection (RST), or PortStatus.FILTERED
        if the probe times out (no response / dropped by a firewall).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return PortStatus.OPEN
        if result in (111, 61, 10061):  # ECONNREFUSED (linux/mac/windows)
            return PortStatus.CLOSED
        return PortStatus.FILTERED
    except socket.timeout:
        return PortStatus.FILTERED
    except OSError:
        return PortStatus.FILTERED
    finally:
        sock.close()
