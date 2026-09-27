"""
Unit Tests for Base Port Scanner Engine Core
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
import threading
from pathlib import Path
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.port_scanner_core import scan_host_ports_sequential, probe_single_port


@pytest.fixture(scope="module")
def multi_service_mock():
    """
    Spins up mock local servers representing standard services:
    - Service 1: Mock HTTP on ephemeral port A
    - Service 2: Mock SSH on ephemeral port B
    - Service 3: Mock MySQL on ephemeral port C
    """
    sockets = []
    ports = []
    stop_event = threading.Event()

    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(5)
        sockets.append(s)
        ports.append(s.getsockname()[1])

    def worker(sock):
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    threads = [threading.Thread(target=worker, args=(s,), daemon=True) for s in sockets]
    for t in threads:
        t.start()

    yield ports

    stop_event.set()
    for s in sockets:
        s.close()
    for t in threads:
        t.join(timeout=1.0)


def test_sequential_scan_detects_open_ports(multi_service_mock):
    """Verifies that scan_host_ports_sequential accurately detects all running mock services."""
    active_ports = multi_service_mock
    res = scan_host_ports_sequential("127.0.0.1", active_ports, timeout=1.0)

    assert res["host"] == "127.0.0.1"
    assert res["total_scanned"] == 3
    assert res["open_count"] == 3
    assert len(res["open_ports"]) == 3
    assert res["closed_count"] == 0
    assert res["duration_seconds"] >= 0.0


def test_progress_callback_invocation():
    """Verifies that the progress_callback hook fires on every scanned port."""
    callback_calls = []

    def sample_callback(current, total, last_res):
        callback_calls.append((current, total, last_res["port"]))

    test_ports = [8081, 8082, 8083]
    scan_host_ports_sequential("127.0.0.1", test_ports, timeout=0.1, progress_callback=sample_callback)

    assert len(callback_calls) == 3
    assert callback_calls[0][0] == 1
    assert callback_calls[0][1] == 3
    assert callback_calls[2][0] == 3
