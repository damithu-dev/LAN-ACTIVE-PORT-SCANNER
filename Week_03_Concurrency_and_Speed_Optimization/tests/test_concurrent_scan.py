"""
Integration Test Suite for Concurrent Port Scanner Engine
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
import threading
from pathlib import Path
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.concurrent_scan import ConcurrentPortScanner, STATUS_OPEN, STATUS_CLOSED


@pytest.fixture(scope="module")
def multi_listener_fixture():
    """Starts 5 mock local TCP listeners on ephemeral ports."""
    sockets = []
    ports = []
    stop_event = threading.Event()

    for _ in range(5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(10)
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


def test_concurrent_scan_accuracy(multi_listener_fixture):
    """Verifies that all 5 active ports are correctly identified as OPEN under 50-thread concurrency."""
    open_ports = multi_listener_fixture
    # Add 15 dummy closed ports to test mixed classification
    target_ports = open_ports + [9991, 9992, 9993, 9994, 9995]

    scanner = ConcurrentPortScanner(max_workers=50, default_timeout=0.5)
    res = scanner.scan_host("127.0.0.1", target_ports)

    assert res["total_scanned"] == len(target_ports)
    assert res["open_count"] == 5
    detected_open_ports = [r["port"] for r in res["open_ports"]]
    for p in open_ports:
        assert p in detected_open_ports
    assert res["worker_threads"] == 50


def test_thread_safe_progress_callback():
    """Verifies that thread-safe callback receives updates for 100% of tasks without dropped counts."""
    callback_records = []
    lock = threading.Lock()

    def thread_safe_cb(current, total, result):
        with lock:
            callback_records.append((current, total))

    test_ports = list(range(10001, 10051))  # 50 ports
    scanner = ConcurrentPortScanner(max_workers=25, default_timeout=0.1)
    res = scanner.scan_host("127.0.0.1", test_ports, progress_callback=thread_safe_cb)

    assert res["total_scanned"] == 50
    assert len(callback_records) == 50
    # Final callback should report 50/50
    final_entry = callback_records[-1]
    assert final_entry[0] == 50
    assert final_entry[1] == 50


def test_invalid_scanner_initialization():
    """Verifies boundary checking on scanner constructor parameters."""
    with pytest.raises(ValueError):
        ConcurrentPortScanner(max_workers=0)

    with pytest.raises(ValueError):
        ConcurrentPortScanner(default_timeout=-1.0)
