"""
Unit Test Suite for Network Resilience & Retry Heuristics
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.resilience import probe_with_resilience, STATUS_OPEN, STATUS_CLOSED, STATUS_FILTERED


@pytest.fixture(scope="module")
def mock_open_listener():
    """Starts a reliable local TCP listener."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)

    stop_event = threading.Event()

    def worker():
        srv.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    yield ("127.0.0.1", port)

    stop_event.set()
    srv.close()
    t.join(timeout=1.0)


def test_resilience_open_port_single_attempt(mock_open_listener):
    """Verifies that an open port succeeds on attempt 1 without triggering redundant retries."""
    host, port = mock_open_listener
    res = probe_with_resilience(host, port, initial_timeout=0.5, max_retries=2)

    assert res["status"] == STATUS_OPEN
    assert res["attempts_made"] == 1
    assert res["resilience_rating"] == "HIGH"


def test_resilience_closed_port_no_retries():
    """Verifies that an immediate RST from a closed port returns immediately without retrying."""
    # Find free unused port
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    port = temp_sock.getsockname()[1]
    temp_sock.close()

    # Use mocked connect_ex to test ECONNREFUSED
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = 10061  # WSAECONNREFUSED

        res = probe_with_resilience("127.0.0.1", port, initial_timeout=0.3, max_retries=2)
        assert res["status"] == STATUS_CLOSED
        assert res["attempts_made"] == 1


def test_resilience_recovers_after_intermittent_drop():
    """Simulates a packet drop on attempt 1, followed by a successful connection on retry attempt 2."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Attempt 1 returns timeout (10060), Attempt 2 returns success (0)
        mock_sock.connect_ex.side_effect = [10060, 0]

        res = probe_with_resilience("192.168.1.50", 80, initial_timeout=0.2, max_retries=2)
        assert res["status"] == STATUS_OPEN
        assert res["attempts_made"] == 2
        assert res["resilience_rating"] == "RECOVERED"


def test_resilience_exhausts_retries_on_permanent_filter():
    """Validates that a truly firewalled port retries up to max_retries before returning FILTERED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = 10060  # Consistently times out

        res = probe_with_resilience("10.0.0.99", 443, initial_timeout=0.1, max_retries=2)
        assert res["status"] == STATUS_FILTERED
        assert res["attempts_made"] == 3  # Initial + 2 retries
