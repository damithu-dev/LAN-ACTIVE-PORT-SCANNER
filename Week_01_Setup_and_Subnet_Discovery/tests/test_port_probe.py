"""
Unit Test Suite for Week 1 TCP Socket Probe
Author: Damithu (Quality Assurance & Solution Architecture Lead)
Framework: pytest
"""

import sys
import os
import socket
import threading
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.port_probe import (
    probe_tcp_port,
    STATUS_OPEN,
    STATUS_CLOSED,
    STATUS_FILTERED,
    WSAECONNREFUSED,
    WSAETIMEDOUT,
)


@pytest.fixture(scope="module")
def mock_open_server():
    """Starts a temporary local TCP echo listener on localhost to test OPEN status."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))  # OS chooses free ephemeral port
    assigned_port = srv.getsockname()[1]
    srv.listen(5)

    stop_event = threading.Event()

    def server_worker():
        srv.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    thread = threading.Thread(target=server_worker, daemon=True)
    thread.start()

    yield ("127.0.0.1", assigned_port)

    stop_event.set()
    srv.close()
    thread.join(timeout=1.0)


def test_probe_open_port(mock_open_server):
    """Verifies that an actively listening local port correctly returns STATUS_OPEN."""
    host, port = mock_open_server
    res = probe_tcp_port(host, port, timeout=1.0)

    assert res["host"] == host
    assert res["port"] == port
    assert res["status"] == STATUS_OPEN
    assert res["error_code"] == 0
    assert res["latency_ms"] >= 0.0


def test_probe_closed_port():
    """
    Verifies that an unallocated port on localhost returns STATUS_CLOSED.
    Note: On Windows loopback, TCP stack retransmits SYN once before returning
    WSAECONNREFUSED (~2.0s), whereas Linux returns RST immediately. A 2.5s timeout
    ensures clean cross-platform execution without premature timeout.
    """
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()  # Port is now unallocated

    res = probe_tcp_port("127.0.0.1", free_port, timeout=2.5)
    assert res["port"] == free_port
    assert res["status"] == STATUS_CLOSED
    assert res["error_code"] in (10061, 111)  # WSAECONNREFUSED or ECONNREFUSED
    assert res["latency_ms"] >= 0.0


def test_probe_closed_port_mocked():
    """Validates CLOSED status mapping using a mocked socket returning ECONNREFUSED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = WSAECONNREFUSED

        res = probe_tcp_port("127.0.0.1", 9999, timeout=0.5)
        assert res["status"] == STATUS_CLOSED
        assert res["error_code"] == WSAECONNREFUSED


def test_probe_filtered_port_via_timeout():
    """Simulates a non-responsive (firewalled) target port returning STATUS_FILTERED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock_inst = MagicMock()
        mock_socket_class.return_value = mock_sock_inst
        mock_sock_inst.connect_ex.side_effect = socket.timeout("Timed out")

        res = probe_tcp_port("192.0.2.1", 80, timeout=0.2)
        assert res["status"] == STATUS_FILTERED


def test_probe_filtered_error_code():
    """Validates that Winsock / POSIX timeout error codes map to STATUS_FILTERED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock_inst = MagicMock()
        mock_socket_class.return_value = mock_sock_inst
        mock_sock_inst.connect_ex.return_value = WSAETIMEDOUT

        res = probe_tcp_port("10.255.255.1", 443, timeout=0.2)
        assert res["status"] == STATUS_FILTERED
        assert res["error_code"] == WSAETIMEDOUT


def test_invalid_port_range_validation():
    """Verifies that out-of-range port numbers raise ValueError."""
    with pytest.raises(ValueError):
        probe_tcp_port("127.0.0.1", 0)

    with pytest.raises(ValueError):
        probe_tcp_port("127.0.0.1", 65536)

    with pytest.raises(ValueError):
        probe_tcp_port("127.0.0.1", -5)


def test_invalid_parameter_types():
    """Verifies type assertions for host and port parameters."""
    with pytest.raises(TypeError):
        probe_tcp_port(127001, 80)  # Host not string

    with pytest.raises(TypeError):
        probe_tcp_port("127.0.0.1", "80")  # Port not int


def test_so_reuseaddr_set_on_socket():
    """Verifies that the SO_REUSEADDR socket option is configured on socket creation."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock_inst = MagicMock()
        mock_socket_class.return_value = mock_sock_inst
        mock_sock_inst.connect_ex.return_value = 0

        probe_tcp_port("127.0.0.1", 80)
        mock_sock_inst.setsockopt.assert_any_call(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
