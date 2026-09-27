"""
Unit Tests for UDP Probing and ICMP Unreachable Response Handling
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.advanced_probe import (
    probe_udp_port,
    STATUS_OPEN,
    STATUS_CLOSED,
    STATUS_OPEN_FILTERED,
)


def test_udp_dns_probe_open_response():
    """Verifies that an application-layer reply on UDP port 53 returns STATUS_OPEN."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        # Mock receiving DNS response payload
        mock_sock.recvfrom.return_value = (b"\xaa\xbb\x81\x80\x00\x01\x00\x01", ("8.8.8.8", 53))

        res = probe_udp_port("8.8.8.8", 53, timeout=1.0)
        assert res["protocol"] == "UDP"
        assert res["status"] == STATUS_OPEN


def test_udp_icmp_unreachable_maps_to_closed():
    """Verifies that an OS-level ICMP Port Unreachable (ConnectionResetError) maps to STATUS_CLOSED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recvfrom.side_effect = ConnectionResetError("ICMP Port Unreachable")

        res = probe_udp_port("127.0.0.1", 49152, timeout=0.5)
        assert res["protocol"] == "UDP"
        assert res["status"] == STATUS_CLOSED


def test_udp_timeout_maps_to_open_filtered():
    """Verifies that dropped UDP packets map to standard RFC STATUS_OPEN_FILTERED."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout("Timed out waiting for UDP datagram")

        res = probe_udp_port("192.168.1.1", 161, timeout=0.2)
        assert res["protocol"] == "UDP"
        assert res["status"] == STATUS_OPEN_FILTERED
