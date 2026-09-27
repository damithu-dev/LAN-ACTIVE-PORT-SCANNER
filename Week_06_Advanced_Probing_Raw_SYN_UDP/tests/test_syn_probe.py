"""
Unit Tests for TCP SYN Stealth Probing & Non-Root Fallback
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
    probe_syn_stealth,
    probe_tcp_connect_fallback,
    is_privileged,
    STATUS_OPEN,
    STATUS_CLOSED,
)


def test_non_root_fallback_when_unprivileged():
    """Verifies that non-root users automatically degrade to TCP-CONNECT-FALLBACK without error."""
    with patch("scanner.advanced_probe.is_privileged", return_value=False):
        with patch("scanner.advanced_probe.probe_tcp_connect_fallback") as mock_fallback:
            mock_fallback.return_value = {
                "host": "127.0.0.1",
                "port": 80,
                "status": STATUS_OPEN,
                "probe_type": "TCP-CONNECT-FALLBACK",
                "latency_ms": 1.5,
                "raw_privilege": False,
            }

            res = probe_syn_stealth("127.0.0.1", 80)
            assert res["probe_type"] == "TCP-CONNECT-FALLBACK"
            assert res["raw_privilege"] is False
            mock_fallback.assert_called_once()


def test_privileged_syn_probe_execution():
    """Verifies that when running as root/admin, raw socket SYN probe logic is triggered."""
    with patch("scanner.advanced_probe.is_privileged", return_value=True):
        with patch("socket.socket") as mock_socket:
            mock_sock_inst = MagicMock()
            mock_socket.return_value = mock_sock_inst

            res = probe_syn_stealth("192.168.1.1", 443)
            assert res["probe_type"] == "TCP-SYN-STEALTH"
            assert res["raw_privilege"] is True
            assert res["status"] == STATUS_OPEN


def test_raw_socket_permission_error_triggers_fallback():
    """Verifies that if creating raw socket raises PermissionError, fallback succeeds."""
    with patch("scanner.advanced_probe.is_privileged", return_value=True):
        original_socket = socket.socket

        def conditional_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
            if type == socket.SOCK_RAW:
                raise PermissionError("Raw socket operation not permitted")
            mock_stream = MagicMock()
            mock_stream.connect_ex.return_value = 0
            return mock_stream

        with patch("socket.socket", side_effect=conditional_socket):
            res = probe_syn_stealth("10.0.0.1", 22)
            assert res["probe_type"] == "TCP-CONNECT-FALLBACK"
            assert res["raw_privilege"] is False
            assert res["status"] == STATUS_OPEN
