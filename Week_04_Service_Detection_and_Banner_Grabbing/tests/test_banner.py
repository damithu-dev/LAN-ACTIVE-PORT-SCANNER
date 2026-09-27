"""
Unit Test Suite for Service Banner Grabbing & Regex Parsing
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.banner import parse_service_banner, grab_service_banner


def test_parse_nginx_http_banner():
    raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n"
    res = parse_service_banner(raw, 80)
    assert res["service_name"] == "Nginx"
    assert res["version"] == "1.18.0"


def test_parse_apache_http_banner():
    raw = "HTTP/1.1 200 OK\r\nDate: Mon, 23 Jan 2026\r\nServer: Apache/2.4.52 (Unix)\r\n"
    res = parse_service_banner(raw, 80)
    assert res["service_name"] == "Apache HTTPD"
    assert res["version"] == "2.4.52"


def test_parse_openssh_banner():
    raw = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    res = parse_service_banner(raw, 22)
    assert res["service_name"] == "OpenSSH"
    assert res["version"] == "8.9p1"


def test_parse_vsftpd_banner():
    raw = "220 (vsFTPd 3.0.3)\r\n"
    res = parse_service_banner(raw, 21)
    assert res["service_name"] == "vsftpd"
    assert res["version"] == "3.0.3"


def test_empty_and_unknown_banner():
    # An unassigned high port with empty banner should return unknown
    res = parse_service_banner("", 49152)
    assert res["service_name"] == "unknown"
    assert res["version"] == "unknown"

    # Known port 80 with unparsed content falls back to HTTP
    res2 = parse_service_banner("Some random gibberish", 80)
    assert res2["service_name"] == "HTTP"


def test_timeout_safeguard_prevents_hanging():
    """Validates that a connection that never sends bytes terminates cleanly at timeout."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        # Simulate timeout on recv()
        mock_sock.recv.side_effect = socket.timeout("Timed out reading banner")

        res = grab_service_banner("127.0.0.1", 80, timeout=0.2)
        assert res["service_name"] == "HTTP"  # Port fallback
        assert res["raw_banner"] == ""
        mock_sock.close.assert_called_once()
