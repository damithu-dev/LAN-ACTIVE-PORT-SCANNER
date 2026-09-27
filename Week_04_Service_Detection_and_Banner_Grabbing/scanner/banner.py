"""
LAN Scanner - Week 4: Service Detection & Banner Grabbing Engine
Author: Damithu (Quality Assurance & Solution Architecture Lead)

Description:
    Socket read buffer module that captures initial service greeting banners,
    dispatches active protocol probe triggers (HTTP, SSH, FTP, SMTP), and parses
    raw banner strings via regular expressions into clean service and version strings.
"""

import socket
import re
from typing import Dict, Any, Optional

# Active probe trigger payloads for interactive application-layer services
PROBE_PAYLOADS = {
    80: b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: LANScanner/1.0\r\nConnection: close\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: LANScanner/1.0\r\nConnection: close\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: LANScanner/1.0\r\nConnection: close\r\n\r\n",
    25: b"EHLO scanner.local\r\n",
    21: b"",  # FTP emits greeting immediately upon connection
    22: b"",  # SSH emits greeting immediately upon connection
}

# Compiled Regular Expressions for Service & Version Extraction
BANNER_PATTERNS = [
    # SSH patterns: e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([^\r\n ]+)", re.IGNORECASE), "OpenSSH", "SSH"),
    (re.compile(r"SSH-[\d.]+-([^\r\n ]+)", re.IGNORECASE), "Generic SSH", "SSH"),
    # HTTP Server patterns: e.g. Server: nginx/1.18.0 (Ubuntu)
    (re.compile(r"Server:\s*nginx(?:/([\d.]+))?", re.IGNORECASE), "Nginx", "HTTP"),
    (re.compile(r"Server:\s*Apache(?:/([\d.]+))?", re.IGNORECASE), "Apache HTTPD", "HTTP"),
    (re.compile(r"Server:\s*Microsoft-IIS(?:/([\d.]+))?", re.IGNORECASE), "Microsoft IIS", "HTTP"),
    (re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE), "Custom Web Server", "HTTP"),
    # FTP patterns: e.g. 220[ -].*vsftpd 3.0.3
    (re.compile(r"220[ -].*vsftpd\s*([0-9.]+)?", re.IGNORECASE), "vsftpd", "FTP"),
    (re.compile(r"220[ -].*Pure-FTPd", re.IGNORECASE), "Pure-FTPd", "FTP"),
    (re.compile(r"220[ -]([^\r\n]+)", re.IGNORECASE), "Generic FTP", "FTP"),
    # SMTP patterns: e.g. 220 mail.example.com ESMTP Postfix
    (re.compile(r"220[ -].*Postfix", re.IGNORECASE), "Postfix SMTP", "SMTP"),
    (re.compile(r"220[ -].*Exim\s*([0-9.]+)?", re.IGNORECASE), "Exim SMTP", "SMTP"),
    # Redis: e.g. -ERR unknown command or redis_version:6.0.9
    (re.compile(r"redis_version:([0-9.]+)", re.IGNORECASE), "Redis", "Redis"),
]

# Standard well-known port fallback dictionary
PORT_FALLBACKS = {
    80: "HTTP",
    8080: "HTTP",
    443: "HTTPS",
    8443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    53: "DNS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}


def parse_service_banner(raw_banner: str, port: int) -> Dict[str, str]:
    """
    Parses a raw text banner using regex patterns to extract service name and version.

    Args:
        raw_banner: Raw string received from service socket.
        port: Destination port number for contextual fallback.

    Returns:
        Dict containing 'service_name', 'version', and 'raw_banner'.
    """
    fallback_svc = PORT_FALLBACKS.get(port, "unknown")

    if raw_banner:
        for pattern, service_label, _ in BANNER_PATTERNS:
            match = pattern.search(raw_banner)
            if match:
                version = "unknown"
                if match.groups() and match.group(1):
                    version = match.group(1).strip()
                return {
                    "service_name": service_label,
                    "version": version,
                    "raw_banner": raw_banner[:200].strip(),
                }

    return {
        "service_name": fallback_svc,
        "version": "unknown",
        "raw_banner": raw_banner[:200].strip() if raw_banner else "",
    }


def grab_service_banner(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Connects to a target TCP port, dispatches active probe triggers,
    and captures the service banner within a strict timeout boundary.

    Args:
        host: Target IP or hostname.
        port: Target TCP port.
        timeout: Maximum duration in seconds to wait for socket response (default: 1.0s).

    Returns:
        Dict with service_name, version, raw_banner, and status.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    raw_response = ""
    try:
        sock.connect((host, port))

        # Check if an active protocol probe payload should be dispatched
        payload = PROBE_PAYLOADS.get(port, b"")
        if payload:
            sock.sendall(payload)

        # Bounded read buffer (2048 bytes maximum to avoid buffer overflow risks)
        data = sock.recv(2048)
        raw_response = data.decode("utf-8", errors="replace")
    except (socket.timeout, TimeoutError):
        # Service connected but emitted no banner within timeout safeguard
        raw_response = ""
    except Exception:
        raw_response = ""
    finally:
        sock.close()

    parsed = parse_service_banner(raw_response, port)
    return {
        "host": host,
        "port": port,
        "service_name": parsed["service_name"],
        "version": parsed["version"],
        "raw_banner": parsed["raw_banner"],
    }
