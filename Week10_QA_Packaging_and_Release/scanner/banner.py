"""
scanner/banner.py
------------------
Lightweight banner grabbing for OPEN ports. Used by the CVE mapping
engine (Week 8) as the source of "service fingerprint" strings.
"""
import socket


HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    """Connect to host:port and try to read a service greeting banner.

    Passive read first (works for SSH, FTP, SMTP which greet immediately).
    If nothing arrives, sends a minimal HTTP HEAD request as an active probe
    (works for HTTP/HTTPS-style services that wait for the client first).

    Returns an empty string if no banner could be captured.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
                if data:
                    return data.decode(errors="replace").strip()
            except socket.timeout:
                pass

            try:
                sock.sendall(HTTP_PROBE)
                data = sock.recv(256)
                return data.decode(errors="replace").strip()
            except (socket.timeout, OSError):
                return ""
    except OSError:
        return ""
