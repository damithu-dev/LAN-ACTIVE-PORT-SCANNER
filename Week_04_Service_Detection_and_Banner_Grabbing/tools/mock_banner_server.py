"""
Week 4: Mock Multi-Service Banner Server
Author: Damithu (QA & Solution Architecture Lead)
"""

import socket
import threading
import time
import sys

SERVICES = {
    8080: b"HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\nContent-Type: text/html\r\n\r\n<h1>Mock Web Server</h1>",
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    2121: b"220 (vsFTPd 3.0.3)\r\n",
}


def start_mock_service(port: int, banner: bytes, stop_event: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.5)

    print(f"[*] Mock service listening on port {port}...")

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
            # If HTTP, wait for request before sending header; else send immediately
            if port == 8080:
                conn.settimeout(1.0)
                try:
                    conn.recv(1024)
                except Exception:
                    pass
            conn.sendall(banner)
            time.sleep(0.05)
            conn.close()
        except (socket.timeout, OSError):
            continue

    srv.close()


def run_all_mocks():
    stop_event = threading.Event()
    threads = []
    for port, banner in SERVICES.items():
        t = threading.Thread(target=start_mock_service, args=(port, banner, stop_event), daemon=True)
        t.start()
        threads.append(t)

    print("[+] All mock service servers started. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping mock servers...")
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        print("[+] Mock servers shut down cleanly.")


if __name__ == "__main__":
    run_all_mocks()
