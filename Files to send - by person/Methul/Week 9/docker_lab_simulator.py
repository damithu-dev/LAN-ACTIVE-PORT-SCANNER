"""
stress/docker_lab_simulator.py
--------------------------------
Week 8 (Damithu, Day 52): "high-density Docker lab" stand-in.

The real Week 8 plan spins up 50+ Docker containers on a virtual bridge
network. A QA sandbox cannot run Docker-in-Docker reliably, so this module
achieves the same *test objective* -- many independent, addressable service
endpoints to scan concurrently -- by spinning up 50+ lightweight TCP socket
servers on 127.0.0.1, each on its own port, each replying with a distinct
mock service banner. This is documented to the team as a like-for-like
substitution; see the Week 8 QA report for the justification.
"""
import socket
import threading
import time
from typing import List, Tuple

MOCK_BANNERS = [
    "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n",
    "Server: Apache/2.4.29 (Ubuntu)\r\n\r\n",
    "220 ProFTPD 1.3.5 Server ready\r\n",
    "Server: nginx/1.14.0 (Ubuntu)\r\n\r\n",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
]


def _serve(sock: socket.socket, banner: str, stop_event: threading.Event):
    sock.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.sendall(banner.encode())
        except OSError:
            pass
        finally:
            conn.close()


class MockLab:
    """Spins up `count` mock service endpoints on 127.0.0.1."""

    def __init__(self, count: int = 50, base_port: int = 45000):
        self.count = count
        self.base_port = base_port
        self._sockets: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self.endpoints: List[Tuple[str, int]] = []

    def start(self):
        for i in range(self.count):
            port = self.base_port + i
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(20)
            banner = MOCK_BANNERS[i % len(MOCK_BANNERS)]
            thread = threading.Thread(target=_serve, args=(sock, banner, self._stop_event), daemon=True)
            thread.start()
            self._sockets.append(sock)
            self._threads.append(thread)
            self.endpoints.append(("127.0.0.1", port))
        time.sleep(0.2)  # let listeners settle
        return self.endpoints

    def stop(self):
        self._stop_event.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=1)


if __name__ == "__main__":
    lab = MockLab(count=50)
    endpoints = lab.start()
    print(f"Mock lab up: {len(endpoints)} endpoints, ports "
          f"{endpoints[0][1]}-{endpoints[-1][1]}")
    time.sleep(1)
    lab.stop()
    print("Mock lab stopped.")
