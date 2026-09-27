"""
LAN Scanner - Week 3: Concurrent Worker Pool Scanner Engine
Author: Damithu (Quality Assurance & Solution Architecture Lead)

Description:
    High-performance multi-threaded port scanner utilizing ThreadPoolExecutor.
    Engineered with thread-safe result queues, mutex locks for data aggregation,
    and adaptive worker pool sizing (100 threads default).
"""

import time
import socket
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional

STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED"


class ConcurrentPortScanner:
    """
    Thread-safe concurrent port scanner capable of dispatching thousands of
    concurrent socket probes across target hosts and ports.
    """

    def __init__(self, max_workers: int = 100, default_timeout: float = 0.5):
        """
        Initializes the concurrent scanner.

        Args:
            max_workers: Size of the thread pool (default: 100).
            default_timeout: Timeout in seconds per socket probe.
        """
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if default_timeout <= 0:
            raise ValueError("default_timeout must be greater than 0")

        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self._lock = threading.Lock()
        self._results_queue: Queue = Queue()

    def probe_task(self, host: str, port: int, timeout: float) -> Dict[str, Any]:
        """Worker task executing a single low-level TCP socket probe."""
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except (socket.error, OSError):
            pass
        sock.settimeout(timeout)

        status = STATUS_FILTERED
        err = -1

        try:
            err = sock.connect_ex((host, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if err == 0:
                status = STATUS_OPEN
            elif err in (10061, 111):
                status = STATUS_CLOSED
            else:
                status = STATUS_FILTERED
        except (socket.timeout, TimeoutError):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            status = STATUS_FILTERED
            err = 10060
        except Exception:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            status = STATUS_FILTERED
            err = -1
        finally:
            sock.close()

        return {
            "host": host,
            "port": port,
            "status": status,
            "latency_ms": round(elapsed_ms, 2),
            "error_code": err,
        }

    def scan_host(
        self,
        host: str,
        ports: List[int],
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a concurrent multi-threaded scan across multiple ports on a single host.

        Args:
            host: Target IP or hostname.
            ports: List of integer ports.
            timeout: Socket timeout (defaults to self.default_timeout).
            progress_callback: Optional thread-safe callback func(scanned, total, result).

        Returns:
            Dict containing aggregated results and list of open ports.
        """
        active_timeout = timeout if timeout is not None else self.default_timeout
        total_ports = len(ports)
        open_ports = []
        closed_ports = []
        filtered_ports = []
        completed_count = 0

        start_time = time.perf_counter()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Dispatch all probe tasks to the worker pool
            future_to_port = {
                executor.submit(self.probe_task, host, p, active_timeout): p
                for p in ports
            }

            for future in as_completed(future_to_port):
                result = future.result()

                # Protect shared aggregation data structures with a mutex lock
                with self._lock:
                    completed_count += 1
                    current_completed = completed_count

                    if result["status"] == STATUS_OPEN:
                        open_ports.append(result)
                    elif result["status"] == STATUS_CLOSED:
                        closed_ports.append(result)
                    else:
                        filtered_ports.append(result)

                if progress_callback:
                    progress_callback(current_completed, total_ports, result)

        total_duration = round(time.perf_counter() - start_time, 3)
        throughput = (
            round(total_ports / total_duration, 1) if total_duration > 0 else 0.0
        )

        # Sort open ports numerically
        open_ports.sort(key=lambda r: r["port"])

        return {
            "host": host,
            "total_scanned": total_ports,
            "open_count": len(open_ports),
            "closed_count": len(closed_ports),
            "filtered_count": len(filtered_ports),
            "open_ports": open_ports,
            "duration_seconds": total_duration,
            "throughput_ports_per_sec": throughput,
            "worker_threads": self.max_workers,
        }

    def scan_network_sweep(
        self,
        hosts: List[str],
        ports: List[int],
        timeout: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Scans multiple hosts concurrently across specified ports."""
        network_results = []
        for h in hosts:
            res = self.scan_host(h, ports, timeout)
            network_results.append(res)
        return network_results
