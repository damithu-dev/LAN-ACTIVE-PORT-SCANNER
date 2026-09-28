"""
LAN Scanner - Week 7: UI/Backend Test Adapter & Progress Throttling Engine
Author: Damithu (Quality Assurance & Solution Architecture Lead)

Description:
    Decoupled adapter layer validating JSON schema contracts between scanning core
    and UI representations, with built-in callback debouncing to prevent UI event loop
    freezing during high-concurrency multi-threaded sweeps.
"""

import time
import json
import socket
import threading
from typing import Dict, Any, Callable, Optional, List


def validate_ui_scan_payload(payload: Dict[str, Any]) -> bool:
    """
    Validates that data emitted by scanner core adheres strictly to the UI data contract.

    Required fields:
        - 'host': str
        - 'total_scanned': int
        - 'open_count': int
        - 'open_ports': list of dicts (each containing 'port' and 'status')
        - 'duration_seconds': float
    """
    if not isinstance(payload, dict):
        raise TypeError("Payload must be a dictionary")

    required_keys = {"host", "total_scanned", "open_count", "open_ports", "duration_seconds"}
    for k in required_keys:
        if k not in payload:
            raise ValueError(f"Missing mandatory UI payload key: '{k}'")

    if not isinstance(payload["host"], str):
        raise TypeError("'host' must be a string")
    if not isinstance(payload["total_scanned"], int):
        raise TypeError("'total_scanned' must be an integer")
    if not isinstance(payload["open_count"], int):
        raise TypeError("'open_count' must be an integer")
    if not isinstance(payload["open_ports"], list):
        raise TypeError("'open_ports' must be a list")

    for item in payload["open_ports"]:
        if not isinstance(item, dict) or "port" not in item or "status" not in item:
            raise ValueError("Items in 'open_ports' must be dicts with 'port' and 'status'")

    return True


class ThrottledProgressCallback:
    """
    Throttles / debounces high-frequency callbacks emitted by 100+ concurrent threads,
    preventing UI GUI/CLI rendering event loops from freezing while ensuring 100%
    completion delivery.
    """

    def __init__(self, target_ui_callback: Callable[[int, int, float], None], min_interval_sec: float = 0.05):
        self.target_ui_callback = target_ui_callback
        self.min_interval_sec = min_interval_sec
        self.last_fired_time = 0.0
        self.lock = threading.Lock()
        self.call_count = 0

    def __call__(self, current: int, total: int, last_result: Dict[str, Any]):
        now = time.perf_counter()
        with self.lock:
            self.call_count += 1
            # Always fire on final completion or if time interval threshold has elapsed
            if current == total or (now - self.last_fired_time) >= self.min_interval_sec:
                percent = round((current / total) * 100.0, 1) if total > 0 else 100.0
                self.last_fired_time = now
                self.target_ui_callback(current, total, percent)


def handle_scanner_exception_for_ui(exc: Exception) -> Dict[str, str]:
    """Translates raw system/socket exceptions into user-friendly UI alert cards."""
    if isinstance(exc, (socket.gaierror, ValueError)):
        return {
            "severity": "ERROR",
            "title": "Invalid Target Host",
            "message": "The specified IP address or hostname could not be resolved. Please verify network syntax.",
        }
    elif isinstance(exc, PermissionError):
        return {
            "severity": "WARNING",
            "title": "Elevation Required",
            "message": "Raw socket stealth scanning requires administrative/root privileges. Running in fallback mode.",
        }
    elif isinstance(exc, OSError) and getattr(exc, "errno", 0) in (101, 10051):
        return {
            "severity": "ERROR",
            "title": "Network Interface Down",
            "message": "The network interface dropped or host is unreachable. Please verify Wi-Fi/Ethernet connection.",
        }
    else:
        return {
            "severity": "ERROR",
            "title": "Scanning Engine Error",
            "message": f"An unexpected error occurred during execution: {str(exc)}",
        }
