"""
Unit Test Suite for UI Adapter, Callback Throttling & Exception Mapping
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import socket
import time
from pathlib import Path
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.ui_adapter import (
    validate_ui_scan_payload,
    ThrottledProgressCallback,
    handle_scanner_exception_for_ui,
)


def test_valid_payload_contract():
    payload = {
        "host": "10.0.0.1",
        "total_scanned": 10,
        "open_count": 1,
        "duration_seconds": 0.42,
        "open_ports": [{"port": 80, "status": "OPEN"}],
    }
    assert validate_ui_scan_payload(payload) is True


def test_missing_mandatory_keys():
    incomplete = {"host": "10.0.0.1", "total_scanned": 10}
    with pytest.raises(ValueError):
        validate_ui_scan_payload(incomplete)


def test_invalid_field_types():
    bad_type = {
        "host": 10001,  # Should be string
        "total_scanned": "10",  # Should be int
        "open_count": 0,
        "duration_seconds": 0.1,
        "open_ports": [],
    }
    with pytest.raises(TypeError):
        validate_ui_scan_payload(bad_type)


def test_throttled_callback_under_burst_load():
    """Verifies that 100 rapid events are throttled without dropping the final 100% notification."""
    events = []

    def ui_handler(current, total, pct):
        events.append((current, total, pct))

    throttler = ThrottledProgressCallback(ui_handler, min_interval_sec=0.05)

    # Dispatch 100 rapid events in 10ms
    for i in range(1, 101):
        throttler(i, 100, {"port": i})
        time.sleep(0.0001)

    assert len(events) < 100  # Proves throttling occurred
    # Crucial assertion: the final 100/100 event MUST always be delivered!
    final_event = events[-1]
    assert final_event[0] == 100
    assert final_event[1] == 100
    assert final_event[2] == 100.0


def test_ui_exception_card_generation():
    """Verifies mapping of system errors to clean user-facing UI messages."""
    dns_err = socket.gaierror("Name or service not known")
    card1 = handle_scanner_exception_for_ui(dns_err)
    assert card1["severity"] == "ERROR"
    assert "Invalid Target Host" in card1["title"]

    perm_err = PermissionError("Elevation needed")
    card2 = handle_scanner_exception_for_ui(perm_err)
    assert card2["severity"] == "WARNING"
    assert "Elevation Required" in card2["title"]
