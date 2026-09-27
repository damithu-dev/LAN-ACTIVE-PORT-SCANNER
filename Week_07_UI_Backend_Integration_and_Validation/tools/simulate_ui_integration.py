"""
Week 7: Headless UI Integration & Export Pipeline Simulator
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.ui_adapter import validate_ui_scan_payload, ThrottledProgressCallback
from scanner.export_manager import export_to_json, export_to_csv, export_to_xml


def run_ui_simulation():
    print("=" * 60)
    print("       HEADLESS UI INTEGRATION & EXPORT SIMULATOR")
    print("=" * 60)

    # Simulated scan results payload
    mock_payload = {
        "host": "192.168.1.100",
        "total_scanned": 100,
        "open_count": 3,
        "closed_count": 97,
        "filtered_count": 0,
        "duration_seconds": 1.45,
        "open_ports": [
            {"port": 22, "status": "OPEN", "latency_ms": 1.2, "service": "OpenSSH", "version": "8.9p1"},
            {"port": 80, "status": "OPEN", "latency_ms": 0.8, "service": "Nginx", "version": "1.18.0"},
            {"port": 443, "status": "OPEN", "latency_ms": 1.5, "service": "Nginx", "version": "1.18.0"},
        ],
    }

    print("[*] Validating UI Payload Contract...")
    is_valid = validate_ui_scan_payload(mock_payload)
    print(f"    Payload Schema Validation: {'PASSED [OK]' if is_valid else 'FAILED'}")

    print("\n[*] Testing Throttled Callback Dispatcher (50 rapid updates)...")
    ui_render_count = 0

    def mock_ui_renderer(current, total, pct):
        nonlocal ui_render_count
        ui_render_count += 1
        print(f"    [UI Screen Render] Progress: {current}/{total} ({pct}%)")

    throttler = ThrottledProgressCallback(mock_ui_renderer, min_interval_sec=0.05)
    for i in range(1, 101):
        throttler(i, 100, {"port": i, "status": "CLOSED"})
        time.sleep(0.002)  # High-frequency burst

    print(f"    Total Backend Invocations: 100")
    print(f"    Total UI Render Events:    {ui_render_count} (Render throttled to save CPU!)")

    print("\n[*] Generating Multi-Format Report Exports...")
    output_dir = Path("exports_output")
    json_ok = export_to_json(mock_payload, str(output_dir / "report.json"))
    csv_ok = export_to_csv(mock_payload, str(output_dir / "report.csv"))
    xml_ok = export_to_xml(mock_payload, str(output_dir / "report.xml"))

    print(f"    JSON Export Integrity: {'VALID [OK]' if json_ok else 'CORRUPT'}")
    print(f"    CSV Export Integrity:  {'VALID [OK]' if csv_ok else 'CORRUPT'}")
    print(f"    XML Export Integrity:  {'VALID [OK]' if xml_ok else 'CORRUPT'}")
    print("=" * 60)


if __name__ == "__main__":
    run_ui_simulation()
