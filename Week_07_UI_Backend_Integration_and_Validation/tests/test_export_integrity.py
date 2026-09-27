"""
Unit Test Suite for Report Export Integrity (CSV, JSON, XML)
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
import tempfile
import os
from pathlib import Path
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.export_manager import (
    export_to_json,
    export_to_csv,
    export_to_xml,
    validate_file_integrity,
)


@pytest.fixture
def sample_scan_data():
    return {
        "host": "192.168.1.50",
        "total_scanned": 5,
        "duration_seconds": 0.25,
        "open_ports": [
            {"port": 22, "status": "OPEN", "latency_ms": 1.2, "service": "SSH", "version": "8.9"},
            {"port": 80, "status": "OPEN", "latency_ms": 0.9, "service": "HTTP", "version": "1.18"},
        ],
    }


def test_json_export_and_validation(sample_scan_data, tmp_path):
    target_file = str(tmp_path / "test_out.json")
    assert export_to_json(sample_scan_data, target_file) is True
    assert validate_file_integrity(target_file, "json") is True


def test_csv_export_and_validation(sample_scan_data, tmp_path):
    target_file = str(tmp_path / "test_out.csv")
    assert export_to_csv(sample_scan_data, target_file) is True
    assert validate_file_integrity(target_file, "csv") is True


def test_xml_export_and_validation(sample_scan_data, tmp_path):
    target_file = str(tmp_path / "test_out.xml")
    assert export_to_xml(sample_scan_data, target_file) is True
    assert validate_file_integrity(target_file, "xml") is True


def test_empty_or_corrupt_file_validation(tmp_path):
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("{ incomplete json ...", encoding="utf-8")
    assert validate_file_integrity(str(corrupt_file), "json") is False

    empty_file = tmp_path / "empty.csv"
    empty_file.write_text("", encoding="utf-8")
    assert validate_file_integrity(str(empty_file), "csv") is False
