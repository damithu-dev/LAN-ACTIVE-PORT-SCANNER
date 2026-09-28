"""
LAN Scanner - Week 7: Export Manager & File Integrity Validator
Author: Damithu (Quality Assurance & Solution Architecture Lead)
"""

import csv
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from pathlib import Path


def export_to_json(scan_data: Dict[str, Any], filepath: str) -> bool:
    """Exports scan results to JSON file format with indentation."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=4)
    return validate_file_integrity(filepath, expected_format="json")


def export_to_csv(scan_data: Dict[str, Any], filepath: str) -> bool:
    """Exports open port details to a structured CSV file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    host = scan_data.get("host", "unknown")
    open_ports = scan_data.get("open_ports", [])

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Status", "Latency_ms", "Service", "Version"])
        for item in open_ports:
            writer.writerow([
                host,
                item.get("port", ""),
                item.get("status", "OPEN"),
                item.get("latency_ms", 0.0),
                item.get("service", "unknown"),
                item.get("version", "unknown"),
            ])

    return validate_file_integrity(filepath, expected_format="csv")


def export_to_xml(scan_data: Dict[str, Any], filepath: str) -> bool:
    """Exports scan results to standard hierarchical XML format."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    root = ET.Element("LANScannerReport")
    host_elem = ET.SubElement(root, "Host", ip=str(scan_data.get("host", "")))
    host_elem.set("totalScanned", str(scan_data.get("total_scanned", 0)))
    host_elem.set("durationSec", str(scan_data.get("duration_seconds", 0.0)))

    ports_elem = ET.SubElement(host_elem, "OpenPorts")
    for item in scan_data.get("open_ports", []):
        p_elem = ET.SubElement(ports_elem, "Port", number=str(item.get("port", "")))
        p_elem.set("status", str(item.get("status", "OPEN")))
        p_elem.set("latencyMs", str(item.get("latency_ms", 0.0)))

    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return validate_file_integrity(filepath, expected_format="xml")


def validate_file_integrity(filepath: str, expected_format: str) -> bool:
    """
    Validates file existence, non-zero file size, and semantic format parsing.
    """
    path = Path(filepath)
    if not path.is_file() or path.stat().st_size == 0:
        return False

    try:
        if expected_format == "json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return isinstance(data, dict) and "host" in data
        elif expected_format == "csv":
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                return "Host" in header and "Port" in header
        elif expected_format == "xml":
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "LANScannerReport"
        return False
    except Exception:
        return False
