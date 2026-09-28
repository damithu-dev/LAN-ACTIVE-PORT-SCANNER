"""exporters/json_exporter.py -- Week 4 (Senura): serialize scan results to JSON."""
import json
from typing import List, Dict


def export_json(rows: List[Dict], filepath: str) -> None:
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
