"""exporters/csv_exporter.py -- Week 6 (Senura): flattened tabular CSV export."""
import csv
from typing import List, Dict


def export_csv(rows: List[Dict], filepath: str) -> None:
    if not rows:
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("")
        return
    fieldnames = list(rows[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
