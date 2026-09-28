"""exporters/csv_exporter.py -- Week 6 (Senura): flattened tabular CSV export.

Week 10 QA fix (Damithu, Day 65): the original implementation derived its
column headers from only the first row's keys. Since --cve mode only adds
cve_id/severity keys to rows for OPEN ports with a known CVE, any export
where an early row lacked those keys crashed with
"ValueError: dict contains fields not in fieldnames" the moment a later
row had them. Fixed by taking the union of keys across all rows.
"""
import csv
from typing import List, Dict


def export_csv(rows: List[Dict], filepath: str) -> None:
    if not rows:
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("")
        return

    fieldnames = list(rows[0].keys())
    for row in rows[1:]:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, restval="")
        writer.writeheader()
        writer.writerows(rows)
