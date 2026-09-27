"""
cve/cve_mapper.py
------------------
Week 8 (Damithu, Day 50-51): offline CVE lookup engine.

Parses a raw service banner string (e.g. "SSH-2.0-OpenSSH_7.2p2 ...") into
a (service, version) pair, then looks that pair up against the offline
nvd_mock_db.json dictionary. Designed to be swapped for a real, periodically
refreshed NVD dataset later without changing the calling code.

Week 10 QA fix (Damithu, Day 64-65): when this project is bundled with
PyInstaller in --onefile mode, files are extracted at runtime to a temp
folder referenced by sys._MEIPASS, NOT to the path next to this source
file. The original `Path(__file__).parent` lookup worked when running
from source but raised FileNotFoundError inside the packaged binary --
found while QA-testing the Week 10 executable. Fixed by resolving the
data file relative to sys._MEIPASS when frozen, falling back to the
source-relative path otherwise. See packaging/build_pyinstaller.sh,
which also had to be updated to explicitly --add-data the cve/ folder.
"""
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    DB_PATH = Path(sys._MEIPASS) / "cve" / "nvd_mock_db.json"
else:
    DB_PATH = Path(__file__).parent / "nvd_mock_db.json"

# (regex, service_name) pairs, checked in order. Add new services here.
_PATTERNS = [
    (re.compile(r"OpenSSH[_ ]([\w.]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"Apache/([\w.]+)", re.IGNORECASE), "Apache httpd"),
    (re.compile(r"ProFTPD ([\w.]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"nginx/([\w.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"Microsoft-IIS/([\w.]+)", re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"vsFTPd ([\w.]+)", re.IGNORECASE), "vsftpd"),
]


@dataclass
class CveMatch:
    service: Optional[str]
    version: Optional[str]
    cve_id: Optional[str]
    cvss_score: Optional[float]
    severity: Optional[str]
    summary: Optional[str]


def parse_banner(banner: str):
    """Extract (service, version) from a raw banner string, or (None, None)."""
    for pattern, service_name in _PATTERNS:
        match = pattern.search(banner)
        if match:
            return service_name, match.group(1)
    return None, None


def _load_db() -> List[dict]:
    with open(DB_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["entries"]


def lookup(service: str, version: str, db: Optional[List[dict]] = None) -> Optional[dict]:
    db = db if db is not None else _load_db()
    for entry in db:
        if entry["service"] == service and entry["version"] == version:
            return entry
    return None


def map_banner_to_cve(banner: str, db: Optional[List[dict]] = None) -> CveMatch:
    """Full pipeline: banner string -> parsed service/version -> CVE record."""
    service, version = parse_banner(banner)
    if not service:
        return CveMatch(None, None, None, None, None, None)

    entry = lookup(service, version, db=db)
    if entry:
        return CveMatch(
            service=service,
            version=version,
            cve_id=entry["cve_id"],
            cvss_score=entry["cvss_score"],
            severity=entry["severity"],
            summary=entry["summary"],
        )
    return CveMatch(
        service=service, version=version, cve_id=None,
        cvss_score=None, severity=None, summary=None,
    )
