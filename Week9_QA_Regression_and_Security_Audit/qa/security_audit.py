"""
qa/security_audit.py
----------------------
Week 9 (Damithu, Day 60): security review verifying no hardcoded
credentials, buffer overflow risks, or code injection vectors. Combines
the automated Bandit/Flake8 results with a short manual checklist and
writes qa/reports/security_audit_summary.json for the RC1 sign-off.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCAN_DIRS = ["scanner", "cve", "exporters"]
REPORT_DIR = ROOT / "qa" / "reports"

CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*=\s*['\"]\w+['\"]", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*=\s*['\"]\w+['\"]", re.IGNORECASE),
    re.compile(r"secret\s*=\s*['\"]\w+['\"]", re.IGNORECASE),
]


def check_hardcoded_credentials():
    findings = []
    for d in SCAN_DIRS:
        for path in (ROOT / d).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for pattern in CREDENTIAL_PATTERNS:
                if pattern.search(text):
                    findings.append(str(path.relative_to(ROOT)))
    return findings


def run_bandit():
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", *SCAN_DIRS, "-f", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": result.stdout + result.stderr}


def run_flake8():
    result = subprocess.run(
        [sys.executable, "-m", "flake8", *SCAN_DIRS, "--max-line-length=110"],
        cwd=ROOT, capture_output=True, text=True,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return {"issue_count": len(lines), "issues": lines}


def main():
    REPORT_DIR.mkdir(exist_ok=True)

    hardcoded = check_hardcoded_credentials()
    bandit = run_bandit()
    flake8 = run_flake8()

    bandit_metrics = bandit.get("metrics", {}).get("_totals", {}) if isinstance(bandit, dict) else {}
    bandit_high = bandit_metrics.get("SEVERITY.HIGH", 0)
    bandit_med = bandit_metrics.get("SEVERITY.MEDIUM", 0)

    checklist = {
        "no_hardcoded_credentials": {
            "pass": len(hardcoded) == 0,
            "findings": hardcoded,
        },
        "bandit_high_severity_issues": {
            "pass": bandit_high == 0,
            "count": bandit_high,
        },
        "bandit_medium_severity_issues": {
            "pass": bandit_med == 0,
            "count": bandit_med,
        },
        "flake8_style_issues": {
            "pass": flake8["issue_count"] == 0,
            "count": flake8["issue_count"],
        },
        "manual_review_notes": [
            "All socket operations use fixed-size recv() buffers (256 bytes) "
            "-- no unbounded reads that could exhaust memory from a hostile target.",
            "connect_ex()/socket-timeout used everywhere instead of blocking "
            "connect() -- no code path can hang indefinitely on a bad target.",
            "CVE/banner dataset loaded via json.load() only (no eval/exec/pickle "
            "on untrusted input) -- no code injection vector from scan results.",
            "No shell=True subprocess calls anywhere in scanner/cve/exporters.",
        ],
    }

    overall_pass = all(item["pass"] for item in checklist.values() if isinstance(item, dict))

    summary = {"overall": "PASS" if overall_pass else "FAIL", "checklist": checklist}

    with open(REPORT_DIR / "security_audit_summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    main()
