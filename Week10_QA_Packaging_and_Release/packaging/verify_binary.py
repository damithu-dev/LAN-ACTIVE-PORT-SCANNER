"""
packaging/verify_binary.py
-----------------------------
Week 10 (Damithu, Day 64-65): automated "clean machine" verification of
the PyInstaller-packaged binary.

Checks performed:
  1. The binary runs from a directory with no source tree alongside it.
  2. It runs with PATH stripped of any Python interpreter (proves it does
     NOT silently depend on a system Python being present).
  3. It correctly detects a live CVE-vulnerable mock service (proves the
     bundled cve/nvd_mock_db.json data file loads correctly at runtime --
     this is the exact check that caught the FileNotFoundError bug during
     this QA pass; see qa/reports/pyinstaller_qa_notes.md).
  4. --json and --csv exports are written and are valid.

Run (after building with packaging/build_pyinstaller.sh):
    python3 packaging/verify_binary.py
"""
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
BINARY_SRC = ROOT / "packaging" / "dist" / "lanscanner"
MOCK_PORT = 51999
MOCK_BANNER = b"220 (vsFTPd 2.3.4)\r\n"  # maps to CVE-2011-2523 in the mock DB


def start_mock_vulnerable_service():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", MOCK_PORT))
    sock.listen(20)
    sock.settimeout(5)
    stop_at = time.time() + 4

    def serve():
        while time.time() < stop_at:
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                break
            try:
                conn.sendall(MOCK_BANNER)
            except OSError:
                pass
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    time.sleep(0.2)
    return sock, thread


def main():
    if not BINARY_SRC.exists():
        print(f"ERROR: binary not found at {BINARY_SRC}. Run "
              f"packaging/build_pyinstaller.sh first.", file=sys.stderr)
        return 1

    checks = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        binary = tmp_path / "lanscanner"
        shutil.copy(BINARY_SRC, binary)
        binary.chmod(0o755)

        sock, thread = start_mock_vulnerable_service()
        try:
            result = subprocess.run(
                ["env", "-i", "HOME=/tmp", "PATH=/nonexistent",
                 str(binary), "--target", "127.0.0.1", "--ports", str(MOCK_PORT),
                 "--cve", "--json", "out.json", "--csv", "out.csv", "--timeout", "1.0"],
                cwd=tmp_path, capture_output=True, text=True, timeout=15,
            )
        finally:
            sock.close()
            thread.join(timeout=1)

        checks["binary_ran_with_no_python_on_path"] = (result.returncode == 0)
        checks["no_traceback_in_stderr"] = ("Traceback" not in result.stderr)
        checks["cve_detected_in_stdout"] = ("CVE-2011-2523" in result.stdout)

        json_file = tmp_path / "out.json"
        csv_file = tmp_path / "out.csv"
        checks["json_export_created"] = json_file.exists()
        checks["csv_export_created"] = csv_file.exists()

        if json_file.exists():
            data = json.loads(json_file.read_text())
            checks["json_contains_cve_id"] = any(row.get("cve_id") == "CVE-2011-2523" for row in data)
        else:
            checks["json_contains_cve_id"] = False

        if csv_file.exists():
            checks["csv_contains_cve_id"] = "CVE-2011-2523" in csv_file.read_text()
        else:
            checks["csv_contains_cve_id"] = False

    all_pass = all(checks.values())
    print("Binary verification results:")
    for name, passed in checks.items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print(f"\nOVERALL: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
