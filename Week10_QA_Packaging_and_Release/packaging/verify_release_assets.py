"""
packaging/verify_release_assets.py
------------------------------------
Week 10 (Damithu, Day 68): final check of the assets attached to the
GitHub v1.0.0 release tag.

Confirms every expected file is present in packaging/release/ and that
each one's SHA-256 checksum matches SHA256SUMS.txt -- catching a
corrupted or incomplete upload before the release goes live.

Run:  python3 packaging/verify_release_assets.py
"""
import hashlib
import sys
from pathlib import Path

RELEASE_DIR = Path(__file__).parent / "release"
CHECKSUM_FILE = RELEASE_DIR / "SHA256SUMS.txt"
REQUIRED_FILES = ["lanscanner-linux-x86_64", "README.md", "RC1_signoff.md"]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not CHECKSUM_FILE.exists():
        print(f"ERROR: {CHECKSUM_FILE} not found. Run this after building the release folder.")
        return 1

    expected = {}
    for line in CHECKSUM_FILE.read_text().splitlines():
        digest, _, name = line.strip().partition("  ")
        expected[name.strip()] = digest.strip()

    all_ok = True
    print(f"{'File':35} {'Present':10} {'Checksum OK':12}")
    print("-" * 60)
    for name in REQUIRED_FILES:
        path = RELEASE_DIR / name
        present = path.exists()
        checksum_ok = False
        if present and name in expected:
            checksum_ok = sha256_of(path) == expected[name]
        status_ok = present and checksum_ok
        all_ok = all_ok and status_ok
        print(f"{name:35} {'yes' if present else 'NO':10} {'yes' if checksum_ok else 'NO':12}")

    print("\nOVERALL:", "PASS -- release assets complete and uncorrupted" if all_ok
          else "FAIL -- do not publish this release yet")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
