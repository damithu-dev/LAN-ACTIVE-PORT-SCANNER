#!/bin/bash
# packaging/build_pyinstaller.sh
# ---------------------------------
# Week 10 (Damithu QA + Kevindu/Methul build): builds the standalone binary.
#
# IMPORTANT (Week 10 QA finding, Day 64-65): PyInstaller's --onefile mode
# only bundles Python code it can trace by import. Plain data files like
# cve/nvd_mock_db.json are NOT picked up automatically and must be added
# explicitly with --add-data, or the packaged binary crashes with
# FileNotFoundError the first time it tries to read them (see cve_mapper.py
# for the matching runtime-path fix, and qa/reports/pyinstaller_qa_notes.md
# for how this was found).
#
# Usage (Linux / WSL):
#   bash packaging/build_pyinstaller.sh
#
# Usage (Windows, from a Windows Python install -- PyInstaller does NOT
# cross-compile, so a Windows .exe must be built ON a Windows machine):
#   py -m pip install pyinstaller rich
#   py -m PyInstaller --onefile --name lanscanner --add-data "cve;cve" main.py

set -e
cd "$(dirname "$0")/.."

python3 -m PyInstaller --onefile --name lanscanner \
    --add-data "$(pwd)/cve/nvd_mock_db.json:cve" \
    --distpath packaging/dist \
    --workpath packaging/build \
    --specpath packaging \
    main.py

echo ""
echo "Build complete: packaging/dist/lanscanner"
echo "Verify with:    python3 packaging/verify_binary.py"
