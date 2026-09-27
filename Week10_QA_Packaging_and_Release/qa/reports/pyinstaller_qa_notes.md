# Week 10 — PyInstaller Packaging QA Notes (Damithu, Days 64-65)

## Bug #1 — CSV exporter crashed on mixed-schema rows

**Found:** while testing `--cve` mode export against a scan where an early
result had no CVE match and a later one did.

**Symptom:** `ValueError: dict contains fields not in fieldnames:
'cve_id', 'severity'` — the CSV writer took its column headers from only
the *first* result row, so any later row with extra keys crashed the
whole export.

**Fix:** `exporters/csv_exporter.py` now builds its header from the union
of keys across *all* rows, not just the first one, and fills missing
cells blank instead of raising.

**Regression test added:** `tests/test_regression.py::
test_csv_export_handles_rows_with_inconsistent_keys`

---

## Bug #2 — Packaged binary crashed loading the CVE database

**Found:** first real run of the PyInstaller `--onefile` binary against a
live mock vulnerable service.

**Symptom:**
```
FileNotFoundError: [Errno 2] No such file or directory:
'/tmp/_MEI000003.../cve/nvd_mock_db.json'
```

**Root cause:** PyInstaller's `--onefile` mode only auto-bundles Python
modules it can trace through imports. Plain data files (our CVE JSON
dictionary) are invisible to it unless explicitly listed with
`--add-data`. The code's `Path(__file__).parent` lookup also breaks once
frozen, because at runtime the app is unpacked into a temp folder
(`sys._MEIPASS`), not run from its original source location.

**Fix (two parts):**
1. `cve/cve_mapper.py` now detects `sys.frozen` / `sys._MEIPASS` and
   resolves the database path there when running as a packaged binary,
   falling back to the normal source-relative path otherwise.
2. `packaging/build_pyinstaller.sh` explicitly adds the data file with
   `--add-data ".../cve/nvd_mock_db.json:cve"`.

**Verification:** `packaging/verify_binary.py` runs the compiled binary
in a clean temp directory with `PATH` stripped of any Python interpreter,
against a live mock CVE-vulnerable service, and confirms the CVE is
correctly detected end-to-end (banner grab -> lookup -> JSON/CSV export)
— 7/7 checks PASS.

---

## Why this matters for the report

Both of these are exactly the class of bug this Week 10 QA pass exists to
catch: things that work perfectly when run as `python3 main.py` from the
source tree, but break the moment the application is packaged into the
single-file executable end users actually receive. Neither would have
been caught by the Week 9 regression suite alone, because that suite runs
against the source code, not the compiled artifact.

## Known scope limitation

This QA pass built and verified the **Linux** binary in full (PyInstaller
does not cross-compile — a Windows `.exe` must be built by running
PyInstaller *on* a Windows machine). The `packaging/build_pyinstaller.sh`
script's PowerShell equivalent is included for the team to run and verify
on an actual Windows test machine before the v1.0.0 release.
