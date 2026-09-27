# Release Candidate v1.0.0-RC1 — QA Sign-off

**Signed off by:** Damithu (Quality Assurance, Solution Architecture)
**Date of sign-off:** Week 9, Day 62

## Gate results

| Gate | Tool / Script | Result |
|---|---|---|
| Master regression suite | `pytest tests/` | 26 / 26 PASSED |
| Code coverage | `pytest --cov` | 99% (target: >95%) — PASS |
| Static security scan | Bandit | 0 High, 0 Medium issues — PASS |
| Style / lint | Flake8 | 0 issues — PASS |
| Hardcoded credential scan | manual regex sweep | 0 findings — PASS |
| Rate-limiting under low bandwidth | `tests/test_rate_limit.py` | PASS |
| 500-thread concurrency stress test | `stress/stress_test_concurrency.py` | PASS, no errors at any thread level |
| 12-hour soak (accelerated, 200 cycles) memory profile | `stress/memory_profile_test.py` | PASS, 0.73 KB/iteration drift (well under leak threshold) |
| Abrupt host-shutdown error recovery | `qa/error_recovery_test.py` | PASS, 0 unhandled exceptions |
| CVE lookup precision/recall | `qa/cve_benchmark.py` | 100% precision, 100% recall on the 8-case mock dataset |

## Decision

All QA gates above are met. **Release Candidate v1.0.0-RC1 is approved for code freeze** and hand-off to Week 10 packaging.

## Known limitations carried into RC1 (documented, not blocking)

- The CVE dataset is a small offline mock set (8 test cases / 6 CVE records) built for pipeline validation, not a full NVD mirror. Any real-world use needs the offline dictionary refreshed from the actual NVD feed.
- The Week 8 "Docker lab" and "500-thread stress test" were run against a 50-endpoint local mock service lab (127.0.0.1) rather than real multi-container Docker infrastructure, because the QA sandbox this project was authored in cannot reliably run Docker-in-Docker. The test *objective* (many concurrent addressable services under load) was preserved; this substitution is recorded here for transparency and should be re-run against real Docker infrastructure before any external deployment.
