"""
tests/test_regression.py
--------------------------
Week 9 (Damithu, Day 57-58): master regression suite spanning the scanner
core, CVE mapper, and export helpers. Run with:

    pytest tests/ -v --cov=scanner --cov=cve --cov=exporters --cov-report=html
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.port_probe import probe_port, PortStatus  # noqa: E402
from scanner.banner import grab_banner  # noqa: E402
from scanner.concurrent_scan import run_concurrent_scan  # noqa: E402
from cve.cve_mapper import parse_banner, map_banner_to_cve  # noqa: E402
from exporters.json_exporter import export_json  # noqa: E402
from exporters.csv_exporter import export_csv  # noqa: E402
from stress.docker_lab_simulator import MockLab  # noqa: E402


# ---------- fixtures ----------

import pytest  # noqa: E402


@pytest.fixture(scope="module")
def mock_lab():
    lab = MockLab(count=5, base_port=48000)
    endpoints = lab.start()
    yield endpoints
    lab.stop()


# ---------- port_probe ----------

def test_probe_open_port(mock_lab):
    host, port = mock_lab[0]
    assert probe_port(host, port, timeout=1.0) == PortStatus.OPEN


def test_probe_closed_port():
    # Nothing listens here -> connection actively refused -> CLOSED
    assert probe_port("127.0.0.1", 48999, timeout=0.5) == PortStatus.CLOSED


def test_probe_filtered_on_timeout(monkeypatch):
    # FILTERED must be returned whenever the connect attempt times out.
    # A live "silently dropped by a firewall" target isn't reproducible
    # inside this sandbox's network egress, so the socket-level timeout is
    # simulated directly -- this keeps the test deterministic instead of
    # depending on a specific network's firewall behaviour (a real finding
    # from this QA pass, written up in the Week 9 report).
    import socket as socket_module

    class _TimeoutSocket:
        def settimeout(self, *_a, **_k):
            pass

        def connect_ex(self, *_a, **_k):
            raise socket_module.timeout()

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: _TimeoutSocket())
    assert probe_port("10.255.255.1", 81, timeout=0.3) == PortStatus.FILTERED


# ---------- banner ----------

def test_grab_banner_returns_text(mock_lab):
    host, port = mock_lab[0]
    banner = grab_banner(host, port, timeout=1.0)
    assert isinstance(banner, str)
    assert len(banner) > 0


def test_grab_banner_closed_port_returns_empty():
    assert grab_banner("127.0.0.1", 48999, timeout=0.3) == ""


# ---------- concurrent_scan ----------

def test_concurrent_scan_covers_all_targets(mock_lab):
    report = run_concurrent_scan(mock_lab, max_workers=10, timeout=1.0)
    assert len(report.results) == len(mock_lab)
    assert all(r.status == PortStatus.OPEN for r in report.results)


def test_concurrent_scan_no_worker_crashes_on_bad_targets():
    targets = [("127.0.0.1", 48999)] * 5
    report = run_concurrent_scan(targets, max_workers=5, timeout=0.3)
    assert len(report.errors) == 0
    assert all(r.status == PortStatus.CLOSED for r in report.results)


# ---------- CVE mapper ----------

@pytest.mark.parametrize("banner,expected_service,expected_version", [
    ("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10", "OpenSSH", "7.2p2"),
    ("Server: Apache/2.4.29 (Ubuntu)", "Apache httpd", "2.4.29"),
    ("Server: nginx/1.14.0 (Ubuntu)", "nginx", "1.14.0"),
])
def test_parse_banner(banner, expected_service, expected_version):
    service, version = parse_banner(banner)
    assert service == expected_service
    assert version == expected_version


def test_map_banner_to_known_cve():
    result = map_banner_to_cve("220 (vsFTPd 2.3.4)")
    assert result.cve_id == "CVE-2011-2523"
    assert result.severity == "CRITICAL"


def test_map_banner_unknown_service_returns_none():
    result = map_banner_to_cve("totally unrecognised banner string")
    assert result.cve_id is None
    assert result.service is None


# ---------- exporters ----------

def test_json_export_roundtrip(tmp_path):
    data = [{"host": "127.0.0.1", "port": 22, "status": "OPEN"}]
    out_file = tmp_path / "out.json"
    export_json(data, str(out_file))
    assert out_file.exists()
    import json
    loaded = json.loads(out_file.read_text())
    assert loaded == data


def test_csv_export_has_header_and_rows(tmp_path):
    data = [{"host": "127.0.0.1", "port": 22, "status": "OPEN"}]
    out_file = tmp_path / "out.csv"
    export_csv(data, str(out_file))
    content = out_file.read_text()
    assert "host,port,status" in content
    assert "127.0.0.1,22,OPEN" in content


def test_csv_export_empty_rows_writes_empty_file(tmp_path):
    out_file = tmp_path / "empty.csv"
    export_csv([], str(out_file))
    assert out_file.exists()
    assert out_file.read_text() == ""


# ---------- additional edge cases (Week 9 coverage push) ----------

def test_grab_banner_active_http_probe(mock_lab):
    # First endpoint in the mock lab sends its banner immediately (passive
    # path); force the active HTTP-probe branch by hitting a port that
    # accepts but sends nothing until spoken to isn't available in the mock
    # lab, so this exercises the same call path with a live OPEN port and
    # confirms it never raises.
    host, port = mock_lab[1]
    banner = grab_banner(host, port, timeout=1.0)
    assert isinstance(banner, str)


def test_grab_banner_connection_refused_returns_empty():
    assert grab_banner("127.0.0.1", 48998, timeout=0.3) == ""


def test_grab_banner_active_probe_path():
    # Server that waits silently for the client to speak first (HTTP-style),
    # exercising the passive-read-timeout -> active-HTTP-probe branch.
    import socket as socket_module
    import threading as threading_module

    srv = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    srv.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        conn.recv(256)  # wait for the HTTP HEAD probe
        conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
        conn.close()

    thread = threading_module.Thread(target=handle, daemon=True)
    thread.start()
    try:
        banner = grab_banner("127.0.0.1", port, timeout=1.0)
        assert "200 OK" in banner
    finally:
        srv.close()
        thread.join(timeout=1)


def test_grab_banner_active_probe_times_out_returns_empty():
    # Server that accepts but never replies to either the passive read or
    # the active HTTP probe -> both timeouts -> "" (line 36-37 in banner.py).
    import socket as socket_module
    import threading as threading_module

    srv = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    srv.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        import time as time_module
        time_module.sleep(0.5)
        conn.close()

    thread = threading_module.Thread(target=handle, daemon=True)
    thread.start()
    try:
        banner = grab_banner("127.0.0.1", port, timeout=0.1)
        assert banner == ""
    finally:
        srv.close()
        thread.join(timeout=1)


def test_map_banner_to_cve_service_known_version_unknown():
    # OpenSSH 8.9p1 is a real, patched service string with no CVE match
    # in the offline dataset -- must resolve cleanly with cve_id=None.
    result = map_banner_to_cve("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
    assert result.service == "OpenSSH"
    assert result.version == "8.9p1"
    assert result.cve_id is None


def test_run_concurrent_scan_empty_target_list():
    report = run_concurrent_scan([], max_workers=5)
    assert report.results == []
    assert report.errors == []


def test_scan_worker_catches_unexpected_exception(monkeypatch):
    # Forces probe_port to raise so _scan_one's defensive except-branch
    # (concurrent_scan.py lines 53-54) is exercised instead of a worker
    # thread crashing the whole pool.
    import scanner.concurrent_scan as concurrent_scan_module

    def _boom(*_a, **_k):
        raise RuntimeError("simulated worker fault")

    monkeypatch.setattr(concurrent_scan_module, "probe_port", _boom)
    report = run_concurrent_scan([("127.0.0.1", 1)], max_workers=1)
    assert len(report.results) == 1
    assert report.results[0].error == "simulated worker fault"
    assert "simulated worker fault" in report.errors[0]


def test_probe_port_unexpected_oserror_returns_filtered(monkeypatch):
    # port_probe.py's outer `except OSError` (e.g. network unreachable,
    # too many open files) must degrade to FILTERED, not raise.
    import socket as socket_module

    class _BrokenSocket:
        def settimeout(self, *_a, **_k):
            pass

        def connect_ex(self, *_a, **_k):
            raise OSError("simulated network unreachable")

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: _BrokenSocket())
    assert probe_port("10.0.0.1", 80, timeout=0.2) == PortStatus.FILTERED


def test_throttle_enforces_minimum_interval(mock_lab):
    import time as time_module
    start = time_module.monotonic()
    run_concurrent_scan(mock_lab[:3], max_workers=3, timeout=1.0, min_interval=0.05)
    elapsed = time_module.monotonic() - start
    # 3 targets at >=0.05s apart should take at least ~0.1s total
    assert elapsed >= 0.09
