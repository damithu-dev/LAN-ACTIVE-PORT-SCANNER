"""
main.py
--------
LAN Scanner & Active Port Scanner -- CLI entry point.

This is the single application that gets bundled by PyInstaller in Week 10
into a standalone Windows .exe / Linux binary. It ties together every
module built across the project:

    scanner.port_probe      -- Week 1-2  (TCP connect scanning)
    scanner.banner          -- Week 4    (service banner grabbing)
    scanner.concurrent_scan -- Week 3    (multi-threaded scanning + rate limit)
    cve.cve_mapper          -- Week 8    (offline CVE lookup)
    exporters.json_exporter -- Week 4    (JSON export)
    exporters.csv_exporter  -- Week 6    (CSV export)

Usage:
    python3 main.py --target 127.0.0.1 --ports 20-25,80,443
    python3 main.py --target 127.0.0.1 --ports 1-1024 --threads 100 --json out.json --csv out.csv
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console                       # noqa: E402
from rich.table import Table                           # noqa: E402

from scanner.banner import grab_banner                 # noqa: E402
from scanner.concurrent_scan import run_concurrent_scan  # noqa: E402
from scanner.port_probe import PortStatus               # noqa: E402
from cve.cve_mapper import map_banner_to_cve            # noqa: E402
from exporters.json_exporter import export_json          # noqa: E402
from exporters.csv_exporter import export_csv            # noqa: E402

console = Console()

STATUS_COLOR = {
    PortStatus.OPEN: "green",
    PortStatus.CLOSED: "red",
    PortStatus.FILTERED: "yellow",
}


def parse_ports(spec: str):
    """Parse '20-25,80,443' into a sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="lanscanner",
        description="LAN Scanner & Active Port Scanner (local/authorized-lab use only)",
    )
    parser.add_argument("--target", required=True, help="Target IP/hostname (e.g. 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024", help="Ports: '80', '20-25', '80,443,8080'")
    parser.add_argument("--threads", type=int, default=100, help="Thread pool size (default 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds")
    parser.add_argument("--min-interval", type=float, default=0.0,
                         help="Rate limit: minimum seconds between probes (0 = off)")
    parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
    parser.add_argument("--csv", metavar="FILE", help="Write results to a CSV file")
    parser.add_argument("--cve", action="store_true",
                         help="Grab banners and attempt offline CVE lookup on OPEN ports")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    ports = parse_ports(args.ports)
    targets = [(args.target, p) for p in ports]

    console.print(f"[bold cyan]LAN Scanner[/bold cyan] -- scanning {args.target} "
                  f"({len(ports)} ports, {args.threads} threads)")

    start = time.monotonic()
    report = run_concurrent_scan(
        targets, max_workers=args.threads, timeout=args.timeout, min_interval=args.min_interval
    )
    elapsed = time.monotonic() - start

    results = sorted(report.results, key=lambda r: r.port)

    table = Table(title=f"Scan results for {args.target}")
    table.add_column("Port", justify="right")
    table.add_column("Status")
    if args.cve:
        table.add_column("Banner")
        table.add_column("CVE")

    export_rows = []
    for result in results:
        status_text = f"[{STATUS_COLOR[result.status]}]{result.status.value}[/{STATUS_COLOR[result.status]}]"
        row = [str(result.port), status_text]
        export_row = {"host": result.host, "port": result.port, "status": result.status.value}

        if args.cve:
            banner = ""
            cve_text = ""
            if result.status == PortStatus.OPEN:
                banner = grab_banner(result.host, result.port, timeout=args.timeout)
                if banner:
                    match = map_banner_to_cve(banner)
                    if match.cve_id:
                        cve_text = f"[bold red]{match.cve_id}[/bold red] ({match.severity})"
                        export_row["cve_id"] = match.cve_id
                        export_row["severity"] = match.severity
            row += [banner[:40], cve_text]

        if result.status != PortStatus.FILTERED or args.timeout <= 1.0:
            table.add_row(*row)
        export_rows.append(export_row)

    console.print(table)
    open_count = sum(1 for r in results if r.status == PortStatus.OPEN)
    console.print(f"[bold]Done[/bold] in {elapsed:.2f}s -- "
                   f"{open_count} open / {len(results)} scanned "
                   f"({len(report.errors)} worker errors)")

    if args.json:
        export_json(export_rows, args.json)
        console.print(f"[green]JSON report written to {args.json}[/green]")
    if args.csv:
        export_csv(export_rows, args.csv)
        console.print(f"[green]CSV report written to {args.csv}[/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
