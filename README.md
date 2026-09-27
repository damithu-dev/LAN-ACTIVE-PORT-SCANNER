# LAN Scanner & Active Port Scanner

A Python-based network discovery and active port scanning tool, built over a
10-week team sprint. It combines host discovery, multi-threaded TCP/UDP/SYN
port probing, service banner detection, offline CVE lookups, and multi-format
reporting (CSV/JSON) into a single CLI tool — packaged as a standalone
executable via PyInstaller.

> ⚠️ **For local/authorized-lab use only.** Port scanning and discovery tests
> must strictly target local loopback (`127.0.0.1`) or an explicitly
> authorized network/lab environment. Do not scan networks or hosts you do
> not own or have permission to test.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Kali Linux](#kali-linux)
  - [VirtualBox (Ubuntu/Debian guest)](#virtualbox-ubuntudebian-guest)
  - [Windows PowerShell](#windows-powershell)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Team & Roles](#team--roles)
- [Releases](#releases)
- [License](#license)

## Features

- **Host & port discovery** — TCP connect scanning across single ports, comma
  lists, and ranges (`80`, `20-25`, `80,443,8080`)
- **Concurrent scanning** — multi-threaded scan engine (`ThreadPoolExecutor`)
  with a configurable thread pool and optional rate limiting
- **Service detection** — banner grabbing on open ports to identify running
  services
- **Offline CVE mapping** — matches grabbed service banners against a local
  vulnerability dataset to flag known CVEs and severity
- **Multi-format export** — save scan results to JSON and CSV
- **Rich terminal output** — colored, tabulated results (green/red/yellow for
  open/closed/filtered)
- **Standalone executable** — no Python installation required to run the
  compiled release binary

## Installation

Requires Python 3.10+ if running from source.

### Kali Linux

```bash
git clone https://github.com/YOUR_USERNAME/LAN-ACTIVE-PORT-SCANNER.git
cd LAN-ACTIVE-PORT-SCANNER
python3 -m venv venv
source venv/bin/activate
pip install rich pytest
python3 main.py --target 127.0.0.1 --ports 20-25,80,443
```

### VirtualBox (Ubuntu/Debian guest)

Same as above inside your VM. If scanning anything beyond the VM itself,
set the VM's network adapter to **Bridged** (not NAT) so it can see other
hosts on the LAN — but only within your own authorized lab network.

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip
git clone https://github.com/YOUR_USERNAME/LAN-ACTIVE-PORT-SCANNER.git
cd LAN-ACTIVE-PORT-SCANNER
python3 -m venv venv
source venv/bin/activate
pip install rich pytest
python3 main.py --target 127.0.0.1 --ports 1-1024
```

### Windows PowerShell

```powershell
git clone https://github.com/YOUR_USERNAME/LAN-ACTIVE-PORT-SCANNER.git
cd LAN-ACTIVE-PORT-SCANNER
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install rich pytest
python main.py --target 127.0.0.1 --ports 20-25,80,443
```

> If PowerShell blocks the activation script, run it as Administrator once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Or just run the compiled release binary

No Python setup needed — download the executable from the
[Releases](#releases) page and run it directly:

```bash
./lanscanner-linux-x86_64 --target 127.0.0.1 --ports 1-1024
```

## Usage

```
usage: lanscanner --target TARGET [--ports PORTS] [--threads THREADS]
                   [--timeout TIMEOUT] [--min-interval MIN_INTERVAL]
                   [--json FILE] [--csv FILE] [--cve]

Required:
  --target        Target IP/hostname (e.g. 127.0.0.1)

Optional:
  --ports          Ports to scan (default: 1-1024). Examples: '80', '20-25', '80,443,8080'
  --threads        Thread pool size (default: 100)
  --timeout        Per-port timeout in seconds (default: 0.5)
  --min-interval   Minimum seconds between probes, for rate limiting (default: 0 = off)
  --json FILE      Write results to a JSON file
  --csv FILE       Write results to a CSV file
  --cve            Grab banners and attempt offline CVE lookup on open ports
```

**Examples:**

```bash
# Basic scan
python3 main.py --target 127.0.0.1 --ports 20-25,80,443

# Full port range, more threads, export to both formats
python3 main.py --target 127.0.0.1 --ports 1-1024 --threads 100 --json out.json --csv out.csv

# With banner grabbing + CVE lookup
python3 main.py --target 127.0.0.1 --ports 1-1024 --cve
```

## Project Structure

```
LAN Scanner/
├── Week_01_Setup_and_Subnet_Discovery/
├── Week_02_Base_Port_Scanner/
├── Week_03_Concurrency_and_Speed_Optimization/
├── Week_04_Service_Detection_and_Banner_Grabbing/
├── Week_05_Testing_Lab_Benchmarking_Docker/
├── Week_06_Advanced_Probing_Raw_SYN_UDP/
├── Week_07_UI_Backend_Integration_and_Validation/
├── Week_08_CVE_Vulnerability_Mapping_and_Stress_Testing/
├── Week9_QA_Regression_and_Security_Audit/
└── Week10_QA_Packaging_and_Release/
    ├── main.py                # CLI entry point (final build)
    ├── scanner/                # core scan engine
    ├── exporters/              # JSON/CSV export
    ├── cve/                    # offline CVE mapping
    ├── tests/                  # pytest suite
    └── packaging/              # PyInstaller build config + release assets
```

Each week's folder contains that week's incremental build, tests, and a
technical/architecture report documenting the work done. Week 10 contains the
final, integrated version of the tool.

## Team & Roles

| Member | Role |
|---|---|
| Kevindu | Technical Lead, Project Coordinator, Communicator, Presentation Lead |
| Methul | Solution Architecture, Operational Lead |
| Damithu | Quality Assurance, Solution Architecture |
| Senura | User Experience Lead, Research & Documentation Lead |
| Ayami | Communication & Presentation Lead, Research & Documentation Lead |

## Releases

Compiled standalone binaries (no Python installation required) are published
under [Releases](../../releases) — see **v1.0.0** for the final build.

## License
MIT License

Copyright (c) 2026 Damithu Randiv

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This project is licensed under the [MIT License](LICENSE) — see the `LICENSE`
file for the full text.
