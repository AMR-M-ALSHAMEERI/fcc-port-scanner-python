# FCC Port Scanner

A lightweight TCP port scanner built for the freeCodeCamp Information Security curriculum. It resolves hostnames, scans a port range, and can print a simple service table in verbose mode.

## Quick Start
- Requirements: Python 3.8+ and network access.
- Run the sample script: `py main.py`
- Call directly in your own code:
  - `port_scanner.get_open_ports("scanme.nmap.org", [20, 80])` → returns a list of open ports.
  - `port_scanner.get_open_ports("scanme.nmap.org", [20, 80], True)` → returns a formatted report.

## Project Files
- Core scanner logic: [port_scanner.py](port_scanner.py)
- Common port → service map: [common_ports.py](common_ports.py)
- Sample runner: [main.py](main.py)
- Tests: [test_module.py](test_module.py)

## Testing
Run the unit suite: `py -m unittest`

## Disclaimer
Built for the freeCodeCamp certification project and provided for educational use only. Do not use this scanner on networks or hosts without explicit permission.
