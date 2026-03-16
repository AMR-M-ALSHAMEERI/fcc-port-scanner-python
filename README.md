# FCC Port Scanner

A lightweight TCP port scanner built for the freeCodeCamp Information Security curriculum. It resolves hostnames, performs parallel scanning for extreme performance, and captures service banners upon connection.

## Features
- **Concurrent Scanning:** Uses multi-threading to scan hundreds of ports per second.
- **Flexible Port Input:** Supports single ports (`80`), domains (`20-30`), or mixed lists (`22,80,443,1000-2000`).
- **Banner Grabbing**: Actively retrieves service strings (like `HTTP/1.1`) to identify what application is running behind an open port.
- **Output Exports**: Run scans with `--output results.txt` to seamlessly save findings for later review.
- **Host Discovery (Ping Sweeps)**: Targets with a CIDR subnet mask (like `192.168.1.0/24`) or the `--sweep` flag automatically utilize hard-coded ICMP raw sockets to discover live hosts rapidly sweeping the network prior to executing port scans.

## Quick Start
- Requirements: Python 3.8+ and network access.
- You can run the scanner interactively via the built-in Command Line Interface (CLI). 

To view the **Help Manual**, run:
```bash
py main.py --help
```

### Usage Examples
Scan a local machine for a few common ports:
```bash
py main.py --target localhost --ports 20,22,80,443 -v
```

Scan a range of ports on an external server and save the output to a text file:
```bash
py main.py --target scanme.nmap.org --ports 1-1000 -v --output scan_results.txt
```

Scan a complete local subnet (/24) to find live hosts, then scan those specific live machines:
*(Note: Requires running your terminal as Administrator due to raw sockets)*
```bash
py main.py --target 192.168.1.0/24 --ports 80,443 -v
```

## Project Files
- Core scanner logic: [port_scanner.py](port_scanner.py)
- Common port → service map: [common_ports.py](common_ports.py)
- Sample runner: [main.py](main.py)
- Tests: [test_module.py](test_module.py)

## Testing
Run the unit suite: `py -m unittest`

## Disclaimer
Built for the freeCodeCamp certification project and provided for educational use only. Do not use this scanner on networks or hosts without explicit permission.
