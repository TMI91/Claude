# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run scanner (auto-detects local /24 subnet)
python vuln_scanner.py

# Run with specific target and mode
python vuln_scanner.py --target 192.168.1.0/24 --mode fast
python vuln_scanner.py --target 192.168.1.1 --mode thorough --output report.json
```

Nmap must be installed system-wide (`winget install nmap`). The script must run as Administrator for raw socket access.

## Architecture

`vuln_scanner.py` is a single-file script with four layers:

1. **Risk registry** (`RISKY_PORTS`) — static dict mapping port numbers to `(service, severity, note)` tuples.
2. **Network helpers** — subnet auto-detection via outbound UDP socket to derive local /24.
3. **Scanning** — `discover_hosts()` does a ping sweep (`-sn`), then `scan_host()` runs port/service/vuln scan per host using `python-nmap`. Risk is assessed in `_assess_port()` which combines the static registry with live nmap NSE script output.
4. **Reporting** — `print_host_report()` renders a Rich table (falls back to plain text if Rich is not installed); `save_report()` writes JSON.

Output format is JSON (`--output`). Severity order: CRITICAL → HIGH → MEDIUM → LOW → INFO.
