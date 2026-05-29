# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

```
/                   — root, subproject index
vuln_scanner/       — network vulnerability scanner
  vuln_scanner.py
  requirements.txt
```

## vuln_scanner

```bash
cd vuln_scanner

# Install dependencies
pip install -r requirements.txt

# Run scanner (auto-detects local /24 subnet)
python vuln_scanner.py --mode normal

# Run with specific target and mode
python vuln_scanner.py --target 192.168.1.0/24 --mode fast
python vuln_scanner.py --target 192.168.1.1 --mode thorough --output report.json
```

Nmap must be installed system-wide (`winget install nmap`). Run as Administrator for raw socket access.

### Architecture

`vuln_scanner.py` is a single-file script with four layers:

1. **Risk registry** (`RISKY_PORTS`) — static dict mapping port numbers to `(service, severity, note)` tuples.
2. **Network helpers** — subnet auto-detection via outbound UDP socket to derive local /24.
3. **Scanning** — two-phase: `discover_hosts()` ping sweep, then `scan_host()` does port discovery first (no `-sV`) and targeted service/vuln scan only on open ports. Thorough mode uses T3 timing to avoid packet loss on home routers.
4. **Reporting** — Rich table to console; `save_report()` writes JSON + Markdown when `--output` is given.

Severity order: CRITICAL → HIGH → MEDIUM → LOW → INFO.
