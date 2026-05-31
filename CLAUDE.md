# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

```
/                   — root, subproject index
vuln_scanner/       — network vulnerability scanner
  vuln_scanner.py
  requirements.txt
traffic_monitor/    — passive network traffic capture and analysis
  traffic_monitor.py
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

## traffic_monitor

```bash
cd traffic_monitor

# Install dependencies
pip install -r requirements.txt

# Run with live display (Ctrl+C to stop)
python traffic_monitor.py --mode live

# Capture for 60 seconds, save report
python traffic_monitor.py --duration 60 --output capture.json

# Capture on a specific interface with BPF filter
python traffic_monitor.py --interface Wi-Fi --filter "host 192.168.1.1" --duration 30 --output filtered.json
```

Npcap must be installed (bundled with nmap: `winget install nmap`). Run as Administrator.

**Scope:** On a switched LAN, only traffic to/from this machine plus broadcasts is captured. For full-subnet visibility, enable port mirroring on your managed switch (mirror all ports to this machine's port), or run on the router/gateway directly.

### Architecture

`traffic_monitor.py` is a single-file script with seven layers:

1. **Config registries** — `WELL_KNOWN_PORTS`, `SUSPICIOUS_PORTS`, `PROTOCOL_NAMES`, anomaly threshold constants, `SEVERITY_ORDER`/`SEVERITY_COLORS`.
2. **Network helpers** — `get_host_ip()` via UDP socket, `get_default_interface()` via scapy `conf.ifaces`, `_format_bytes()`.
3. **FlowTable** — thread-safe in-memory per-IP stats (`bytes_in/out`, `packets_in/out`, `ports_contacted`, `protocols`, timestamps). Lock-protected for concurrent sniffer + display access.
4. **Packet processor** — scapy `prn` callback; extracts IP/TCP/UDP/ARP fields, determines direction vs `host_ip`, calls `FlowTable.update()`. Silently skips malformed packets.
5. **Sniffer thread** — `scapy.sniff()` with `store=False` on a daemon thread. `threading.Event` coordinates shutdown via `stop_filter`.
6. **Anomaly detector** — `detect_anomalies()` pure function; checks port scan, high volume, unexpected protocol, suspicious port.
7. **Reporting** — Rich live table (top-10 talkers, active alerts); `save_report()` writes JSON + Markdown when `--output` is given.

Severity order: CRITICAL → HIGH → MEDIUM → LOW → INFO.
