# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

```
/                        — root, subproject index
vuln_scanner/            — network vulnerability scanner
  vuln_scanner.py
  requirements.txt
traffic_monitor/         — passive network traffic capture and analysis
  traffic_monitor.py
  requirements.txt
wazuh_agent_emulator/    — Wazuh 4.x agent emulator (register, send, replay, stress)
  wazuh_agent_emulator.py
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

## wazuh_agent_emulator

```bash
cd wazuh_agent_emulator

# Install dependencies
pip install -r requirements.txt

# Register agent with manager, save key
python wazuh_agent_emulator.py --manager 10.0.0.1 --mode register --save-key agent.json

# Send synthetic events (auto-registers if no key file)
python wazuh_agent_emulator.py --manager 10.0.0.1 --mode send --duration 60 --rate 2

# Replay a log file
python wazuh_agent_emulator.py --manager 10.0.0.1 --mode replay --log-file auth.log --save-key agent.json

# Stress test: 10 agents, 5 ev/s total, 30 seconds
python wazuh_agent_emulator.py --manager 10.0.0.1 --mode stress --count 10 --rate 5 --duration 30
```

Requires a reachable Wazuh 4.x manager. Run as Administrator if needed.
`pycryptodome` enables Blowfish encryption (matches real agent wire format); without it the tool falls back to plaintext framing useful for local testing with netcat.

### Architecture

`wazuh_agent_emulator.py` is a single-file script with seven layers:

1. **WazuhKey** — dataclass holding agent identity + Blowfish key derivation (`MD5(name) + MD5(IP) + MD5(secret[:15])`). Serialises to/from JSON.
2. **WazuhRegistrar** — TCP 1515 registration handshake (`OSSEC A:'<name>'` → `OSSEC K:'<b64key>'`). Optional TLS (default on).
3. **MessageCrypto** — Blowfish CBC encryption with random IV and per-message counter + MD5 checksum payload format.
4. **WazuhAgentSession** — TCP 1514 session: sends 4-byte length-prefixed, encrypted frames. Handles startup handshake.
5. **EventGenerator** — synthetic syslog templates or line-by-line log file replay.
6. **AgentRunner** — orchestrates one agent: ensure key → connect → stream events. Thread-safe via `threading.Event` stop signal.
7. **StressRunner / CLI** — spawns N `AgentRunner` threads; Rich live table shows per-agent events, KB sent, errors, ev/s.
