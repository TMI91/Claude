# traffic_monitor

A passive network traffic capture and analysis tool. Monitors all traffic in and out of this machine, tracks per-IP statistics (bytes, packets, ports, protocols), detects anomalies, and provides an automatic analysis of what it finds.

## Requirements

- Python 3.10+
- [Npcap](https://npcap.com/) installed — bundled with Nmap (`winget install nmap`)
- Run as **Administrator** (raw socket capture)

```bash
pip install -r requirements.txt
```

## Usage

```
python traffic_monitor.py [--interface NIC [NIC ...]] [--duration SEC]
                          [--mode MODE] [--output FILE] [--filter EXPR]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--interface` | interactive picker | NIC name(s); omit to get a numbered selection menu |
| `--duration` | `30` | Capture duration in seconds |
| `--mode` | `live` | `live` (real-time table) or `quiet` (silent, summary at end) |
| `--output` | none | Save report as JSON + Markdown (e.g. `capture.json`) |
| `--filter` | none | BPF filter expression (e.g. `"host 192.168.1.1"`) |

### Help

```bash
python traffic_monitor.py ?        # also: /? --? -?  or  --help
```

### Examples

```bash
# Start with defaults: Wi-Fi, 30s, live display
python traffic_monitor.py

# Capture 60 seconds on Wi-Fi, save report
python traffic_monitor.py --duration 60 --output capture.json

# Capture on two interfaces simultaneously
python traffic_monitor.py --interface Wi-Fi Ethernet --duration 60

# Investigate a specific host
python traffic_monitor.py --filter "host 192.168.1.50" --duration 30 --mode quiet --output host.json

# Run without the interface picker (skip straight to capture)
python traffic_monitor.py --interface Wi-Fi
```

### Default behaviour

Running with no arguments shows the available interfaces and lets you choose:

```
Available interfaces:
  1  Wi-Fi       192.168.178.162  Realtek 8822CE Wireless LAN  *
  2  Ethernet    (no IP)          Intel Ethernet Connection

  Type number(s) to capture on (e.g. 1 or 1 2), or press Enter for default [Wi-Fi]:

Network Traffic Monitor
  Interface : Wi-Fi  (other: Ethernet)
  Duration  : 30s    (other: until Ctrl+C)
  Mode      : live   (other: quiet)
```

Press **Enter** to start immediately with the marked default, or type a number (or multiple numbers separated by spaces) to select different interfaces.

## Live display

The live table refreshes every 2 seconds and shows the top-10 remote IPs by traffic volume:

```
Network Traffic Monitor  Wi-Fi | 28s elapsed — 1,808 packets

  Remote IP         Hostname          In        Out   Pkts   Protocols   Top Ports   Alert
  34.107.218.251    amazonaws.com   255.3 KB   14.8 KB  318   TCP, UDP   443, 443/UDP
  185.159.159.148   protonmail.ch   151.0 KB    2.8 KB  171   TCP        443
  ...
```

The **Alert** column shows the anomaly type and detail when something is flagged.

## Output

At the end of each capture:

- **Capture Summary** — duration, total packets, top-5 talkers
- **Anomalies** — full table with severity, type, and detail
- **Traffic Analysis** — automatic interpretation:
  - Local network devices (RFC 1918 addresses) listed separately
  - External IPs classified by provider (Google, Microsoft, AWS, Cloudflare, etc.)
  - Observations about common patterns (QUIC/HTTP3, NetBIOS, DNS resolvers, unencrypted HTTP)
  - Recommendations for unrecognised IPs with notable traffic, including a ready-to-run `--filter` command

With `--output`:
- **`.json`** — full flow table, anomaly list, and capture metadata
- **`.md`** — Markdown report with summary table, anomaly section, and full flow table in a collapsible block

## Anomaly detection

| Type | Threshold | Severity |
|------|-----------|----------|
| Port scan | > 15 unique destination ports from one IP | HIGH |
| High volume | > 50 MB transferred by one IP | MEDIUM |
| Suspicious port | Port in known-bad registry (Metasploit, Tor, Docker unencrypted, backdoors, …) | CRITICAL – LOW |
| Unexpected protocol | Non-TCP/UDP/ICMP/IGMP protocol observed | LOW |

## Scope limitation

On a **switched LAN**, only traffic to/from this machine and broadcast/multicast frames are visible. Switch hardware does not forward other hosts' unicast frames to your NIC.

To monitor all hosts on the subnet:
- **Managed switch** — enable port mirroring (mirror all ports to this machine's port)
- **Router/gateway** — run the tool directly on the router (OpenWrt/Linux)
- **Unmanaged network** — replace the switch with a hub

## Architecture

`traffic_monitor.py` is a single-file script with seven layers:

1. **Config registries** — `WELL_KNOWN_PORTS`, `SUSPICIOUS_PORTS`, `PROTOCOL_NAMES`, `KNOWN_PROVIDERS`, anomaly thresholds, severity colours
2. **Network helpers** — `get_host_ip()`, `get_default_interface()`, `list_interfaces()`, `DNSCache` (async background reverse-DNS)
3. **FlowTable** — thread-safe in-memory per-IP stats; lock-protected for concurrent sniffer and display access
4. **Packet processor** — scapy `prn` callback; extracts IP/TCP/UDP/ARP fields, determines direction, calls `FlowTable.update()`; re-parses as Ethernet when scapy falls back to a generic frame class (common on Wi-Fi)
5. **Sniffer thread** — `scapy.sniff()` with `store=False` on a daemon thread; `threading.Event` coordinates shutdown; BPF filter with Python-level fallback when the interface datalink type cannot be determined
6. **Anomaly detector** — `detect_anomalies()` pure function; safe to call repeatedly during live display
7. **Reporting** — Rich live table; `_print_summary()`, `_print_analysis()`; `save_report()` writes JSON + Markdown
