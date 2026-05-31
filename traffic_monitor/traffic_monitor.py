"""
Passive network traffic capture and analysis tool.
Captures traffic to/from this machine and reports per-IP, per-port,
per-protocol statistics with basic anomaly detection.
"""

import argparse
import json
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Rich — graceful fallback to plain text
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.live import Live
    RICH = True
except ImportError:
    RICH = False

console = Console(force_terminal=True) if RICH else None


def _print(msg: str, style: str = "") -> None:
    if RICH:
        console.print(msg, style=style if style else None)
    else:
        import re
        print(re.sub(r"\[/?[^\]]*\]", "", msg))


# ---------------------------------------------------------------------------
# Config registries
# ---------------------------------------------------------------------------

WELL_KNOWN_PORTS = {
    20: "FTP-data",     21: "FTP",          22: "SSH",
    23: "Telnet",       25: "SMTP",         53: "DNS",
    67: "DHCP",         68: "DHCP",         80: "HTTP",
    110: "POP3",        123: "NTP",         135: "MSRPC",
    137: "NetBIOS-NS",  139: "NetBIOS",     143: "IMAP",
    161: "SNMP",        162: "SNMP-trap",   389: "LDAP",
    443: "HTTPS",       445: "SMB",         465: "SMTPS",
    514: "Syslog",      587: "SMTP-sub",    636: "LDAPS",
    993: "IMAPS",       995: "POP3S",       1080: "SOCKS",
    1433: "MSSQL",      1521: "Oracle",     3306: "MySQL",
    3389: "RDP",        4444: "Backdoor",   5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis",      8080: "HTTP-alt",   8443: "HTTPS-alt",
    8888: "Jupyter",    27017: "MongoDB",
}

SUSPICIOUS_PORTS = {
    23:    ("Telnet — plaintext remote shell", "CRITICAL"),
    4444:  ("Metasploit default listener", "CRITICAL"),
    12345: ("NetBus backdoor", "CRITICAL"),
    27374: ("Sub7 trojan", "CRITICAL"),
    31337: ("Elite/Back Orifice backdoor", "CRITICAL"),
    2375:  ("Docker daemon — unencrypted", "CRITICAL"),
    1337:  ("Common backdoor port", "HIGH"),
    4899:  ("Radmin remote admin", "HIGH"),
    5555:  ("Android ADB over network", "HIGH"),
    6666:  ("IRC — often C2 channel", "HIGH"),
    6667:  ("IRC — often C2 channel", "HIGH"),
    9001:  ("Tor default ORPort", "HIGH"),
    9050:  ("Tor SOCKS proxy", "HIGH"),
    1080:  ("SOCKS proxy — verify intent", "MEDIUM"),
    2376:  ("Docker TLS daemon", "MEDIUM"),
    8888:  ("Jupyter Notebook — often unauthenticated", "MEDIUM"),
}

PROTOCOL_NAMES = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6-in-IPv4",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

# Anomaly thresholds
PORT_SCAN_THRESHOLD        = 15
HIGH_VOLUME_BYTES          = 50 * 1024 * 1024   # 50 MB
UNEXPECTED_PROTO_WHITELIST = {1, 2, 6, 17}       # ICMP, IGMP, TCP, UDP
TOP_TALKERS_DISPLAY        = 10
LIVE_REFRESH_INTERVAL      = 2.0


# ---------------------------------------------------------------------------
# FlowTable — thread-safe per-IP traffic state
# ---------------------------------------------------------------------------

class FlowTable:
    def __init__(self, host_ip: str, ip_filter: str = "") -> None:
        self.host_ip = host_ip
        self.ip_filter = ip_filter   # Python-level IP filter when BPF unavailable
        self._lock = threading.Lock()
        self._flows: dict = {}
        self.total_packets = 0
        self.sniffer_warning: str = ""
        self.start_time = time.time()

    def _new_entry(self, ip: str) -> dict:
        return {
            "ip":              ip,
            "bytes_in":        0,
            "bytes_out":       0,
            "packets_in":      0,
            "packets_out":     0,
            "ports_contacted": set(),
            "protocols":       set(),
            "first_seen":      time.time(),
            "last_seen":       time.time(),
        }

    def update(self, pkt_info: dict) -> None:
        src = pkt_info["src_ip"]
        dst = pkt_info["dst_ip"]
        proto = pkt_info["proto_name"]
        length = pkt_info["length"]
        port = pkt_info.get("dport") or pkt_info.get("sport")

        if src == self.host_ip:
            remote = dst
            direction = "out"
        elif dst == self.host_ip:
            remote = src
            direction = "in"
        else:
            return  # not our traffic

        # Python-level IP filter fallback (used when BPF was unavailable)
        if self.ip_filter and self.ip_filter not in (src, dst):
            return

        now = time.time()
        with self._lock:
            if remote not in self._flows:
                self._flows[remote] = self._new_entry(remote)
            entry = self._flows[remote]
            entry["last_seen"] = now
            if direction == "out":
                entry["bytes_out"] += length
                entry["packets_out"] += 1
                if port:
                    entry["ports_contacted"].add((port, proto))
            else:
                entry["bytes_in"] += length
                entry["packets_in"] += 1
            entry["protocols"].add(proto)

    def snapshot(self) -> dict:
        with self._lock:
            result = {}
            for ip, entry in self._flows.items():
                result[ip] = {
                    **entry,
                    "ports_contacted": sorted(entry["ports_contacted"]),
                    "protocols":       sorted(entry["protocols"]),
                }
        return result

    def to_serializable(self) -> dict:
        snap = self.snapshot()
        for entry in snap.values():
            entry["first_seen"] = datetime.fromtimestamp(entry["first_seen"]).isoformat()
            entry["last_seen"]  = datetime.fromtimestamp(entry["last_seen"]).isoformat()
        return snap


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_host_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_default_interface() -> str:
    host_ip = get_host_ip()
    # Try scapy first (works when running as admin with Npcap)
    try:
        from scapy.config import conf
        if conf.ifaces:
            for iface_name, iface in conf.ifaces.items():
                if getattr(iface, "ip", None) == host_ip:
                    return iface_name
        if conf.iface:
            return str(conf.iface)
    except Exception:
        pass
    # Windows-native fallback: find adapter whose IP matches host_ip
    try:
        import subprocess
        out = subprocess.check_output(
            ["powershell", "-Command",
             f"Get-NetIPAddress -IPAddress {host_ip} | Select-Object -ExpandProperty InterfaceAlias"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        if out:
            return out.splitlines()[0].strip()
    except Exception:
        pass
    return "Wi-Fi"  # sensible Windows default


# ---------------------------------------------------------------------------
# DNS cache — async background reverse-lookup, never blocks the display
# ---------------------------------------------------------------------------

class DNSCache:
    def __init__(self) -> None:
        self._cache: dict = {}   # ip -> hostname string
        self._pending: set = set()
        self._lock = threading.Lock()

    def resolve(self, ip: str) -> str:
        """Return cached hostname, or ip itself while the background lookup runs."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                t = threading.Thread(target=self._lookup, args=(ip,), daemon=True)
                t.start()
        return ""   # blank until resolved

    def _lookup(self, ip: str) -> None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            hostname = self._shorten(hostname)
        except Exception:
            hostname = ""
        with self._lock:
            self._cache[ip] = hostname
            self._pending.discard(ip)

    @staticmethod
    def _shorten(hostname: str) -> str:
        """Keep the last 2 domain parts for long hostnames."""
        parts = hostname.rstrip(".").split(".")
        if len(parts) > 3:
            return ".".join(parts[-2:])
        return hostname


def _extract_ip_from_filter(bpf_filter: str) -> str:
    """Pull the target IP from simple BPF expressions like 'host X' or 'src X'."""
    import re
    m = re.match(r'^(?:host|src host|dst host|src|dst)\s+([\d.]+)$',
                 bpf_filter.strip(), re.IGNORECASE)
    return m.group(1) if m else ""


def _format_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


# ---------------------------------------------------------------------------
# Packet processor — scapy prn callback
# ---------------------------------------------------------------------------

def process_packet(pkt, flow_table: FlowTable) -> None:
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether, ARP

        # Count every raw packet received, regardless of whether we can decode it
        with flow_table._lock:
            flow_table.total_packets += 1


        # When scapy can't determine the datalink type it delivers a generic
        # Packet with no sub-layers. Re-parse as Ethernet so we get IP/TCP/UDP.
        if IP not in pkt and ARP not in pkt and Ether not in pkt:
            try:
                pkt = Ether(bytes(pkt))
            except Exception:
                return

        if ARP in pkt:
            arp = pkt[ARP]
            pkt_info = {
                "src_ip":    arp.psrc,
                "dst_ip":    arp.pdst,
                "proto_name": "ARP",
                "length":    len(pkt),
                "sport":     None,
                "dport":     None,
            }
            flow_table.update(pkt_info)
            return

        if IP not in pkt:
            return

        ip = pkt[IP]
        proto_name = PROTOCOL_NAMES.get(ip.proto, f"proto-{ip.proto}")
        sport = dport = None

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        pkt_info = {
            "src_ip":    ip.src,
            "dst_ip":    ip.dst,
            "proto_name": proto_name,
            "length":    ip.len,
            "sport":     sport,
            "dport":     dport,
        }
        flow_table.update(pkt_info)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_worker(iface: str, flow_table: FlowTable,
                    stop_event: threading.Event, bpf_filter: str) -> None:
    from scapy.sendrecv import sniff
    from scapy.config import conf as scapy_conf
    scapy_conf.verb = 0  # suppress "Unable to guess datalink type" and similar

    filters_to_try = [bpf_filter, None] if bpf_filter else [None]
    for f in filters_to_try:
        try:
            sniff(
                iface=iface,
                prn=lambda pkt: process_packet(pkt, flow_table),
                store=False,
                stop_filter=lambda _: stop_event.is_set(),
                filter=f or None,
            )
            return
        except Exception as exc:
            if f is not None:
                # BPF filter failed (likely unknown datalink type) — retry without
                flow_table.sniffer_warning = (
                    f"BPF filter not supported on this interface ({exc}). "
                    "Capturing all traffic and filtering in Python."
                )
            else:
                flow_table.sniffer_warning = f"Sniffer error: {exc}"
                return


def start_sniffer(iface: str, flow_table: FlowTable,
                  stop_event: threading.Event, bpf_filter: str) -> threading.Thread:
    t = threading.Thread(
        target=_sniffer_worker,
        args=(iface, flow_table, stop_event, bpf_filter),
        daemon=True,
    )
    t.start()
    return t


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

def detect_anomalies(flow_table: FlowTable) -> list:
    snap = flow_table.snapshot()
    anomalies = []
    seen = set()

    for ip, entry in snap.items():
        ports = entry["ports_contacted"]

        # Port scan
        if len(ports) > PORT_SCAN_THRESHOLD:
            key = (ip, "port_scan")
            if key not in seen:
                seen.add(key)
                top = ", ".join(f"{p}/{pr}" for p, pr in ports[:8])
                if len(ports) > 8:
                    top += f", +{len(ports) - 8} more"
                anomalies.append({
                    "ip":       ip,
                    "type":     "port_scan",
                    "severity": "HIGH",
                    "detail":   f"Contacted {len(ports)} unique ports: {top}",
                })

        # High volume
        total = entry["bytes_in"] + entry["bytes_out"]
        if total > HIGH_VOLUME_BYTES:
            key = (ip, "high_volume")
            if key not in seen:
                seen.add(key)
                anomalies.append({
                    "ip":       ip,
                    "type":     "high_volume",
                    "severity": "MEDIUM",
                    "detail":   (
                        f"Transferred {_format_bytes(total)} "
                        f"(in: {_format_bytes(entry['bytes_in'])}, "
                        f"out: {_format_bytes(entry['bytes_out'])})"
                    ),
                })

        # Unexpected protocol
        for proto_name in entry["protocols"]:
            # Reverse-lookup proto number
            proto_num = next(
                (k for k, v in PROTOCOL_NAMES.items() if v == proto_name), None
            )
            if proto_num is not None and proto_num not in UNEXPECTED_PROTO_WHITELIST:
                key = (ip, "unexpected_protocol", proto_name)
                if key not in seen:
                    seen.add(key)
                    anomalies.append({
                        "ip":       ip,
                        "type":     "unexpected_protocol",
                        "severity": "LOW",
                        "detail":   f"Protocol {proto_name} observed (not TCP/UDP/ICMP/IGMP)",
                    })

        # Suspicious port
        for port, proto in ports:
            if port in SUSPICIOUS_PORTS:
                reason, severity = SUSPICIOUS_PORTS[port]
                key = (ip, "suspicious_port", port)
                if key not in seen:
                    seen.add(key)
                    anomalies.append({
                        "ip":       ip,
                        "type":     "suspicious_port",
                        "severity": severity,
                        "detail":   f"Port {port}/{proto} — {reason}",
                    })

    anomalies.sort(key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a["ip"]))
    return anomalies


# ---------------------------------------------------------------------------
# Live display
# ---------------------------------------------------------------------------

def build_live_table(flow_table: FlowTable, anomalies: list,
                     dns: "DNSCache") -> "Table":
    snap = flow_table.snapshot()
    elapsed = int(time.time() - flow_table.start_time)

    # Build highest-severity anomaly index per IP
    anomaly_map: dict = {}
    for a in anomalies:
        ip = a["ip"]
        if ip not in anomaly_map or SEVERITY_ORDER[a["severity"]] < SEVERITY_ORDER[anomaly_map[ip]["severity"]]:
            anomaly_map[ip] = a

    sorted_flows = sorted(
        snap.values(),
        key=lambda e: e["bytes_in"] + e["bytes_out"],
        reverse=True,
    )[:TOP_TALKERS_DISPLAY]

    warn = f"\n[yellow]{flow_table.sniffer_warning}[/yellow]" if flow_table.sniffer_warning else ""
    table = Table(
        title=f"[bold cyan]Network Traffic Monitor[/bold cyan]  "
              f"[dim]{elapsed}s elapsed — {flow_table.total_packets:,} packets[/dim]{warn}",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Remote IP",  style="cyan",  no_wrap=True)
    table.add_column("Hostname",   style="dim",   overflow="fold")
    table.add_column("In",         justify="right")
    table.add_column("Out",        justify="right")
    table.add_column("Pkts",       justify="right")
    table.add_column("Protocols",  overflow="fold")
    table.add_column("Top Ports",  overflow="fold")
    table.add_column("Alert",      overflow="fold", min_width=22)

    for entry in sorted_flows:
        ip = entry["ip"]
        hostname = dns.resolve(ip)

        top_ports = ", ".join(
            f"{p}/{pr}" if pr != "TCP" else str(p)
            for p, pr in entry["ports_contacted"][:4]
        )
        if len(entry["ports_contacted"]) > 4:
            top_ports += f" +{len(entry['ports_contacted']) - 4}"

        alert_cell = ""
        if ip in anomaly_map:
            a = anomaly_map[ip]
            color = SEVERITY_COLORS.get(a["severity"], "")
            label = a["type"].replace("_", " ").upper()
            detail = a["detail"]
            if len(detail) > 38:
                detail = detail[:35] + "..."
            alert_cell = f"[{color}]{label}[/{color}]\n[dim]{detail}[/dim]"

        table.add_row(
            ip,
            hostname,
            _format_bytes(entry["bytes_in"]),
            _format_bytes(entry["bytes_out"]),
            str(entry["packets_in"] + entry["packets_out"]),
            ", ".join(entry["protocols"][:3]),
            top_ports,
            alert_cell,
        )

    return table


def run_live_display(flow_table: FlowTable, stop_event: threading.Event,
                     duration: int | None, dns: "DNSCache") -> None:
    deadline = time.time() + duration if duration else None

    with Live(console=console, refresh_per_second=0.5, screen=False) as live:
        while not stop_event.is_set():
            anomalies = detect_anomalies(flow_table)
            live.update(build_live_table(flow_table, anomalies, dns))
            time.sleep(LIVE_REFRESH_INTERVAL)
            if deadline and time.time() >= deadline:
                stop_event.set()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def save_markdown_report(flows: dict, anomalies: list, meta: dict,
                         output_path: Path) -> None:
    md_path = output_path.with_suffix(".md")
    lines = []
    lines.append("# Traffic Monitor Report\n")
    lines.append(f"**Capture time:** {meta['capture_time']}  ")
    lines.append(f"**Interface:** {meta['interface']}  ")
    lines.append(f"**Host IP:** {meta['host_ip']}  ")
    dur = f"{meta['duration_seconds']}s" if meta["duration_seconds"] else "until stopped"
    lines.append(f"**Duration:** {dur}  ")
    lines.append(f"**Total packets:** {meta['total_packets']:,}  ")
    bpf = meta["bpf_filter"] or "(none)"
    lines.append(f"**BPF filter:** {bpf}  \n")
    lines.append("---\n")

    # Summary table
    lines.append("## Top Talkers\n")
    lines.append("| Remote IP | In | Out | Packets | Protocols | Top Ports |")
    lines.append("|-----------|-----|-----|---------|-----------|-----------|")
    sorted_flows = sorted(
        flows.values(),
        key=lambda e: e["bytes_in"] + e["bytes_out"],
        reverse=True,
    )[:TOP_TALKERS_DISPLAY]
    for entry in sorted_flows:
        top_ports = ", ".join(
            f"{p}/{pr}" for p, pr in (entry["ports_contacted"] or [])[:4]
        )
        lines.append(
            f"| {entry['ip']} "
            f"| {_format_bytes(entry['bytes_in'])} "
            f"| {_format_bytes(entry['bytes_out'])} "
            f"| {entry['packets_in'] + entry['packets_out']} "
            f"| {', '.join((entry['protocols'] or [])[:3])} "
            f"| {top_ports} |"
        )
    lines.append("")

    # Anomalies
    lines.append("---\n")
    lines.append("## Anomaly Alerts\n")
    if anomalies:
        lines.append("| Severity | IP | Type | Detail |")
        lines.append("|----------|----|------|--------|")
        for a in anomalies:
            lines.append(
                f"| {a['severity']} | {a['ip']} "
                f"| {a['type']} | {a['detail']} |"
            )
    else:
        lines.append("*(No anomalies detected.)*")
    lines.append("")

    # Full flow table
    lines.append("---\n")
    lines.append("## Full Flow Table\n")
    lines.append(f"<details>\n<summary>All remote IPs ({len(flows)} entries)</summary>\n")
    lines.append("| IP | In | Out | Pkts in | Pkts out | Protocols | First Seen | Last Seen |")
    lines.append("|----|-----|-----|---------|----------|-----------|------------|-----------|")
    for entry in sorted(flows.values(), key=lambda e: e["bytes_in"] + e["bytes_out"], reverse=True):
        lines.append(
            f"| {entry['ip']} "
            f"| {_format_bytes(entry['bytes_in'])} "
            f"| {_format_bytes(entry['bytes_out'])} "
            f"| {entry['packets_in']} "
            f"| {entry['packets_out']} "
            f"| {', '.join(entry['protocols'] or [])} "
            f"| {entry['first_seen']} "
            f"| {entry['last_seen']} |"
        )
    lines.append("</details>\n")
    lines.append(f"---\n*Generated by traffic_monitor.py on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    _print(f"[green]Markdown report:[/green] {md_path}")


def save_report(flow_table: FlowTable, anomalies: list, meta: dict,
                output_path: Path) -> None:
    flows = flow_table.to_serializable()
    data = {**meta, "flows": flows, "anomalies": anomalies}
    output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    _print(f"[green]JSON report:    [/green] {output_path}")
    save_markdown_report(flows, anomalies, meta, output_path)


# ---------------------------------------------------------------------------
# Summary (post-capture console output)
# ---------------------------------------------------------------------------

def _print_summary(flow_table: FlowTable, anomalies: list,
                   dns: "DNSCache") -> None:
    snap = flow_table.snapshot()
    elapsed = int(time.time() - flow_table.start_time)

    _print("\n[bold]--- Capture Summary ---[/bold]")
    _print(f"  Duration : {elapsed}s")
    _print(f"  Packets  : {flow_table.total_packets:,}")
    _print(f"  Remote IPs seen: {len(snap)}")

    if snap:
        _print("\n[bold]Top 5 talkers:[/bold]")
        top5 = sorted(snap.values(), key=lambda e: e["bytes_in"] + e["bytes_out"], reverse=True)[:5]
        if RICH:
            t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            t.add_column("IP",       style="cyan")
            t.add_column("Hostname", style="dim")
            t.add_column("In",       justify="right")
            t.add_column("Out",      justify="right")
            t.add_column("Protocols")
            for entry in top5:
                t.add_row(
                    entry["ip"],
                    dns.resolve(entry["ip"]),
                    _format_bytes(entry["bytes_in"]),
                    _format_bytes(entry["bytes_out"]),
                    ", ".join(entry["protocols"][:3]),
                )
            console.print(t)
        else:
            for entry in top5:
                hostname = dns.resolve(entry["ip"])
                label = f"{entry['ip']} ({hostname})" if hostname else entry["ip"]
                print(f"  {label:40} in={_format_bytes(entry['bytes_in'])} out={_format_bytes(entry['bytes_out'])}")

    if anomalies:
        _print(f"\n[bold red]Anomalies detected: {len(anomalies)}[/bold red]")
        if RICH:
            t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            t.add_column("Sev",    width=8)
            t.add_column("IP",     style="cyan")
            t.add_column("Type")
            t.add_column("Detail")
            for a in anomalies:
                color = SEVERITY_COLORS.get(a["severity"], "")
                t.add_row(
                    f"[{color}]{a['severity']}[/{color}]",
                    a["ip"],
                    a["type"].replace("_", " "),
                    a["detail"],
                )
            console.print(t)
        else:
            for a in anomalies:
                print(f"  [{a['severity']}] {a['ip']} — {a['type']}: {a['detail']}")
    else:
        _print("[green]No anomalies detected.[/green]")


# ---------------------------------------------------------------------------
# Help / usage
# ---------------------------------------------------------------------------

def print_usage() -> None:
    _print("[bold cyan]Network Traffic Monitor[/bold cyan]")
    _print("Passively captures and analyzes traffic on this machine's NIC.\n")
    _print("[bold]SCOPE NOTICE[/bold]")
    _print("  On a switched LAN, only traffic TO/FROM this machine plus broadcasts")
    _print("  is visible. Other hosts' unicast traffic is not forwarded to your NIC.")
    _print("  To monitor all hosts on the subnet, enable port mirroring on your")
    _print("  managed switch (mirror all ports to the port this machine connects to),")
    _print("  then run this tool normally — it captures all mirrored traffic.")
    _print("  On consumer routers without port mirroring, run on the router itself")
    _print("  (OpenWrt/Linux) or replace the switch with an unmanaged hub.\n")
    _print("[bold]USAGE[/bold]")
    _print("  python traffic_monitor.py [OPTIONS]\n")
    _print("[bold]OPTIONS[/bold]")
    _print("  --interface NIC   NIC name to capture on  [default: auto-detect]")
    _print("  --duration  SEC   Capture for N seconds   [default: until Ctrl+C]")
    _print("  --output    FILE  Save JSON + Markdown report  e.g. capture.json")
    _print("  --mode      MODE  live (default) | quiet")
    _print("  --filter    EXPR  BPF filter string  e.g. \"host 192.168.1.1\"\n")
    _print("[bold]MODES[/bold]")
    _print("  live    Rich live-updating table of top talkers + anomaly alerts")
    _print("  quiet   Capture silently; print summary + report at end\n")
    _print("[bold]EXAMPLES[/bold]")
    _print("  # Capture until Ctrl+C with live display")
    _print("  python traffic_monitor.py --mode live\n")
    _print("  # Capture 60s on Wi-Fi, save report")
    _print("  python traffic_monitor.py --duration 60 --interface Wi-Fi --output capture.json\n")
    _print("  # Quiet capture, filter to one host")
    _print("  python traffic_monitor.py --filter \"host 192.168.1.50\" --mode quiet\n")
    _print("[bold]REQUIREMENTS[/bold]")
    _print("  - Npcap installed  (bundled with nmap: winget install nmap)")
    _print("  - pip install -r requirements.txt  (scapy, rich)")
    _print("  - Run as Administrator (raw socket capture requires elevated privileges)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--interface", default=None,
                        help="NIC display name (e.g. Wi-Fi, Ethernet)")
    parser.add_argument("--duration", type=int, default=None,
                        help="Capture duration in seconds (default: until Ctrl+C)")
    parser.add_argument("--output", default=None,
                        help="Save JSON + Markdown report to this path")
    parser.add_argument("--mode", choices=["live", "quiet"], default="live",
                        help="Display mode (default: live)")
    parser.add_argument("--filter", default="", dest="bpf_filter",
                        help="BPF filter expression (e.g. 'host 192.168.1.1')")
    args = parser.parse_args()

    # Preflight: verify scapy + Npcap
    try:
        from scapy.config import conf
        _ = conf.ifaces
    except Exception as exc:
        _print(f"[bold red]Scapy initialisation failed:[/bold red] {exc}")
        _print("Ensure Npcap is installed (bundled with nmap: winget install nmap)")
        _print("and run this script as Administrator.")
        sys.exit(1)

    host_ip    = get_host_ip()
    iface      = args.interface or get_default_interface()
    ip_filter  = _extract_ip_from_filter(args.bpf_filter)
    flow_table = FlowTable(host_ip=host_ip, ip_filter=ip_filter)

    capture_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _print(f"[bold cyan]Network Traffic Monitor[/bold cyan]")
    _print(f"  Interface : [cyan]{iface}[/cyan]")
    _print(f"  Host IP   : [cyan]{host_ip}[/cyan]")
    _print(f"  Duration  : {'{}s'.format(args.duration) if args.duration else 'until Ctrl+C'}")
    if args.bpf_filter:
        _print(f"  BPF filter: {args.bpf_filter}")
    _print("")

    dns = DNSCache()
    stop_event = threading.Event()
    sniffer_thread = start_sniffer(iface, flow_table, stop_event, args.bpf_filter)

    try:
        if args.mode == "live" and RICH:
            run_live_display(flow_table, stop_event, args.duration, dns)
        else:
            dur_str = f"{args.duration}s" if args.duration else "until Ctrl+C"
            _print(f"[dim]Capturing {dur_str}... press Ctrl+C to stop.[/dim]")
            if args.duration:
                stop_event.wait(timeout=args.duration)
                stop_event.set()
            else:
                stop_event.wait()
            # Surface any sniffer warning (e.g. BPF filter fallback)
            if flow_table.sniffer_warning:
                _print(f"[yellow]Note:[/yellow] {flow_table.sniffer_warning}")
    except KeyboardInterrupt:
        _print("\n[yellow]Stopping capture...[/yellow]")
        stop_event.set()

    sniffer_thread.join(timeout=5.0)

    anomalies = detect_anomalies(flow_table)
    _print_summary(flow_table, anomalies, dns)

    if args.output:
        meta = {
            "capture_time":     capture_time,
            "interface":        iface,
            "host_ip":          host_ip,
            "duration_seconds": args.duration,
            "total_packets":    flow_table.total_packets,
            "bpf_filter":       args.bpf_filter,
        }
        _print("")
        save_report(flow_table, anomalies, meta, Path(args.output))


if __name__ == "__main__":
    main()
