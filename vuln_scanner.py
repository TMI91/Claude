#!/usr/bin/env python3
"""
Network Vulnerability Scanner
Scans local network for open ports, service versions, and known vulnerabilities.
Requires: nmap (system), python-nmap, rich  —  see README or run with --help
"""

import nmap
import socket
import ipaddress
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ── Risk registry ──────────────────────────────────────────────────────────────

RISKY_PORTS = {
    21:    ("FTP",        "HIGH",     "Plaintext file transfer — credentials exposed"),
    22:    ("SSH",        "INFO",     "Ensure key-based auth; disable root login"),
    23:    ("Telnet",     "CRITICAL", "Unencrypted remote shell — replace with SSH immediately"),
    25:    ("SMTP",       "MEDIUM",   "Verify open relay is disabled"),
    53:    ("DNS",        "MEDIUM",   "Verify recursive queries are restricted"),
    80:    ("HTTP",       "LOW",      "Unencrypted — consider HTTPS redirect"),
    110:   ("POP3",       "HIGH",     "Plaintext mail retrieval"),
    135:   ("MSRPC",      "HIGH",     "Windows RPC — common attack surface"),
    137:   ("NetBIOS-NS", "HIGH",     "Leaks network topology"),
    139:   ("NetBIOS",    "HIGH",     "Legacy SMB — frequent malware vector"),
    143:   ("IMAP",       "HIGH",     "Plaintext mail access"),
    161:   ("SNMP",       "HIGH",     "v1/v2 use plaintext community strings"),
    389:   ("LDAP",       "MEDIUM",   "Verify anonymous bind is disabled"),
    443:   ("HTTPS",      "INFO",     "Check TLS version and certificate validity"),
    445:   ("SMB",        "CRITICAL", "Primary vector for EternalBlue/WannaCry/ransomware"),
    512:   ("rexec",      "CRITICAL", "Legacy unencrypted remote exec — disable"),
    513:   ("rlogin",     "CRITICAL", "Legacy unencrypted remote login — disable"),
    514:   ("rsh",        "CRITICAL", "Legacy unencrypted remote shell — disable"),
    1433:  ("MSSQL",      "HIGH",     "Database should not be internet-exposed"),
    1521:  ("Oracle",     "HIGH",     "Database should not be internet-exposed"),
    2049:  ("NFS",        "HIGH",     "Verify exports are tightly restricted"),
    3306:  ("MySQL",      "HIGH",     "Database should not be internet-exposed"),
    3389:  ("RDP",        "HIGH",     "Frequently brute-forced — restrict by IP"),
    4444:  ("Backdoor?",  "CRITICAL", "Common backdoor/Metasploit default port"),
    5432:  ("PostgreSQL", "HIGH",     "Database should not be internet-exposed"),
    5900:  ("VNC",        "HIGH",     "Often weak or no authentication"),
    5985:  ("WinRM-HTTP", "HIGH",     "Windows remote management over HTTP"),
    5986:  ("WinRM-HTTPS","MEDIUM",   "Windows remote management — verify access control"),
    6379:  ("Redis",      "CRITICAL", "Default config has no auth — full data exposure"),
    8080:  ("HTTP-alt",   "LOW",      "Check for exposed admin panels or debug endpoints"),
    8443:  ("HTTPS-alt",  "LOW",      "Check TLS and exposed services"),
    27017: ("MongoDB",    "CRITICAL", "Default config has no auth — full data exposure"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


# ── Network helpers ────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def get_local_subnet() -> str:
    ip = get_local_ip()
    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return str(network)


# ── Scanning ───────────────────────────────────────────────────────────────────

def discover_hosts(target: str, nm: nmap.PortScanner) -> list[str]:
    """Ping sweep to find live hosts."""
    _print(f"[bold]Host discovery:[/bold] {target}", style="blue")
    nm.scan(hosts=target, arguments="-sn -T4 --host-timeout 5s")
    hosts = sorted(
        [h for h in nm.all_hosts() if nm[h].state() == "up"],
        key=lambda h: tuple(int(p) for p in h.split("."))
    )
    _print(f"Found {len(hosts)} live host(s)\n", style="green")
    return hosts


def scan_host(host: str, mode: str, nm: nmap.PortScanner) -> dict:
    """Port scan + service detection + vulnerability scripts for one host.

    Two-phase approach: fast port discovery first, then targeted service/script
    scan only on open ports.  Avoids --host-timeout killing results on hosts with
    many open services (e.g. NAS devices).
    """
    # Phase 1 — fast port discovery, no service detection yet.
    # Thorough uses T3 + retries: T4 with -p- floods home routers causing packet
    # loss and false negatives (open ports reported as closed).
    discovery_args = {
        "fast":     "-Pn -T4 --top-ports 200",
        "normal":   "-Pn -T4 --top-ports 1000",
        "thorough": "-Pn -T3 --max-retries 3 -p-",
    }
    nm.scan(hosts=host, arguments=discovery_args[mode])

    if host not in nm.all_hosts():
        return {"host": host, "hostname": "", "ports": []}

    open_ports = [
        str(port)
        for proto in nm[host].all_protocols()
        for port in nm[host][proto]
        if nm[host][proto][port]["state"] == "open"
    ]

    if not open_ports:
        return {"host": host, "hostname": "", "ports": []}

    # Phase 2 — service detection + scripts only on confirmed open ports.
    # T3 for thorough keeps retries consistent with phase 1.
    ports_str = ",".join(open_ports)
    detail_args = {
        "fast":     f"-Pn -sV -T4 -p {ports_str}",
        "normal":   f"-Pn -sV -T4 -p {ports_str} --script=default,vuln",
        "thorough": f"-Pn -sV -T3 --max-retries 3 -p {ports_str} --script=default,vuln",
    }
    nm.scan(hosts=host, arguments=detail_args[mode])

    if host not in nm.all_hosts():
        return {"host": host, "hostname": "", "ports": []}

    hostname = ""
    try:
        hostname = socket.gethostbyaddr(host)[0]
    except socket.herror:
        pass

    ports = []
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            svc = nm[host][proto][port]
            if svc["state"] != "open":
                continue

            script_output = svc.get("script", {})
            risk = _assess_port(port, svc, script_output)

            ports.append({
                "port":     port,
                "proto":    proto,
                "service":  svc.get("name", ""),
                "product":  svc.get("product", ""),
                "version":  svc.get("version", ""),
                "scripts":  script_output,
                "risk":     risk,
            })

    return {"host": host, "hostname": hostname, "ports": ports}


def _assess_port(port: int, svc: dict, scripts: dict) -> dict:
    """Derive risk level from port number and nmap script output."""
    severity = "INFO"
    notes = []

    if port in RISKY_PORTS:
        _, sev, note = RISKY_PORTS[port]
        severity = sev
        notes.append(note)

    # Escalate if nmap vuln scripts found something
    vuln_hits = [k for k in scripts if "vuln" in k.lower() or "exploit" in k.lower()]
    for k in vuln_hits:
        output = scripts[k].lower()
        if any(w in output for w in ("vulnerable", "likely vulnerable", "exploitable")):
            severity = "CRITICAL"
            notes.append(f"nmap script {k}: potential vulnerability detected")
        elif "not vulnerable" not in output:
            notes.append(f"nmap script {k}: see raw output")

    return {"severity": severity, "notes": notes}


# ── Reporting ──────────────────────────────────────────────────────────────────

def _print(msg: str, style: str = ""):
    if RICH:
        console.print(msg, style=style if style else None)
    else:
        import re
        print(re.sub(r"\[/?[^\]]*\]", "", msg))


def print_usage():
    _print("""
[bold cyan]Network Vulnerability Scanner[/bold cyan]
[dim]Scant je lokale netwerk op open poorten, service-versies en bekende kwetsbaarheden via nmap.[/dim]

[bold]GEBRUIK[/bold]
  python vuln_scanner.py [OPTIES]

  Zonder argumenten wordt dit scherm getoond.
  Geef minimaal één optie mee om een scan te starten.

[bold]OPTIES[/bold]
  [bold]--target[/bold] TARGET      IP-adres, hostnaam of CIDR-bereik om te scannen
                        Weglaten = automatisch lokaal /24-subnet detecteren
  [bold]--mode[/bold] MODE          [cyan]fast[/cyan] | [cyan]normal[/cyan] | [cyan]thorough[/cyan]   (standaard: normal)
  [bold]--output[/bold] BESTAND     Sla resultaten op als JSON én Markdown
                        Voorbeeld: --output rapport.json
                        Genereert: rapport.json  +  rapport.md
  [bold]--no-discovery[/bold]       Sla ping-sweep over, scan --target direct

[bold]SCAN-MODI[/bold]
  [cyan]fast[/cyan]      Top 200 poorten, alleen service-detectie          (~10 sec/host)
  [cyan]normal[/cyan]    Top 1000 poorten + vuln-scripts                  (~2-5 min/host)
  [cyan]thorough[/cyan]  Alle 65535 poorten + vuln-scripts (betrouwbaarst) (~15+ min/host)

[bold]VOORBEELDEN[/bold]
  [dim]# Automatisch lokaal netwerk scannen (normal modus)[/dim]
  python vuln_scanner.py --mode normal

  [dim]# Specifiek subnet, snel[/dim]
  python vuln_scanner.py --target 192.168.1.0/24 --mode fast

  [dim]# Één host grondig scannen met rapport[/dim]
  python vuln_scanner.py --target 192.168.1.40 --mode thorough --output rapport.json

  [dim]# Lokaal netwerk scannen en rapport opslaan[/dim]
  python vuln_scanner.py --output rapport.json

[bold]VEREISTEN[/bold]
  • nmap geïnstalleerd  (winget install nmap)
  • python-nmap, rich   (pip install -r requirements.txt)
  • Uitvoeren als [bold]Administrator[/bold] voor volledige functionaliteit

[dim]Gebruik alleen op netwerken waarvoor je toestemming hebt.[/dim]
""")


def print_host_report(result: dict):
    host_label = result["host"]
    if result["hostname"]:
        host_label += f"  ({result['hostname']})"

    _print(f"\n{'─'*60}", style="dim")
    _print(f"  Host: {host_label}", style="bold white")
    _print(f"{'─'*60}", style="dim")

    if not result["ports"]:
        _print("  No open ports found.", style="dim")
        return

    # Sort by severity then port number
    ports = sorted(result["ports"],
                   key=lambda p: (SEVERITY_ORDER.get(p["risk"]["severity"], 99), p["port"]))

    if RICH:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Port",     style="bold", width=8)
        table.add_column("Service",  width=14)
        table.add_column("Version",  width=20)
        table.add_column("Severity", width=10)
        table.add_column("Notes")

        for p in ports:
            sev = p["risk"]["severity"]
            color = SEVERITY_COLORS.get(sev, "")
            notes = "; ".join(p["risk"]["notes"]) or ""
            version = " ".join(filter(None, [p["product"], p["version"]])) or "—"
            table.add_row(
                f"{p['port']}/{p['proto']}",
                p["service"] or "—",
                version,
                f"[{color}]{sev}[/{color}]",
                notes,
            )
        console.print(table)
    else:
        for p in ports:
            sev = p["risk"]["severity"]
            version = " ".join(filter(None, [p["product"], p["version"]])) or ""
            notes = "; ".join(p["risk"]["notes"])
            print(f"  {p['port']:>5}/{p['proto']:<3}  {p['service']:<14}  {version:<20}  [{sev}]  {notes}")

    # Print raw nmap script output for anything flagged
    for p in ports:
        for k, v in p["scripts"].items():
            if v.strip():
                _print(f"\n  [dim]Script {k} on port {p['port']}:[/dim]")
                for line in v.strip().splitlines()[:20]:
                    _print(f"    {line}", style="dim")


def summary_stats(results: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for p in r["ports"]:
            sev = p["risk"]["severity"]
            counts[sev] = counts.get(sev, 0) + 1
    return counts


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def save_markdown_report(results: list[dict], stats: dict, meta: dict, output_path: Path):
    lines = []

    lines.append("# Network Vulnerability Scan Report\n")
    lines.append(f"**Scantijd:** {meta['scan_time']}  ")
    lines.append(f"**Target:** {meta['target']}  ")
    lines.append(f"**Modus:** {meta['mode']}  ")
    lines.append(f"**Hosts gescand:** {len(results)}  \n")

    lines.append("---\n")
    lines.append("## Samenvatting\n")
    lines.append("| Ernst | Bevindingen |")
    lines.append("|-------|-------------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats.get(sev, 0)
        if count:
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev} | {count} |")
    lines.append("")

    lines.append("---\n")
    lines.append("## Bevindingen per host\n")

    for result in results:
        host_label = result["host"]
        if result["hostname"]:
            host_label += f" — {result['hostname']}"
        lines.append(f"### {host_label}\n")

        if not result.get("ports"):
            lines.append("Geen open poorten gevonden.\n")
            lines.append("---\n")
            continue

        ports = sorted(result["ports"],
                       key=lambda p: (SEVERITY_ORDER.get(p["risk"]["severity"], 99), p["port"]))

        lines.append("| Poort | Service | Versie | Ernst | Notities |")
        lines.append("|-------|---------|--------|-------|----------|")
        for p in ports:
            sev = p["risk"]["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "")
            version = " ".join(filter(None, [p["product"], p["version"]])) or "—"
            notes = "; ".join(p["risk"]["notes"]) or "—"
            lines.append(
                f"| {p['port']}/{p['proto']} | {p['service'] or '—'} | {version} "
                f"| {emoji} {sev} | {notes} |"
            )
        lines.append("")

        # Script output in collapsible blocks
        script_sections = []
        for p in ports:
            for k, v in p.get("scripts", {}).items():
                if v.strip():
                    script_sections.append((k, p["port"], v.strip()))

        if script_sections:
            lines.append("<details>")
            lines.append("<summary>Script-output</summary>\n")
            for name, port, output in script_sections:
                lines.append(f"**{name}** op poort {port}:\n")
                lines.append("```")
                lines.extend(output.splitlines()[:30])
                lines.append("```\n")
            lines.append("</details>\n")

        lines.append("---\n")

    lines.append(f"*Gegenereerd door vuln_scanner.py op {meta['scan_time']}*")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    _print(f"Markdown rapport:  {output_path}", style="dim")


def save_report(results: list[dict], stats: dict, meta: dict, output_path: Path):
    report = {
        "scan_time":     meta["scan_time"],
        "target":        meta["target"],
        "mode":          meta["mode"],
        "hosts_scanned": len(results),
        "results":       results,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _print(f"JSON rapport:      {output_path}", style="dim")

    md_path = output_path.with_suffix(".md")
    save_markdown_report(results, stats, meta, md_path)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--target", help="IP, hostnaam of CIDR-bereik (standaard: auto-detect /24)")
    parser.add_argument("--mode", choices=["fast", "normal", "thorough"], default="normal")
    parser.add_argument("--output", help="Sla rapport op (bijv. rapport.json) — genereert ook .md")
    parser.add_argument("--no-discovery", action="store_true",
                        help="Sla ping-sweep over, scan --target direct")
    args = parser.parse_args()

    target = args.target or get_local_subnet()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = {"scan_time": scan_time, "target": target, "mode": args.mode}

    _print(f"\n[bold cyan]Network Vulnerability Scanner[/bold cyan]")
    _print(f"Target : {target}")
    _print(f"Modus  : {args.mode}")
    _print(f"Tijd   : {scan_time}\n")

    nm = nmap.PortScanner()

    # Host discovery
    if args.no_discovery:
        hosts = [target]
    else:
        hosts = discover_hosts(target, nm)
        if not hosts:
            _print("Geen live hosts gevonden. Probeer --no-discovery voor een directe hostscan.", style="yellow")
            sys.exit(0)

    # Scan each host
    results = []
    for i, host in enumerate(hosts, 1):
        _print(f"[{i}/{len(hosts)}] Scannen {host} ...", style="blue")
        result = scan_host(host, args.mode, nm)
        results.append(result)
        print_host_report(result)

    # Summary
    stats = summary_stats(results)
    _print(f"\n{'─'*60}", style="dim")
    _print("  Samenvatting", style="bold white")
    _print(f"{'─'*60}", style="dim")
    _print(f"  Hosts gescand : {len(results)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats.get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "")
            _print(f"  {sev:<10}: {count}", style=color)

    if args.output:
        _print("")
        save_report(results, stats, meta, Path(args.output))


if __name__ == "__main__":
    main()
