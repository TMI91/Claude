# vuln_scanner

A network vulnerability scanner for home and small-office networks. Discovers live hosts on your local subnet, identifies open ports, and reports known-risky services with severity ratings.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/) installed system-wide (`winget install nmap`)
- Run as **Administrator** (raw socket access)

```bash
pip install -r requirements.txt
```

## Usage

```
python vuln_scanner.py [--target TARGET] [--mode MODE] [--output FILE] [--no-discovery]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--target` | auto-detect local /24 | IP, hostname, or CIDR range to scan |
| `--mode` | `normal` | Scan depth: `fast`, `normal`, or `thorough` |
| `--output` | none | Save report as JSON + Markdown (e.g. `report.json`) |
| `--no-discovery` | off | Skip ping sweep; scan target directly |

### Examples

```bash
# Scan local subnet with auto-detection
python vuln_scanner.py

# Fast scan of a specific subnet
python vuln_scanner.py --target 192.168.1.0/24 --mode fast

# Thorough scan of one host, save report
python vuln_scanner.py --target 192.168.1.1 --mode thorough --output report.json

# Scan without host discovery (useful if ICMP is blocked)
python vuln_scanner.py --target 192.168.1.0/24 --no-discovery
```

### Scan modes

| Mode | Timing | Ports | Notes |
|------|--------|-------|-------|
| `fast` | T4 | Top 200 | Quick overview |
| `normal` | T4 | Top 1000 + vuln scripts | Balanced default |
| `thorough` | T3 | All 65535 + retries | Slow; use for full audits |

## Output

Results are printed to the console as a Rich table sorted by severity. With `--output`:

- **`.json`** — machine-readable full results
- **`.md`** — Markdown report with collapsible script output sections

## Severity levels

`CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO`

Severity is assigned from a built-in risk registry (`RISKY_PORTS`) and escalated if nmap vulnerability scripts detect an active exploit.

## Architecture

`vuln_scanner.py` is a single-file script with four layers:

1. **Risk registry** (`RISKY_PORTS`) — static dict mapping port numbers to `(service, severity, note)` tuples
2. **Network helpers** — subnet auto-detection via outbound UDP socket to derive local /24
3. **Scanning** — two-phase: `discover_hosts()` ping sweep, then `scan_host()` does fast port discovery first and targeted service/vuln scan only on confirmed open ports
4. **Reporting** — Rich table to console; `save_report()` writes JSON + Markdown when `--output` is given
