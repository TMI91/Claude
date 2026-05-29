# Claude

A collection of security and utility tools.

## Subprojects

| Project | Beschrijving |
|---------|-------------|
| [vuln_scanner](vuln_scanner/) | Netwerk vulnerability scanner via nmap |

---

## vuln_scanner

Scant je lokale netwerk op live hosts, open poorten, service-versies en bekende kwetsbaarheden via nmap NSE-scripts.

### Vereisten

**1. Installeer nmap** (systeemtool — vereist voor python-nmap)

```
winget install nmap
```
Of download van https://nmap.org/download.html en installeer met de standaardinstellingen.

> **Let op:** voer de scanner uit als Administrator. Nmap heeft verhoogde rechten nodig voor SYN-scans en sommige scripts.

**2. Installeer Python-packages**

```
cd vuln_scanner
pip install -r requirements.txt
```

---

### Gebruik

```
cd vuln_scanner

# Automatisch je /24-subnet detecteren en scannen (normaal modus)
python vuln_scanner.py --mode normal

# Specifiek subnet of host
python vuln_scanner.py --target 192.168.1.0/24
python vuln_scanner.py --target 192.168.1.1

# Snelle scan (top 200 poorten, geen vuln-scripts)
python vuln_scanner.py --mode fast

# Grondige scan (alle poorten + alle vuln-scripts — kan lang duren)
python vuln_scanner.py --mode thorough

# Resultaten opslaan als JSON én Markdown
python vuln_scanner.py --output rapport.json
```

### Scan-modi

| Modus     | Poorten      | Scripts          | Tijd per host  |
|-----------|-------------|------------------|----------------|
| fast      | Top 200     | Geen             | ~10 seconden   |
| normal    | Top 1000    | default + vuln   | 2–5 minuten    |
| thorough  | Alle 65535  | default + vuln   | 15+ minuten    |

### Risico-niveaus

| Niveau   | Betekenis                                              |
|----------|--------------------------------------------------------|
| CRITICAL | Directe actie vereist (bijv. open Redis, SMB 445, Telnet) |
| HIGH     | Serieus risico — controleer configuratie               |
| MEDIUM   | Potentieel risico — beoordeel zelf                     |
| LOW      | Aandachtspunt, vaak acceptabel                         |
| INFO     | Geen risico, alleen ter info                           |

---

> Gebruik deze tool alleen op netwerken waarvoor je toestemming hebt.
