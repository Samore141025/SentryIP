# SentryIP 🛡️

**Autonomous Blue Team / SOC Threat Intelligence AI Analyst**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![User Manual](https://img.shields.io/badge/docs-User%20Manual-brightgreen.svg)](MANUAL.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

SentryIP is a terminal-based autonomous threat intelligence AI agent designed for SOC analysts, incident responders, and blue teamers. When provided with an IP address or CIDR range, SentryIP autonomously queries, cross-correlates, and synthesizes multi-source passive threat feeds using **Google Gemini** or **Claude** to produce full forensic reports, MITRE ATT&CK TTP maps, attack-surface topology graphs, ready-to-paste firewall containment rules, and verified verdicts: **`SAFE`**, **`SUSPICIOUS`**, or **`MALICIOUS`**.

> 📖 **Looking for the complete operator handbook?** See the full [**MANUAL.md**](MANUAL.md) for every command, flag, workflow, and FAQ.

---

## ⚡ 1-Click Quick Install

Install SentryIP in one command with automated virtual environment configuration:

### Linux / macOS:
```bash
curl -fsSL https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.sh | bash
```

### Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.ps1 | iex
```

### Docker 1-Liner:
```bash
docker build -t sentryip .
docker run -it --rm sentryip 8.8.8.8
```

---

## 🚀 Key Capabilities

- **Strictly Passive Intelligence**: Zero port-scanning, pinging, or active connections to the target IP. Purely passive and safe for SOC use.
- **MITRE ATT&CK TTP Mapping**: Automatically links observed brute-force ports, unpatched CVEs, botnet C2s, and Tor exits to MITRE techniques (e.g. `T1110`, `T1190`, `T1071`, `T1090`).
- **Attack Surface Topology Tree**: Generates visual Rich ASCII topology graphs showing `Target IP` ➔ `ASN` ➔ `rDNS / Provider` ➔ `Exposed Ports` ➔ `CVEs` ➔ `MITRE TTPs`.
- **Interactive Dark-Mode Forensic HTML Export**: Generate standalone, dark-mode, printable forensic briefing documents for executive management (`--html briefing.html`).
- **Automated Firewall & EDR Containment Generator**: Instantly produces ready-to-execute block commands for Linux (`iptables`, `ufw`, `nftables`), Windows PowerShell, Cisco IOS/ASA, Palo Alto, AWS VPC NACL, and Cloudflare WAF (`--generate-block-script`).
- **CIDR Subnet Range Scanning**: Parallel investigation of entire netblocks (e.g., `sentryip 192.0.2.0/28`) with aggregated SOC threat breakdown matrices.
- **Continuous Watchdog Daemon**: Background polling daemon that monitors high-value targets every $X$ seconds and triggers audio/visual alarms on verdict transition (`--watch <IP>`).
- **Slack & Discord Webhook Alerts**: Routes instant card-style threat briefings directly to your incident response channels (`--webhook <URL>`).
- **Dark Web & Pastebin Breach Checking**: Correlates targets against public text dumps and breach paste indexes.
- **In-Terminal Key Manager**: Configure keys securely without editing files using `sentryip --keys` or typing `keys` in the console.

---

## Intelligence Feeds & API Keys

| Source / Tool | Key Requirement | Environment Variable | Cost / Registration |
| :--- | :--- | :--- | :--- |
| **Google Gemini** | **Recommended (Single Key Brain)** | `GEMINI_API_KEY` | Free tier / Paid |
| **Anthropic Claude** | Alternative Brain | `ANTHROPIC_API_KEY` | Commercial API key |
| **RDAP / Whois** | Built-in | None | Free / Public RDAP |
| **DNS / FCrDNS** | Built-in | None | Free / Standard DNS |
| **Shodan InternetDB** | Built-in | None | Free passive endpoint |
| **GreyNoise Community & RIOT**| Built-in | None | Free community API |
| **Tor & Botnet Blocklists** | Built-in | None | Free (Feodo, Spamhaus, ET, Tor Project) |
| **Pastebin / Leak Indexes** | Built-in | None | Free public index |
| **Geolocation (ip-api)** | Built-in (Fallback) | None | Free tier |
| **VirusTotal v3** | Optional | `VT_API_KEY` | Free API key |
| **AbuseIPDB** | Optional | `ABUSEIPDB_API_KEY` | Free API key (1,000/day) |
| **AlienVault OTX** | Optional | `OTX_API_KEY` | Free API key |
| **IPInfo.io** | Optional | `IPINFO_TOKEN` | Free tier / Paid |

---

## CLI Usage Guide

### 1. Interactive Terminal Console
```bash
sentryip
```
Commands inside console:
- Type any IP address (e.g., `8.8.8.8`) to run full live analysis.
- Type `graph 8.8.8.8` to view attack surface topology.
- Type `192.0.2.0/28` to scan an entire subnet.
- Type `keys` to configure or change API keys.
- Type `exit` or `quit` to leave.

### 2. Standalone Investigation with Topology & Firewall Script
```bash
sentryip 185.220.101.5 --graph --generate-block-script
```

### 3. Generate Executive Dark-Mode HTML Briefing
```bash
sentryip 8.8.8.8 --html soc_briefing.html
```

### 4. CIDR Subnet Range Scan
```bash
sentryip 192.0.2.0/28
```

### 5. SOC Alerting via Slack or Discord
```bash
sentryip 185.196.11.210 --webhook "https://discord.com/api/webhooks/..."
```

### 6. Continuous Watchdog Monitoring Daemon
```bash
sentryip --watch 185.220.101.5 --watch-interval 1800 --webhook "https://hooks.slack.com/..."
```

### 7. Configure API Keys In Terminal
```bash
sentryip --keys
```

---

## Running Unit Tests

```bash
pytest -v
```

---

## Disclaimer

> **ADVISORY NOTICE**: SentryIP provides automated intelligence synthesis based on third-party passive feeds and large language model correlation. All scores, verdicts, and recommendations are advisory and intended to assist SOC analysts. Security personnel should verify indicators in accordance with their organization's standard operating procedures before initiating disruptive containment actions.
