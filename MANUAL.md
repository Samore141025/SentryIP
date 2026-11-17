# 📖 SentryIP User Manual & Complete Command Reference

Welcome to the **SentryIP** Operator Manual. This guide provides every command, flag, environment option, workflow scenario, and installation method needed to use SentryIP effectively as a Blue Team / SOC analyst.

---

## 📑 Table of Contents
1. [Overview & Architecture](#overview--architecture)
2. [1-Click Installation & Setup](#1-click-installation--setup)
3. [Managing API Keys in the Terminal](#managing-api-keys-in-the-terminal)
4. [Interactive SOC Console (REPL)](#interactive-soc-console-repl)
5. [Single IP Investigation Commands](#single-ip-investigation-commands)
6. [Attack Surface & MITRE ATT&CK Mapping](#attack-surface--mitre-attck-mapping)
7. [Automated Firewall / EDR Containment Rules](#automated-firewall--edr-containment-rules)
8. [CIDR Subnet Range Scanning](#cidr-subnet-range-scanning)
9. [Batch Processing from File](#batch-processing-from-file)
10. [Executive Dark-Mode HTML Reporting](#executive-dark-mode-html-reporting)
11. [Slack & Discord Webhook Alerts](#slack--discord-webhook-alerts)
12. [Continuous Watchdog Monitoring Daemon](#continuous-watchdog-monitoring-daemon)
13. [Docker Container Usage](#docker-container-usage)
14. [Full CLI Flag Cheat Sheet](#full-cli-flag-cheat-sheet)
15. [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Overview & Architecture

SentryIP operates strictly as a **passive threat intelligence correlator**:
- 🚫 **Zero Active Probing**: Never pings, port-scans, or establishes direct connections to target IPs.
- 🛡️ **RFC1918 Protection**: Automatically identifies private, loopback, and bogon IP addresses and safely halts before making public queries.
- 🧠 **Dual AI Brain Support**: Can be powered by a single **Google Gemini** key (`GEMINI_API_KEY`) or **Anthropic Claude** (`ANTHROPIC_API_KEY`), with a fully autonomous built-in heuristic fallback engine when no AI keys are configured.
- ⚡ **Passive Feeds Included**: RDAP/Whois, Reverse DNS & FCrDNS, Shodan InternetDB, GreyNoise RIOT, Tor Exit Lists, Spamhaus DROP, Feodo Botnet Tracker, and Dark Web / Pastebin leak indexes.

---

## 1-Click Installation & Setup

### Option A: Linux & macOS (1-Click)
Installs Python virtual environment, builds entry point, and symlinks `sentryip` to `~/.local/bin`:
```bash
curl -fsSL https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.sh | bash
```

### Option B: Windows (PowerShell 1-Click)
Installs SentryIP into `~/.sentryip-app` and makes `sentryip` available system-wide:
```powershell
irm https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.ps1 | iex
```

### Option C: Manual Git Clone
```bash
git clone https://github.com/Samore141025/SentryIP.git
cd SentryIP
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -e .
```

---

## Managing API Keys in the Terminal

You **never** need to open or edit `.env` files manually. You can manage keys entirely inside the terminal.

### Launch the Key Wizard:
```bash
sentryip --keys
```
Or type `keys` anytime inside the interactive prompt:
```text
sentryip > keys
```

### Supported API Keys
| Key | Provider | Purpose | Cost |
| :--- | :--- | :--- | :--- |
| `GEMINI_API_KEY` | Google Gemini | Primary AI Brain (Single Key Recommended) | Free tier available |
| `ANTHROPIC_API_KEY` | Anthropic Claude | Alternative AI Brain | Commercial key |
| `VT_API_KEY` | VirusTotal v3 | 70+ Antivirus detection engines | Free account |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Community reports & confidence score | Free account (1,000/day) |
| `OTX_API_KEY` | AlienVault OTX | Threat pulses & malware campaigns | Free account |
| `IPINFO_TOKEN` | IPinfo.io | Enhanced ASN & carrier data | Free account |

> **Security Note:** Keys are saved locally in `.env` and are strictly ignored by Git. They are never pushed to GitHub.

---

## Interactive SOC Console (REPL)

Start the interactive terminal analyst:
```bash
sentryip
```

### Available Interactive Commands:
- `8.8.8.8` — Enter any IP address to immediately trigger full autonomous investigation.
- Press <kbd>Enter</kbd> without typing an IP to automatically analyze your own network connection.
- `graph <IP>` — Analyze target and display an ASCII Attack Surface Topology Tree (e.g. `graph 1.1.1.1`).
- `192.0.2.0/28` — Type any CIDR notation to trigger an aggregated subnet scan.
- `keys` — Launch the in-terminal API Key Manager.
- `exit` or `quit` or `q` — Safely exit the terminal session.

---

## Single IP Investigation Commands

### Basic Investigation
```bash
sentryip 1.1.1.1
```

### Automatically Analyze Your Host's Current External IP
```bash
sentryip --auto
```

### Verbose Mode (Inspect Live API Calls & Payloads)
```bash
sentryip 185.220.101.5 --verbose
```

### Bypass Local 12-Hour SQLite Cache
```bash
sentryip 8.8.8.8 --no-cache
```

### Machine-Readable JSON Output (For Piping to `jq` or SIEMs)
```bash
sentryip 8.8.8.8 --json
```

### Save JSON Report to a File
```bash
sentryip 8.8.8.8 --output investigation_report.json
```

---

## Attack Surface & MITRE ATT&CK Mapping

Render visual attack surface trees and map observed indicators directly to the **MITRE ATT&CK Matrix**:
```bash
sentryip 185.196.11.210 --graph
```

### Sample Rendered Topology:
```text
🎯 Target: 1.1.1.1 (PUBLIC) [Risk: 5/100]
├── 🏢 Autonomous System: AS13335 (APNIC-LABS)
│   ├── 🌐 Netblock (CIDR): 1.1.1.0/24
│   └── ✉️ Abuse Contact: research@apnic.net
├── 📡 DNS Resolution: one.one.one.one
│   ├── Provider (ISP): Cloudflare, Inc
│   └── Attributes: Hosting/Datacenter
├── 🔌 Passive Attack Surface (3 exposed ports)
│   ├── Port 53/tcp
│   ├── Port 80/tcp (Web)
│   └── Port 443/tcp (Web)
└── ⚔️ MITRE ATT&CK TTPs
    └── T1595.001 - Active Scanning: Scanning IP Blocks
```

---

## Automated Firewall / EDR Containment Rules

Generate ready-to-paste containment commands for perimeter firewalls, cloud security groups, and endpoint agents:
```bash
sentryip 185.196.11.210 --generate-block-script
```

### Supported Syntaxes Generated:
- **Linux `iptables`**: `sudo iptables -I INPUT 1 -s <IP> -j DROP`
- **Linux `ufw`**: `sudo ufw deny from <IP> to any`
- **Linux `nftables`**: `sudo nft add rule inet filter input ip saddr <IP> drop`
- **Windows PowerShell**: `New-NetFirewallRule -DisplayName "SentryIP Block - <IP>" -Direction Inbound -Action Block -RemoteAddress "<IP>"`
- **Cisco IOS / ASA**: `access-list 100 deny ip host <IP> any log`
- **Palo Alto CLI**: `set rulebase security rules 'BLOCK_<IP>' from any to any source <IP> action drop`
- **AWS VPC NACL**: `aws ec2 create-network-acl-entry --network-acl-id acl-xxxx --cidr-block <IP>/32 --rule-action deny`
- **Cloudflare WAF Expression**: `(ip.src eq <IP>)`

---

## CIDR Subnet Range Scanning

Scan an entire network range in parallel and receive an aggregated risk breakdown table:
```bash
sentryip 192.0.2.0/28
```
*(Safety Cap: By default, CIDR scans analyze up to 32 host IPs concurrently).*

---

## Batch Processing from File

Investigate multiple IP addresses line-by-line from a text file:
```bash
sentryip --file sample_ips.txt --output batch_results.json
```

---

## Executive Dark-Mode HTML Reporting

Generate an executive, printable HTML forensic report complete with risk gauges, attribution cards, and attack surface graphs:
```bash
sentryip 8.8.8.8 --html soc_forensic_report.html
```
Open `soc_forensic_report.html` in any browser or save it directly to PDF using your browser's Print dialog.

---

## Slack & Discord Webhook Alerts

Automatically push card-style incident briefings into your team's SOC channel:

### Discord Webhook:
```bash
sentryip 185.196.11.210 --webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

### Slack Incoming Webhook:
```bash
sentryip 185.196.11.210 --webhook "https://hooks.slack.com/services/YOUR/SLACK/URL"
```

---

## Continuous Watchdog Monitoring Daemon

Deploy SentryIP as a background monitoring daemon for high-value external IPs. It polls threat feeds periodically and sounds an audio/visual alarm if an IP's verdict transitions:
```bash
# Poll every 1800 seconds (30 minutes) and send Discord/Slack alerts on status change:
sentryip --watch 185.220.101.5 --watch-interval 1800 --webhook "https://discord.com/api/webhooks/..."
```

---

## Docker Container Usage

Run SentryIP anywhere with zero local Python dependencies:

```bash
# 1. Build the lightweight container image:
docker build -t sentryip .

# 2. Run an immediate automated check:
docker run -it --rm sentryip 8.8.8.8

# 3. Run with your API key:
docker run -it --rm -e GEMINI_API_KEY="your_key" sentryip 185.220.101.5 --graph
```

---

## Full CLI Flag Cheat Sheet

| Command / Flag | Argument | Description |
| :--- | :--- | :--- |
| `sentryip` | None | Launches the interactive SOC terminal console (REPL). |
| `sentryip <IP>` | `IP Address` | Runs autonomous passive investigation on target IP. |
| `sentryip <CIDR>` | `CIDR block` | Scans entire netblock (e.g. `192.0.2.0/28`) in parallel. |
| `--auto` | None | Auto-detects and analyzes your host's external public IP. |
| `--keys` | None | Interactive in-terminal API key configuration wizard. |
| `--graph` | None | Renders visual attack surface topology tree. |
| `--generate-block-script` | None | Outputs firewall & EDR block rules (iptables, ufw, PowerShell, Cisco, AWS). |
| `--html <FILE>` | File path | Generates standalone dark-mode HTML forensic briefing. |
| `--webhook <URL>` | Webhook URL | Dispatches formatted alerts to Slack or Discord. |
| `--watch <IP>` | IP Address | Runs continuous background monitoring daemon. |
| `--watch-interval <SEC>` | Integer | Polling frequency for watchdog daemon (default: 3600s). |
| `-f, --file <FILE>` | Text file | Batch processes multiple IP addresses line-by-line. |
| `--json` | None | Outputs raw structured JSON instead of Rich terminal UI. |
| `-o, --output <FILE>` | File path | Saves validated JSON output report to disk. |
| `-v, --verbose` | None | Displays live tool execution and raw response previews. |
| `--no-cache` | None | Bypasses local SQLite cache to fetch fresh intelligence. |

---

## Troubleshooting & FAQ

### Q: Why did an IP show "Skipped (PRIVATE address)"?
**A:** Addresses like `192.168.x.x`, `10.x.x.x`, and `172.16.x.x - 172.31.x.x` are local LAN/Wi-Fi addresses (RFC1918). Querying public threat intelligence feeds with private IPs leaks internal network details. SentryIP enforces safety rules by halting early and explaining the allocation.

### Q: Can I run SentryIP completely free without paying for API keys?
**A:** **Yes!** SentryIP includes an autonomous heuristic correlation engine that queries public feeds (RDAP, Shodan InternetDB, GreyNoise Community/RIOT, Tor/Spamhaus/Feodo blocklists, and Pastebin leak indexes) with **zero API keys required**. If you want LLM-powered reasoning, a free Google Gemini key (`gemini-2.5-flash`) is fully supported.

### Q: Where are logs stored?
**A:** Logs are stored at `~/.sentryip/logs/sentryip.log`. All API keys, authorization tokens, and credentials are automatically scrubbed and redacted before writing to disk.

---

*SentryIP is licensed under the [MIT License](LICENSE).*
