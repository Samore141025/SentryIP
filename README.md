# SentryIP 🛡️

**Autonomous Blue Team / SOC Threat Intelligence AI Analyst**

SentryIP is a terminal-based autonomous AI agent designed for SOC analysts, incident responders, and blue teamers. When provided with an IP address, SentryIP autonomously queries, cross-correlates, and synthesizes multi-source threat intelligence using Claude (via the Anthropic Tool-Use Agent Loop) to produce a comprehensive tactical report and clear actionable verdict: **`SAFE`**, **`SUSPICIOUS`**, or **`MALICIOUS`**.

---

## Key Features

- **Autonomous Multi-Step Agent Loop**: Leverages Claude tool calling to orchestrate data collection in parallel, trace evidence, and evaluate indicators.
- **Strictly Passive Intelligence**: Zero port-scanning, pinging, or active connections to the target IP. Purely passive and safe for SOC use.
- **Prompt Injection Defense**: Sanitizes all input and treats untrusted API/Whois/DNS data as potentially adversarial.
- **Pre-flight RFC1918 / Bogon Filter**: Automatically flags private, loopback, link-local, and bogon addresses and terminates early without consuming external API rate limits or LLM tokens.
- **High-Fidelity Terminal UX**: Interactive live spinner showing tool calls in progress, and full Rich-formatted SOC panels with risk gauges, attribution tables, and mitigation actions.
- **Local SQLite Caching**: Automatically caches intelligence feeds (e.g. Tor exit lists, Spamhaus DROP, Feodo Tracker) with a 12-hour TTL.
- **Auditable Logging**: Redacts all API keys and tokens in `~/.sentryip/logs/sentryip.log`.

---

## Intelligence Feeds & API Keys

SentryIP runs immediately out-of-the-box. Free/unauthenticated feeds will execute automatically, while authenticated services gracefully skip with informative notifications if their key is omitted.

| Source / Tool | Key Requirement | Environment Variable | Cost / Registration |
| :--- | :--- | :--- | :--- |
| **Anthropic Claude** | **Required** | `ANTHROPIC_API_KEY` | Commercial API key |
| **RDAP / Whois** | Built-in | None | Free / Public RDAP |
| **DNS / FCrDNS** | Built-in | None | Free / Standard DNS |
| **Shodan InternetDB** | Built-in | None | Free passive endpoint |
| **GreyNoise Community** | Built-in | None | Free community API |
| **Tor & Blocklists** | Built-in | None | Free (Feodo, Spamhaus, ET, Tor Project) |
| **Geolocation (ip-api)** | Built-in (Fallback) | None | Free tier |
| **IPInfo.io** | Optional | `IPINFO_TOKEN` | Free tier / Paid |
| **AbuseIPDB** | Optional | `ABUSEIPDB_API_KEY` | Free API key |
| **VirusTotal v3** | Optional | `VT_API_KEY` | Free API key |
| **AlienVault OTX** | Optional | `OTX_API_KEY` | Free API key |

---

## Installation

### Prerequisites
- Python 3.11+
- Virtual environment recommended (`venv` or `uv`)

### 1. Clone & Install
```bash
git clone https://github.com/example/sentryip.git
cd sentryip

# Create virtual environment
python -m venv .venv

# Activate on Linux/macOS:
source .venv/bin/activate
# Activate on Windows:
.venv\Scripts\activate

# Install in editable mode with dependencies
pip install -e .
```

### 2. Configure Environment
Copy `.env.example` to `.env` and set your Anthropic API key:
```bash
cp .env.example .env
```
Edit `.env`:
```env
ANTHROPIC_API_KEY=sk-ant-api03-...
SENTRYIP_MODEL=claude-sonnet-4-5
ABUSEIPDB_API_KEY=...
VT_API_KEY=...
```

---

## Usage

### 1. Interactive Terminal REPL
Simply execute `sentryip` to start an interactive SOC session:
```bash
sentryip
```
```
   _____            _              _____ _____  
  / ____|          | |            |_   _|  __ \ 
 | (___   ___ _ __ | |_ _ __ _   _  | | | |__) |
  \___ \ / _ \ '_ \| __| '__| | | | | | |  ___/ 
  ____) |  __/ | | | |_| |  | |_| |_| |_| |     
 |_____/ \___|_| |_|\__|_|   \__, |_____|_|     
                              __/ |             
                             |___/              
Autonomous Blue Team SOC IP Threat Intelligence Analyst v0.1.0

sentryip > 8.8.8.8
```

### 2. One-Shot Investigation
Investigate a single IP directly:
```bash
sentryip 1.1.1.1
```

### 3. Verbose Mode
View real-time tool calls and API responses:
```bash
sentryip 185.220.101.5 --verbose
```

### 4. Structured Machine-Readable JSON
Output pure JSON for downstream piping to `jq`, SIEMs, or scripts:
```bash
sentryip 8.8.8.8 --json
```

### 5. Save Report to Disk
```bash
sentryip 8.8.8.8 --output report.json
```

### 6. Batch Investigation (File Processing)
Provide a list of IPs in a text file (one per line):
```bash
sentryip --file suspicious_ips.txt --output batch_results.json
```

### 7. Bypass Local Cache
```bash
sentryip 1.1.1.1 --no-cache
```

---

## Example Terminal Report

```text
╭──────────────────────────────────────────────────────────────────────────╮
│ Target: 1.1.1.1 (PUBLIC)                                                 │
│ Assessment:  SAFE   |  Risk Score: [█░░░░░░░░░░░░░░░░░░░] 5/100  |  Conf: 95%│
│ Timestamp: 2026-11-12T12:00:00Z                                          │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ 📋 Executive Summary ───────────────────────────────────────────────────╮
│ Target IP 1.1.1.1 is operated by Cloudflare, Inc. as their public DNS    │
│ resolver. Correlated intelligence across GreyNoise RIOT, VirusTotal, and │
│ public blocklists confirms clean reputation and zero malicious activity. │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ 🌐 Infrastructure & Network Attribution ────────────────────────────────╮
│ Organization / Owner   Cloudflare, Inc.                                  │
│ ASN                    AS13335                                           │
│ CIDR / Netblock        1.1.1.0/24                                        │
│ Country / Abuse        US | abuse@cloudflare.com                         │
│ Reverse DNS (rDNS)     one.one.one.one                                   │
│ Network Attributes     Hosting/Datacenter                                │
│ Location               San Francisco, CA, US                             │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ 🔌 Passive Attack Surface ──────────────────────────────────────────────╮
│ Passive Open Ports: 53, 853, 443                                         │
│ Associated Vulnerabilities (CVEs): No known public vulnerabilities       │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ 🛡️ SOC Analysis & Recommended Actions ─────────────────────────────────╮
│ Analyst Chain of Evidence:                                               │
│  • Primary rDNS resolves to one.one.one.one with forward confirmation.   │
│  • GreyNoise verifies this IP under RIOT (benign public infrastructure). │
│  • Not listed on any active botnet, C2, or spam blocklists.              │
│                                                                          │
│ Recommended SOC Mitigations:                                             │
│  [1] No blocking or containment required.                                │
│  [2] Permit standard outbound DNS queries if configured in environment.  │
╰──────────────────────────────────────────────────────────────────────────╯
```

---

## Running Unit Tests

```bash
pytest -v
```

---

## Disclaimer

> **ADVISORY NOTICE**: SentryIP provides automated intelligence synthesis based on third-party passive feeds and large language model correlation. All scores, verdicts, and recommendations are advisory and intended to assist SOC analysts. Security personnel should verify indicators in accordance with their organization's standard operating procedures before initiating disruptive containment actions.

