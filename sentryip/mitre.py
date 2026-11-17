"""
Automated MITRE ATT&CK TTP mapping based on observed threat indicators,
open ports, blocklists, malware pulses, and abuse categories.
"""

from __future__ import annotations

from typing import Any, Dict, List
from sentryip.models import MitreTechnique


def map_mitre_ttps(
    open_ports: List[int],
    vulns: List[str],
    blocklist_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    is_tor: bool,
) -> List[MitreTechnique]:
    """Map indicators to MITRE ATT&CK Techniques."""
    ttps: List[MitreTechnique] = []
    seen: set[str] = set()

    def add_ttp(tid: str, tactic: str, name: str, desc: str):
        if tid not in seen:
            seen.add(tid)
            ttps.append(MitreTechnique(
                technique_id=tid,
                tactic=tactic,
                name=name,
                description=desc,
            ))

    # 1. Tor Exit Node
    if is_tor:
        add_ttp(
            "T1090.003",
            "Command and Control",
            "Proxy: Multi-hop Proxy (Tor)",
            "Target communicates through Tor network infrastructure to anonymize C2 or ingress."
        )

    # 2. Remote management ports (SSH / RDP / Telnet)
    if 22 in open_ports or 23 in open_ports or 3389 in open_ports:
        add_ttp(
            "T1110",
            "Credential Access",
            "Brute Force",
            f"Exposed remote access interfaces (ports {[p for p in [22, 23, 3389] if p in open_ports]}) commonly targeted or used for credential brute-forcing."
        )
        if 3389 in open_ports:
            add_ttp(
                "T1021.001",
                "Lateral Movement",
                "Remote Services: Remote Desktop Protocol",
                "Exposed RDP port 3389 facilitates unauthorized remote administration sessions."
            )
        if 22 in open_ports:
            add_ttp(
                "T1021.004",
                "Lateral Movement",
                "Remote Services: SSH",
                "Exposed SSH port 22 allows remote interactive command execution."
            )

    # 3. Known CVEs
    if vulns:
        add_ttp(
            "T1190",
            "Initial Access",
            "Exploit Public-Facing Application",
            f"Host exposes unpatched public CVEs ({', '.join(vulns[:3])}) vulnerable to remote exploitation."
        )

    # 4. Botnet / Feodo Tracker matches
    matches = blocklist_data.get("blocklist_matches", [])
    if any("feodo" in m.lower() for m in matches):
        add_ttp(
            "T1071.001",
            "Command and Control",
            "Application Layer Protocol: Web Protocols",
            "Listed on Feodo Tracker as an active botnet Command & Control (C2) server."
        )

    # 5. Emerging Threats or Spamhaus matches
    if any("emerging" in m.lower() for m in matches):
        add_ttp(
            "T1584",
            "Resource Development",
            "Compromised Infrastructure",
            "Host identified on Emerging Threats feed as compromised internet asset."
        )

    # 6. Abuse categories (AbuseIPDB)
    # Categories: 18=Brute-Force, 19=Bad Web Bot, 14=Port Scan, 15=Hacking, 9=Open Proxy
    categories = abuse_data.get("recent_categories", [])
    if 14 in categories:
        add_ttp(
            "T1595.001",
            "Reconnaissance",
            "Active Scanning: Scanning IP Blocks",
            "Observed performing automated port and host reconnaissance across target networks."
        )
    if 18 in categories:
        add_ttp(
            "T1110.001",
            "Credential Access",
            "Password Guessing",
            "Repeatedly reported for automated online credential guessing."
        )

    # 7. VirusTotal communicating files / detections
    if vt_data.get("malicious_count", 0) >= 3:
        add_ttp(
            "T1566",
            "Initial Access",
            "Phishing / Malware Delivery",
            "Multiple security engines link this address to active malware distribution or weaponized payloads."
        )

    return ttps
