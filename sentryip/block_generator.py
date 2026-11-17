"""
Firewall and EDR rule generation for incident response and active containment.
Produces ready-to-paste mitigation rules for Linux, Windows, Cisco, Palo Alto, AWS, and Cloudflare.
"""

from __future__ import annotations

from typing import Dict


def generate_block_rules(ip: str, comment: str = "SentryIP SOC Block") -> Dict[str, str]:
    """Generate ready-to-execute containment syntax for major firewalls and EDRs."""
    return {
        "Linux iptables": f"sudo iptables -I INPUT 1 -s {ip} -m comment --comment '{comment}' -j DROP",
        "Linux ufw": f"sudo ufw deny from {ip} to any comment '{comment}'",
        "Linux nftables": f"sudo nft add rule inet filter input ip saddr {ip} drop comment '{comment}'",
        "Windows PowerShell": (
            f"New-NetFirewallRule -DisplayName '{comment} - {ip}' "
            f"-Direction Inbound -Action Block -RemoteAddress '{ip}' -Protocol Any"
        ),
        "Cisco IOS / ASA": (
            f"access-list 100 deny ip host {ip} any log\n"
            f"access-list OUTSIDE_IN deny ip host {ip} any"
        ),
        "Palo Alto CLI": (
            f"set rulebase security rules 'BLOCK_{ip.replace('.', '_')}' from any to any source {ip} action drop"
        ),
        "AWS VPC NACL": (
            f"aws ec2 create-network-acl-entry --network-acl-id acl-xxxxxx --ingress "
            f"--rule-number 50 --protocol -1 --port-range From=0,To=0 --cidr-block {ip}/32 --rule-action deny"
        ),
        "Cloudflare WAF Expression": f'(ip.src eq {ip})',
    }


def format_block_script_output(ip: str) -> str:
    """Format firewall commands as a clean terminal text block."""
    rules = generate_block_rules(ip)
    lines = [f"# ============================================================",
             f"# SENTRYIP AUTOMATED MITIGATION SCRIPT FOR: {ip}",
             f"# Generated for Blue Team / SOC Containment",
             f"# ============================================================\n"]
    for platform, cmd in rules.items():
        lines.append(f"## {platform}:")
        lines.append(f"{cmd}\n")
    return "\n".join(lines)
