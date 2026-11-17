"""
Network attack surface tree graph generator using Rich Tree representations.
"""

from __future__ import annotations

from rich.tree import Tree
from sentryip.models import FinalReport, Verdict


def build_attack_surface_tree(report: FinalReport) -> Tree:
    """Build an ASCII/Rich network topology and attribution tree."""
    # Root
    verdict_style = "bold green" if report.verdict == Verdict.SAFE else ("bold yellow" if report.verdict == Verdict.SUSPICIOUS else "bold red")
    root = Tree(f"[{verdict_style}]🎯 Target: {report.ip}[/{verdict_style}] ({report.ip_type.value.upper()}) [Risk: {report.risk_score}/100]")

    # 1. Ownership & AS Branch
    own = report.ownership
    asn_label = f"🏢 Autonomous System: [bold cyan]{own.asn or 'Unknown'}[/bold cyan] ({own.org or 'Unknown Org'})"
    as_branch = root.add(asn_label)
    if own.cidr:
        as_branch.add(f"🌐 Netblock (CIDR): [dim]{own.cidr}[/dim]")
    if own.country:
        as_branch.add(f"📍 Country: {own.country}")
    if own.abuse_contact:
        as_branch.add(f"✉️ Abuse Contact: [dim cyan]{own.abuse_contact}[/dim cyan]")

    # 2. Hostname & DNS Resolution
    net = report.network
    dns_branch = root.add(f"📡 DNS Resolution: [bold white]{net.rdns or 'No PTR Record'}[/bold white]")
    if net.isp:
        dns_branch.add(f"Provider (ISP): {net.isp}")
    attr_flags = []
    if net.hosting:
        attr_flags.append("[magenta]Hosting/Datacenter[/magenta]")
    if net.vpn_proxy:
        attr_flags.append("[yellow]VPN/Proxy[/yellow]")
    if net.tor:
        attr_flags.append("[bold red]TOR Exit Node[/bold red]")
    if attr_flags:
        dns_branch.add(f"Attributes: {', '.join(attr_flags)}")

    # 3. Passive Attack Surface (Ports & Services)
    ports_branch = root.add(f"🔌 Passive Attack Surface ({len(report.open_ports)} exposed ports)")
    if report.open_ports:
        for p in report.open_ports:
            tag = " [red](SSH/Brute Target)[/red]" if p in [22, 23] else (" [red](RDP/Remote Admin)[/red]" if p == 3389 else (" [cyan](Web)[/cyan]" if p in [80, 443, 8080, 8443] else ""))
            ports_branch.add(f"Port {p}/tcp{tag}")
    else:
        ports_branch.add("[dim]No open ports in passive database[/dim]")

    # 4. Known Vulnerabilities
    if report.vulns:
        vulns_branch = root.add(f"🚨 Vulnerabilities ({len(report.vulns)} CVEs cataloged)")
        for v in report.vulns[:5]:
            vulns_branch.add(f"[bold red]{v}[/bold red]")
        if len(report.vulns) > 5:
            vulns_branch.add(f"[dim]...and {len(report.vulns) - 5} more[/dim]")

    # 5. MITRE ATT&CK TTPs
    if report.mitre_attack:
        mitre_branch = root.add(f"⚔️ MITRE ATT&CK TTPs ({len(report.mitre_attack)} techniques)")
        for m in report.mitre_attack:
            mitre_branch.add(f"[bold yellow]{m.technique_id}[/bold yellow] - {m.name} ([dim]{m.tactic}[/dim])")

    return root
