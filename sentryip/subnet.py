"""
CIDR subnet range parsing, parallel investigation, and aggregated SOC risk matrix.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from sentryip.agent import SentryIPAgent
from sentryip.models import FinalReport, Verdict
from sentryip.report import _get_verdict_badge

console = Console()


async def scan_cidr_subnet(
    cidr_str: str,
    max_hosts: int = 32,
    verbose: bool = False,
    no_cache: bool = False,
) -> List[FinalReport]:
    """Scan all hosts within a CIDR netblock concurrently and render an aggregated breakdown."""
    try:
        network = ipaddress.ip_network(cidr_str.strip(), strict=False)
    except ValueError as e:
        console.print(f"[bold red]Invalid CIDR network string: {e}[/bold red]")
        return []

    hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    if len(hosts) > max_hosts:
        console.print(f"[yellow]Subnet contains {len(hosts)} hosts. Limiting scan to first {max_hosts} hosts (safety cap).[/yellow]")
        hosts = hosts[:max_hosts]

    console.print(Panel(
        f"[bold cyan]🌐 SentryIP CIDR Range Scanner[/bold cyan]\n"
        f"Target Network: [bold white]{cidr_str}[/bold white] | Total Hosts to Assess: [bold green]{len(hosts)}[/bold green]\n"
        f"[dim]Running parallel passive threat assessment...[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    agent = SentryIPAgent()
    tasks = [agent.investigate(str(h)) for h in hosts]
    reports: List[FinalReport] = await asyncio.gather(*tasks, return_exceptions=False)

    # Render aggregated summary table
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Host IP", style="bold cyan", width=18)
    table.add_column("Verdict", width=14)
    table.add_column("Risk Score", width=12)
    table.add_column("Organization / ISP", style="white")
    table.add_column("rDNS", style="dim")
    table.add_column("Top Finding", style="yellow")

    for r in reports:
        badge = _get_verdict_badge(r.verdict)
        score_str = f"{r.risk_score}/100"
        top_finding = r.reputation_findings[0].finding[:45] if r.reputation_findings else "Clean"
        table.add_row(
            r.ip,
            badge,
            score_str,
            r.ownership.org or r.network.isp or "Unknown",
            r.network.rdns or "-",
            top_finding,
        )

    console.print(Panel(
        table,
        title=f"[bold green]📊 Aggregated Subnet Assessment: {cidr_str}[/bold green]",
        border_style="green",
        box=box.ROUNDED,
    ))

    return reports
