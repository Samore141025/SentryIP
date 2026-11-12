"""
Rich terminal UI rendering for SOC analyst reports.
"""

from __future__ import annotations

from typing import List
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from sentryip.models import FinalReport, Verdict

console = Console()


def _get_verdict_badge(verdict: Verdict) -> Text:
    if verdict == Verdict.SAFE:
        return Text(" SAFE ", style="bold black on green")
    elif verdict == Verdict.SUSPICIOUS:
        return Text(" SUSPICIOUS ", style="bold black on yellow")
    elif verdict == Verdict.MALICIOUS:
        return Text(" MALICIOUS ", style="bold white on red")
    else:
        return Text(" UNKNOWN ", style="bold white on blue")


def _get_score_bar(score: int, width: int = 20) -> str:
    filled = int((score / 100.0) * width)
    unfilled = width - filled
    return f"[{'█' * filled}{'░' * unfilled}] {score}/100"


def render_report(report: FinalReport, target_console: Console = console) -> None:
    """Renders the FinalReport model into high-fidelity Rich SOC terminal panels."""

    # 1. Header Banner
    badge = _get_verdict_badge(report.verdict)
    header_text = Text()
    header_text.append(f"Target: {report.ip} ({report.ip_type.value.upper()})\n", style="bold cyan")
    header_text.append(f"Assessment: ", style="bold")
    header_text.append_text(badge)
    header_text.append(f"  |  Risk Score: ", style="bold")

    if report.risk_score >= 60:
        header_text.append(_get_score_bar(report.risk_score), style="bold red")
    elif report.risk_score >= 25:
        header_text.append(_get_score_bar(report.risk_score), style="bold yellow")
    else:
        header_text.append(_get_score_bar(report.risk_score), style="bold green")

    header_text.append(f"  |  Confidence: {report.confidence}%\n", style="bold magenta")
    header_text.append(f"Timestamp: {report.timestamp}", style="dim")

    target_console.print()
    target_console.print(
        Panel(
            header_text,
            title="[bold blue]🛡️ SentryIP Threat Intelligence Assessment[/bold blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )

    # 2. Executive Summary
    summary_panel = Panel(
        Text(report.summary, style="white"),
        title="[bold yellow]📋 Executive Summary[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED,
    )
    target_console.print(summary_panel)

    # 3. Ownership & Network Infrastructure (Side-by-side or consecutive tables)
    info_table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    info_table.add_column("Category", style="cyan bold", width=20)
    info_table.add_column("Details", style="white")

    # Ownership rows
    own = report.ownership
    info_table.add_row("Organization / Owner", own.org or "[dim]N/A[/dim]")
    info_table.add_row("ASN", own.asn or "[dim]N/A[/dim]")
    info_table.add_row("CIDR / Netblock", own.cidr or "[dim]N/A[/dim]")
    info_table.add_row("Country / Abuse", f"{own.country or 'N/A'} | {own.abuse_contact or 'N/A'}")

    # Network rows
    net = report.network
    info_table.add_row("Reverse DNS (rDNS)", net.rdns or "[dim]None / Unresolved[/dim]")
    info_table.add_row("ISP", net.isp or "[dim]N/A[/dim]")

    flags = []
    if net.hosting:
        flags.append("[bold magenta]Hosting/Datacenter[/bold magenta]")
    if net.vpn_proxy:
        flags.append("[bold yellow]VPN/Proxy[/bold yellow]")
    if net.tor:
        flags.append("[bold red]TOR Exit Node[/bold red]")
    flag_str = ", ".join(flags) if flags else "[green]Direct / Clean Consumer/Enterprise[/green]"
    info_table.add_row("Network Attributes", flag_str)

    # Geolocation rows
    geo = report.geolocation
    geo_parts = [p for p in [geo.city, geo.region, geo.country] if p]
    geo_str = ", ".join(geo_parts) if geo_parts else "[dim]Unknown[/dim]"
    info_table.add_row("Location", f"{geo_str} ({geo.latitude or 0.0}, {geo.longitude or 0.0})")

    target_console.print(
        Panel(
            info_table,
            title="[bold cyan]🌐 Infrastructure & Network Attribution[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # 4. Passive Services & Known Vulnerabilities (InternetDB)
    ports_table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    ports_table.add_column("Passive Open Ports", style="green", width=30)
    ports_table.add_column("Associated Vulnerabilities (CVEs)", style="red")

    ports_str = ", ".join(str(p) for p in report.open_ports) if report.open_ports else "[dim]No open ports in passive database[/dim]"
    vulns_str = ", ".join(report.vulns) if report.vulns else "[green]No known public vulnerabilities cataloged[/green]"
    ports_table.add_row(ports_str, vulns_str)

    target_console.print(
        Panel(
            ports_table,
            title="[bold magenta]🔌 Passive Attack Surface[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

    # 5. Reputation & Intelligence Findings
    if report.reputation_findings:
        rep_table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
        rep_table.add_column("Threat Source", style="cyan bold", width=22)
        rep_table.add_column("Severity", width=12)
        rep_table.add_column("Observation / Evidence", style="white")

        for f in report.reputation_findings:
            sev = f.severity.lower()
            if sev in ["high", "critical"]:
                sev_styled = f"[bold red]{f.severity.upper()}[/bold red]"
            elif sev == "medium":
                sev_styled = f"[bold yellow]{f.severity.upper()}[/bold yellow]"
            else:
                sev_styled = f"[dim cyan]{f.severity.upper()}[/dim cyan]"
            rep_table.add_row(f.source, sev_styled, f.finding)

        target_console.print(
            Panel(
                rep_table,
                title="[bold red]🚨 Correlated Threat Findings[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    # 6. Analyst Reasoning & Blue Team Recommendations
    reasoning_text = Text()
    for idx, r in enumerate(report.reasoning, 1):
        reasoning_text.append(f" • {r}\n", style="white")

    actions_text = Text()
    for idx, a in enumerate(report.recommended_actions, 1):
        actions_text.append(f" [{idx}] {a}\n", style="bold green")

    combined_group = Group(
        Text("Analyst Chain of Evidence:", style="bold underline yellow"),
        reasoning_text,
        Text("Recommended SOC Mitigations:", style="bold underline green"),
        actions_text,
    )

    target_console.print(
        Panel(
            combined_group,
            title="[bold green]🛡️ SOC Analysis & Recommended Actions[/bold green]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    # 7. Execution Telemetry Footer
    footer_text = Text()
    footer_text.append(f"Tools Executed: {', '.join(report.tools_used) or 'None'}\n", style="dim cyan")
    if report.tools_skipped:
        footer_text.append(f"Tools Skipped: {', '.join(report.tools_skipped)} (API key unconfigured)", style="dim yellow")
    target_console.print(footer_text)
    target_console.print()

