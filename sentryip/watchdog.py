"""
Continuous IP Watchdog Daemon for periodic SOC threat monitoring and alerting.
"""

from __future__ import annotations

import asyncio
import time
from rich.console import Console
from rich.panel import Panel
from sentryip.agent import SentryIPAgent
from sentryip.models import FinalReport, Verdict
from sentryip.report import render_report
from sentryip.webhook import send_webhook_alert

console = Console()


async def run_watchdog_loop(
    ip: str,
    interval_seconds: int = 3600,
    webhook_url: str | None = None,
) -> None:
    """Continuously poll an IP address and alert if verdict changes or becomes non-SAFE."""
    console.print(Panel(
        f"[bold red]👁️ SENTRYIP WATCHDOG DAEMON ACTIVATED[/bold red]\n"
        f"Monitoring Target: [bold cyan]{ip}[/bold cyan]\n"
        f"Poll Interval: Every {interval_seconds}s | Webhook: {'Configured' if webhook_url else 'None'}\n"
        f"[dim]Press Ctrl+C to terminate the watchdog process.[/dim]",
        border_style="red",
    ))

    last_verdict: Verdict | None = None
    agent = SentryIPAgent()

    iteration = 0
    while True:
        iteration += 1
        console.print(f"\n[dim cyan][{time.strftime('%Y-%m-%d %H:%M:%S')}] Polling threat feeds for {ip} (Check #{iteration})...[/dim cyan]")
        try:
            report: FinalReport = await agent.investigate(ip)

            # Check for alert state
            verdict_changed = last_verdict is not None and report.verdict != last_verdict
            is_threat = report.verdict in [Verdict.SUSPICIOUS, Verdict.MALICIOUS]

            if verdict_changed or iteration == 1 or is_threat:
                render_report(report, console)

            if verdict_changed:
                console.bell()
                console.print(Panel(
                    f"[bold red]🚨 WATCHDOG ALERT: Verdict Transition Detected for {ip}![/bold red]\n"
                    f"Previous: [bold]{last_verdict.value}[/bold] ➔ Current: [bold red]{report.verdict.value}[/bold red]\n"
                    f"Risk Score: {report.risk_score}/100",
                    border_style="red",
                ))

            if webhook_url and (verdict_changed or is_threat):
                await send_webhook_alert(webhook_url, report)

            last_verdict = report.verdict

        except Exception as e:
            console.print(f"[bold red]Watchdog check error: {e}[/bold red]")

        await asyncio.sleep(interval_seconds)
