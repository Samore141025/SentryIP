"""
Interactive terminal UI, animated telemetry, Matrix cyber rain,
and real-time execution dashboards for SentryIP.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich import box

from sentryip.agent import SentryIPAgent
from sentryip.cache import cache
from sentryip.config import settings
from sentryip.fx import hacker_auth_sequence
from sentryip.keymanager import configure_keys_interactive
from sentryip.logging import logger
from sentryip.models import FinalReport
from sentryip.report import render_report

console = Console()

BANNER = r"""[bold green]
   ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗██╗██████╗ 
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║██╔══██╗
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ██║██████╔╝
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ██║██╔═══╝ 
   ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ██║██║     
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     
[/bold green][bold cyan]⚡ AUTONOMOUS SOC THREAT INTELLIGENCE AGENT ⚡[/bold cyan]
[dim white]Passive Threat Surface Defense • Zero-Touch Forensic Correlation[/dim white]
"""

TOOL_DISPLAY_MAP = {
    "validate_ip": "Address Classification & RFC1918 Bogon Check",
    "rdap_whois": "RDAP Registration, Netblock & Abuse Contacts",
    "reverse_dns": "Reverse DNS (PTR) & Forward-Confirmed FCrDNS",
    "geolocate": "Global Geolocation, ASN & Proxy/Hosting Flags",
    "abuseipdb_check": "AbuseIPDB Threat Confidence & Community Reports",
    "virustotal_ip": "VirusTotal v3 Multi-Engine Security Detections",
    "greynoise_check": "GreyNoise RIOT (Rule It Out) & Mass Scanner Intel",
    "shodan_internetdb": "Passive Attack Surface, Open Ports & Known CVEs",
    "tor_and_blocklist_check": "Tor Exit Node Directory & Botnet Feeds (Feodo/Spamhaus)",
    "otx_pulses": "AlienVault OTX Threat Pulses & Adversary Campaigns",
}


def print_banner() -> None:
    console.print(BANNER)
    feeds = []
    if settings.gemini_api_key:
        feeds.append("[bold green]Google Gemini (Brain)[/bold green]")
    elif settings.anthropic_api_key:
        feeds.append("[bold green]Claude 3.5 (Brain)[/bold green]")
    else:
        feeds.append("[bold yellow]Autonomous Correlator[/bold yellow]")

    if settings.vt_api_key:
        feeds.append("[green]VirusTotal (Active)[/green]")
    if settings.abuseipdb_api_key:
        feeds.append("[green]AbuseIPDB (Active)[/green]")

    feeds.append("[cyan]RDAP/Whois[/cyan]")
    feeds.append("[cyan]Shodan InternetDB[/cyan]")
    feeds.append("[cyan]GreyNoise RIOT[/cyan]")
    feeds.append("[cyan]Tor & Feodo Feeds[/cyan]")

    feed_line = " • ".join(feeds)
    console.print(Panel(
        f"[bold white]Intelligence Feeds:[/bold white] {feed_line}\n"
        f"[bold white]Defense Policy:[/bold white] [bold green]Strictly Passive (Zero Port Scanning)[/bold green] | "
        f"[bold white]Commands:[/bold white] [cyan]keys[/cyan] (configure keys) | [red]exit[/red] / [red]quit[/red] (exit)",
        border_style="bright_blue",
        box=box.ROUNDED,
    ))


def get_public_ip() -> Optional[str]:
    """Auto-detect current host's external public IP."""
    try:
        req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "SentryIP/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            return data.get("ip")
    except Exception:
        return None


class AnimatedInvestigator:
    """Manages real-time live terminal telemetry dashboard and animations."""

    def __init__(self, ip: str, verbose: bool = False):
        self.ip = ip
        self.verbose = verbose
        self.statuses: Dict[str, str] = {
            t: "Pending" for t in TOOL_DISPLAY_MAP.keys()
        }
        self.details: Dict[str, str] = {}
        self.start_time = time.time()

    def update_tool(self, name: str, status: str, detail: str = ""):
        self.statuses[name] = status
        if detail:
            self.details[name] = detail

    def generate_dashboard(self) -> Panel:
        elapsed = time.time() - self.start_time
        table = Table(box=box.SIMPLE, show_header=True, expand=True)
        table.add_column("Threat Intelligence Feed", style="white bold", width=38)
        table.add_column("Status", width=16)
        table.add_column("Telemetry / Observation", style="dim")

        for key, title in TOOL_DISPLAY_MAP.items():
            st = self.statuses.get(key, "Pending")
            detail = self.details.get(key, "")

            if st == "Running":
                st_text = "[bold yellow]⏳ Running...[/bold yellow]"
            elif st == "Done":
                st_text = "[bold green]✔ Complete[/bold green]"
            elif st == "Skipped":
                st_text = "[dim yellow]⚠ Skipped[/dim yellow]"
            elif st == "Failed":
                st_text = "[bold red]✖ Error[/bold red]"
            else:
                st_text = "[dim]• Queued[/dim]"

            table.add_row(title, st_text, detail[:65] if detail else "")

        header = (
            f"[bold cyan]Target IP:[/bold cyan] [bold white]{self.ip}[/bold white]  "
            f"[dim]|[/dim]  [bold cyan]Elapsed:[/bold cyan] [bold yellow]{elapsed:.1f}s[/bold yellow]  "
            f"[dim]|[/dim]  [bold green]Autonomous Orchestration[/bold green]"
        )

        return Panel(
            Group(
                Text.from_markup(header),
                table,
            ),
            title="[bold yellow]⚡ Autonomous Investigation Pipeline in Progress...[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )


async def run_investigation_with_animation(
    ip: str,
    verbose: bool = False,
    no_cache: bool = False,
) -> FinalReport:
    """Runs investigation with full live Rich terminal animation."""
    if no_cache:
        cache.clear()

    animator = AnimatedInvestigator(ip, verbose=verbose)

    with Live(animator.generate_dashboard(), refresh_per_second=8, console=console) as live:

        def on_tool_start(tool_name: str, args: dict):
            animator.update_tool(tool_name, "Running", "Querying feed...")
            live.update(animator.generate_dashboard())

        def on_tool_finish(tool_name: str, result: dict):
            if result.get("skipped"):
                animator.update_tool(tool_name, "Skipped", result.get("reason", "Key unconfigured"))
            elif result.get("error"):
                animator.update_tool(tool_name, "Failed", result.get("error", "Failed"))
            else:
                summary = ""
                if tool_name == "validate_ip":
                    summary = f"{result.get('version', '')} {result.get('ip_type', '')}"
                elif tool_name == "rdap_whois":
                    summary = f"{result.get('asn', '')} ({result.get('org_name', '')})"
                elif tool_name == "reverse_dns":
                    summary = result.get("primary_ptr") or "No rDNS"
                elif tool_name == "geolocate":
                    summary = f"{result.get('city', '')}, {result.get('country', '')}"
                elif tool_name == "shodan_internetdb":
                    ports = result.get("open_ports", [])
                    vulns = result.get("vulns", [])
                    summary = f"Ports: {len(ports)} | Vulns: {len(vulns)}"
                elif tool_name == "tor_and_blocklist_check":
                    matches = len(result.get("blocklist_matches", []))
                    tor = "Tor Exit" if result.get("is_tor_exit_node") else "Clean"
                    summary = f"{tor} | Feeds: {matches} hit(s)"
                elif tool_name == "greynoise_check":
                    summary = f"RIOT: {result.get('riot', False)} | {result.get('classification', 'unknown')}"
                elif tool_name == "abuseipdb_check":
                    summary = f"Score: {result.get('abuse_confidence_score', 0)}% | Reports: {result.get('total_reports', 0)}"
                elif tool_name == "virustotal_ip":
                    summary = f"Malicious: {result.get('malicious_count', 0)} engines"
                elif tool_name == "otx_pulses":
                    summary = f"Pulses: {result.get('pulse_count', 0)}"

                animator.update_tool(tool_name, "Done", summary)

            live.update(animator.generate_dashboard())

        agent = SentryIPAgent(
            on_tool_start=on_tool_start,
            on_tool_finish=on_tool_finish,
        )

        report = await agent.investigate(ip)

        # If non-public IP stopped early, mark remaining feeds clearly
        if report.ip_type != "public":
            for tool_key in TOOL_DISPLAY_MAP.keys():
                if animator.statuses.get(tool_key) == "Pending":
                    animator.update_tool(tool_key, "Skipped", f"N/A ({report.ip_type.value.upper()} address)")

        live.update(animator.generate_dashboard())
        await asyncio.sleep(0.4)

    return report


def handle_report_output(
    report: FinalReport,
    json_mode: bool = False,
    output_file: Optional[str] = None,
) -> None:
    json_data = report.model_dump_json(indent=2)
    if output_file:
        out_path = Path(output_file)
        out_path.write_text(json_data, encoding="utf-8")
        console.print(f"[bold green]✔ Report saved successfully to {out_path.resolve()}[/bold green]")

    if json_mode:
        print(json_data)
    else:
        render_report(report, console)


async def interactive_repl(verbose: bool = False, no_cache: bool = False) -> None:
    """Continuous SOC interactive terminal with clean exit & key management."""
    print_banner()

    my_ip = get_public_ip()
    if my_ip:
        console.print(f"[dim white]💡 Auto-detected external IP: [bold cyan]{my_ip}[/bold cyan] (Press Enter to analyze, or type any target)[/dim white]")
    console.print("[dim]Type [bold red]'exit'[/bold red] to close, or [bold cyan]'keys'[/bold cyan] to configure API keys.\n[/dim]")

    while True:
        try:
            prompt_str = f"[bold green]sentryip[/bold green] [dim]({my_ip or 'target'})[/dim] >"
            user_input = Prompt.ask(prompt_str, default=my_ip or "")
            clean = user_input.strip()

            # Clean exit handling
            if clean.lower() in ["exit", "quit", "q", "bye"]:
                console.print(Panel("[bold green]✔ SentryIP session terminated safely. Goodbye, Analyst.[/bold green]", border_style="green"))
                break

            # In-terminal key manager
            if clean.lower() in ["keys", "key", "config", "configure"]:
                configure_keys_interactive()
                print_banner()
                continue

            if not clean:
                continue

            report = await run_investigation_with_animation(clean, verbose=verbose, no_cache=no_cache)
            handle_report_output(report, json_mode=False)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Session cancelled by user. Exiting safely.[/bold yellow]")
            break
        except Exception as e:
            console.print(f"[bold red]Investigation error: {e}[/bold red]")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentryip",
        description="Autonomous SOC AI Analyst for IP Threat Intelligence.",
    )
    parser.add_argument(
        "ip",
        nargs="?",
        default=None,
        help="Target IP address for immediate autonomous investigation",
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="Display cool hacker matrix binary rain animation on launch",
    )
    parser.add_argument(
        "--keys",
        action="store_true",
        help="Configure API keys directly from the terminal",
    )
    parser.add_argument(
        "-a", "--auto",
        action="store_true",
        help="Automatically detect and investigate current host's external public IP",
    )
    parser.add_argument(
        "-f", "--file",
        dest="file",
        default=None,
        help="Path to a text file with multiple IP addresses (one per line)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Output raw structured JSON instead of Rich terminal UI",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        help="Save final JSON report to specified file path",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show live tool execution details and intermediate responses",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass local SQLite threat intelligence cache",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Terminal key configuration command
    if args.keys:
        configure_keys_interactive()
        sys.exit(0)

    # Fast hacker operator authentication sequence
    if not args.json_mode and (not args.file or sys.stdin.isatty()):
        hacker_auth_sequence()

    try:
        target_ip = args.ip
        if args.auto or (not target_ip and not args.file and sys.stdin.isatty() is False):
            target_ip = get_public_ip()

        if args.file:
            path = Path(args.file)
            if not path.is_file():
                console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
                sys.exit(1)
            ips = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]
            for idx, ip in enumerate(ips, 1):
                console.print(f"\n[bold cyan][{idx}/{len(ips)}] Investigating {ip}...[/bold cyan]")
                report = asyncio.run(run_investigation_with_animation(ip, verbose=args.verbose, no_cache=args.no_cache))
                handle_report_output(report, json_mode=args.json_mode, output_file=args.output_file)
        elif target_ip:
            print_banner()
            report = asyncio.run(run_investigation_with_animation(target_ip, verbose=args.verbose, no_cache=args.no_cache))
            handle_report_output(report, json_mode=args.json_mode, output_file=args.output_file)
        else:
            asyncio.run(interactive_repl(verbose=args.verbose, no_cache=args.no_cache))

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user. Exiting.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Fatal error: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
