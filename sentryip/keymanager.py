"""
Interactive terminal-based API key management for SentryIP.
Allows analysts to set, update, or view API keys entirely from the terminal.
"""

from __future__ import annotations

import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import box
from sentryip.config import settings

console = Console()
ENV_FILE = Path(".env")


def get_current_keys() -> dict[str, str]:
    keys = {
        "GEMINI_API_KEY": settings.gemini_api_key,
        "ANTHROPIC_API_KEY": settings.anthropic_api_key,
        "VT_API_KEY": settings.vt_api_key,
        "ABUSEIPDB_API_KEY": settings.abuseipdb_api_key,
        "OTX_API_KEY": settings.otx_api_key,
        "IPINFO_TOKEN": settings.ipinfo_token,
    }
    return keys


def save_key_to_env(key_name: str, value: str) -> None:
    lines = []
    found = False
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()

    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{key_name}="):
            new_lines.append(f"{key_name}={value.strip()}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{key_name}={value.strip()}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    os.environ[key_name] = value.strip()


def configure_keys_interactive() -> None:
    """Terminal wizard to configure API keys interactively."""
    console.print(Panel(
        "[bold cyan]🔑 SentryIP Terminal Key Manager[/bold cyan]\n"
        "[dim]All keys are written exclusively to your local .env (never committed to git)[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    keys = [
        ("GEMINI_API_KEY", "Google Gemini API Key (Powers Autonomous AI Analysis)"),
        ("ANTHROPIC_API_KEY", "Anthropic Claude API Key (Optional Alternative)"),
        ("VT_API_KEY", "VirusTotal v3 API Key (70+ AV Engine Scans)"),
        ("ABUSEIPDB_API_KEY", "AbuseIPDB API Key (Global Abuse Reports)"),
        ("OTX_API_KEY", "AlienVault OTX Key (Threat Pulses)"),
        ("IPINFO_TOKEN", "IPinfo.io Token (Enhanced Geolocation & ASN)"),
    ]

    for key_name, desc in keys:
        current = os.getenv(key_name, getattr(settings, key_name.lower(), ""))
        masked = f"{current[:6]}...{current[-4:]}" if len(current) > 10 else ("Configured" if current else "[dim red]Not Set[/dim red]")

        console.print(f"\n[bold white]{desc}[/bold white]")
        console.print(f"Current Status: {masked}")
        new_val = Prompt.ask(
            f"Enter new value for [cyan]{key_name}[/cyan] (press Enter to keep existing)",
            default="",
            show_default=False,
        )

        if new_val.strip():
            save_key_to_env(key_name, new_val.strip())
            console.print(f"[bold green]✔ Saved {key_name} to .env[/bold green]")

    console.print("\n[bold green]✔ Key configuration complete! SentryIP is ready.[/bold green]\n")
