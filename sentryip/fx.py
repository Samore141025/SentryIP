"""
Hacker authentication startup sequence for SentryIP.
Fast, crisp, and lag-free.
"""

from __future__ import annotations

import time
from rich.console import Console

console = Console()


def hacker_auth_sequence(delay: float = 0.08) -> None:
    """Fast, crisp hacker authentication sequence."""
    console.print("\n[bold green]>>> INITIALIZING SENTRY-IP DEFENSE NODE...[/bold green]")
    time.sleep(delay)

    steps = [
        ("Establishing encrypted tunnel TLS 1.3...", "cyan"),
        ("Loading passive threat signature databases...", "cyan"),
        ("Verifying local sandbox & runtime boundaries...", "cyan"),
        ("Synchronizing feed hashes (Spamhaus, Feodo, Tor)...", "cyan"),
        ("AUTHENTICATION CLEARED: ACCESS LEVEL 5 - SOC OPERATOR", "bold green"),
    ]

    for step_text, style in steps:
        time.sleep(delay)
        console.print(f" [bold green]>[/bold green] [{style}]{step_text}[/{style}]")

    time.sleep(delay)
    console.print("\n[bold green]>>> SYSTEM READY. WELCOME, OPERATOR.[/bold green]\n")
    time.sleep(delay)
