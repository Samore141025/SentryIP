"""
Hacker-style terminal visual effects: matrix digital rain, authentication sequence,
cyberpunk banners, and audio-visual cues.
"""

from __future__ import annotations

import asyncio
import os
import random
import shutil
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

MATRIX_CHARS = "010101010101ABCDEF0123456789!@#$%^&*<>[]{}~=+-_"


def matrix_rain_animation(duration_seconds: float = 2.5, speed: float = 0.08) -> None:
    """Render a slow, smooth matrix digital rain animation in the terminal."""
    try:
        width, height = shutil.get_terminal_size(fallback=(80, 24))
        width = max(40, min(width, 100))
        lines_count = max(10, min(height - 4, 20))

        drops = [random.randint(0, lines_count) for _ in range(width)]
        end_time = time.time() + duration_seconds

        console.clear()
        while time.time() < end_time:
            frame_lines = []
            for y in range(lines_count):
                line = Text()
                for x in range(0, width, 2):
                    if drops[x] == y:
                        line.append(random.choice("01"), style="bold white on black")
                        line.append(" ", style="black on black")
                    elif (drops[x] - y) in range(1, 4):
                        char = random.choice(MATRIX_CHARS)
                        line.append(char, style="bold green on black")
                        line.append(" ", style="black on black")
                    elif (drops[x] - y) in range(4, 8):
                        char = random.choice("01")
                        line.append(char, style="dim green on black")
                        line.append(" ", style="black on black")
                    else:
                        line.append("  ", style="black on black")

                frame_lines.append(line)

            # Move drop positions down
            for i in range(0, width, 2):
                if random.random() > 0.35:
                    drops[i] = (drops[i] + 1) % (lines_count + 6)

            # Render frame
            console.clear()
            for fl in frame_lines:
                console.print(fl)

            time.sleep(speed)

    except Exception:
        pass


def hacker_auth_sequence() -> None:
    """Simulate a cool sci-fi / cyberpunk hacker authentication hand-shake."""
    console.clear()
    console.print("\n[bold green]>>> INITIALIZING SENTRY-IP DEFENSE NODE...[/bold green]")
    time.sleep(0.3)

    steps = [
        ("Establishing encrypted tunnel TLS 1.3...", "cyan"),
        ("Loading passive threat signature databases...", "cyan"),
        ("Verifying local sandbox & runtime boundaries...", "cyan"),
        ("Synchronizing feed hashes (Spamhaus, Feodo, Tor)...", "cyan"),
        ("AUTHENTICATION CLEARED: ACCESS LEVEL 5 - SOC OPERATOR", "bold green"),
    ]

    for step_text, style in steps:
        time.sleep(0.35)
        console.print(f" [bold green]>[/bold green] [{style}]{step_text}[/{style}]")

    time.sleep(0.4)
    console.print("\n[bold green]>>> SYSTEM READY. WELCOME, ANALYST.[/bold green]\n")
    time.sleep(0.6)
