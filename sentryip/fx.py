"""
Hacker-style terminal visual effects: matrix digital rain, authentication sequence,
and live background binary rain stream renderer.
"""

from __future__ import annotations

import random
import shutil
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

MATRIX_CHARS = "010101010101ABCDEF0123456789!@#$%^&*<>[]{}~=+-_"


def matrix_rain_animation(duration_seconds: float = 2.2, speed: float = 0.08) -> None:
    """Render a slow, smooth matrix digital rain full-screen animation in the terminal."""
    try:
        width, height = shutil.get_terminal_size(fallback=(80, 24))
        width = max(40, min(width, 95))
        lines_count = max(8, min(height - 4, 18))

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
                    elif (drops[x] - y) in range(4, 7):
                        char = random.choice("01")
                        line.append(char, style="dim green on black")
                        line.append(" ", style="black on black")
                    else:
                        line.append("  ", style="black on black")

                frame_lines.append(line)

            for i in range(0, width, 2):
                if random.random() > 0.35:
                    drops[i] = (drops[i] + 1) % (lines_count + 5)

            console.clear()
            for fl in frame_lines:
                console.print(fl)

            time.sleep(speed)

    except Exception:
        pass


def hacker_auth_sequence() -> None:
    """Simulate a cool sci-fi / cyberpunk hacker authentication handshake."""
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
        time.sleep(0.3)
        console.print(f" [bold green]>[/bold green] [{style}]{step_text}[/{style}]")

    time.sleep(0.3)
    console.print("\n[bold green]>>> SYSTEM READY. WELCOME, OPERATOR.[/bold green]\n")
    time.sleep(0.5)


class MatrixRainStream:
    """Generates continuous live binary rain lines behind or around live panels."""

    def __init__(self, cols: int = 36, rows: int = 3):
        self.cols = cols
        self.rows = rows
        self.drops = [random.randint(0, rows * 2) for _ in range(cols)]

    def get_lines(self) -> Text:
        txt = Text()
        for r in range(self.rows):
            for c in range(self.cols):
                dist = (self.drops[c] - r)
                if dist == 0:
                    txt.append(random.choice("01"), style="bold white on black")
                elif dist in (1, 2):
                    txt.append(random.choice("0123456789ABCDEF"), style="bold green on black")
                elif dist in (3, 4, 5):
                    txt.append(random.choice("01"), style="dim green on black")
                else:
                    txt.append(" ", style="black on black")
                txt.append(" ")

            if r < self.rows - 1:
                txt.append("\n")

            # Shift drops down
            for c in range(self.cols):
                if random.random() > 0.4:
                    self.drops[c] = (self.drops[c] + 1) % (self.rows + 6)

        return txt
