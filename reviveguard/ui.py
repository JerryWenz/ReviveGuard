"""Terminal presentation: the logo, colors and command highlighting.

Colors are used only on a capable terminal (TTY, ``TERM`` not ``dumb``, ``NO_COLOR`` unset,
no ``--no-color``); otherwise everything is plain ASCII/UTF-8 text, readable over SSH and in
logs. The logo is shown only on a TTY.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

RESET = "\033[0m"
CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}
SEVERITY_STYLE = {
    "CRITICAL": ("red", "bold"),
    "HIGH": ("red",),
    "MEDIUM": ("yellow",),
    "LOW": ("blue",),
    "INFO": ("cyan",),
    "OK": ("green",),
    "SKIP": ("dim",),
    "ERROR": ("magenta", "bold"),
}
_QUOTED = re.compile(r"'([^'\n]{2,80})'")

_GLYPHS = {
    "R": [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"],
    "E": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
    "V": ["__     __", "\\ \\   / /", " \\ \\ / / ", "  \\ V /  ", "   \\_/   "],
    "I": [" ___ ", "|_ _|", " | | ", " | | ", "|___|"],
}
HEARTBEAT = "_______/\\______/\\/\\____/\\_______"  # the "revive" pulse, plain ASCII


def logo_lines() -> list[str]:
    word = "REVIVE"
    return ["".join(_GLYPHS[ch][row] for ch in word).rstrip() for row in range(5)]


@dataclass(frozen=True)
class Style:
    enabled: bool = False  # colors
    fancy: bool = False  # logo (TTY output)

    def paint(self, text: str, *names: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\033[{';'.join(CODES[n] for n in names)}m{text}{RESET}"

    def bold(self, text: str) -> str:
        return self.paint(text, "bold")

    def dim(self, text: str) -> str:
        return self.paint(text, "dim")

    def cmd(self, text: str) -> str:
        return self.paint(text, "cyan", "bold")

    def tag(self, label: str) -> str:
        """``[HIGH]``-style tag colored by its meaning."""
        return self.paint(f"[{label}]", *SEVERITY_STYLE.get(label, ("bold",)))

    def markup(self, text: str) -> str:
        """Highlight 'quoted' commands and settings inside a message."""
        if not self.enabled:
            return text
        return _QUOTED.sub(lambda m: "'" + self.cmd(m.group(1)) + "'", text)

    def step(self, current: int, total: int, title: str) -> str:
        return self.paint(f"[{current}/{total}]", "green", "bold") + " " + self.bold(title)

    def rule(self, width: int = 60) -> str:
        return self.dim("-" * width)


def detect(stream, no_color: bool = False, env: dict[str, str] | None = None) -> Style:
    env = os.environ if env is None else env
    tty = bool(getattr(stream, "isatty", lambda: False)())
    colors = tty and not no_color and "NO_COLOR" not in env and env.get("TERM") != "dumb"
    return Style(enabled=colors, fancy=tty)


def banner(style: Style, tagline: str, version: str) -> str:
    """The REVIVE logo with the heartbeat line (TTY only; otherwise a plain title)."""
    if not style.fancy:
        return f"ReviveGuard {version}\n{tagline}\n"
    logo = [style.paint(line, "green", "bold") for line in logo_lines()]
    pulse = style.paint(HEARTBEAT, "red")
    footer = f"{style.bold('ReviveGuard')} {style.dim(version)}  {style.dim(tagline)}"
    return "\n".join(["", *logo, pulse, footer, ""]) + "\n"
