"""
Shared terminal UI primitives — ANSI colors, panel rendering, text wrapping.

Supports flat panels, nested sub-panels, and free-form text lines.
Used by ``observability.py`` (per-step callbacks) and ``cli.py``
(startup/conclusion panels).
"""
from __future__ import annotations

import shutil
import sys
import textwrap
from typing import Any

from shared.utils.env import env_value


# ── ANSI escape codes ────────────────────────────────────────────────

class Ansi:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[36m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE   = "\033[34m"
    WHITE  = "\033[37m"


# ── Helpers ──────────────────────────────────────────────────────────

def color_enabled() -> bool:
    force = (env_value("ADK_FORCE_COLOR", "true") or "true").lower()
    if force in {"0", "false", "no"}:
        return False
    return sys.stdout.isatty() or force in {"1", "true", "yes"}


def color(text: str, color_code: str) -> str:
    if not color_enabled():
        return text
    return f"{color_code}{text}{Ansi.RESET}"


def terminal_width() -> int:
    width = shutil.get_terminal_size((120, 20)).columns
    return max(72, min(width, 160))


# ── Text wrapping ────────────────────────────────────────────────────

def wrap_text(text: str, width: int) -> list[str]:
    """Wrap multi-line text to fit within *width* columns."""
    result: list[str] = []
    for raw_line in str(text).splitlines():
        wrapped = textwrap.wrap(raw_line, width=width) or [""]
        result.extend(wrapped)
    return result


def wrap_row(label: str, value: Any, width: int) -> list[str]:
    """Format ``label: value`` with continuation-indent wrapping."""
    prefix = f"{label}: "
    available = max(12, width - len(prefix))
    chunks = wrap_text(str(value), available)
    lines = [f"{prefix}{chunks[0]}"]
    indent = " " * len(prefix)
    for extra in chunks[1:]:
        lines.append(f"{indent}{extra}")
    return lines


# ── Panel rendering ─────────────────────────────────────────────────

def _render_box(
    title: str,
    body_lines: list[str],
    color_code: str,
    width: int | None = None,
    *,
    indent: int = 0,
) -> list[str]:
    """
    Render a Unicode box with *title* and *body_lines*.

    Returns a list of ready-to-print strings (no trailing newline).
    *indent* adds leading spaces (used for nested sub-panels).
    """
    max_w = (width or terminal_width()) - 2 - indent
    title_text = f" {title} "

    content_w = max(
        len(title_text),
        max((len(l) for l in body_lines), default=0),
        36,
    )
    content_w = min(content_w, max_w)

    # Normalize lines that exceed content_w
    normalized: list[str] = []
    for line in body_lines:
        if len(line) <= content_w:
            normalized.append(line)
        else:
            normalized.extend(textwrap.wrap(line, width=content_w))

    pad = " " * indent
    right_fill = content_w - len(title_text)
    top = f"{pad}╭─{title_text}{'─' * right_fill}╮"
    bot = f"{pad}╰{'─' * (content_w + 1)}╯"

    out = [top]
    for line in normalized:
        out.append(f"{pad}│ {line.ljust(content_w)}│")
    out.append(bot)
    return [color(l, color_code) for l in out]


def print_panel(title: str, rows: list[tuple[str, Any]], color_code: str) -> None:
    """Print a simple key-value panel (backward-compatible API)."""
    w = terminal_width()
    body: list[str] = []
    for label, value in rows:
        body.extend(wrap_row(label, value, w - 6))
    lines = _render_box(title, body, color_code, w)
    print("")
    print("\n".join(lines))


# ── Rich panel (new UI) ─────────────────────────────────────────────

def print_compact_panel(title: str, body: str, color_code: str) -> None:
    """
    Print a compact single-body panel::

        ╭─ title ─────────╮
        │ body text here   │
        ╰──────────────────╯
    """
    w = terminal_width()
    body_lines = wrap_text(body, w - 6)
    lines = _render_box(title, body_lines, color_code, w)
    print("")
    print("\n".join(lines))


def print_rich_panel(
    title: str,
    *,
    header_line: str | None = None,
    sub_panel_title: str | None = None,
    sub_panel_body: str | None = None,
    footer_line: str | None = None,
    color_code: str = Ansi.GREEN,
) -> None:
    """
    Print a rich panel with optional nested sub-panel::

        ╭─ title ──────────────────────────────────╮
        │ header_line                               │
        │                                           │
        │ ╭─ sub_panel_title ────────────────────╮  │
        │ │ sub_panel_body                        │  │
        │ ╰──────────────────────────────────────╯  │
        │                                           │
        │  footer_line                              │
        ╰───────────────────────────────────────────╯
    """
    w = terminal_width()
    inner_w = w - 6  # account for outer box padding (│ + space + content + space + │)

    body: list[str] = []

    if header_line:
        body.extend(wrap_text(header_line, inner_w))
        body.append("")

    if sub_panel_title and sub_panel_body is not None:
        # Render nested sub-panel with indent, but we need to handle it specially
        # Calculate width for sub-panel content: inner_w - 2 (for " " prefix we'll add manually)
        sub_inner_w = inner_w - 2
        sub_body = wrap_text(sub_panel_body, sub_inner_w - 4)  # -4 for sub-panel's │ padding
        
        # Render sub-panel without indent first
        sub_lines_raw = _render_box(sub_panel_title, sub_body, color_code, sub_inner_w, indent=0)
        
        # Strip ANSI codes and add single-space prefix manually
        for sl in sub_lines_raw:
            plain = sl
            if color_enabled():
                # Remove color codes
                plain = plain.replace(color_code, "").replace(Ansi.RESET, "")
            # Add single space prefix for visual indent
            body.append(" " + plain)
        body.append("")

    if footer_line:
        body.extend(wrap_text(footer_line, inner_w))

    lines = _render_box(title, body, color_code, w)
    print("")
    print("\n".join(lines))
