"""Terminal output."""

import os
import sys

# ANSI colors, dropped automatically when output is piped to a file.
COLORS = {
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def use_color(stream=None):
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text, color, enabled):
    if not enabled or color not in COLORS:
        return text
    return COLORS[color] + text + COLORS["reset"]


def mask(secret, keep=4):
    """Hide the middle of a secret so the report is safe to paste into a ticket.

    Short values get blanked out completely, since showing 4 characters of an
    8 character password gives away half of it.
    """
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return secret[:keep] + "..." + secret[-keep:]


def print_report(findings, scanned_count, show_secrets=False, stream=None):
    """Write the human readable report.

    Findings are grouped by file, and within a file the worst ones come first.
    """
    stream = stream or sys.stdout
    color = use_color(stream)

    if not findings:
        stream.write("No secrets found. Scanned %d file%s.\n"
                     % (scanned_count, "" if scanned_count == 1 else "s"))
        return

    by_file = {}
    for f in findings:
        by_file.setdefault(f.path, []).append(f)

    for path in sorted(by_file):
        stream.write("\n" + paint(path, "bold", color) + "\n")
        items = sorted(by_file[path],
                       key=lambda f: (CONFIDENCE_RANK[f.confidence], f.line_number))
        for f in items:
            shown = f.value if show_secrets else mask(f.value)
            label = paint(f.confidence.upper().ljust(6), f.confidence, color)
            stream.write("  line %-5d %s %s\n" % (f.line_number, label, f.type))
            stream.write("      %s\n" % paint(shown, "dim", color))
            if f.entropy is not None:
                stream.write("      %s\n"
                             % paint("entropy %.2f bits/char" % f.entropy, "dim", color))

    counts = summarize(findings)
    stream.write("\n" + paint("-" * 52, "dim", color) + "\n")
    stream.write("%d finding%s in %d file%s (%d scanned)\n"
                 % (len(findings), "" if len(findings) == 1 else "s",
                    len(by_file), "" if len(by_file) == 1 else "s",
                    scanned_count))
    stream.write("  high: %d   medium: %d   low: %d\n"
                 % (counts["high"], counts["medium"], counts["low"]))
    if not show_secrets:
        stream.write(paint("  values are masked, pass --show-secrets to see them\n",
                           "dim", color))


def summarize(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.confidence] += 1
    return counts
