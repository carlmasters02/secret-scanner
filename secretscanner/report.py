"""Terminal output and the JSON report."""

import json
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


def plural(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def print_report(findings, scanned_count, show_secrets=False, stream=None,
                 unit="file"):
    """Write the human readable report.

    Findings are grouped by file, and within a file the worst ones come first.
    unit is what scanned_count counts, which is commits in history mode.
    """
    stream = stream or sys.stdout
    color = use_color(stream)

    if not findings:
        stream.write("No secrets found. Scanned %s.\n"
                     % plural(scanned_count, unit))
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
            if f.commit is not None:
                stream.write("      %s\n"
                             % paint("introduced in commit %s" % f.commit[:10],
                                     "dim", color))

    counts = summarize(findings)
    stream.write("\n" + paint("-" * 52, "dim", color) + "\n")
    stream.write("%s in %s (%s scanned)\n"
                 % (plural(len(findings), "finding"),
                    plural(len(by_file), "file"),
                    plural(scanned_count, unit)))
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


def print_json(findings, scanned_count, show_secrets=False, stream=None,
               unit="file"):
    """Dump the same findings as JSON for scripts and CI to consume."""
    stream = stream or sys.stdout

    items = []
    for f in findings:
        item = f.as_dict()
        if not show_secrets:
            item["match"] = mask(item["match"])
        items.append(item)

    payload = {
        "%ss_scanned" % unit: scanned_count,
        "findings_count": len(findings),
        "summary": summarize(findings),
        "masked": not show_secrets,
        "findings": items,
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")
