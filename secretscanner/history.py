"""Scanning git history instead of just the files on disk.

Deleting a secret from a file does not remove it from the repository. It is
still sitting in whatever commit added it, and anyone who clones the repo gets
it. This module walks back through the commits and scans the lines each one
added.

Rather than reading git's object database directly, it runs "git log -p" and
parses the diff output. That is much less code, and the line scanner from
scanner.py can be reused unchanged.
"""

import re
import subprocess

from .scanner import Finding, MAX_LINE_LENGTH, scan_line

# Marks the start of each commit in the log output. Using an unlikely prefix
# means a line of source code cannot be mistaken for a commit header.
COMMIT_MARKER = "__COMMIT__"

# "@@ -1,0 +12,3 @@" tells us the added lines start at line 12 of the new file.
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

DEFAULT_MAX_COMMITS = 500


class NotAGitRepo(Exception):
    pass


def is_git_repo(path):
    """Check whether path is inside a git working tree."""
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        # git is not installed at all.
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def get_log_output(path, max_commits=DEFAULT_MAX_COMMITS):
    """Run git log and hand back the raw patch text.

    -U0 asks for zero lines of context, so every line starting with "+" in the
    output is genuinely a new line rather than surrounding code. --all covers
    every branch, not only the one that happens to be checked out.
    """
    command = [
        "git", "-C", path, "log",
        "--all",
        "--no-merges",
        "--no-color",
        "--max-count=%d" % max_commits,
        "-p",
        "-U0",
        "--pretty=format:%s %%H" % COMMIT_MARKER,
    ]
    result = subprocess.run(command, capture_output=True, text=True,
                            errors="replace")
    if result.returncode != 0:
        raise NotAGitRepo(result.stderr.strip() or "git log failed")
    return result.stdout


def parse_added_lines(log_text):
    """Pull the added lines out of git log patch output.

    Yields (commit, filename, line_number, text) for every line a commit added.
    Line numbers refer to the file as it looked in that commit, which is what
    you want when going back to look at it.
    """
    commit = None
    filename = None
    line_number = 0

    for raw in log_text.splitlines():
        if raw.startswith(COMMIT_MARKER):
            commit = raw.split()[-1]
            filename = None
            continue

        if raw.startswith("+++ "):
            target = raw[4:].strip()
            # "+++ /dev/null" means the file was deleted in this commit.
            if target == "/dev/null":
                filename = None
            else:
                # Strip git's "b/" prefix.
                filename = target[2:] if target.startswith("b/") else target
            continue

        # "--- a/old" lines carry no information we need with -U0.
        if raw.startswith(("--- ", "diff --git")):
            continue

        hunk = HUNK_HEADER.match(raw)
        if hunk:
            line_number = int(hunk.group(1))
            continue

        if raw.startswith("+") and filename is not None:
            text = raw[1:]
            if len(text) <= MAX_LINE_LENGTH:
                yield commit, filename, line_number, text
            line_number += 1


def scan_history(path, max_commits=DEFAULT_MAX_COMMITS, use_entropy=True):
    """Scan every line added by the last max_commits commits.

    Returns (findings, commits_seen). The same secret usually appears in more
    than one commit, so results are deduplicated on file, line and value and
    the oldest commit that introduced it is the one reported.
    """
    if not is_git_repo(path):
        raise NotAGitRepo("%s is not a git repository" % path)

    log_text = get_log_output(path, max_commits)
    commits_seen = log_text.count(COMMIT_MARKER)

    seen = {}
    for commit, filename, number, text in parse_added_lines(log_text):
        for match in scan_line(text, use_entropy):
            key = (filename, number, match["value"])
            # git log walks newest first, so a later iteration is an older
            # commit and is the better one to point at.
            seen[key] = Finding(filename, number, text, match, commit=commit)

    findings = list(seen.values())
    findings.sort(key=lambda f: (f.path, f.line_number))
    return findings, commits_seen
