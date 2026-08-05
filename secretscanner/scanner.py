"""Walks a directory tree and runs both detectors over every file."""

import os

from .entropy import find_entropy_matches
from .gitignore import IgnoreStack
from .patterns import find_pattern_matches

# Directories that are never worth scanning. These get skipped even without a
# .gitignore file.
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    ".tox",
}

# Binary or generated files. Scanning these is slow and only produces noise.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ogg", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a",
    ".class", ".jar", ".wasm",
    ".lock",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB, anything bigger is probably not source

# Long lines are almost always minified JS or embedded data. Skipping them
# keeps the entropy check from drowning the report.
MAX_LINE_LENGTH = 500


class Finding:
    """One suspected secret at one place in one file."""

    def __init__(self, path, line_number, line_text, match):
        self.path = path
        self.line_number = line_number
        self.line = line_text.strip()
        self.type = match["type"]
        self.value = match["value"]
        self.confidence = match["confidence"]
        self.entropy = match.get("entropy")

    def as_dict(self):
        d = {
            "file": self.path,
            "line": self.line_number,
            "type": self.type,
            "confidence": self.confidence,
            "match": self.value,
        }
        if self.entropy is not None:
            d["entropy"] = self.entropy
        return d

    def __repr__(self):
        return "<Finding %s:%d %s>" % (self.path, self.line_number, self.type)


def is_probably_binary(path):
    """Read the first chunk of a file and look for a null byte."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
    except OSError:
        return True
    return b"\x00" in chunk


def should_skip_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return True
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return True
    except OSError:
        return True
    return is_probably_binary(path)


def scan_line(line, use_entropy=True):
    """Both detectors against one line, regex first.

    If the regex layer already claimed a value we do not report the same string
    again as a high entropy token.
    """
    matches = find_pattern_matches(line)
    if use_entropy:
        claimed = [m["value"] for m in matches]
        for hit in find_entropy_matches(line):
            if any(hit["value"] in c or c in hit["value"] for c in claimed):
                continue
            matches.append(hit)
    return matches


def scan_file(path, use_entropy=True):
    """Scan a single file and return a list of Finding objects."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if len(line) > MAX_LINE_LENGTH:
                    continue
                for match in scan_line(line, use_entropy):
                    findings.append(Finding(path, number, line, match))
    except OSError as err:
        # Unreadable file is worth mentioning but should not stop the scan.
        print("warning: could not read %s (%s)" % (path, err))
    return findings


def walk_files(root, use_gitignore=True):
    """Yield every scannable file under root.

    Handles being pointed at a single file too, since that is a convenient way
    to check one thing quickly.
    """
    if os.path.isfile(root):
        if not should_skip_file(root):
            yield root
        return

    ignores = IgnoreStack(root) if use_gitignore else None

    for dirpath, dirnames, filenames in os.walk(root):
        if ignores is not None and ".gitignore" in filenames:
            ignores.add_file(os.path.join(dirpath, ".gitignore"))

        # Trimming dirnames in place stops os.walk from descending into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if ignores is not None:
            dirnames[:] = [
                d for d in dirnames
                if not ignores.is_ignored(os.path.join(dirpath, d), is_dir=True)
            ]
        dirnames.sort()

        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if ignores is not None and ignores.is_ignored(full):
                continue
            if not should_skip_file(full):
                yield full


def scan_path(root, use_entropy=True, use_gitignore=True):
    """Scan a file or directory.

    Returns (findings, files_scanned). The count is handy for the report, since
    "no secrets found" means something very different after 2 files than
    after 900.
    """
    results = []
    scanned = 0
    for path in walk_files(root, use_gitignore):
        scanned += 1
        results.extend(scan_file(path, use_entropy))
    results.sort(key=lambda f: (f.path, f.line_number))
    return results, scanned
