"""Minimal .gitignore support.

This is not all of git's ignore rules. It covers the parts that actually turn
up in real .gitignore files: comments, blank lines, plain names, globs like
"*.log", directory patterns ending in a slash, patterns anchored with a leading
slash, and "!" exceptions. Nested .gitignore files are picked up as the walk
goes and apply to their own directory and below.

What is deliberately left out is listed in the README.
"""

import fnmatch
import os


def path_matches(pattern, rel_path, is_dir):
    """Does one pattern match one path?

    rel_path is relative to the directory that the .gitignore lives in, using
    forward slashes.
    """
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")

    if dir_only and not is_dir:
        return False

    if pattern.startswith("/"):
        # A leading slash anchors the pattern to the top of this directory, so
        # "/build" matches ./build but not ./src/build.
        return fnmatch.fnmatch(rel_path, pattern.lstrip("/"))

    if "/" in pattern:
        # Patterns with a slash inside them are matched against the whole path.
        return fnmatch.fnmatch(rel_path, pattern)

    # Everything else matches a name at any depth, so "*.log" catches
    # ./debug.log and ./logs/debug.log alike.
    return any(fnmatch.fnmatch(part, pattern) for part in rel_path.split("/"))


class IgnoreList:
    """The ignore rules collected so far while walking a tree.

    Patterns starting with "!" are kept separately and checked first. Git
    resolves those by rule order, which is fiddlier; checking exceptions first
    gets the same answer for normal files and errs toward scanning a file
    rather than skipping it, which is the safer mistake for this tool.
    """

    def __init__(self):
        self.rules = []       # (pattern, directory the rule came from)
        self.exceptions = []  # same, for "!" patterns

    def add_file(self, gitignore_path):
        """Read a .gitignore and add its rules."""
        base = os.path.dirname(os.path.abspath(gitignore_path))
        try:
            with open(gitignore_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                self.exceptions.append((line[1:], base))
            else:
                self.rules.append((line, base))

    def relative_to(self, path, base):
        """Path relative to base, or None if it is not inside base."""
        rel = os.path.relpath(os.path.abspath(path), base)
        if rel.startswith(".."):
            return None
        return rel.replace(os.sep, "/")

    def is_ignored(self, path, is_dir=False):
        for pattern, base in self.exceptions:
            rel = self.relative_to(path, base)
            if rel is not None and path_matches(pattern, rel, is_dir):
                return False

        for pattern, base in self.rules:
            rel = self.relative_to(path, base)
            if rel is not None and path_matches(pattern, rel, is_dir):
                return True

        return False
