"""Minimal .gitignore support.

This is not a full implementation of git's ignore rules, but it covers what
shows up in practice: comments, blank lines, directory-only patterns ending in
a slash, patterns anchored with a leading slash, negation with "!", and the
usual glob characters. Nested .gitignore files are picked up as the walk goes,
and each one applies to its own directory and below.
"""

import os
import re


class IgnoreRule:
    def __init__(self, pattern, base_dir):
        self.negated = pattern.startswith("!")
        if self.negated:
            pattern = pattern[1:]

        self.dir_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")

        # A slash anywhere except the end means the pattern is relative to the
        # directory holding the .gitignore, not matched against basenames.
        self.anchored = "/" in pattern
        self.pattern = pattern.lstrip("/")
        self.base_dir = base_dir
        self.regex = _compile_pattern(self.pattern)

    def matches(self, rel_path, is_dir):
        if self.dir_only and not is_dir:
            return False

        if self.anchored:
            return self.regex.match(rel_path) is not None

        # Unanchored patterns match at any depth, so try each path segment.
        parts = rel_path.split("/")
        for i in range(len(parts)):
            if self.regex.match("/".join(parts[i:])) is not None:
                return True
            if self.regex.match(parts[i]) is not None:
                return True
        return False

    def __repr__(self):
        return "IgnoreRule(%r)" % self.pattern


def _compile_pattern(pattern):
    """Turn a gitignore glob into a regex.

    fnmatch alone is not quite right because it lets "*" match across slashes,
    so "*" and "**" are handled by hand and the rest is left to fnmatch.
    """
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                # Swallow the slash after "**/" so it can also match zero dirs.
                if pattern[i:i + 1] == "/":
                    i += 1
                    out.append("/?")
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                body = pattern[i + 1:end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = end + 1
                continue
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("".join(out) + "(/.*)?$")


def parse_gitignore(path, base_dir):
    """Read one .gitignore file and return its rules."""
    rules = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\n").strip()
                if not line or line.startswith("#"):
                    continue
                rules.append(IgnoreRule(line, base_dir))
    except OSError:
        pass
    return rules


class IgnoreStack:
    """Holds the rules collected so far while walking a tree.

    Later rules win over earlier ones, which is how git resolves a "!" that
    re-includes something an earlier line excluded.
    """

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.rules = []

    def add_file(self, gitignore_path):
        base = os.path.dirname(os.path.abspath(gitignore_path))
        self.rules.extend(parse_gitignore(gitignore_path, base))

    def is_ignored(self, path, is_dir=False):
        abs_path = os.path.abspath(path)
        result = False
        for rule in self.rules:
            # A rule only applies to things inside the directory it came from.
            try:
                rel = os.path.relpath(abs_path, rule.base_dir)
            except ValueError:
                continue
            if rel.startswith(".."):
                continue
            rel = rel.replace(os.sep, "/")
            if rule.matches(rel, is_dir):
                result = not rule.negated
        return result
