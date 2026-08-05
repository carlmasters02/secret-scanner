"""Regex patterns for well known secret formats.

Each pattern gets a name, a compiled regex, and a confidence level. Confidence
is basically how sure we can be that a match is really a secret. A key that
starts with "AKIA" is almost certainly an AWS key, but something matching
"api_key = ..." could easily be a placeholder.
"""

import re

# (name, regex, confidence)
_PATTERN_SOURCE = [
    (
        "aws_access_key_id",
        r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b",
        "high",
    ),
    (
        "aws_secret_access_key",
        r"(?i)aws.{0,20}?(?:secret|key).{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]",
        "high",
    ),
    ("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", "high"),
    ("github_fine_grained_pat", r"\b(github_pat_[A-Za-z0-9_]{60,})\b", "high"),
    ("slack_token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})", "high"),
    (
        "slack_webhook",
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})",
        "high",
    ),
    ("google_api_key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", "high"),
    ("stripe_secret_key", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b", "high"),
    ("openai_api_key", r"\b(sk-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b", "high"),
    ("npm_token", r"\b(npm_[A-Za-z0-9]{36})\b", "high"),
    (
        "private_key_header",
        r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)",
        "high",
    ),
    (
        "jwt",
        r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b",
        "medium",
    ),
    (
        "basic_auth_url",
        r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]{4,}@[^\s/]+)",
        "medium",
    ),
    # Catch-all for "SOMETHING_KEY = 'value'" style assignments. Lots of false
    # positives here, hence medium.
    (
        "generic_secret_assignment",
        r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token"
        r"|client[_\-]?secret|passwd|password|secret)\s*[:=]\s*"
        r"['\"]([^'\"\s]{8,})['\"]",
        "medium",
    ),
]

PATTERNS = [(name, re.compile(rx), conf) for name, rx, conf in _PATTERN_SOURCE]

# Values that show up constantly in example code and configs. If a match is one
# of these we drop it instead of reporting it.
PLACEHOLDERS = {
    "changeme",
    "example",
    "password",
    "placeholder",
    "redacted",
    "secret",
    "test",
    "todo",
    "xxxxxxxx",
    "your_api_key",
    "your_api_key_here",
    "yourkeyhere",
    "none",
    "null",
    "undefined",
}


def looks_like_placeholder(value):
    """True if the matched value is obviously not a real secret."""
    low = value.strip().lower()
    if low in PLACEHOLDERS:
        return True
    if low.startswith("your") or low.startswith("<") or low.startswith("${"):
        return True
    if low.startswith("os.environ") or low.startswith("process.env"):
        return True
    # Repeated filler like "xxxxxxxx" or "********".
    if len(set(low)) <= 2:
        return True
    return False


_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def find_pattern_matches(line):
    """Run every regex against one line of text.

    Returns a list of dicts with the pattern name, the matched value and the
    confidence. A single line can produce more than one match.
    """
    found = {}
    for name, regex, confidence in PATTERNS:
        for m in regex.finditer(line):
            # Group 1 is the secret itself when the pattern needs surrounding
            # context to match, otherwise the whole match is the secret.
            value = m.group(1) if m.lastindex else m.group(0)
            if looks_like_placeholder(value):
                continue
            hit = {
                "type": name,
                "value": value,
                "confidence": confidence,
                "column": m.start(),
            }
            # A Stripe key also matches the generic "api_key = ..." pattern, so
            # keep whichever match we trust more for a given value.
            previous = found.get(value)
            if previous is None or _CONFIDENCE_ORDER[confidence] > _CONFIDENCE_ORDER[previous["confidence"]]:
                found[value] = hit
    return list(found.values())
