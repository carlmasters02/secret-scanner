"""Entropy based detection for secrets the regex list does not know about.

The idea: a real credential is usually random, and random strings use their
character set much more evenly than English words or code identifiers do.
Shannon entropy measures exactly that, so we pull out candidate tokens and
flag the ones that score above a threshold.
"""

import math
import re

# Character sets we care about, with the threshold (in bits per character)
# above which a token of that set looks random. A base64 string can hold up to
# 6 bits per char and a hex string up to 4, so the cutoffs are set a bit under
# the max for each.
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
HEX_CHARS = "0123456789abcdefABCDEF"

BASE64_THRESHOLD = 4.5
HEX_THRESHOLD = 3.0

MIN_TOKEN_LENGTH = 20

# Tokens are split on characters that almost never appear inside a credential.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9+/=\-_]+")

# Things that are long and random looking but boring: hashes in lockfiles, git
# SHAs in comments, content hashes in build output.
_SKIP_CONTEXT = re.compile(
    r"(?i)\b(sha1|sha256|sha512|md5|integrity|checksum|commit|revision|"
    r"etag|uuid|guid|base64,)\b"
)


def shannon_entropy(data):
    """Return the Shannon entropy of a string in bits per character.

    Counts how often each distinct character appears, then sums
    -p * log2(p) over those frequencies. An empty string scores 0.
    """
    if not data:
        return 0.0

    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / len(data)
        entropy -= p * math.log2(p)
    return entropy


def charset_of(token):
    """Guess which character set a token is drawn from.

    Returns "hex", "base64", or None when it is neither.
    """
    if all(c in HEX_CHARS for c in token):
        return "hex"
    if all(c in BASE64_CHARS for c in token):
        return "base64"
    return None


def is_high_entropy(token):
    """True when the token is long enough and random enough to be suspicious."""
    if len(token) < MIN_TOKEN_LENGTH:
        return False

    charset = charset_of(token)
    if charset is None:
        return False

    limit = HEX_THRESHOLD if charset == "hex" else BASE64_THRESHOLD
    return shannon_entropy(token) > limit


def _looks_like_words(token):
    """Filter out camelCase identifiers and snake_case names.

    These can be long, but they are built from real words so their entropy sits
    well below a random string of the same length. The vowel ratio check is a
    cheap second opinion for cases that sneak past the threshold.
    """
    if "_" in token or "-" in token:
        parts = [p for p in re.split(r"[-_]", token) if p]
        # Several short chunks joined by separators reads like a name, not a key.
        if len(parts) >= 3 and all(len(p) <= 8 for p in parts):
            return True

    letters = [c for c in token.lower() if c.isalpha()]
    if len(letters) >= 12:
        vowels = sum(1 for c in letters if c in "aeiou")
        ratio = vowels / len(letters)
        # Random strings land near 0.19 (5 vowels out of 26 letters). English
        # text is closer to 0.40.
        if ratio > 0.34:
            return True
    return False


def find_entropy_matches(line):
    """Pull high entropy tokens out of a single line.

    Returns the same dict shape as the regex matcher so the two can be merged.
    Confidence is medium for tokens well over the threshold and low otherwise,
    since this check produces more noise than the named patterns do.
    """
    if _SKIP_CONTEXT.search(line):
        return []

    hits = []
    for token in _TOKEN_SPLIT.split(line):
        if not is_high_entropy(token):
            continue
        if _looks_like_words(token):
            continue

        score = shannon_entropy(token)
        charset = charset_of(token)
        limit = HEX_THRESHOLD if charset == "hex" else BASE64_THRESHOLD

        hits.append(
            {
                "type": "high_entropy_%s" % charset,
                "value": token,
                "confidence": "medium" if score > limit + 0.4 else "low",
                "column": line.find(token),
                "entropy": round(score, 2),
            }
        )
    return hits
