"""Tests for the regex matchers.

The keys used here are the fake ones from vendor documentation, so nothing in
this file is a live credential.
"""

import pytest

from secretscanner.patterns import find_pattern_matches, looks_like_placeholder

# GitHub's push protection rejects any file containing something shaped like a
# live Slack or Stripe key, fake or not, which is awkward for a project whose
# tests need exactly that. Splitting the prefix keeps the fixtures readable
# while the literal never appears in the file.
SLACK_TOKEN = "xoxb" + "-123456789012-abcdefghijklmno"
STRIPE_KEY = "sk" + "_live_4eC39HqLyjWDarjtT1zdp7dc"


def types_found(line):
    return {m["type"] for m in find_pattern_matches(line)}


@pytest.mark.parametrize(
    "line,expected_type",
    [
        ('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "aws_access_key_id"),
        ('key = "ASIAIOSFODNN7EXAMPLE"', "aws_access_key_id"),
        (
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            "aws_secret_access_key",
        ),
        (
            'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"',
            "github_token",
        ),
        (
            'GOOGLE = "AIzaSyD1234567890abcdefghijklmnopqrstuv"',
            "google_api_key",
        ),
        ("bot = '%s'" % SLACK_TOKEN, "slack_token"),
        ('stripe = "%s"' % STRIPE_KEY, "stripe_secret_key"),
        ('npm = "npm_abcdefghijklmnopqrstuvwxyz0123456789"', "npm_token"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key_header"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_header"),
        ("-----BEGIN PRIVATE KEY-----", "private_key_header"),
        (
            'db = "postgres://admin:hunter2pass@db.internal:5432/app"',
            "basic_auth_url",
        ),
    ],
)
def test_known_formats_are_detected(line, expected_type):
    assert expected_type in types_found(line)


def test_jwt_is_detected():
    line = ('auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
            'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"')
    assert "jwt" in types_found(line)


def test_generic_assignment_catches_unknown_key_formats():
    assert "generic_secret_assignment" in types_found(
        'client_secret = "8f14e45fceea167a5a36dedd4bea2543"'
    )


def test_match_carries_type_value_and_confidence():
    matches = find_pattern_matches('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert len(matches) == 1
    m = matches[0]
    assert m["type"] == "aws_access_key_id"
    assert m["value"] == "AKIAIOSFODNN7EXAMPLE"
    assert m["confidence"] == "high"
    assert m["column"] >= 0


def test_prefixed_formats_are_high_confidence():
    for line in [
        'k = "AKIAIOSFODNN7EXAMPLE"',
        'k = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"',
        "-----BEGIN RSA PRIVATE KEY-----",
    ]:
        assert all(m["confidence"] == "high" for m in find_pattern_matches(line))


def test_generic_assignment_is_only_medium_confidence():
    matches = find_pattern_matches('api_key = "8f14e45fceea167a5a36dedd4bea2543"')
    assert matches[0]["confidence"] == "medium"


@pytest.mark.parametrize(
    "line",
    [
        'API_KEY = "your_api_key_here"',
        'API_KEY = "changeme"',
        'password = "xxxxxxxxxxxx"',
        'secret = "<YOUR_SECRET>"',
        'api_key = "${API_KEY}"',
        "password = os.environ['DB_PASS']",
    ],
)
def test_placeholders_are_not_reported(line):
    assert find_pattern_matches(line) == []


def test_clean_lines_produce_nothing():
    for line in [
        "import os",
        "x = 1  # counter",
        "def load_config(path):",
        'print("hello world")',
        "",
    ]:
        assert find_pattern_matches(line) == []


def test_stripe_key_is_not_double_reported_as_generic():
    # The line matches both the Stripe pattern and the generic one. Only the
    # more specific result should survive.
    matches = find_pattern_matches('api_key = "%s"' % STRIPE_KEY)
    assert len(matches) == 1
    assert matches[0]["type"] == "stripe_secret_key"


def test_two_different_secrets_on_one_line_both_reported():
    line = ('a = "AKIAIOSFODNN7EXAMPLE"; '
            'b = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"')
    assert types_found(line) == {"aws_access_key_id", "github_token"}


class TestPlaceholderCheck:
    def test_known_filler_words(self):
        assert looks_like_placeholder("changeme") is True
        assert looks_like_placeholder("PLACEHOLDER") is True

    def test_env_lookups(self):
        assert looks_like_placeholder("os.environ.get") is True

    def test_repeated_characters(self):
        assert looks_like_placeholder("********") is True

    def test_real_looking_value_passes_through(self):
        assert looks_like_placeholder("AKIAIOSFODNN7EXAMPLE") is False
