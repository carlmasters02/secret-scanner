import math

import pytest

from secretscanner.entropy import (
    charset_of,
    find_entropy_matches,
    is_high_entropy,
    shannon_entropy,
)


def test_empty_string_has_no_entropy():
    assert shannon_entropy("") == 0.0


def test_single_repeated_character_is_zero():
    # Only one symbol means zero surprise per character.
    assert shannon_entropy("aaaaaaaa") == 0.0


@pytest.mark.parametrize(
    "text,expected",
    [
        ("ab", 1.0),        # 2 equally likely symbols = 1 bit
        ("abcd", 2.0),      # 4 symbols = 2 bits
        ("abcdefgh", 3.0),  # 8 symbols = 3 bits
    ],
)
def test_uniform_strings_hit_log2_of_alphabet_size(text, expected):
    assert shannon_entropy(text) == pytest.approx(expected)


def test_skewed_distribution_scores_below_uniform():
    # "aaab" is 4 chars but mostly one symbol, so it should score under 1 bit.
    assert shannon_entropy("aaab") < shannon_entropy("aabb")


def test_entropy_matches_manual_calculation():
    text = "aaabbc"
    expected = -(3 / 6 * math.log2(3 / 6)
                 + 2 / 6 * math.log2(2 / 6)
                 + 1 / 6 * math.log2(1 / 6))
    assert shannon_entropy(text) == pytest.approx(expected)


def test_random_key_scores_higher_than_english():
    random_key = "kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o"
    english = "the quick brown fox jumps over it"
    assert shannon_entropy(random_key) > shannon_entropy(english)


class TestCharsetDetection:
    def test_hex_string(self):
        assert charset_of("a8f5f167f44f4964") == "hex"

    def test_base64_string(self):
        assert charset_of("kJ8dR2mQzXvW9pLc+/=") == "base64"

    def test_ordinary_sentence_is_neither(self):
        assert charset_of("hello there!") is None


def test_short_tokens_are_ignored_even_if_random():
    # Under MIN_TOKEN_LENGTH, so it should not count no matter how random.
    assert is_high_entropy("kJ8dR2mQ") is False


def test_long_random_base64_is_flagged():
    assert is_high_entropy("kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o") is True


def test_long_repetitive_string_is_not_flagged():
    assert is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") is False


def test_finds_high_entropy_token_in_a_line():
    line = 'SESSION_KEY = "kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o"'
    hits = find_entropy_matches(line)
    assert len(hits) == 1
    assert hits[0]["value"] == "kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o"
    assert hits[0]["type"] == "high_entropy_base64"
    assert hits[0]["entropy"] > 4.5


def test_hex_token_reports_hex_type():
    line = 'sig = "a8f5f167f44f4964e6c998dee827110c9a1f2b3d"'
    hits = find_entropy_matches(line)
    assert hits[0]["type"] == "high_entropy_hex"


def test_normal_code_produces_nothing():
    lines = [
        "def calculate_total_order_price(order, customer, discount):",
        "this_is_a_normal_variable_name_here = 5",
        "import collections",
        "return sorted(results, key=lambda f: f.line_number)",
    ]
    for line in lines:
        assert find_entropy_matches(line) == [], line


def test_checksum_lines_are_skipped():
    # Lockfile hashes are high entropy but not secrets.
    line = '"integrity": "sha512-9dR2mQzXvW9pLcYtNbF4gHs7aEuI3okJ8dR2mQzXvW"'
    assert find_entropy_matches(line) == []


def test_uuid_context_is_skipped():
    line = 'uuid = "d9b2d63d-a233-4123-847a-cbf0d0e0a2b1"'
    assert find_entropy_matches(line) == []


def test_confidence_drops_to_low_near_the_threshold():
    # Sits above the cutoff but not far above it.
    hits = find_entropy_matches('x = "abcdefghijabcdefghijabcdefghij0123"')
    for h in hits:
        assert h["confidence"] in ("low", "medium")
