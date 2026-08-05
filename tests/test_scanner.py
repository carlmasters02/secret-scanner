"""Tests for the file walking, gitignore handling and output layers."""

import json
import io
import subprocess

import pytest

from secretscanner.cli import main
from secretscanner.report import mask
from secretscanner.scanner import scan_file, scan_path, scan_line, walk_files


def write(tmp_path, name, text):
    """Create a file (and any parent dirs) under tmp_path."""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_scan_line_merges_both_detectors():
    line = ('aws = "AKIAIOSFODNN7EXAMPLE" '
            'other = "kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o"')
    types = {m["type"] for m in scan_line(line)}
    assert "aws_access_key_id" in types
    assert "high_entropy_base64" in types


def test_entropy_does_not_duplicate_a_regex_match():
    # The AWS key is also a high entropy token, but regex already claimed it.
    matches = scan_line('k = "AKIAIOSFODNN7EXAMPLE"')
    assert len(matches) == 1


def test_scan_line_can_run_without_entropy():
    line = 'other = "kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o"'
    assert scan_line(line, use_entropy=False) == []


def test_scan_file_records_path_and_line_number(tmp_path):
    f = write(tmp_path, "config.py", "x = 1\ny = 2\nKEY = \"AKIAIOSFODNN7EXAMPLE\"\n")
    findings = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].path == str(f)


def test_binary_and_vendor_files_are_skipped(tmp_path):
    write(tmp_path, "src/app.py", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "node_modules/lib.js", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "logo.png", 'K = "AKIAIOSFODNN7EXAMPLE"')
    (tmp_path / "data.bin").write_bytes(b"\x00\x01AKIAIOSFODNN7EXAMPLE")

    found = [f.replace(str(tmp_path), "") for f in walk_files(str(tmp_path))]
    assert found == ["/src/app.py"]


def test_gitignore_is_respected(tmp_path):
    write(tmp_path, ".gitignore", "secrets/\n*.env\n")
    write(tmp_path, "app.py", "clean = True")
    write(tmp_path, "secrets/keys.py", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "prod.env", 'K = "AKIAIOSFODNN7EXAMPLE"')

    findings, _ = scan_path(str(tmp_path))
    assert findings == []


def test_no_gitignore_flag_scans_everything(tmp_path):
    write(tmp_path, ".gitignore", "secrets/\n")
    write(tmp_path, "secrets/keys.py", 'K = "AKIAIOSFODNN7EXAMPLE"')

    findings, _ = scan_path(str(tmp_path), use_gitignore=False)
    assert len(findings) == 1


def test_gitignore_negation_reincludes_a_file(tmp_path):
    write(tmp_path, ".gitignore", "*.txt\n!keep.txt\n")
    write(tmp_path, "drop.txt", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "keep.txt", 'K = "AKIAIOSFODNN7EXAMPLE"')

    files = [f for f in walk_files(str(tmp_path)) if f.endswith(".txt")]
    assert len(files) == 1
    assert files[0].endswith("keep.txt")


def test_nested_gitignore_applies_to_its_own_subtree(tmp_path):
    write(tmp_path, "a/.gitignore", "hidden.py\n")
    write(tmp_path, "a/hidden.py", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "b/hidden.py", 'K = "AKIAIOSFODNN7EXAMPLE"')

    findings, _ = scan_path(str(tmp_path))
    assert len(findings) == 1
    assert "/b/" in findings[0].path


def git_available():
    try:
        subprocess.run(["git", "--version"], capture_output=True)
    except FileNotFoundError:
        return False
    return True


@pytest.mark.skipif(not git_available(), reason="git not installed")
def test_ignore_rules_agree_with_git(tmp_path):
    """Compare the walker against git's own answer.

    Writing a .gitignore parser from scratch means guessing at the rules, so
    the useful test is not "does it do what I think", it is "does it do what
    git does". This builds a repo, asks git which files it would track, and
    checks the walker reaches the same set.
    """
    (tmp_path / ".gitignore").write_text(
        "# comments and blank lines are skipped\n"
        "\n"
        "secrets/\n"
        "*.env\n"
        "*.log\n"
        "/toplevel_only.py\n"
        "!important.log\n"
        "src/generated.py\n"
    )
    for name in [
        "src/app.py", "src/keep.py", "src/generated.py", "src/toplevel_only.py",
        "secrets/leaked.py", "nested/secrets/deep.py",
        "prod.env", "toplevel_only.py",
        "logs/debug.log", "logs/important.log",
    ]:
        write(tmp_path, name, "x = 1\n")

    run = lambda *args: subprocess.run(
        ["git", "-C", str(tmp_path)] + list(args),
        capture_output=True, text=True, check=True,
    )
    run("init", "-q")
    tracked = run("add", "-An", "--dry-run", ".").stdout
    expected = sorted(
        line.split(" ", 1)[1].strip().strip("'")
        for line in tracked.splitlines() if line.startswith("add ")
    )

    walked = sorted(
        f.replace(str(tmp_path) + "/", "") for f in walk_files(str(tmp_path))
    )
    assert walked == expected


def test_findings_are_sorted_by_file_then_line(tmp_path):
    write(tmp_path, "b.py", 'K = "AKIAIOSFODNN7EXAMPLE"')
    write(tmp_path, "a.py", 'x = 1\nK = "AKIAIOSFODNN7EXAMPLE"\n')

    findings, count = scan_path(str(tmp_path))
    assert count == 2
    assert findings[0].path.endswith("a.py")
    assert findings[1].path.endswith("b.py")


class TestMasking:
    def test_long_secret_keeps_the_ends(self):
        assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"

    def test_short_secret_is_fully_hidden(self):
        assert mask("hunter2") == "*" * 7

    def test_masked_value_is_shorter_than_the_original(self):
        secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
        assert len(mask(secret)) < len(secret)


def test_json_output_shape(tmp_path, capsys):
    write(tmp_path, "app.py", 'K = "AKIAIOSFODNN7EXAMPLE"')

    code = main([str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 1
    assert payload["findings_count"] == 1
    assert payload["files_scanned"] == 1
    assert payload["masked"] is True
    assert payload["summary"]["high"] == 1
    assert payload["findings"][0]["type"] == "aws_access_key_id"
    assert payload["findings"][0]["match"] == "AKIA...MPLE"


def test_show_secrets_disables_masking(tmp_path, capsys):
    write(tmp_path, "app.py", 'K = "AKIAIOSFODNN7EXAMPLE"')

    main([str(tmp_path), "--json", "--show-secrets"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["masked"] is False
    assert payload["findings"][0]["match"] == "AKIAIOSFODNN7EXAMPLE"


def test_exit_code_is_zero_on_a_clean_tree(tmp_path, capsys):
    write(tmp_path, "app.py", "print('hello')")
    assert main([str(tmp_path)]) == 0
    assert "No secrets found" in capsys.readouterr().out


def test_missing_path_exits_with_two(capsys):
    assert main(["/does/not/exist/anywhere"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_min_confidence_filters_lower_results(tmp_path, capsys):
    write(tmp_path, "app.py",
          'a = "AKIAIOSFODNN7EXAMPLE"\nclient_secret = "8f14e45fceea167a5a36d"\n')

    main([str(tmp_path), "--json"])
    everything = json.loads(capsys.readouterr().out)

    main([str(tmp_path), "--json", "--min-confidence", "high"])
    only_high = json.loads(capsys.readouterr().out)

    assert everything["findings_count"] > only_high["findings_count"]
    assert all(f["confidence"] == "high" for f in only_high["findings"])


def test_report_writes_something_for_each_finding(tmp_path):
    from secretscanner.report import print_report

    write(tmp_path, "app.py", 'K = "AKIAIOSFODNN7EXAMPLE"')
    findings, scanned = scan_path(str(tmp_path))

    out = io.StringIO()
    print_report(findings, scanned, stream=out)
    text = out.getvalue()

    assert "aws_access_key_id" in text
    assert "app.py" in text
    assert "line 1" in text
    assert "AKIA...MPLE" in text
