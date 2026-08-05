"""Tests for scanning git history.

The parsing tests feed in canned "git log -p" text so they do not need a real
repository. The tests at the bottom build a throwaway repo and run git for
real, which is the only way to be sure the log format is being read correctly.
"""

import subprocess

import pytest

from secretscanner.history import (
    COMMIT_MARKER,
    NotAGitRepo,
    is_git_repo,
    parse_added_lines,
    scan_history,
)

SAMPLE_LOG = """\
{marker} abc123
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +2,2 @@
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
+DEBUG = True
{marker} def456
diff --git a/notes.txt b/notes.txt
--- /dev/null
+++ b/notes.txt
@@ -0,0 +1 @@
+first line
""".format(marker=COMMIT_MARKER)


def test_parses_commit_file_and_line_number():
    rows = list(parse_added_lines(SAMPLE_LOG))
    assert rows[0] == ("abc123", "app.py", 2, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')


def test_line_numbers_advance_within_a_hunk():
    rows = list(parse_added_lines(SAMPLE_LOG))
    assert rows[0][2] == 2
    assert rows[1][2] == 3


def test_commit_and_filename_reset_between_commits():
    rows = list(parse_added_lines(SAMPLE_LOG))
    assert rows[2] == ("def456", "notes.txt", 1, "first line")


def test_diff_headers_are_not_treated_as_content():
    # "+++ b/app.py" starts with "+" but is a header, not an added line.
    texts = [row[3] for row in parse_added_lines(SAMPLE_LOG)]
    assert not any(t.startswith("+ ") or t.startswith("b/") for t in texts)
    assert len(texts) == 3


def test_deleted_file_contributes_nothing():
    log = "%s abc123\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n" % COMMIT_MARKER
    assert list(parse_added_lines(log)) == []


def test_empty_log_is_handled():
    assert list(parse_added_lines("")) == []


# The tests below run git, so skip them cleanly if it is not installed.
def git_available():
    try:
        subprocess.run(["git", "--version"], capture_output=True)
    except FileNotFoundError:
        return False
    return True


needs_git = pytest.mark.skipif(not git_available(), reason="git not installed")


def make_repo(tmp_path):
    """Create a repo with a secret that gets added and then removed."""
    run = lambda *args: subprocess.run(
        ["git", "-C", str(tmp_path)] + list(args), capture_output=True, check=True
    )
    run("init", "-q")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "Test")

    (tmp_path / "app.py").write_text("x = 1\n")
    run("add", "-A")
    run("commit", "-qm", "first")

    (tmp_path / "app.py").write_text('x = 1\nKEY = "AKIAIOSFODNN7EXAMPLE"\n')
    run("add", "-A")
    run("commit", "-qm", "add key")

    (tmp_path / "app.py").write_text('x = 1\nKEY = os.environ["KEY"]\n')
    run("add", "-A")
    run("commit", "-qm", "remove key")
    return tmp_path


@needs_git
def test_finds_a_secret_that_was_deleted_from_the_working_tree(tmp_path):
    repo = make_repo(tmp_path)
    findings, commits = scan_history(str(repo))

    assert commits == 3
    assert len(findings) == 1
    assert findings[0].type == "aws_access_key_id"
    assert findings[0].path == "app.py"
    assert findings[0].line_number == 2


@needs_git
def test_finding_points_at_the_commit_that_introduced_it(tmp_path):
    repo = make_repo(tmp_path)
    findings, _ = scan_history(str(repo))

    subject = subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--format=%s", findings[0].commit],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert subject == "add key"


@needs_git
def test_same_secret_added_twice_is_reported_once(tmp_path):
    repo = make_repo(tmp_path)
    # Put the secret back, so two separate commits add the same line. It should
    # still come out as a single finding, blamed on the earlier commit.
    (repo / "app.py").write_text('x = 1\nKEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "oops, back again"],
                   check=True, capture_output=True)

    findings, commits = scan_history(str(repo))

    assert commits == 4
    assert len(findings) == 1

    subject = subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--format=%s", findings[0].commit],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert subject == "add key"


@needs_git
def test_max_commits_limits_how_far_back_it_looks(tmp_path):
    repo = make_repo(tmp_path)
    findings, commits = scan_history(str(repo), max_commits=1)

    assert commits == 1
    assert findings == []


@needs_git
def test_history_findings_carry_the_commit_in_json(tmp_path):
    repo = make_repo(tmp_path)
    findings, _ = scan_history(str(repo))
    assert "commit" in findings[0].as_dict()


@needs_git
def test_is_git_repo_says_yes_for_a_repo(tmp_path):
    assert is_git_repo(str(make_repo(tmp_path))) is True


def test_is_git_repo_says_no_for_a_plain_directory(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert is_git_repo(str(plain)) is False


def test_scan_history_raises_on_a_plain_directory(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(NotAGitRepo):
        scan_history(str(plain))
