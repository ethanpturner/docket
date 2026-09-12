"""Locator resolution: every verdict, and the two refusals that matter."""

from __future__ import annotations

import pytest

from docket.hashing import hash_text, is_content_hash
from docket.resolve import MAX_QUOTED_LINES, Resolution, resolve_locator


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "app.py").write_text(
        "\n".join(f"line {number}" for number in range(1, 11)) + "\n", encoding="utf-8"
    )
    (tmp_path / "pkg" / "blob.bin").write_bytes(b"\x00\x01\x02\xff\xfe")
    (tmp_path / "outside.txt").write_text("x\n", encoding="utf-8")
    return tmp_path


def test_bare_path_resolves(repo):
    outcome = resolve_locator("pkg/app.py", repo)
    assert outcome.resolution is Resolution.RESOLVES
    assert outcome.quoted_text is None, "a bare path cites no span, so none is quoted"


def test_line_in_range_resolves_and_quotes(repo):
    outcome = resolve_locator("pkg/app.py:3", repo)
    assert outcome.resolution is Resolution.RESOLVES
    assert outcome.quoted_text == "line 3"
    assert outcome.content_hash == hash_text("line 3")
    assert is_content_hash(outcome.content_hash or "")


def test_range_quotes_every_line(repo):
    outcome = resolve_locator("pkg/app.py:2-4", repo)
    assert outcome.resolution is Resolution.RESOLVES
    assert outcome.quoted_text == "line 2\nline 3\nline 4"
    assert outcome.start_line == 2 and outcome.end_line == 4


def test_missing_path_is_absent(repo):
    outcome = resolve_locator("pkg/nope.py:1", repo)
    assert outcome.resolution is Resolution.PATH_ABSENT
    assert outcome.path == "pkg/nope.py"


def test_a_near_miss_is_not_searched_for(repo):
    """`app.py` exists at `pkg/app.py`. Finding it would hide the broken citation."""
    assert resolve_locator("app.py:1", repo).resolution is Resolution.PATH_ABSENT


def test_line_past_end_is_out_of_range(repo):
    outcome = resolve_locator("pkg/app.py:99", repo)
    assert outcome.resolution is Resolution.LINE_OUT_OF_RANGE
    assert outcome.line_count == 10, "the file's length is recorded so a reviewer sees how far out"


def test_backwards_range_is_out_of_range(repo):
    assert resolve_locator("pkg/app.py:8-2", repo).resolution is Resolution.LINE_OUT_OF_RANGE


def test_directory_is_absent_not_resolving(repo):
    assert resolve_locator("pkg", repo).resolution is Resolution.PATH_ABSENT


def test_empty_string_is_not_a_locator(repo):
    assert resolve_locator("   ", repo).resolution is Resolution.NOT_A_LOCATOR


def test_traversal_never_leaves_the_repository(repo):
    """A locator is attacker-controlled text used to build a path."""
    outcome = resolve_locator("../../../../etc/passwd:1", repo)
    assert outcome.resolution is Resolution.PATH_ABSENT
    assert outcome.quoted_text is None


def test_absolute_path_never_escapes(repo):
    outcome = resolve_locator("/etc/passwd:1", repo)
    assert outcome.resolution is Resolution.PATH_ABSENT
    assert outcome.quoted_text is None


def test_binary_file_resolves_without_a_quotation(repo):
    """The path is present, so the citation is checkable; the bytes are not text to quote."""
    outcome = resolve_locator("pkg/blob.bin:1", repo)
    assert outcome.resolution is Resolution.RESOLVES
    assert outcome.quoted_text is None
    assert outcome.line_count is None


def test_a_huge_range_is_truncated_not_dumped(tmp_path):
    (tmp_path / "big.py").write_text(
        "\n".join(f"row {number}" for number in range(1, 501)) + "\n", encoding="utf-8"
    )
    outcome = resolve_locator("big.py:1-500", tmp_path)
    assert outcome.resolution is Resolution.RESOLVES
    assert outcome.truncated is True
    assert (outcome.quoted_text or "").count("\n") + 1 == MAX_QUOTED_LINES


def test_the_locator_is_recorded_as_spelled(repo):
    assert resolve_locator("  pkg/app.py:3  ", repo).locator == "  pkg/app.py:3  "
