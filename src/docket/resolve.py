"""Does the claim point at code that exists?

This is the whole of Phase 0's automated work, and it is deliberately small. A claim cites
`src/app.py:42`. Either that file is in the repository at the pinned commit and has at least 42
lines, or it does not. Nothing here reads the claim's prose, weighs its plausibility, or decides
whether the code at line 42 is vulnerable.

**Four verdicts, and `resolves` is the weakest of them.** A locator that resolves establishes only
that the citation is checkable -- the file is there and the line is in range. It says nothing about
whether the cited code does what the claim says. The other three are the useful ones, because they
are the cases where a reviewer can stop reading: a path that is not in the repository at this
commit is a citation of nothing.

**Never guess a path.** A locator naming `app.py` when the repository holds `src/app.py` is
`path_absent`. Searching for a plausible match would turn a broken citation into a working one and
hide the failure this module exists to surface; a tool that cannot address the code it reviewed is
reporting something the reviewer needs to see.

**The traversal check is not decoration.** A locator is attacker-controlled text -- it arrives in a
report written by a stranger -- and it is used to build a filesystem path. `../../etc/passwd`
resolves outside the repository root, and reading it would put the contents of an arbitrary file
into a record that gets published. A locator that escapes the root is `path_absent`, and the file
is never opened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

from docket.hashing import hash_text

__all__ = ["LocatorResolution", "Resolution", "resolve_locator"]

# `path`, `path:line`, or `path:start-end`. The path is everything before the last colon that is
# followed only by digits and an optional `-digits`; a Windows drive letter or a path containing a
# colon is refused as `not_a_locator` rather than being silently re-read.
_LOCATOR: Final = re.compile(
    r"^(?P<path>.+?)(?::(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?)?$"
)

# A quoted span is read into the record, so an unbounded range would let a claim citing
# `app.py:1-9999999` pull an entire file into a published document. The cap is on lines quoted,
# not on the range accepted: a larger range still resolves, and the record says it was truncated.
MAX_QUOTED_LINES: Final = 40


class Resolution(StrEnum):
    """What happened when the locator was checked against the repository."""

    RESOLVES = "resolves"
    """The path names a file inside the repository and any line range lies within it."""

    PATH_ABSENT = "path_absent"
    """No such file at this commit, or the path escapes the repository root."""

    LINE_OUT_OF_RANGE = "line_out_of_range"
    """The file exists; the cited line or range is past its end, or the range runs backwards."""

    NOT_A_LOCATOR = "not_a_locator"
    """The string does not parse as a path with an optional line range."""


@dataclass(frozen=True, slots=True)
class LocatorResolution:
    """One locator, checked."""

    locator: str
    """The string as the source spelled it, verbatim."""

    resolution: Resolution
    path: str | None = None
    """The repository-relative path, when the locator parsed. Not normalised beyond `resolve()`."""

    start_line: int | None = None
    end_line: int | None = None
    line_count: int | None = None
    """The file's length, when the file was found. Lets a reviewer see how far out a bad line was."""

    quoted_text: str | None = None
    """The cited span, verbatim, when the locator resolves and a line range was given."""

    content_hash: str | None = None
    """The digest of `quoted_text`, so a record can be checked against the repository later."""

    truncated: bool = False
    """Whether the quoted span stops short of the cited range at `MAX_QUOTED_LINES`."""

    @property
    def resolved(self) -> bool:
        return self.resolution is Resolution.RESOLVES


def _read_lines(path: Path) -> list[str] | None:
    """The file's lines, or None when it is not readable as UTF-8 text.

    A binary file is not a citation failure -- the path is there -- so this returns None and the
    caller records a resolution without a quoted span.
    """
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError, OSError:
        return None


def resolve_locator(locator: str, repo: Path) -> LocatorResolution:
    """Check one locator against the repository worktree.

    `repo` must already be at the commit the claim was made against; this function does not check
    out anything, and the commit is recorded by the caller.
    """
    match = _LOCATOR.match(locator.strip())
    if match is None or not match.group("path").strip():
        return LocatorResolution(locator=locator, resolution=Resolution.NOT_A_LOCATOR)

    relative = match.group("path").strip()
    root = repo.resolve()
    candidate = (root / relative).resolve()

    # An absolute path in the locator makes `root / relative` discard the root entirely, so the
    # containment check below is what catches it as well as `../` traversal.
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return LocatorResolution(locator=locator, resolution=Resolution.PATH_ABSENT, path=relative)

    start_text = match.group("start")
    if start_text is None:
        return LocatorResolution(locator=locator, resolution=Resolution.RESOLVES, path=relative)

    start = int(start_text)
    end = int(match.group("end") or start_text)
    lines = _read_lines(candidate)
    line_count = len(lines) if lines is not None else None

    if end < start:
        return LocatorResolution(
            locator=locator,
            resolution=Resolution.LINE_OUT_OF_RANGE,
            path=relative,
            start_line=start,
            end_line=end,
            line_count=line_count,
        )
    if line_count is not None and (start > line_count or end > line_count):
        return LocatorResolution(
            locator=locator,
            resolution=Resolution.LINE_OUT_OF_RANGE,
            path=relative,
            start_line=start,
            end_line=end,
            line_count=line_count,
        )

    quoted: str | None = None
    digest: str | None = None
    truncated = False
    if lines is not None:
        last = min(end, start + MAX_QUOTED_LINES - 1)
        truncated = last < end
        quoted = "\n".join(lines[start - 1 : last])
        digest = hash_text(quoted)

    return LocatorResolution(
        locator=locator,
        resolution=Resolution.RESOLVES,
        path=relative,
        start_line=start,
        end_line=end,
        line_count=line_count,
        quoted_text=quoted,
        content_hash=digest,
        truncated=truncated,
    )
