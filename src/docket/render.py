"""The one-page rendering a reviewer reads.

The record is JSON because tools consume it. This is the same record for a person: what was
claimed, who claimed it, which citations hold up, and the current disposition. A reviewer should
be able to decide whether to spend twenty minutes on a claim from this page alone.

**The claim's text is quoted, not summarised.** It is reproduced inside a fenced block, and any
sequence that could close that fence is neutralised first. An inbound report is written by someone
outside the project and may contain anything, including text shaped like instructions to whatever
reads it next. Fencing is what keeps the reviewer's document from being a delivery mechanism.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from docket.resolve import Resolution

if TYPE_CHECKING:
    from docket.disposition import DispositionRecord

__all__ = ["FENCE", "neutralize_fence", "render_markdown"]

# A fence long enough that ordinary triple-backtick content in a report cannot close it.
FENCE: Final = "`````"

_FENCE_LIKE: Final = re.compile(r"`{3,}")
_NEUTRALIZED: Final = "``​`"

_RESOLUTION_NOTE: Final = {
    Resolution.RESOLVES: "the file is present and the range is in it",
    Resolution.PATH_ABSENT: "no such file at this commit",
    Resolution.LINE_OUT_OF_RANGE: "the file is present; the cited lines are not",
    Resolution.NOT_A_LOCATOR: "not a path with an optional line range",
}


def neutralize_fence(text: str) -> str:
    """Make `text` unable to close the block it is quoted in.

    A zero-width space between backticks leaves the text readable and visually unchanged while
    stopping the run from being a delimiter. Deleting the characters would alter what the reporter
    wrote, and the record's value depends on the quotation being faithful.
    """
    return _FENCE_LIKE.sub(_NEUTRALIZED, text)


def _summary_line(record: DispositionRecord) -> str:
    if record.locator_count == 0:
        return "The claim cites no positions, so nothing was checked against the repository."
    if record.fully_unresolved:
        return (
            f"**None of the {record.locator_count} cited positions resolve at this commit.** The "
            f"claim addresses code that is not in this repository at `{record.commit[:12]}`."
        )
    return (
        f"{record.resolved_count} of {record.locator_count} cited positions resolve at this commit."
    )


def render_markdown(record: DispositionRecord) -> str:
    """The record as a page."""
    claim = record.claim
    lines: list[str] = [
        f"# Disposition: {claim.title or claim.claim_id}",
        "",
        f"**Status: `{record.disposition.status.value}`** - {record.disposition.reason}",
        "",
        _summary_line(record),
        "",
        "## The claim, as received",
        "",
        "| | |",
        "|---|---|",
        f"| Claim | `{claim.claim_id}` |",
        f"| Source | {claim.source.tool}"
        + (f" {claim.source.version}" if claim.source.version else "")
        + f" (read as `{claim.source.format}`) |",
        f"| Weakness claimed | {claim.weakness or 'not stated'} |",
        f"| Severity claimed | {claim.severity or 'not stated'} |",
        f"| Repository | `{record.repository}` at `{record.commit}` |",
        "",
    ]

    if claim.raw_text.strip():
        lines += [
            "The source's own words, verbatim and unverified:",
            "",
            FENCE,
            neutralize_fence(claim.raw_text.strip()),
            FENCE,
            "",
        ]

    lines += ["## Cited positions", ""]
    if not record.locators:
        lines += [
            "The claim cites no position that can be checked mechanically. A reviewer adds one by",
            "hand, or the claim stays undetermined on the record.",
            "",
        ]
    else:
        lines += [
            "| Locator | Resolution | Notes |",
            "|---|---|---|",
        ]
        for item in record.locators:
            note = _RESOLUTION_NOTE[item.resolution]
            if item.resolution is Resolution.LINE_OUT_OF_RANGE and item.line_count is not None:
                note = f"{note}; the file has {item.line_count} lines"
            lines.append(f"| `{item.locator}` | `{item.resolution.value}` | {note} |")
        lines.append("")

        quoted = [item for item in record.locators if item.quoted_text]
        if quoted:
            lines += ["### What the cited code says", ""]
            for item in quoted:
                suffix = " (truncated)" if item.truncated else ""
                lines += [
                    f"**`{item.locator}`**{suffix}, `{item.content_hash}`:",
                    "",
                    FENCE,
                    neutralize_fence(item.quoted_text or ""),
                    FENCE,
                    "",
                ]

    lines += [
        "## What this record does not say",
        "",
        "It does not say whether the claim is true. A resolving locator means the citation is",
        "checkable, not that the code is vulnerable; a failing one means the citation is broken,",
        "not that the underlying weakness is absent. The status stays `undetermined` until a",
        "person decides it and the record names them.",
        "",
        f"Recorded by docket {record.docket_version} at {record.recorded_at.isoformat()}.",
    ]
    return "\n".join(lines) + "\n"
