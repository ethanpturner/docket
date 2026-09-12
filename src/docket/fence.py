"""Quoting untrusted text so that it cannot act.

An inbound claim is written by a stranger, and in Phase 1 it is read by a model that is also
reading the codebase and answering a question. Text shaped like an instruction, arriving inside a
document something is reading in order to decide, is the ordinary attack rather than an exotic one.

Three rules, and the third is the one that is usually missed:

**The claim's text only ever appears between markers.** Never in a system message, never
interpolated into a sentence the model reads as its own, never as a heading.

**Anything inside the quoted text that could close a marker is neutralised**, so the quotation
cannot end early and the text after it cannot be read as the document's own voice.

**Every string outside the markers is one this tool owns.** Not the file name, not the claim's
title, not the tool that produced it, not a section heading taken from the report. A value chosen
by whoever wrote the claim, appearing in the part of the prompt that reads as the application's
instructions, is inside the boundary however carefully the text between the markers is handled.
Where a claim-supplied string has to be identified at all, it is replaced by an identifier this
tool allocated and the mapping is recorded.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "FENCE",
    "MARKER_END",
    "MARKER_START",
    "fenced",
    "neutralize_fence",
]

# A fence long enough that ordinary triple-backtick content in a report cannot close it.
FENCE: Final = "`````"

MARKER_START: Final = "<<<UNTRUSTED-{label}>>>"
MARKER_END: Final = "<<<END-UNTRUSTED-{label}>>>"

_FENCE_LIKE: Final = re.compile(r"`{3,}")
_NEUTRALIZED: Final = "``​`"

# Anything resembling either marker, whatever the label, so a claim cannot forge a boundary of
# its own. Matched case-insensitively because a marker is recognised by shape, not spelling.
_MARKER_LIKE: Final = re.compile(r"<{2,}\s*/?\s*(?:END-)?UNTRUSTED[^>]*>{2,}", re.IGNORECASE)
_MARKER_NEUTRALIZED: Final = "<​<neutralised-marker>​>"


def neutralize_fence(text: str) -> str:
    """Make `text` unable to close the block it is quoted in.

    A zero-width space between backticks leaves the text readable and visually unchanged while
    stopping the run from acting as a delimiter. Deleting characters would alter what the reporter
    wrote, and a record's value depends on the quotation being faithful.
    """
    return _FENCE_LIKE.sub(_NEUTRALIZED, text)


def _neutralize_markers(text: str) -> str:
    """Stop quoted text from forging the markers that bound it."""
    return _MARKER_LIKE.sub(_MARKER_NEUTRALIZED, text)


def fenced(text: str, *, label: str) -> str:
    """`text`, quoted between markers it cannot close.

    `label` is chosen by this tool, never by the claim, so a claim cannot name a region into
    existence. Both fence-like runs and marker-like runs inside the text are neutralised.
    """
    if not re.fullmatch(r"[A-Z0-9-]{1,32}", label):
        raise ValueError(
            f"label {label!r} must be an application-chosen identifier: "
            f"uppercase letters, digits, and hyphens"
        )
    body = _neutralize_markers(neutralize_fence(text))
    return "\n".join([MARKER_START.format(label=label), body, MARKER_END.format(label=label)])
