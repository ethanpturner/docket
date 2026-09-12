"""What an inbound finding is, before anyone has assessed it.

A `Claim` is the normalised form of something a person or a tool asserted about a codebase. It is
not a finding, and the difference is the whole point: a finding is a conclusion the project stands
behind, and a claim is a conclusion somebody else reached, which may be true, false, or about code
that does not exist.

**The claim's text is untrusted and stays that way.** An inbound report is a document written by
someone outside the project -- a bug bounty submitter, an agentic scanner, a stranger. Its prose is
carried verbatim because a disposition has to quote what was actually claimed, and it is never
parsed for instructions, never interpolated into anything that reads as a command, and never
treated as a statement of fact about the system. `raw_text` is evidence that a claim was made. It
is not evidence of the weakness the claim describes.

**Locators are strings until they are resolved.** A tool citing `src/app.py:42` has produced two
assertions: that the file exists, and that line 42 is the relevant one. Phase 0 checks the first
mechanically and never guesses at a path that does not exist -- see `resolve.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Claim", "ClaimSource"]


@dataclass(frozen=True, slots=True)
class ClaimSource:
    """Who or what asserted the claim, and in what version.

    `tool` is the producer's own name for itself, read from the input where the format carries one
    (SARIF's `tool.driver.name`) and set to the ingest format's name otherwise. A claim whose
    producer is unknown says so; it does not default to a friendly label.
    """

    tool: str
    version: str | None = None
    format: str = "unknown"
    """Which ingest read it: `sarif`, `mantis`, `codex-security`, `text`."""


@dataclass(frozen=True, slots=True)
class Claim:
    """One assertion about a codebase, as received.

    Every field is what the source said. Nothing here has been checked.
    """

    claim_id: str
    """The source's own identifier where it has one, otherwise a digest of the claim's content.

    Never invented sequentially: two ingests of the same report produce the same identifier, and
    two different claims never collide into one.
    """

    title: str
    """The source's one-line summary, verbatim. Empty when the source gives none."""

    raw_text: str
    """Everything the source said, verbatim and untrusted. Quoted in the record, never interpreted."""

    locators: tuple[str, ...] = ()
    """Claimed positions, as spelled by the source: `path`, `path:line`, or `path:start-end`."""

    weakness: str | None = None
    """The source's claimed weakness class, usually a CWE identifier. Not validated against MITRE."""

    severity: str | None = None
    """The source's claimed severity, in the source's own vocabulary. Not normalised: `HIGH` and
    `high` and `7.5` are three tools' words, and flattening them would assert an equivalence
    nobody established."""

    source: ClaimSource = field(default=ClaimSource(tool="unknown"))
