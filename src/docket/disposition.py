"""The record: what was claimed, what was checked, and what nobody has decided yet.

A disposition is the answer to a question a triage queue asks all day. Somebody asserted a
weakness. Is it real? There are exactly three honest answers, and the third is the one no existing
tool writes down:

- **exploitable** - the evidence supports the claim
- **not_exploitable** - the evidence contradicts it, and the reason is named
- **undetermined** - nobody has established either, and that is the state of the record

Collapsing the third into the second is the failure this tool exists to prevent. "We looked and it
is fine" and "nobody looked" are different facts about a system, they are reached by different
work, and an auditor asking which one applies deserves an answer rather than a shrug rendered as
a pass.

**Phase 0 writes `undetermined` and nothing else.** There is no code path to another status, and a
test pins that. The tool checks whether a claim points at code that exists; it does not decide
whether the code is vulnerable. A status is set by a person, in a later phase, and the record
carries who set it and why.

**The status and the reason travel together.** A status with no reason is an assertion without an
argument, which is what a triage queue is already full of.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from docket._version import __version__
from docket.resolve import Resolution

if TYPE_CHECKING:
    from docket.claim import Claim
    from docket.resolve import LocatorResolution

__all__ = [
    "NO_ASSESSMENT",
    "Disposition",
    "DispositionRecord",
    "Status",
    "record_for",
    "record_from_dict",
]

# Phase 0's only reason. Stated as a constant so the string in the record, the string in the tests,
# and the string in the README are one thing.
NO_ASSESSMENT = "no assessment performed"


class Status(StrEnum):
    """The three answers. See the module docstring for why there are exactly three."""

    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class Disposition:
    """A status and the argument for it.

    `decided_by` is absent in Phase 0 and required for any status other than `undetermined` in
    later phases: a verdict nobody signed is a verdict nobody is accountable for.

    The justification fields mirror what OpenVEX requires of a `not_affected` statement, and they
    are checked here rather than only at emission. A record that cannot be emitted as valid VEX
    should not exist, and finding that out at the end of a pipeline is how an invalid record comes
    to be written to disk and read by somebody.
    """

    status: Status
    reason: str
    decided_by: str | None = None
    decided_at: datetime | None = None
    justification: str | None = None
    """One of OpenVEX's five labels, set only on `not_exploitable`. See `vex.JUSTIFICATIONS`."""

    impact_statement: str | None = None
    """The spec's free-prose alternative to a justification, for a dismissal no label fits."""

    override_reason: str | None = None
    """Present when the reviewer selected a justification the assessment did not offer. Its own
    field, so that deciding against the evidence never looks like agreeing with it."""

    def __post_init__(self) -> None:
        from docket.vex import JUSTIFICATIONS

        if not self.reason.strip():
            raise ValueError("a disposition states its reason; a status alone is an assertion")
        if self.status is not Status.UNDETERMINED and self.decided_by is None:
            raise ValueError(
                f"status {self.status.value!r} requires `decided_by`: a person decides a "
                f"disposition, and the record names them"
            )
        if self.justification is not None and self.justification not in JUSTIFICATIONS:
            raise ValueError(
                f"{self.justification!r} is not an OpenVEX justification; the catalogue is fixed "
                f"at five labels"
            )
        if self.justification is not None and self.status is not Status.NOT_EXPLOITABLE:
            raise ValueError(
                f"a justification is a reason a product is not affected, so it belongs only on "
                f"{Status.NOT_EXPLOITABLE.value!r}, not {self.status.value!r}"
            )
        if self.status is Status.NOT_EXPLOITABLE and not (
            self.justification or (self.impact_statement or "").strip()
        ):
            raise ValueError(
                "OpenVEX requires a `not_affected` statement to carry a justification or an "
                "impact statement; a dismissal states its argument"
            )

    @property
    def is_decided(self) -> bool:
        """Whether a person set this status. Phase 0's `undetermined` was not decided by anyone."""
        return self.decided_by is not None


@dataclass(frozen=True, slots=True)
class DispositionRecord:
    """One claim, the repository it was made against, and every locator checked."""

    claim: Claim
    repository: str
    """The repository as the caller named it: a path, a URL, whatever identifies it to a reader."""

    commit: str
    """The commit the claim was checked against. Recorded, never inferred from the worktree."""

    locators: tuple[LocatorResolution, ...]
    disposition: Disposition
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    docket_version: str = __version__
    """The version that wrote this record, stamped rather than hardcoded."""

    @property
    def resolved_count(self) -> int:
        return sum(1 for item in self.locators if item.resolved)

    @property
    def locator_count(self) -> int:
        return len(self.locators)

    @property
    def fully_unresolved(self) -> bool:
        """Every cited locator failed to resolve.

        The signal worth acting on: a claim that cites positions and hits none of them is about a
        codebase other than the one at this commit, whatever its prose says. A claim citing
        nothing is not in this category, because it made no positional assertion to be wrong about.
        """
        return self.locator_count > 0 and self.resolved_count == 0

    def to_dict(self) -> dict[str, Any]:
        """The record as JSON-ready data. Every field a reader needs to check the work."""
        return {
            "docket_version": self.docket_version,
            "recorded_at": self.recorded_at.isoformat(),
            "claim": {
                "claim_id": self.claim.claim_id,
                "title": self.claim.title,
                "weakness": self.claim.weakness,
                "severity_claimed": self.claim.severity,
                "source": {
                    "tool": self.claim.source.tool,
                    "version": self.claim.source.version,
                    "format": self.claim.source.format,
                },
                "raw_text": self.claim.raw_text,
                "locators_claimed": list(self.claim.locators),
            },
            "target": {"repository": self.repository, "commit": self.commit},
            "locators": [
                {
                    "locator": item.locator,
                    "resolution": item.resolution.value,
                    "path": item.path,
                    "start_line": item.start_line,
                    "end_line": item.end_line,
                    "line_count": item.line_count,
                    "quoted_text": item.quoted_text,
                    "content_hash": item.content_hash,
                    "truncated": item.truncated,
                }
                for item in self.locators
            ],
            "locator_summary": {
                "total": self.locator_count,
                "resolved": self.resolved_count,
                "by_resolution": {
                    value.value: sum(1 for item in self.locators if item.resolution is value)
                    for value in Resolution
                },
            },
            "disposition": {
                "status": self.disposition.status.value,
                "reason": self.disposition.reason,
                "decided_by": self.disposition.decided_by,
                "decided_at": (
                    self.disposition.decided_at.isoformat() if self.disposition.decided_at else None
                ),
                "justification": self.disposition.justification,
                "impact_statement": self.disposition.impact_statement,
                "overrides_evidence": self.disposition.override_reason is not None,
                "override_reason": self.disposition.override_reason,
            },
        }


def record_from_dict(data: dict[str, Any]) -> DispositionRecord:
    """Rebuild a record from its own JSON.

    A written record that cannot be read back is not a record; it is a report. `decide` and `bind`
    both operate on a file somebody wrote earlier, so the round trip is load-bearing rather than a
    convenience, and every rebuilt object goes through the same constructors the original did.
    """
    from docket.claim import Claim as ClaimType
    from docket.claim import ClaimSource
    from docket.resolve import LocatorResolution as Loc
    from docket.resolve import Resolution as Res

    claim_data = data["claim"]
    source = claim_data.get("source") or {}
    claim = ClaimType(
        claim_id=str(claim_data["claim_id"]),
        title=str(claim_data.get("title") or ""),
        raw_text=str(claim_data.get("raw_text") or ""),
        locators=tuple(claim_data.get("locators_claimed") or ()),
        weakness=claim_data.get("weakness"),
        severity=claim_data.get("severity_claimed"),
        source=ClaimSource(
            tool=str(source.get("tool") or "unknown"),
            version=source.get("version"),
            format=str(source.get("format") or "unknown"),
        ),
    )
    locators = tuple(
        Loc(
            locator=str(item["locator"]),
            resolution=Res(item["resolution"]),
            path=item.get("path"),
            start_line=item.get("start_line"),
            end_line=item.get("end_line"),
            line_count=item.get("line_count"),
            quoted_text=item.get("quoted_text"),
            content_hash=item.get("content_hash"),
            truncated=bool(item.get("truncated", False)),
        )
        for item in data.get("locators") or ()
    )
    held = data["disposition"]
    decided_at = held.get("decided_at")
    disposition = Disposition(
        status=Status(held["status"]),
        reason=str(held["reason"]),
        decided_by=held.get("decided_by"),
        decided_at=datetime.fromisoformat(decided_at) if decided_at else None,
        justification=held.get("justification"),
        impact_statement=held.get("impact_statement"),
        override_reason=held.get("override_reason"),
    )
    target = data["target"]
    return DispositionRecord(
        claim=claim,
        repository=str(target["repository"]),
        commit=str(target["commit"]),
        locators=locators,
        disposition=disposition,
        recorded_at=datetime.fromisoformat(data["recorded_at"]),
        docket_version=str(data.get("docket_version") or "0.0.0"),
    )


def record_for(
    claim: Claim,
    *,
    repository: str,
    commit: str,
    locators: tuple[LocatorResolution, ...],
) -> DispositionRecord:
    """Build the Phase 0 record for one claim.

    The status is `undetermined` because this is the only status Phase 0 produces. The constant is
    passed here rather than defaulted inside `Disposition`, so that a later phase adding a decided
    status changes a call site rather than a default.
    """
    return DispositionRecord(
        claim=claim,
        repository=repository,
        commit=commit,
        locators=locators,
        disposition=Disposition(status=Status.UNDETERMINED, reason=NO_ASSESSMENT),
    )
