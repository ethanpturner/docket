"""The person. Phases 0 and 1 never set a status; this is where somebody does.

Everything before this point refuses to decide, on the argument that a tool adding a fourth
opinion to a triage queue inherits the complaint the queue already has. That refusal is only worth
anything if the decision, when it finally happens, is recorded better than a queue records it
today. So a decision here carries four things a status field does not:

- **who decided**, because a verdict nobody signed is a verdict nobody is accountable for;
- **why**, in their own words, never optional and never defaulted;
- **which of the five OpenVEX justifications they selected**, when the status needs one, from the
  fixed catalogue rather than free prose;
- **whether they decided against the gathered evidence**, and their reason for doing so.

That last one is the field that matters most, and the one a tool built to be trusted would be
tempted to leave out. A reviewer overruling the assessment is legitimate and common: the evidence
is thin, the questions are narrow, and a person who knows the system knows things the call graph
does not. What must not happen is that the override is invisible. `OVERRIDE` records that the
reviewer selected a justification the evidence did not offer, and makes them say why, so that six
months later the difference between "the tool found this and a person agreed" and "a person
decided this over the tool's objection" is still legible.

**A decision is built once, through a validating constructor.** There is no path that mutates a
decided object into a different decision, because a mutation skips the constructor and therefore
skips every rule below. `tests/test_decision.py` walks the syntax tree of the package and fails on
`dataclasses.replace`, `copy.copy`, `copy.deepcopy`, and `object.__setattr__`, which are the four
ways a frozen dataclass is edited without being validated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from docket.disposition import Disposition, DispositionRecord, Status
from docket.vex import JUSTIFICATIONS

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from docket.evidence import EvidenceRecord

__all__ = [
    "Decision",
    "DecisionError",
    "apply_decision",
    "decide",
    "load_decisions",
    "save_decisions",
]


class DecisionError(ValueError):
    """A decision that is not one: no reason, no decider, or a status the record cannot carry."""


@dataclass(frozen=True, slots=True)
class Decision:
    """One reviewer's disposition of one claim, with the argument attached.

    Construct through `decide`, which is the only path that checks a selected justification
    against the evidence. The constructor checks everything that can be checked without the
    evidence record, so a decision file edited by hand and loaded later is held to the same rules.
    """

    claim_id: str
    status: Status
    reason: str
    """The reviewer's own words. Never optional: a status alone is an assertion without an
    argument, which is what a triage queue is already full of."""

    decided_by: str
    """The identity of the person deciding. A string the reviewer chose; this tool does not
    authenticate it, and says so rather than implying a signature it does not have."""

    justification: str | None = None
    """One of the five OpenVEX labels, and only on `not_exploitable`."""

    impact_statement: str | None = None
    """Free prose, the spec's alternative to a justification. Discouraged by the spec for
    automated consumers, permitted because sometimes no label fits."""

    override: str | None = None
    """Set when the selected justification was not among the assessment's candidates. The
    reviewer's reason for deciding against the gathered evidence, recorded as its own field so
    that it cannot be mistaken for ordinary agreement."""

    decided_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.claim_id.strip():
            raise DecisionError("a decision names the claim it decides")
        if not self.reason.strip():
            raise DecisionError(
                f"claim {self.claim_id}: a decision states its reason. A status with no reason is "
                f"an assertion without an argument."
            )
        if not self.decided_by.strip():
            raise DecisionError(
                f"claim {self.claim_id}: a decision names who made it. A verdict nobody signed is "
                f"a verdict nobody is accountable for."
            )
        if self.justification is not None and self.justification not in JUSTIFICATIONS:
            raise DecisionError(
                f"claim {self.claim_id}: {self.justification!r} is not an OpenVEX justification. "
                f"The catalogue is fixed at five labels: {', '.join(JUSTIFICATIONS)}."
            )
        if self.status is Status.NOT_EXPLOITABLE and not (
            self.justification or (self.impact_statement or "").strip()
        ):
            raise DecisionError(
                f"claim {self.claim_id}: OpenVEX requires a `not_affected` statement to carry "
                f"either a justification from the fixed catalogue or an impact statement. A "
                f"dismissal states its argument."
            )
        if self.justification is not None and self.status is not Status.NOT_EXPLOITABLE:
            raise DecisionError(
                f"claim {self.claim_id}: a justification is a reason a product is NOT affected, "
                f"so it belongs only on {Status.NOT_EXPLOITABLE.value!r}. Status is "
                f"{self.status.value!r}."
            )
        if self.override is not None and not self.override.strip():
            raise DecisionError(
                f"claim {self.claim_id}: an override is a reason for deciding against the "
                f"evidence, so an empty one is not an override"
            )

    @property
    def overrides_evidence(self) -> bool:
        return self.override is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status.value,
            "justification": self.justification,
            "impact_statement": self.impact_statement,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "decided_at": (self.decided_at or datetime.now(UTC)).isoformat(),
            "overrides_evidence": self.overrides_evidence,
            "override_reason": self.override,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        """Rebuild from a decision file, through the same constructor that built it.

        A hand-edited file is the expected case -- `docket decide` writes one and a reviewer
        opens it -- so it is validated exactly as the command-line path is.
        """
        raw_status = str(data.get("status"))
        try:
            status = Status(raw_status)
        except ValueError as error:
            allowed = ", ".join(item.value for item in Status)
            raise DecisionError(
                f"{raw_status!r} is not a disposition. The three are: {allowed}."
            ) from error
        decided_at = data.get("decided_at")
        return cls(
            claim_id=str(data.get("claim_id", "")),
            status=status,
            reason=str(data.get("reason", "")),
            decided_by=str(data.get("decided_by", "")),
            justification=data.get("justification"),
            impact_statement=data.get("impact_statement"),
            override=data.get("override_reason"),
            decided_at=datetime.fromisoformat(decided_at) if decided_at else None,
        )


def _candidate_labels(evidence: EvidenceRecord | None) -> tuple[str, ...]:
    if evidence is None:
        return ()
    return tuple(candidate.justification for candidate in evidence.candidates)


def decide(
    *,
    claim_id: str,
    status: Status,
    reason: str,
    decided_by: str,
    justification: str | None = None,
    impact_statement: str | None = None,
    override: str | None = None,
    evidence: EvidenceRecord | None = None,
    decided_at: datetime | None = None,
) -> Decision:
    """Build a decision, checking the selected justification against the gathered evidence.

    Every rule the constructor can check without context, it checks. This function adds the one
    rule that needs the assessment: a justification the evidence did not offer as a candidate is
    refused unless the reviewer supplies `override`, which is then recorded.

    An assessment that gathered no evidence at all -- `--no-model`, or a claim assessed by
    `record` rather than `assess` -- offers no candidates, so every justification is an override.
    That is the correct reading rather than an inconvenience: selecting `vulnerable_code_not_present`
    when nobody looked at the code is exactly the decision that should leave a trace.
    """
    decision = Decision(
        claim_id=claim_id,
        status=status,
        reason=reason,
        decided_by=decided_by,
        justification=justification,
        impact_statement=impact_statement,
        override=override,
        decided_at=decided_at or datetime.now(UTC),
    )
    check_against_evidence(decision, evidence)
    return decision


def check_against_evidence(decision: Decision, evidence: EvidenceRecord | None) -> None:
    """Refuse a justification the assessment did not offer, unless the reviewer overrode it.

    Raises rather than returning a verdict, because a decision that fails this check is not a
    weaker decision -- it is an unrecorded override, and writing it to a file would lose the one
    fact the field exists to keep.
    """
    if decision.justification is None or decision.overrides_evidence:
        return
    candidates = _candidate_labels(evidence)
    if decision.justification in candidates:
        return
    offered = ", ".join(candidates) if candidates else "none"
    raise DecisionError(
        f"claim {decision.claim_id}: the assessment did not offer {decision.justification!r} as a "
        f"candidate (offered: {offered}). Selecting it is deciding against the gathered evidence, "
        f"which is allowed and recorded: supply an override reason. A justification chosen over "
        f"the evidence, with no note that it was, is the one thing this record cannot lose."
    )


def apply_decision(record: DispositionRecord, decision: Decision) -> DispositionRecord:
    """A new record carrying the decision. Never a mutation, never a copy-with-update.

    The decided objects are constructed field by field so that every rule in `Disposition` and
    every rule in `Decision` runs on the result. A copy-with-update would produce the same fields
    while skipping the constructors, which is how an invalid object comes to exist and serialise
    cleanly.
    """
    if decision.claim_id != record.claim.claim_id:
        raise DecisionError(
            f"decision is for claim {decision.claim_id!r}, record is for {record.claim.claim_id!r}"
        )
    disposition = Disposition(
        status=decision.status,
        reason=decision.reason,
        decided_by=decision.decided_by,
        decided_at=decision.decided_at,
        justification=decision.justification,
        impact_statement=decision.impact_statement,
        override_reason=decision.override,
    )
    return DispositionRecord(
        claim=record.claim,
        repository=record.repository,
        commit=record.commit,
        locators=record.locators,
        disposition=disposition,
        recorded_at=record.recorded_at,
        docket_version=record.docket_version,
    )


def save_decisions(decisions: Iterable[Decision], path: Path) -> Path:
    """Write a decision file: one object per claim, newest write wins for a repeated claim."""
    payload = {
        "format": "docket/decisions/v1",
        "note": (
            "A decision is a person's, and this file is where they made it. Every entry carries "
            "a reason and a decider, and an entry that chose a justification the assessment did "
            "not offer carries the override reason as well."
        ),
        "decisions": [decision.to_dict() for decision in decisions],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_decisions(path: Path) -> dict[str, Decision]:
    """Read a decision file, validating every entry through the constructor.

    Keyed by claim. A file naming the same claim twice is refused rather than resolved by
    ordering: two decisions about one claim is a disagreement someone has to settle, and picking
    the later one silently would settle it by accident.
    """
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != "docket/decisions/v1":
        raise DecisionError(f"{path} is not a docket decision file")
    decisions: dict[str, Decision] = {}
    for entry in data.get("decisions") or []:
        decision = Decision.from_dict(entry)
        if decision.claim_id in decisions:
            raise DecisionError(
                f"{path} decides claim {decision.claim_id!r} twice. Two decisions about one claim "
                f"is a disagreement to settle, not an ordering to resolve."
            )
        decisions[decision.claim_id] = decision
    return decisions
