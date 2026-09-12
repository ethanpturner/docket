"""What was gathered, what it bears on, and what nobody established.

An evidence record is a disposition record with the five questions answered. It adds no status:
`DEC-002` holds, the status is still `undetermined`, and a person still decides. What it adds is
the material a person needs in order to decide, arranged by the only vocabulary a downstream VEX
consumer can read.

**A candidate justification is not a decision, and the record says so in the field name and in the
data.** `is_decision` is `false` on every candidate, and there is no code path that sets it
otherwise. A candidate is the label a reviewer *could* select, the evidence that would support it,
and the reason it might still be wrong — all three, because a suggestion without its caveat is an
anchor.

**What nobody established is a first-class list, not an absence.** The questions that came back
`not_established` are named on the record and on the page. A reviewer reading a page with four
answered questions and one silent one is looking at a different situation from one with five
answers, and a record that only prints what it found makes those look the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from docket.questions import Answer, Question, question_spec

if TYPE_CHECKING:
    from docket.disposition import DispositionRecord

__all__ = [
    "CandidateJustification",
    "EvidenceItem",
    "EvidenceRecord",
    "QuestionFinding",
]


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One piece of material behind an answer.

    `source` is `resolver`, `call_graph`, or `model`, so a reader can tell mechanical evidence
    from a model's reading without inferring it from the wording.
    """

    source: str
    summary: str
    """What this evidence is, in the gatherer's words. For a model, its own summary; for the
    call graph, a generated sentence."""

    locator: str | None = None
    quoted_text: str | None = None
    content_hash: str | None = None
    """The digest of `quoted_text`, so the record can be checked against the repository later."""


@dataclass(frozen=True, slots=True)
class QuestionFinding:
    """One question, its answer, and everything behind it."""

    question: Question
    answer: Answer
    evidence: tuple[EvidenceItem, ...] = ()
    could_not_establish: tuple[str, ...] = ()
    """What the gatherer says it was unable to determine. Reported verbatim on the page: a
    gatherer naming its own limits is the most useful thing it produces."""

    detail: str = ""
    """A sentence on how the answer was reached."""

    model_failed: str | None = None
    """Why the model call failed, when one was attempted and did not produce an answer. A
    question is `not_established` either way; this says whether anyone tried."""

    def to_dict(self) -> dict[str, Any]:
        spec = question_spec(self.question)
        return {
            "question": self.question.value,
            "asks": spec.asks,
            "bears_on_justification": spec.justification,
            "settled_by": spec.settled_by,
            "answer": self.answer.value,
            "detail": self.detail,
            "evidence": [
                {
                    "source": item.source,
                    "summary": item.summary,
                    "locator": item.locator,
                    "quoted_text": item.quoted_text,
                    "content_hash": item.content_hash,
                }
                for item in self.evidence
            ],
            "could_not_establish": list(self.could_not_establish),
            "model_failed": self.model_failed,
        }


@dataclass(frozen=True, slots=True)
class CandidateJustification:
    """A label a reviewer could select, with the evidence and the caveat attached.

    Never a decision. `is_decision` is hard-coded `False` and serialised on every candidate, so a
    consumer reading the JSON cannot mistake this for a selected justification.
    """

    justification: str
    from_question: Question
    evidence_summary: str
    caveat: str
    """Why this candidate might be wrong. Taken from the question's spec, and from the OpenVEX
    spec's own warning where it flags a label as hard to prove."""

    hard_to_prove: bool = False

    @property
    def is_decision(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "justification": self.justification,
            "from_question": self.from_question.value,
            "evidence_summary": self.evidence_summary,
            "caveat": self.caveat,
            "hard_to_prove": self.hard_to_prove,
            "is_decision": self.is_decision,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A disposition record, plus the five questions."""

    disposition: DispositionRecord
    findings: tuple[QuestionFinding, ...]
    candidates: tuple[CandidateJustification, ...] = ()
    model_name: str | None = None
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_seconds: float = 0.0
    assessed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def unestablished(self) -> tuple[QuestionFinding, ...]:
        """The questions nobody answered. Named, never omitted."""
        return tuple(item for item in self.findings if item.answer is Answer.NOT_ESTABLISHED)

    @property
    def established_count(self) -> int:
        return len(self.findings) - len(self.unestablished)

    def to_dict(self) -> dict[str, Any]:
        payload = self.disposition.to_dict()
        payload["assessment"] = {
            "assessed_at": self.assessed_at.isoformat(),
            "model": self.model_name,
            "model_calls": self.model_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "duration_seconds": round(self.duration_seconds, 3),
            "questions": [item.to_dict() for item in self.findings],
            "candidate_justifications": [item.to_dict() for item in self.candidates],
            "not_established": [item.question.value for item in self.unestablished],
            "note": (
                "Candidate justifications are not decisions. The status remains undetermined "
                "until a person sets it, and this tool does not select a justification."
            ),
        }
        return payload
