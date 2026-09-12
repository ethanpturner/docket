"""The five questions, taken from OpenVEX rather than invented.

A triage reviewer dismissing a claim has to say why, and OpenVEX already fixes the vocabulary of
acceptable reasons: five justification labels, no more. So the evidence worth gathering is not a
free-form analysis of a claim. It is whatever bears on those five, because those are the only
dismissals a downstream consumer can read.

| Question | OpenVEX justification | Settled by |
|---|---|---|
| Does the cited component exist here? | `component_not_present` | the resolver, mechanically |
| Does the cited span contain what the claim describes? | `vulnerable_code_not_present` | a model reading both |
| Is the cited code reachable from an entry point? | `vulnerable_code_not_in_execute_path` | the call graph, then a model |
| Can attacker-controlled input reach it? | `vulnerable_code_cannot_be_controlled_by_adversary` | a model |
| Is there a control on the path the claim did not account for? | `inline_mitigations_already_exist` | a model |

**Every answer is three-valued, for the same reason the disposition is.** A question can support
the justification, contradict it, or go unestablished, and the third is the common case. Folding
"nobody could tell" into "the justification does not apply" is how a queue comes to look examined.

**An answer is not a decision.** A question whose evidence supports `vulnerable_code_not_present`
produces a *candidate* justification: the label a person could select, with the evidence behind it
and the reason it might be wrong attached. `DEC-002` forbids this tool from selecting it, and the
candidate carries `is_decision: false` into the record so that no consumer mistakes the two.

The spec itself flags two of the five as hard to prove conclusively —
`vulnerable_code_cannot_be_controlled_by_adversary` and `inline_mitigations_already_exist` — and
that caution is carried on the question rather than left in a document nobody reads at triage time.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "QUESTIONS",
    "Answer",
    "Question",
    "QuestionSpec",
    "question_spec",
]


class Question(StrEnum):
    """The five, keyed by what they ask rather than by the label they support."""

    COMPONENT_PRESENT = "component_present"
    """Is the cited file in this repository at this commit?"""

    CONSTRUCT_PRESENT = "construct_present"
    """Does the cited span actually contain the thing the claim describes?"""

    REACHABLE = "reachable"
    """Can the cited code be reached from an entry point?"""

    ATTACKER_CONTROLLED = "attacker_controlled"
    """Can input an attacker chooses reach the cited code?"""

    MITIGATION_PRESENT = "mitigation_present"
    """Is there a control on the path that the claim did not account for?"""


class Answer(StrEnum):
    """What the gathered evidence says about one question.

    The names describe the evidence's bearing on the *justification*, not on the claim. A
    justification is a reason a product is **not** affected, so `SUPPORTS_JUSTIFICATION` is
    evidence that the claim does not hold here, and `CONTRADICTS_JUSTIFICATION` is evidence that
    this particular escape route is closed — which is not the same as evidence the claim is true.
    """

    SUPPORTS_JUSTIFICATION = "supports_justification"
    CONTRADICTS_JUSTIFICATION = "contradicts_justification"
    NOT_ESTABLISHED = "not_established"
    """Nobody established either. The default, and the honest answer to most questions."""


@dataclass(frozen=True, slots=True)
class QuestionSpec:
    """What one question asks, what answering it would justify, and how it is answered."""

    question: Question
    justification: str
    """The OpenVEX label this question bears on. One of the spec's fixed five."""

    asks: str
    """The question in a sentence, as it appears on the reviewer's page. Human-facing only."""

    proposition: str
    """The justification stated as a proposition, and the only thing a gatherer is asked to judge.

    This field exists because the first version did not have it. A gatherer was shown the
    human-facing question -- "Can input an attacker controls reach the cited code?" -- and asked
    whether its findings supported *the justification*, which is that adversary the code cannot be
    controlled. Two of the three model-answered questions are phrased as the negation of the
    label they bear on, so a model answering the question it could see inverted the answer that
    was recorded: it described a handler reading the HTTP request body and that was filed as
    evidence the code is beyond an attacker's reach.

    The measurement caught it -- 28 `supports` and 0 `contradicts` on a question no real codebase
    answers one way -- and the fix is to stop asking two things at once. The gatherer judges the
    proposition. Nothing else.
    """

    settled_by: str
    """`resolver`, `call_graph`, or `model`. Which mechanism produces the answer."""

    hard_to_prove: bool = False
    """Whether the OpenVEX spec itself warns this justification is difficult to prove
    conclusively. Carried onto the reviewer's page rather than left in the specification."""

    supports_note: str = ""
    """What a `supports_justification` answer does *not* establish. The caveat travels with the
    answer, because a caveat in a footnote is a caveat nobody reads at triage time."""


# The five specs. Ordered cheapest-first, which is also the order a reviewer would work: a claim
# citing a file that is not here needs no further analysis.
QUESTIONS: Final[tuple[QuestionSpec, ...]] = (
    QuestionSpec(
        question=Question.COMPONENT_PRESENT,
        justification="component_not_present",
        asks="Is the cited file present in this repository at this commit?",
        proposition="The cited component is not present in this product.",
        settled_by="resolver",
        supports_note=(
            "The cited path is absent, which makes the citation wrong about this commit. The "
            "weakness may still be real and cited badly, which is common in machine-generated "
            "findings."
        ),
    ),
    QuestionSpec(
        question=Question.CONSTRUCT_PRESENT,
        justification="vulnerable_code_not_present",
        asks="Does the cited span contain the construct the claim describes?",
        proposition=("The code the claim describes is NOT present at the cited position."),
        settled_by="model",
        supports_note=(
            "The cited span does not contain what the claim describes. The construct may be "
            "elsewhere in the file or the repository; only the cited position was examined."
        ),
    ),
    QuestionSpec(
        question=Question.REACHABLE,
        justification="vulnerable_code_not_in_execute_path",
        asks="Is the cited code reachable from an entry point?",
        proposition="The cited code is NOT in any execution path of this product.",
        settled_by="call_graph",
        supports_note=(
            "No caller was found by static analysis. That is not proof of unreachability: "
            "dynamic dispatch, framework registration, reflection, and entry points outside "
            "this repository all defeat a call graph."
        ),
    ),
    QuestionSpec(
        question=Question.ATTACKER_CONTROLLED,
        justification="vulnerable_code_cannot_be_controlled_by_adversary",
        asks="Can input an attacker controls reach the cited code?",
        proposition=(
            "The cited code CANNOT be reached or influenced by input that an attacker controls."
        ),
        settled_by="model",
        hard_to_prove=True,
        supports_note=(
            "No path from attacker-controlled input was identified. OpenVEX flags this "
            "justification as difficult to prove conclusively, and an unidentified path is not "
            "an absent one."
        ),
    ),
    QuestionSpec(
        question=Question.MITIGATION_PRESENT,
        justification="inline_mitigations_already_exist",
        asks="Is there a control on the path that the claim did not account for?",
        proposition=(
            "A control already present on the path prevents the described weakness, and that "
            "control cannot be disabled or configured away by a user."
        ),
        settled_by="model",
        hard_to_prove=True,
        supports_note=(
            "A control was identified on the path. OpenVEX requires such a mitigation to be "
            "non-configurable and non-subvertible to justify a dismissal, and neither property "
            "was checked here."
        ),
    ),
)

_BY_QUESTION: Final[dict[Question, QuestionSpec]] = {spec.question: spec for spec in QUESTIONS}


def question_spec(question: Question) -> QuestionSpec:
    """The spec for one question."""
    return _BY_QUESTION[question]
