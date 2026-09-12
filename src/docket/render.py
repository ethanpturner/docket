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

from typing import TYPE_CHECKING, Final

from docket.fence import FENCE, neutralize_fence
from docket.questions import Answer, question_spec
from docket.resolve import Resolution

if TYPE_CHECKING:
    from docket.disposition import DispositionRecord
    from docket.evidence import EvidenceRecord

__all__ = ["FENCE", "neutralize_fence", "render_evidence_markdown", "render_markdown"]

_RESOLUTION_NOTE: Final = {
    Resolution.RESOLVES: "the file is present and the range is in it",
    Resolution.PATH_ABSENT: "no such file at this commit",
    Resolution.LINE_OUT_OF_RANGE: "the file is present; the cited lines are not",
    Resolution.NOT_A_LOCATOR: "not a path with an optional line range",
}


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


_ANSWER_MARK: Final = {
    Answer.SUPPORTS_JUSTIFICATION: "supports",
    Answer.CONTRADICTS_JUSTIFICATION: "contradicts",
    Answer.NOT_ESTABLISHED: "**not established**",
}


def render_evidence_markdown(record: EvidenceRecord) -> str:
    """The page a reviewer reads to decide.

    Phase 0's page said what was claimed and which citations held up. This one adds the five
    questions, and it is organised so the last section is the one that matters most: what nobody
    established. A page that prints only what was found lets an unexamined question look like a
    settled one.
    """
    base = render_markdown(record.disposition)
    # The base page ends with its own closing note; the assessment goes before it.
    marker = "## What this record does not say"
    head, _, tail = base.partition(marker)

    lines: list[str] = ["## The five questions", ""]
    lines += [
        "Each bears on one of the five justifications OpenVEX allows for a dismissal. An answer",
        "is evidence, not a decision: the status stays `undetermined` and this tool does not",
        "select a justification.",
        "",
        "| Question | Bears on | Answer | Settled by |",
        "|---|---|---|---|",
    ]
    for finding in record.findings:
        spec = question_spec(finding.question)
        lines.append(
            f"| {spec.asks} | `{spec.justification}` | {_ANSWER_MARK[finding.answer]} | "
            f"`{spec.settled_by}` |"
        )
    lines.append("")

    for finding in record.findings:
        spec = question_spec(finding.question)
        lines += [f"### {spec.asks}", ""]
        lines.append(
            f"**{_ANSWER_MARK[finding.answer]}**"
            + (f" - {finding.detail}" if finding.detail else "")
        )
        lines.append("")
        for item in finding.evidence:
            lines.append(f"- *{item.source}*: {item.summary}")
        if finding.model_failed:
            lines.append(f"- no answer: {finding.model_failed}")
        if finding.could_not_establish:
            lines += ["", "Could not establish:"]
            lines += [f"- {gap}" for gap in finding.could_not_establish]
        lines.append("")

    if record.candidates:
        lines += [
            "## Candidate justifications",
            "",
            "Labels a reviewer **could** select, with the evidence and the reason each might be",
            "wrong. None of these is selected, and this tool does not select one.",
            "",
        ]
        for candidate in record.candidates:
            warn = (
                " (the OpenVEX spec warns this is hard to prove conclusively)"
                if candidate.hard_to_prove
                else ""
            )
            lines += [
                f"### `{candidate.justification}`{warn}",
                "",
                f"{candidate.evidence_summary}",
                "",
                f"*Caveat:* {candidate.caveat}",
                "",
            ]
    else:
        lines += [
            "## Candidate justifications",
            "",
            "None. No question produced evidence supporting a dismissal, which is not evidence",
            "that the claim is true.",
            "",
        ]

    lines += ["## What nobody established", ""]
    if record.unestablished:
        for finding in record.unestablished:
            spec = question_spec(finding.question)
            why = finding.model_failed or finding.detail or "no evidence was gathered"
            lines.append(f"- **{spec.asks}** {why}")
    else:
        lines.append("Every question was answered. The status is still a person's to set.")
    lines.append("")

    if record.model_name:
        lines += [
            f"Evidence gathered with `{record.model_name}`, {record.model_calls} call(s), "
            f"{record.input_tokens} in / {record.output_tokens} out, "
            f"{record.duration_seconds:.1f}s. The model gathered; it did not decide.",
            "",
        ]

    return head + "\n".join(lines) + marker + tail
