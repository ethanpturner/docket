"""The page a reviewer reads, and the comment a pull request gets.

One rendering, two destinations. A triage summary has to work as a terminal digest for somebody
running the command by hand and as a Markdown comment on a pull request, and writing those twice
guarantees they drift.

**What goes at the top is what needs a person.** New claims and stale decisions, in that order.
Carried decisions are a count and a fold, because the whole point of carrying them is that nobody
reads them again.

**A stale decision shows its previous reason.** The reviewer re-deciding is usually going to reach
the same conclusion as last time, and making them reconstruct their own argument from nothing is
how a staleness mechanism gets switched off.

**Merges are shown with their basis and their titles.** A merge is a claim this tool makes, and
the titles are how a reviewer catches a bad one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from docket.baseline import State
from docket.questions import Answer

if TYPE_CHECKING:
    from docket.triage import TriageItem, TriageResult

__all__ = ["render_summary", "render_terminal"]


def _locator_line(item: TriageItem) -> str:
    sites = item.identity.sites
    if sites:
        return ", ".join(f"`{site}`" for site in sites)
    return "_no position resolved_"


def _questions_line(item: TriageItem) -> str:
    """How many of the five questions were settled, and how many candidates came out."""
    findings = item.primary.findings
    if not findings:
        return "not assessed"
    settled = sum(1 for finding in findings if finding.answer is not Answer.NOT_ESTABLISHED)
    candidates = len(item.primary.candidates)
    label = f"{settled} of {len(findings)} questions settled"
    if candidates:
        return f"{label}, {candidates} candidate justification(s)"
    return f"{label}, no candidate justification"


def _item_block(item: TriageItem, *, index: int) -> list[str]:
    lines = [f"#### {index}. {item.title or '(untitled claim)'}", ""]
    lines.append(f"- **Where** {_locator_line(item)}")
    if item.identity.weakness:
        lines.append(f"- **Weakness** {item.identity.weakness}")
    lines.append(f"- **Evidence** {_questions_line(item)}")
    if item.merged_count > 1:
        lines.append(
            f"- **Merged** {item.merged_count} reports of this claim, on {item.identity.basis}"
        )
    if item.state.state is State.STALE and item.state.entry is not None:
        previous = item.state.entry
        lines.append(
            f"- **Was** `{previous.status}`"
            + (f" / `{previous.justification}`" if previous.justification else "")
            + f", decided by {previous.decided_by} on {previous.decided_at[:10]}"
        )
        lines.append(f"- **Their reason** {previous.reason}")
        lines.append(f"- **Why it is back** {item.state.detail}")
    lines.append("")
    return lines


def render_summary(result: TriageResult, *, title: str = "docket") -> str:
    """The Markdown summary: a pull-request comment, or a CI job summary."""
    counts = (
        f"{len(result.new)} new, {len(result.stale)} stale, "
        f"{len(result.carried)} carried, from {result.claims_in} claims"
    )
    lines = [
        f"## {title}",
        "",
        f"**{counts}.** {len(result.merges)} merge(s). "
        f"Commit `{result.commit[:12]}`. Nothing here is decided by this tool.",
        "",
    ]

    if result.stale:
        lines += [
            f"### Decisions that went stale ({len(result.stale)})",
            "",
            "The code these were decided against has changed, so they are back in the queue.",
            "",
        ]
        for index, item in enumerate(result.stale, start=1):
            lines += _item_block(item, index=index)

    if result.new:
        lines += [f"### New ({len(result.new)})", "", "Nobody has decided these.", ""]
        for index, item in enumerate(result.new, start=1):
            lines += _item_block(item, index=index)

    if result.carried:
        lines += [
            "<details>",
            f"<summary>Carried, no action needed ({len(result.carried)})</summary>",
            "",
            "| Claim | Status | Decided by | When |",
            "| --- | --- | --- | --- |",
        ]
        for item in result.carried:
            entry = item.state.entry
            status = entry.status if entry else "-"
            who = entry.decided_by if entry else "-"
            when = entry.decided_at[:10] if entry else "-"
            lines.append(f"| {item.title or '(untitled)'} | `{status}` | {who} | {when} |")
        lines += ["", "</details>", ""]

    if result.merges:
        lines += [
            "<details>",
            f"<summary>Merges ({len(result.merges)})</summary>",
            "",
            "Each group is claims this tool judged to be one. Reject a merge by deciding its "
            "members separately.",
            "",
        ]
        for merge in result.merges:
            lines.append(f"- **{merge.size} claims** on {merge.identity.basis}")
            for claim_title in merge.titles:
                lines.append(f"  - {claim_title}")
        lines += ["", "</details>", ""]

    if result.related:
        lines += [
            "<details>",
            f"<summary>Same site, different weakness label ({len(result.related)})</summary>",
            "",
            "Not merged. Equating two CWE identifiers is a taxonomy judgement this tool has no "
            "basis to make, so the groups are shown together and the call is yours.",
            "",
        ]
        for group in result.related:
            lines.append(f"- `{group.anchor}` — {', '.join(group.weaknesses)}")
            for related_title in group.titles:
                lines.append(f"  - {related_title}")
        lines += ["", "</details>", ""]

    if not result.needs_a_person:
        lines += ["Nothing needs a person on this run.", ""]

    return "\n".join(lines)


def render_terminal(result: TriageResult) -> str:
    """The same information, for somebody running the command by hand."""
    lines = [
        f"{result.claims_in} claims -> {len(result.items)} after merging "
        f"({len(result.merges)} merges)",
        f"  new     {len(result.new)}",
        f"  stale   {len(result.stale)}",
        f"  carried {len(result.carried)}",
        "",
    ]
    for item in result.needs_a_person:
        marker = "STALE" if item.state.state is State.STALE else "NEW  "
        where = ", ".join(item.identity.sites) or "(no position resolved)"
        lines.append(f"{marker} {item.title or '(untitled)'}")
        lines.append(f"      {where}")
        if item.state.state is State.STALE:
            lines.append(
                f"      was {item.state.entry.status if item.state.entry else '?'}: "
                f"{item.state.detail}"
            )
    if not result.needs_a_person:
        lines.append("nothing needs a person on this run")
    return "\n".join(lines) + "\n"
