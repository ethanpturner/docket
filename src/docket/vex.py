"""Emitting the disposition as OpenVEX, so a scanner can act on it.

The reason this file exists is the reason the whole tool has a chance: OpenVEX already has a
three-valued vocabulary with `under_investigation` as a first-class state, and tools like Grype
already consume VEX documents as a filter. A disposition that ships as VEX is not a new artifact
anyone has to learn. It is a field that already exists in a format already read, which everybody
currently leaves blank.

The mapping is exact and there is nothing to invent:

| docket | OpenVEX |
|---|---|
| `exploitable` | `affected` |
| `not_exploitable` | `not_affected`, with a `justification` or an `impact_statement` |
| `undetermined` | `under_investigation` |

**`not_affected` carries a justification because the spec requires one.** OpenVEX mandates either a
`justification` from a fixed five-label catalog or a free-form `impact_statement` for any
`not_affected` statement. That requirement is the same discipline this tool applies anyway: a
dismissal states its argument.

**A statement needs a vulnerability identifier, and most claims do not have one.** VEX is built
around CVEs. An agentic reviewer's finding has a rule identifier and a CWE, not a CVE, so the
`vulnerability.name` falls back to the claim's own identifier and the CWE travels in
`description`. That is an honest use of the field -- the claim is the thing being dispositioned --
and it is recorded here rather than left for a reader to work out.
"""

from __future__ import annotations

from typing import Any, Final

from docket.disposition import DispositionRecord, Status

__all__ = ["CONTEXT", "JUSTIFICATIONS", "STATUS_MAP", "vex_document"]

CONTEXT: Final = "https://openvex.dev/ns/v0.2.0"

# The spec's four status labels; docket produces three of them. `fixed` is not a disposition this
# tool reaches, because a fix is a change to the product rather than a judgement about a claim.
STATUS_MAP: Final[dict[Status, str]] = {
    Status.EXPLOITABLE: "affected",
    Status.NOT_EXPLOITABLE: "not_affected",
    Status.UNDETERMINED: "under_investigation",
}

# The five labels a `not_affected` statement may use, from the VEX Working Group's catalog. Listed
# here so a later phase picks from the fixed set rather than writing prose into the field.
JUSTIFICATIONS: Final = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)


def _statement(record: DispositionRecord, product_id: str) -> dict[str, Any]:
    """One VEX statement for one disposition.

    `timestamp` is set on the statement as well as the document. The spec allows it to cascade
    from the document, and setting it explicitly means a statement lifted out of this document
    into another still says when it was true.
    """
    vulnerability: dict[str, Any] = {"name": record.claim.claim_id}
    description = record.claim.title.strip()
    if record.claim.weakness:
        prefix = record.claim.weakness
        description = f"{prefix}: {description}" if description else prefix
    if description:
        vulnerability["description"] = description

    statement: dict[str, Any] = {
        "vulnerability": vulnerability,
        "products": [{"@id": product_id}],
        "status": STATUS_MAP[record.disposition.status],
        "timestamp": record.recorded_at.isoformat(),
    }

    if record.disposition.status is Status.NOT_EXPLOITABLE:
        # The spec requires one of the two. The reviewer's selected label goes in `justification`,
        # the machine-readable half and the only part a consumer can act on; their words go in
        # `impact_statement` beside it, which the spec permits and its own example does. A
        # dismissal carrying neither cannot be constructed -- `Disposition` and `Decision` both
        # refuse it -- so the guard below is the third place this rule holds rather than the first,
        # and it exists because emitting invalid VEX is the one failure a consumer inherits.
        if record.disposition.justification is not None:
            statement["justification"] = record.disposition.justification
        impact = (record.disposition.impact_statement or record.disposition.reason).strip()
        if impact:
            statement["impact_statement"] = impact
        if "justification" not in statement and "impact_statement" not in statement:
            raise ValueError(
                f"claim {record.claim.claim_id}: a not_affected statement needs a justification "
                f"or an impact statement, and this has neither"
            )
        if record.disposition.override_reason:
            # Not a spec field. A consumer ignores it; a human reading the document sees that the
            # label was selected against the assessment rather than from it, which is the one fact
            # a bare justification loses.
            statement["docket_override_reason"] = record.disposition.override_reason
    elif record.disposition.status is Status.EXPLOITABLE:
        statement["action_statement"] = record.disposition.reason

    return statement


def vex_document(
    records: list[DispositionRecord],
    *,
    author: str,
    document_id: str,
    product_id: str,
    version: int = 1,
) -> dict[str, Any]:
    """An OpenVEX document carrying one statement per record.

    Required document fields per the spec: `@context`, `@id`, `author`, `timestamp`, `version`,
    `statements`. The document timestamp is the newest record's, so re-issuing after new work
    moves it forward as the spec's sequencing model expects.
    """
    if not records:
        raise ValueError("a VEX document needs at least one statement")
    timestamp = max(record.recorded_at for record in records)
    return {
        "@context": CONTEXT,
        "@id": document_id,
        "author": author,
        "timestamp": timestamp.isoformat(),
        "version": version,
        "tooling": f"docket/{records[0].docket_version}",
        "statements": [_statement(record, product_id) for record in records],
    }
