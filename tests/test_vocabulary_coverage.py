"""Every value this tool can say must be one some committed example makes it say.

Ported from the sibling attestation project, which was the only one of the five repositories an
audit for unfailable checks found nothing in -- and the only one already testing for the class.
Its evaluation refuses to pass unless every verdict in its vocabulary was produced by at least one
scenario, scored from what the tool emitted rather than from the strings a registry declares. The
comment beside it names the failure: a verification tool that has only ever returned `verified` has
not been tested.

The distinction is the whole point and it is easy to lose. A test that checks a vocabulary is
*declared* cannot fail, because the declaration is the thing being read. A test that checks each
member was *reached by a run* fails the moment a value stops being producible, which is what
happened three times in this repository in its first three days.

**Members are harvested, never named.** Nothing below writes `Resolution.PATH_ABSENT` and calls it
covered. The committed examples are read, and the public functions are run over the committed
example target, and whatever comes back is what counts. Naming a member here would reintroduce
exactly the check that cannot fail.

**A member nothing reaches must be listed with its reason**, in `UNREACHED` below, and the list is
part of the test rather than a comment beside it. The precedent is the sibling model-lineage
project's `SignatureState.VALID`: unreachable, correct, and correct *because* reachability would
have made the tool claim something detection cannot establish -- that a signature verifies, that it
covers the files served today, and that the identity it binds is the publisher's. That entry is a
recorded decision. An unreached member with no entry here is an oversight, and this test is the
difference between the two.

The two reasons are kept apart on purpose. `deliberate` is a value the design refuses to produce.
`unstaged` is a value the code produces in conditions this corpus cannot create for free -- a
provider returning 401, a socket failing. The second is debt and reads as debt; collapsing them
into one list would let a real gap hide behind a principle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest

from docket.baseline import SpanState, State, load_baseline, state_of
from docket.disposition import Status, record_from_dict
from docket.identity import ClaimIdentity, IdentityKind, identity_for
from docket.questions import Answer, Question
from docket.reachability import Reachability, build_call_graph, reachability_of
from docket.resolve import Resolution, resolve_locator
from docket.verdict import Verdict
from docket.vex import JUSTIFICATIONS, STATUS_MAP

EVAL: Final = Path(__file__).resolve().parent.parent / "docs" / "eval"
WORKED: Final = EVAL / "worked-example"
LOOP: Final = EVAL / "loop-example"


@dataclass(frozen=True, slots=True)
class Unreached:
    """One member no committed example produces, and why that is acceptable."""

    reason_kind: str
    """`deliberate` -- the design refuses to produce it. `unstaged` -- producible, not staged."""

    why: str


# Read by the test. Adding a member here is a decision a reader can see and disagree with; the
# alternative is an unreached value nobody notices, which is the defect this file exists to catch.
UNREACHED: Final[dict[str, Unreached]] = {
    "SpanState.ABSENT": Unreached(
        "unstaged",
        "Producible by deleting a cited file between decision and re-run. The loop example "
        "edits a file rather than deleting one, so it reaches `changed`; staging a deletion "
        "would need a fourth run whose only content is a removal.",
    ),
    "IdentityKind.OPAQUE": Unreached(
        "deliberate",
        "Reached only when a claim yields no resolved position, no CWE and no usable title, "
        "which is a claim carrying no content at all. `identity.py` falls back to the claim's "
        "own identifier so it merges with nothing. Producing one would mean committing a "
        "finding with nothing in it.",
    ),
    "FailureReason.TRANSIENT_PROVIDER_FAILURE": Unreached(
        "unstaged", "Needs a provider returning 5xx. No network in this corpus."
    ),
    "FailureReason.TIMEOUT": Unreached(
        "unstaged",
        "Needs a provider that accepts a request and does not answer. Reached in the Phase 1 "
        "measurement -- 21 of 177 calls -- and published as `not_established` there.",
    ),
    "FailureReason.CONNECTION_FAILURE": Unreached(
        "unstaged", "Needs a socket failure. No network in this corpus."
    ),
    "FailureReason.INVALID_REQUEST": Unreached(
        "unstaged", "Needs a provider returning 4xx on a malformed request. No network."
    ),
    "FailureReason.AUTHENTICATION_FAILURE": Unreached(
        "unstaged", "Needs a provider returning 401. No network, and no key by design."
    ),
    "FailureReason.SCHEMA_VALIDATION_FAILURE": Unreached(
        "unstaged",
        "Producible from a model returning a shape the schema refuses, staged with a stub in "
        "`test_assess.py`. Not committed as an example: a recording of a bad response is a "
        "recording of one provider's bad day.",
    ),
}


def _members(enum: type[StrEnum]) -> dict[str, str]:
    """`Class.MEMBER` -> the string it serialises as."""
    return {f"{enum.__name__}.{m.name}": m.value for m in enum}


def _strings_in(payload: object) -> set[str]:
    """Every string anywhere in a decoded JSON structure, at any depth."""
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, str):
            found.add(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                found.add(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return found


def _json_strings(path: Path) -> set[str]:
    """Every string anywhere in a JSON or JSONL document, at any depth."""
    found: set[str] = set()

    def walk(node: object) -> None:
        found.update(_strings_in(node))

    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                walk(json.loads(line))
    else:
        walk(json.loads(text))
    return found


def _harvest_committed() -> set[str]:
    """Every string in every committed example. What the tool has already been made to say."""
    found: set[str] = set()
    for path in sorted(EVAL.rglob("*.json")):
        found |= _json_strings(path)
    for path in sorted(EVAL.rglob("*.jsonl")):
        found |= _json_strings(path)
    return found


def _harvest_from_running() -> set[str]:
    """What the public functions emit when run over the committed example targets.

    Committed documents are one source and a narrow one: they hold the values a finished run
    wrote down, not the values the code reaches on the way. So the resolver, the call graph, the
    identity function and the baseline are each run here against the example target, and whatever
    they return is recorded. Nothing is constructed by name.
    """
    found: set[str] = set()
    target = WORKED / "target"

    # The resolver, over locators the example target does and does not satisfy.
    for locator in (
        "deploy_notifier/main.py:31",
        "deploy_notifier/main.py:1-5",
        "deploy_notifier/does_not_exist.py:1",
        "deploy_notifier/main.py:99999",
        "../../etc/passwd",
        "not:a:locator:at:all",
        "",
    ):
        found.add(resolve_locator(locator, target).resolution.value)

    # The call graph, over every function the example target defines, plus a line that is inside
    # no function. Asking about every function rather than a chosen few is the point: a verdict
    # that stops being produced by any of eighteen real functions is a verdict worth losing.
    graph = build_call_graph(target)
    for site in graph.functions:
        found.add(reachability_of(graph, site.path, site.start_line + 1).verdict.value)
    found.add(reachability_of(graph, "deploy_notifier/__init__.py", 1).verdict.value)

    # Identity, over a committed record and the degraded forms of it. The claim's own fields are
    # emptied one at a time, which is what a producer that cites less would have emitted.
    payload = json.loads((WORKED / "record.json").read_text(encoding="utf-8"))
    record_payload = payload[0] if isinstance(payload, list) else payload
    found.add(identity_for(record_from_dict(record_payload), graph).kind.value)
    without_weakness = json.loads(json.dumps(record_payload))
    without_weakness["claim"]["weakness"] = None
    found.add(identity_for(record_from_dict(without_weakness), graph).kind.value)
    without_sites = json.loads(json.dumps(without_weakness))
    without_sites["claim"]["locators_claimed"] = []
    without_sites["resolutions"] = []
    found.add(identity_for(record_from_dict(without_sites), graph).kind.value)

    # The VEX emitter, over a committed record carried to each status it maps. The statuses come
    # from the committed decisions; what is exercised here is the emission, which no committed
    # document holds for two of the three because the worked example reached only one of them.
    from dataclasses import replace

    from docket.disposition import Disposition
    from docket.vex import vex_document

    base = record_from_dict(record_payload)
    for status, justification in (
        (Status.EXPLOITABLE, None),
        (Status.NOT_EXPLOITABLE, JUSTIFICATIONS[0]),
        (Status.UNDETERMINED, None),
    ):
        decided = Disposition(
            status=status,
            reason="carried to this status so the emitter is exercised for it",
            decided_by="the vocabulary-coverage test",
            justification=justification,
        )
        emitted = vex_document(
            [replace(base, disposition=decided)],
            product_id="test",
            author="the vocabulary-coverage test",
            document_id="https://example.invalid/coverage",
        )
        found |= _strings_in(emitted)

    # The replay seam asked for a request no recording holds. Free, and the one failure reason
    # that does not need a provider.
    from docket.model import ModelRequest, ReplayModel

    failure = ReplayModel(entries={}).generate(
        ModelRequest(
            system="application-owned",
            user="a request no recording holds",
            schema_name="probe",
            schema={"type": "object"},
        )
    )
    reason = getattr(failure, "reason", None)
    if reason is not None:
        found.add(reason.value)

    # The baseline, over the loop example's own target. Every committed entry is re-evaluated
    # against the code as it stands, plus one identity the baseline does not hold, so `new` is
    # reached by asking rather than by being written down.
    baseline = load_baseline(LOOP / "baseline.json")
    loop_target = LOOP / "target"
    loop_graph = build_call_graph(loop_target)
    keys = [*baseline.entries.keys(), "an-identity-no-decision-covers"]
    for key in keys:
        finding = state_of(
            ClaimIdentity(key=key, kind=IdentityKind.SITE),
            baseline,
            repo=loop_target,
            graph=loop_graph,
        )
        found.add(finding.state.value)
        for _locator, span_state in finding.span_states:
            found.add(span_state.value)
    return found


VOCABULARIES: Final[tuple[type[StrEnum], ...]] = (
    Status,
    Verdict,
    Resolution,
    State,
    SpanState,
    Question,
    Answer,
    Reachability,
    IdentityKind,
)


def _all_members() -> dict[str, str]:
    """Every vocabulary member this tool can emit, keyed `Class.MEMBER`."""
    members: dict[str, str] = {}
    for enum in VOCABULARIES:
        members |= _members(enum)
    # `FailureReason` is imported late so a module-level import does not pull the seam into a
    # test that otherwise never touches it.
    from docket.model import FailureReason

    members |= _members(FailureReason)
    members |= {f"JUSTIFICATIONS.{value}": value for value in JUSTIFICATIONS}
    members |= {f"VEX.{status.name}": label for status, label in STATUS_MAP.items()}
    return members


@pytest.fixture(scope="module")
def produced() -> set[str]:
    return _harvest_committed() | _harvest_from_running()


def test_every_vocabulary_member_is_produced_or_recorded_as_unreached(produced):
    """The coverage check. A member nothing produces must have a reason on this page.

    This is the test the audit of 2026-09-14 concluded was the actual remedy. The detector it
    also produced found one real defect in seven candidates and would not have caught any of the
    three that prompted the sweep, because in all three every member was assigned and every
    branch was reachable. This one fails the moment a value stops being producible.
    """
    unreached = sorted(key for key, value in _all_members().items() if value not in produced)
    undocumented = [key for key in unreached if key not in UNREACHED]
    assert undocumented == [], (
        "no committed example makes the tool say these, and nothing records why: "
        f"{undocumented}. Either stage one, or add an entry to UNREACHED saying whether the "
        "design refuses to produce it or the corpus cannot stage it."
    )


def test_the_unreached_list_holds_nothing_that_is_reached(produced):
    """The other direction. An entry that stops being true is a stale excuse.

    Without this, `UNREACHED` only ever grows, and a member that becomes producible keeps its
    exemption forever -- which is how an allow-list turns into the thing it was guarding against.
    """
    members = _all_members()
    stale = sorted(key for key in UNREACHED if key in members and members[key] in produced)
    assert stale == [], (
        f"these are produced by a committed example and no longer need an exemption: {stale}"
    )


def test_every_unreached_entry_names_a_member_that_exists(produced):
    """A typo in the allow-list would silently exempt nothing and hide a real gap."""
    unknown = sorted(key for key in UNREACHED if key not in _all_members())
    assert unknown == [], f"UNREACHED names members that do not exist: {unknown}"


def test_every_unreached_reason_is_one_of_the_two_kinds():
    """`deliberate` and `unstaged` are different facts and the list must keep them apart."""
    wrong = sorted(
        key
        for key, entry in UNREACHED.items()
        if entry.reason_kind not in {"deliberate", "unstaged"}
    )
    assert wrong == [], f"reason_kind must be `deliberate` or `unstaged`: {wrong}"
    for key, entry in UNREACHED.items():
        assert len(entry.why.strip()) > 40, f"{key}: a one-word reason is not a reason"


def test_the_vocabulary_list_covers_every_enum_in_the_package():
    """The list above is a list, so it goes stale. A new vocabulary joins it or fails here."""
    import importlib
    import pkgutil

    import docket

    declared = {enum.__name__ for enum in VOCABULARIES} | {"FailureReason"}
    found: set[str] = set()
    for info in pkgutil.iter_modules(docket.__path__):
        module = importlib.import_module(f"docket.{info.name}")
        for name in dir(module):
            value = getattr(module, name)
            if (
                isinstance(value, type)
                and issubclass(value, StrEnum)
                and value is not StrEnum
                and value.__module__.startswith("docket.")
            ):
                found.add(value.__name__)
    missing = sorted(found - declared)
    assert missing == [], (
        f"these vocabularies are not covered by the coverage test: {missing}. Add them to "
        "VOCABULARIES so their members have to be produced by something."
    )
