"""A decision carries forward until the code it was about changes, and then it does not.

Every suppression mechanism in this category suppresses forever. A finding is marked a false
positive, its fingerprint goes in a file, and the tool never mentions it again -- including after
somebody rewrites the function the dismissal was reasoning about. The dismissal outlives its
argument, silently, and the file that was supposed to reduce noise becomes the place where a real
weakness goes to be ignored.

The material for a better rule is already here. A decision is bound to the bytes at the positions
it cites (`DEC-011`), so the question "is this decision still about the code it was made about" is
a digest comparison, not a judgement. So:

- **carried** -- the decision stands, because every span it rests on reads the same today;
- **stale** -- a span changed or stopped resolving, so the claim returns to the queue and the
  decision is not applied;
- **new** -- no decision exists for this identity.

**A stale decision is never silently reapplied, and never silently discarded.** It is shown with
its previous status, its previous reason, and what changed, because the reviewer re-deciding is
usually going to reach the same conclusion and deserves to start from their own earlier work
rather than from nothing.

**Moving is distinguished from changing.** A span digest differs when somebody inserts a line
above the cited position, which is not a change to the thing the decision was about. So a baseline
entry records the enclosing function's own digest beside the span's: when the span moved and the
function is byte-identical, the decision is `carried` with a note rather than invalidated. Without
that, a formatting pass would re-open every dismissal in the file and the mechanism would be
turned off within a week, which is the failure this whole phase is designed around.

**Staleness is conservative in the remaining cases.** Where no enclosing function is known -- a
locator citing a whole file, a language the call graph does not parse -- a moved span reads as a
changed one. That errs toward asking a person again, which is the direction this tool errs in
everywhere else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from docket.hashing import hash_text
from docket.identity import ClaimIdentity, IdentityKind
from docket.resolve import Resolution, resolve_locator

if TYPE_CHECKING:
    from pathlib import Path

    from docket.decision import Decision
    from docket.disposition import DispositionRecord
    from docket.reachability import CallGraph

__all__ = [
    "FORMAT",
    "Baseline",
    "BaselineEntry",
    "SpanAnchor",
    "SpanState",
    "State",
    "StateFinding",
    "anchors_for",
    "entry_for",
    "load_baseline",
    "save_baseline",
    "state_of",
]

FORMAT: Final = "docket/baseline/v1"

NOTE: Final = (
    "Each entry is a decision and the bytes it was made against. A decision is carried only while "
    "those bytes still read the same; when they change the claim returns to the queue as `stale` "
    "and this file does not suppress it. Deleting an entry re-opens its claim."
)


class State(StrEnum):
    """What the baseline says about a claim on this run."""

    NEW = "new"
    """No decision exists for this identity."""

    CARRIED = "carried"
    """A decision exists and the code it rests on has not changed."""

    STALE = "stale"
    """A decision exists and the code it rests on has changed. It is not applied."""


class SpanState(StrEnum):
    """What happened to one anchored span since the decision was made."""

    UNCHANGED = "unchanged"
    MOVED = "moved"
    """The cited bytes differ, and the enclosing function is byte-identical: the code moved."""

    CHANGED = "changed"
    ABSENT = "absent"
    """The locator no longer resolves at all."""


@dataclass(frozen=True, slots=True)
class SpanAnchor:
    """One cited position, and the two digests that say whether it still means what it meant."""

    locator: str
    path: str
    sha256: str
    """The digest of the quoted span at decision time."""

    symbol: str | None = None
    symbol_sha256: str | None = None
    """The digest of the enclosing function's whole body at decision time, when one was found.

    Present so that a line shift above the citation reads as a move rather than a change. Absent
    for a locator with no enclosing function, and then a moved span is treated as a changed one.
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "locator": self.locator,
            "path": self.path,
            "sha256": self.sha256,
            "symbol": self.symbol,
            "symbol_sha256": self.symbol_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SpanAnchor:
        return cls(
            locator=str(data["locator"]),
            path=str(data.get("path") or ""),
            sha256=str(data["sha256"]),
            symbol=data.get("symbol"),
            symbol_sha256=data.get("symbol_sha256"),
        )


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One decided claim, keyed by content identity rather than by the tool's own label."""

    identity_key: str
    identity_kind: IdentityKind
    identity_basis: str
    status: str
    reason: str
    decided_by: str
    decided_at: str
    justification: str | None = None
    impact_statement: str | None = None
    override_reason: str | None = None
    title: str = ""
    """The title of one claim in the group, so the file is readable by a person."""

    commit: str = ""
    """The commit the decision was made against. Recorded, never used to re-check: the anchors
    below are what a later run compares, because a commit identifier says nothing about which
    parts of the tree moved."""

    anchors: tuple[SpanAnchor, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": {
                "key": self.identity_key,
                "kind": self.identity_kind.value,
                "basis": self.identity_basis,
            },
            "title": self.title,
            "status": self.status,
            "justification": self.justification,
            "impact_statement": self.impact_statement,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "override_reason": self.override_reason,
            "commit": self.commit,
            "anchors": [anchor.to_dict() for anchor in self.anchors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineEntry:
        identity = data.get("identity") or {}
        return cls(
            identity_key=str(identity.get("key") or ""),
            identity_kind=IdentityKind(identity.get("kind") or IdentityKind.OPAQUE.value),
            identity_basis=str(identity.get("basis") or ""),
            status=str(data["status"]),
            reason=str(data.get("reason") or ""),
            decided_by=str(data.get("decided_by") or ""),
            decided_at=str(data.get("decided_at") or ""),
            justification=data.get("justification"),
            impact_statement=data.get("impact_statement"),
            override_reason=data.get("override_reason"),
            title=str(data.get("title") or ""),
            commit=str(data.get("commit") or ""),
            anchors=tuple(SpanAnchor.from_dict(item) for item in data.get("anchors") or ()),
        )


@dataclass(slots=True)
class Baseline:
    """Decisions carried between runs, keyed by content identity."""

    entries: dict[str, BaselineEntry] = field(default_factory=dict)

    def get(self, identity_key: str) -> BaselineEntry | None:
        return self.entries.get(identity_key)

    def put(self, entry: BaselineEntry) -> None:
        self.entries[entry.identity_key] = entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "note": NOTE,
            "updated_at": datetime.now(UTC).isoformat(),
            "entries": [
                entry.to_dict() for entry in sorted(self.entries.values(), key=lambda e: e.title)
            ],
        }


@dataclass(frozen=True, slots=True)
class StateFinding:
    """What the baseline says about one claim, and why."""

    state: State
    entry: BaselineEntry | None = None
    span_states: tuple[tuple[str, SpanState], ...] = ()
    """Each anchor's locator and what happened to it."""

    detail: str = ""
    """A sentence naming what changed, for a stale entry. Empty for `new`."""

    @property
    def moved_only(self) -> bool:
        return bool(self.span_states) and any(
            state is SpanState.MOVED for _, state in self.span_states
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "detail": self.detail,
            "spans": [
                {"locator": locator, "state": state.value} for locator, state in self.span_states
            ],
            "previous": (
                None
                if self.entry is None
                else {
                    "status": self.entry.status,
                    "justification": self.entry.justification,
                    "reason": self.entry.reason,
                    "decided_by": self.entry.decided_by,
                    "decided_at": self.entry.decided_at,
                    "commit": self.entry.commit,
                }
            ),
        }


def _symbol_digest(
    path: str, line: int, repo: Path, graph: CallGraph | None
) -> tuple[str | None, str | None]:
    """The enclosing function's name and the digest of its whole body.

    Returns `(None, None)` when no function encloses the line, which makes a later move
    indistinguishable from a change -- the conservative reading, stated in the module docstring.
    """
    if graph is None:
        return None, None
    site = graph.enclosing(path, line)
    if site is None:
        return None, None
    try:
        lines = (repo / path).read_text(encoding="utf-8").splitlines()
    except OSError, UnicodeDecodeError:
        return site.name, None
    body = "\n".join(lines[site.start_line - 1 : site.end_line])
    return site.name, hash_text(body)


def anchors_for(
    record: DispositionRecord,
    *,
    repo: Path,
    graph: CallGraph | None = None,
) -> tuple[SpanAnchor, ...]:
    """The span anchors for one decided record.

    Only resolved locators with a quoted span are anchored. An unresolved locator has no bytes to
    compare, so anchoring it would put a check in the baseline that can only ever abstain.
    """
    out: list[SpanAnchor] = []
    for item in record.locators:
        if item.resolution is not Resolution.RESOLVES or item.content_hash is None:
            continue
        if not item.path:
            continue
        symbol, symbol_digest = (
            _symbol_digest(item.path, item.start_line, repo, graph)
            if item.start_line is not None
            else (None, None)
        )
        out.append(
            SpanAnchor(
                locator=item.locator,
                path=item.path,
                sha256=item.content_hash,
                symbol=symbol,
                symbol_sha256=symbol_digest,
            )
        )
    return tuple(out)


def _named_symbol_digest(path: str, name: str, repo: Path, graph: CallGraph | None) -> str | None:
    """The digest of the function called `name` in `path`, wherever it now sits.

    Looked up by name rather than by position, because position is the thing that moved. A
    citation of a handler's `def` line lands on the decorator above it after one line is inserted,
    and a positional lookup then finds no enclosing function and reports a rewrite that did not
    happen.
    """
    if graph is None:
        return None
    sites = [site for site in graph.functions if site.path == path and site.name == name]
    if len(sites) != 1:
        # Two definitions of one name in a file, or none. Either way this cannot answer the
        # question, and guessing would be the collapse the three-valued vocabulary exists for.
        return None
    site = sites[0]
    try:
        lines = (repo / path).read_text(encoding="utf-8").splitlines()
    except OSError, UnicodeDecodeError:
        return None
    return hash_text("\n".join(lines[site.start_line - 1 : site.end_line]))


def _span_state(anchor: SpanAnchor, *, repo: Path, graph: CallGraph | None) -> SpanState:
    """What happened to one anchored span since it was recorded.

    Both digests matter, and the cited line alone is the weaker of the two. A claim citing the
    `def` line of a handler is not a claim about that line; it is a claim about the handler. So a
    function whose body was rewritten around an untouched citation is `CHANGED`, even though the
    quoted bytes still match. Checking only the span would carry a dismissal across the rewrite
    that invalidated it, which is the exact failure this module exists to prevent.
    """
    again = resolve_locator(anchor.locator, repo)
    if again.resolution is not Resolution.RESOLVES or again.content_hash is None:
        return SpanState.ABSENT

    symbol_now: str | None = None
    if anchor.symbol is not None and anchor.symbol_sha256 is not None:
        symbol_now = _named_symbol_digest(anchor.path, anchor.symbol, repo, graph)

    if again.content_hash == anchor.sha256:
        # The cited bytes are the same. The enclosing function may still have been rewritten
        # around them, and that is a change to what the decision was about.
        if anchor.symbol_sha256 is not None and symbol_now != anchor.symbol_sha256:
            return SpanState.CHANGED
        return SpanState.UNCHANGED

    if symbol_now is not None and symbol_now == anchor.symbol_sha256:
        return SpanState.MOVED
    return SpanState.CHANGED


def state_of(
    identity: ClaimIdentity,
    baseline: Baseline,
    *,
    repo: Path,
    graph: CallGraph | None = None,
) -> StateFinding:
    """Whether this claim's decision carries, has gone stale, or does not exist.

    An entry with no anchors at all is `stale` rather than `carried`: a decision that recorded no
    bytes cannot be shown to still be about the same code, and carrying it forward would be the
    unfailable check this project keeps finding in other people's tools and its own.
    """
    entry = baseline.get(identity.key)
    if entry is None:
        return StateFinding(state=State.NEW)

    if not entry.anchors:
        return StateFinding(
            state=State.STALE,
            entry=entry,
            detail=(
                "the decision anchored no resolved positions, so nothing establishes that it is "
                "still about this code"
            ),
        )

    states = tuple(
        (anchor.locator, _span_state(anchor, repo=repo, graph=graph)) for anchor in entry.anchors
    )
    absent = [locator for locator, state in states if state is SpanState.ABSENT]
    changed = [locator for locator, state in states if state is SpanState.CHANGED]
    moved = [locator for locator, state in states if state is SpanState.MOVED]

    if absent or changed:
        parts: list[str] = []
        if changed:
            parts.append(f"the code at {', '.join(changed)} is not what the decision quotes")
        if absent:
            parts.append(f"{', '.join(absent)} no longer resolves")
        return StateFinding(
            state=State.STALE,
            entry=entry,
            span_states=states,
            detail="; ".join(parts),
        )

    detail = ""
    if moved:
        detail = (
            f"{', '.join(moved)} moved, and the enclosing function is byte-identical, so the "
            f"decision still stands"
        )
    return StateFinding(state=State.CARRIED, entry=entry, span_states=states, detail=detail)


def entry_for(
    identity: ClaimIdentity,
    decision: Decision,
    record: DispositionRecord,
    *,
    repo: Path,
    graph: CallGraph | None = None,
) -> BaselineEntry:
    """The baseline entry for one decided claim."""
    return BaselineEntry(
        identity_key=identity.key,
        identity_kind=identity.kind,
        identity_basis=identity.basis,
        status=decision.status.value,
        reason=decision.reason,
        decided_by=decision.decided_by,
        decided_at=(decision.decided_at or datetime.now(UTC)).isoformat(),
        justification=decision.justification,
        impact_statement=decision.impact_statement,
        override_reason=decision.override,
        title=record.claim.title,
        commit=record.commit,
        anchors=anchors_for(record, repo=repo, graph=graph),
    )


def save_baseline(baseline: Baseline, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline.to_dict(), indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(path: Path) -> Baseline:
    """Read a baseline file, refusing one that is not this format.

    An unrecognised file is an error rather than an empty baseline: silently starting from nothing
    would re-open every decided claim and look like the tool working.
    """
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != FORMAT:
        raise ValueError(f"{path} is not a docket baseline (expected format {FORMAT!r})")
    entries = [BaselineEntry.from_dict(item) for item in data.get("entries") or ()]
    return Baseline(entries={entry.identity_key: entry for entry in entries})
