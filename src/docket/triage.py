"""The queue: many claims, merged by content, checked against what was already decided.

`record` and `assess` handle one finding file and print one record per claim. That is the right
shape for understanding the tool and the wrong shape for using it. A real queue arrives as a SARIF
file with forty results, most of which are the same three weaknesses reported at different
positions, and most of which somebody already dismissed last week.

Triage is the loop that makes that tractable, and it is three things the earlier phases are not:

- **merged**, by content identity rather than by the producer's own label (`identity.py`);
- **compared against a baseline**, so a decided claim does not come back until the code it was
  about changes (`baseline.py`);
- **concurrent**, because the gathering calls are independent and a queue of forty claims run
  sequentially is a queue nobody waits for.

**Nothing here decides anything.** `DEC-002` holds through the queue exactly as it holds through
`assess`: a claim with no prior decision comes out `undetermined` and goes in front of a person.
What the queue adds is that the person sees six groups instead of forty rows, and that the ones
they already ruled on are marked as such with the reason they gave.

**Exit code zero by default, whatever it finds.** A tool that arrives blocking a pipeline is
uninstalled before anybody reads its output, so gating is opt-in and per-condition: `--fail-on-new`
for a queue that must stay empty, `--fail-on-stale` for a repository where a dismissal going stale
is the event worth interrupting for, `--fail-on-status` for a claim somebody has already called
exploitable. Each names a thing the team agreed to care about, rather than the tool deciding that
its own output is important.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from docket.assess import assess_record
from docket.baseline import Baseline, State, StateFinding, state_of
from docket.disposition import Status
from docket.identity import (
    ClaimIdentity,
    Merge,
    Related,
    group_by_identity,
    identity_for,
    related_groups,
)
from docket.reachability import build_call_graph

if TYPE_CHECKING:
    from pathlib import Path

    from docket.disposition import DispositionRecord
    from docket.evidence import EvidenceRecord
    from docket.model import StructuredModel
    from docket.reachability import CallGraph

__all__ = ["TriageItem", "TriageResult", "triage"]

DEFAULT_WORKERS = 4


@dataclass(frozen=True, slots=True)
class TriageItem:
    """One merged claim in the queue, with its baseline state."""

    identity: ClaimIdentity
    records: tuple[EvidenceRecord, ...]
    """Every claim that merged into this item, in the order the queue received them."""

    state: StateFinding

    @property
    def primary(self) -> EvidenceRecord:
        """The record shown to a reviewer: the first one received."""
        return self.records[0]

    @property
    def title(self) -> str:
        return self.primary.disposition.claim.title

    @property
    def merged_count(self) -> int:
        return len(self.records)

    @property
    def status(self) -> str:
        """The carried decision's status, or `undetermined` where none carries.

        A stale decision's status is deliberately not reported here. It did not carry, so the
        claim's status today is `undetermined`, and showing the old one as current would be the
        silent reapplication this phase exists to prevent.
        """
        if self.state.state is State.CARRIED and self.state.entry is not None:
            return self.state.entry.status
        return Status.UNDETERMINED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "title": self.title,
            "status": self.status,
            "baseline": self.state.to_dict(),
            "merged_claim_ids": [item.disposition.claim.claim_id for item in self.records],
            "merged_count": self.merged_count,
            "record": self.primary.to_dict(),
        }


@dataclass(slots=True)
class TriageResult:
    """One pass of the queue."""

    items: list[TriageItem] = field(default_factory=list)
    merges: list[Merge] = field(default_factory=list)
    related: list[Related] = field(default_factory=list)
    """Groups at one site that were not merged because their weakness labels differ."""
    claims_in: int = 0
    model_calls: int = 0
    duration_seconds: float = 0.0
    repository: str = ""
    commit: str = ""

    def by_state(self, state: State) -> list[TriageItem]:
        return [item for item in self.items if item.state.state is state]

    @property
    def new(self) -> list[TriageItem]:
        return self.by_state(State.NEW)

    @property
    def carried(self) -> list[TriageItem]:
        return self.by_state(State.CARRIED)

    @property
    def stale(self) -> list[TriageItem]:
        return self.by_state(State.STALE)

    @property
    def needs_a_person(self) -> list[TriageItem]:
        """The queue a reviewer actually works: new claims and decisions that went stale."""
        return [item for item in self.items if item.state.state is not State.CARRIED]

    def with_status(self, status: str) -> list[TriageItem]:
        return [item for item in self.items if item.status == status]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {"repository": self.repository, "commit": self.commit},
            "summary": {
                "claims_in": self.claims_in,
                "items": len(self.items),
                "merges": len(self.merges),
                "related_sites": len(self.related),
                "new": len(self.new),
                "carried": len(self.carried),
                "stale": len(self.stale),
                "model_calls": self.model_calls,
                "duration_seconds": round(self.duration_seconds, 3),
            },
            "merges": [merge.to_dict() for merge in self.merges],
            "related": [item.to_dict() for item in self.related],
            "items": [item.to_dict() for item in self.items],
        }


def _assess_all(
    records: list[DispositionRecord],
    *,
    repo: Path,
    graph: CallGraph,
    model: StructuredModel | None,
    workers: int,
) -> list[EvidenceRecord]:
    """Assess every record, concurrently when a model is configured.

    The deterministic path is fast and sequential; there is nothing to overlap. With a model, the
    three gathering calls per claim are independent of every other claim's, so the queue is run on
    a small thread pool. The recording wrapper takes a lock around its append, so a concurrent run
    and a sequential one produce the same recording file modulo ordering.
    """
    if model is None or workers <= 1:
        return [assess_record(item, repo=repo, graph=graph, model=model) for item in records]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(
            pool.map(
                lambda item: assess_record(item, repo=repo, graph=graph, model=model),
                records,
            )
        )


def triage(
    records: list[DispositionRecord],
    *,
    repo: Path,
    baseline: Baseline | None = None,
    model: StructuredModel | None = None,
    workers: int = DEFAULT_WORKERS,
    graph: CallGraph | None = None,
) -> TriageResult:
    """Merge, assess and compare one queue of claims against the baseline.

    The call graph is built once and used three times -- for the reachability question, for the
    symbol half of the identity, and for the moved-versus-changed distinction in the baseline --
    which is why it is threaded through rather than rebuilt per claim.
    """
    started = time.monotonic()
    baseline = baseline if baseline is not None else Baseline()
    graph = graph if graph is not None else build_call_graph(repo)

    groups, merges = group_by_identity(records, graph)

    # One representative per group is assessed. The others are merged into it, and a reviewer
    # deciding the group decides all of them; assessing each member separately would spend a
    # model call to answer the same five questions about the same code.
    representatives = [members[0] for members in groups.values()]
    assessed = _assess_all(representatives, repo=repo, graph=graph, model=model, workers=workers)
    by_claim = {item.disposition.claim.claim_id: item for item in assessed}

    items: list[TriageItem] = []
    for members in groups.values():
        identity = identity_for(members[0], graph)
        primary = by_claim[members[0].claim.claim_id]
        others = tuple(by_claim.get(item.claim.claim_id) or _bare(item) for item in members[1:])
        items.append(
            TriageItem(
                identity=identity,
                records=(primary, *others),
                state=state_of(identity, baseline, repo=repo, graph=graph),
            )
        )

    return TriageResult(
        items=items,
        merges=merges,
        related=related_groups(groups, graph),
        claims_in=len(records),
        model_calls=sum(item.model_calls for item in assessed),
        duration_seconds=time.monotonic() - started,
        repository=records[0].repository if records else str(repo),
        commit=records[0].commit if records else "",
    )


def _bare(record: DispositionRecord) -> EvidenceRecord:
    """A merged-away claim as an evidence record with no questions answered.

    Members other than the representative are not assessed, so they carry no findings. They are
    still kept in full, because a reviewer rejecting a merge needs the claim that was folded in.
    """
    from docket.evidence import EvidenceRecord

    return EvidenceRecord(disposition=record, findings=(), candidates=())
