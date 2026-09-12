"""Which claims are the same claim, derived from content rather than taken on trust.

A queue holding ten runs of one reviewer holds ten reports of the same weakness, and a triage
tool that shows all ten is a triage tool nobody opens twice. So the claims have to be merged, and
the only question is what merges them.

**Not the tool's own identifier.** Every agentic reviewer stamps its findings with a signature or
a fingerprint, and the obvious move is to group on it. Measured against ten runs of one reviewer
over two applications, that identifier repeated across runs exactly never: forty-one distinct
signatures over seventy-two emitted claims, pairwise Jaccard 0.00, while the underlying weakness
was the same one every time. An identifier that changes when the prose changes is an identifier of
the prose. Grouping on it produces a queue that grows linearly with how often you run the scanner.

**Not the line number either.** `main.py:29` and `main.py:34` are the same site after somebody
adds five lines at the top of the file. A line number is a position in a revision, and identity has
to survive a revision or the baseline it feeds is worthless.

So identity is built from three things that move more slowly than either:

- **the site**, as `path::symbol` where the enclosing function is known and `path` where it is not;
- **the weakness class**, normalised to its CWE identifier;
- **the topic**, a stopworded token set from the title, used only when the first two are missing.

**The title is not in the key, and that is a deliberate asymmetry.** Two runs describing one
weakness as "unbounded request buffering occurs before all payload limits" and "unbounded request
buffering enables pre-authentication memory exhaustion" are reporting the same thing in different
words, and keying on the words would refuse the merge that matters. The titles are all carried into
the merge record instead, because a reviewer needs to see what was folded together to be able to
say it was wrong. A merge is a claim this module makes, and every claim in this tool shows its
working.

**Merging is reported, never assumed.** Every group carries the basis it was formed on and the
strength of that basis, so a merge on a resolved symbol and a shared CWE reads differently from a
merge on two titles that happened to normalise to the same tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from docket.hashing import hash_text
from docket.resolve import Resolution

if TYPE_CHECKING:
    from collections.abc import Iterable

    from docket.disposition import DispositionRecord
    from docket.reachability import CallGraph

__all__ = [
    "ClaimIdentity",
    "IdentityKind",
    "Merge",
    "Related",
    "group_by_identity",
    "identity_for",
    "related_groups",
]

# Words that carry no discriminating signal in a finding title. Kept short on purpose: an
# aggressive stoplist merges claims that differ only in the word it removed.
_STOPWORDS: Final = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "before",
        "by",
        "can",
        "for",
        "from",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "through",
        "to",
        "via",
        "with",
        "without",
    }
)

_CWE: Final = re.compile(r"cwe[-_ ]?(\d{1,5})", re.IGNORECASE)
_WORD: Final = re.compile(r"[a-z0-9]+")


class IdentityKind(StrEnum):
    """What the identity was derived from, strongest first.

    Reported on every merge, because a group formed from a resolved symbol and a shared CWE is a
    different quality of evidence from a group formed from two titles.
    """

    SITE_AND_WEAKNESS = "site+weakness"
    """The strongest: at least one resolved position, and a CWE both claims name."""

    SITE = "site"
    """Resolved positions agree; no CWE was given, so the weakness class is unchecked."""

    TOPIC = "topic"
    """No position resolved. The title's token set is all there is, and it is weak."""

    OPAQUE = "opaque"
    """Nothing derivable. The claim keeps its own identifier and merges with nothing."""


@dataclass(frozen=True, slots=True)
class ClaimIdentity:
    """One claim's content-derived identity."""

    key: str
    """A digest over the anchor and the weakness. Stable across runs, tools, and line shifts."""

    kind: IdentityKind
    anchor: str | None = None
    """The single most specific site the claim cites, and the only site in the key.

    Two runs describing one weakness rarely cite the same *set* of positions -- one names the
    handler, the next names the handler and the module around it -- so keying on the set splits a
    claim from itself. The anchor is the innermost thing cited: a `path::symbol` in preference to
    a bare `path`, and the first in sorted order where several tie, because an arbitrary choice
    made the same way every time is still a stable key.
    """

    sites: tuple[str, ...] = ()
    """Every resolved position, sorted and deduplicated. Displayed, not keyed."""

    weakness: str | None = None
    """The normalised CWE identifier, or None when the claim named none."""

    topic: tuple[str, ...] = ()
    """The title's sorted token set. Carried for display and for `TOPIC` identities."""

    @property
    def basis(self) -> str:
        """What this identity was built from, in a sentence a reviewer can argue with."""
        if self.kind is IdentityKind.OPAQUE:
            return "no site, no weakness class, and no usable title: merged with nothing"
        if self.kind is IdentityKind.TOPIC:
            return f"title tokens {', '.join(self.topic)} (no position resolved, so this is weak)"
        if self.kind is IdentityKind.SITE:
            return f"site {self.anchor} (no weakness class given)"
        return f"site {self.anchor} and weakness {self.weakness}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind.value,
            "anchor": self.anchor,
            "sites": list(self.sites),
            "weakness": self.weakness,
            "topic": list(self.topic),
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class Merge:
    """Two or more claims judged to be one, and everything needed to reject that judgement."""

    identity: ClaimIdentity
    claim_ids: tuple[str, ...]
    titles: tuple[str, ...]
    """Every distinct title in the group, verbatim. The merge's own evidence: a reviewer reading
    two unrelated sentences here has found a bad merge."""

    tools: tuple[str, ...]
    weaknesses: tuple[str, ...]
    """Every distinct weakness string the members claimed, before normalisation. Two members
    naming CWE-306 and CWE-347 merged on a shared site is a fact worth seeing."""

    @property
    def size(self) -> int:
        return len(self.claim_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "size": self.size,
            "claim_ids": list(self.claim_ids),
            "titles": list(self.titles),
            "tools": list(self.tools),
            "weaknesses_claimed": list(self.weaknesses),
        }


def _normalise_weakness(value: str | None) -> str | None:
    """`CWE-306` from `cwe 306`, `CWE_306`, or `CWE-306: Missing Authentication`.

    A claim naming several is reduced to the sorted set, joined, so that two members naming the
    same pair agree and a member naming a superset does not.
    """
    if not value:
        return None
    found = sorted({int(match.group(1)) for match in _CWE.finditer(value)})
    if not found:
        return None
    return "+".join(f"CWE-{number}" for number in found)


def _tokens(title: str) -> tuple[str, ...]:
    """The title's discriminating words, lowercased, deduplicated and sorted."""
    words = {word for word in _WORD.findall(title.lower()) if word not in _STOPWORDS}
    return tuple(sorted(words))


def _sites(record: DispositionRecord, graph: CallGraph | None) -> tuple[str, ...]:
    """Every resolved position as `path::symbol`, or `path` where no symbol encloses it.

    Only resolved locators count. An unresolved one names a position in some other codebase, and
    letting it into the key would group claims by a typo.
    """
    out: set[str] = set()
    for item in record.locators:
        if item.resolution is not Resolution.RESOLVES or not item.path:
            continue
        site = item.path
        if graph is not None and item.start_line is not None:
            enclosing = graph.enclosing(item.path, item.start_line)
            if enclosing is not None:
                site = f"{item.path}::{enclosing.name}"
        out.add(site)
    return tuple(sorted(out))


def _anchor(sites: tuple[str, ...]) -> str | None:
    """The innermost cited position: a `path::symbol` over a bare `path`, ties broken by sort.

    Keying on one site rather than the set is what lets two reports of one weakness merge when
    they cite overlapping but unequal positions, which is the common case across runs.
    """
    if not sites:
        return None
    symbols = sorted(site for site in sites if "::" in site)
    return symbols[0] if symbols else sorted(sites)[0]


def identity_for(record: DispositionRecord, graph: CallGraph | None = None) -> ClaimIdentity:
    """This claim's content-derived identity.

    `graph` is optional so that the identity can be computed without parsing a repository; the
    result is then keyed on the file rather than the symbol, which is coarser and said to be.
    """
    sites = _sites(record, graph)
    anchor = _anchor(sites)
    weakness = _normalise_weakness(record.claim.weakness)
    topic = _tokens(record.claim.title or record.claim.raw_text[:200])

    material: tuple[str, ...]
    if anchor and weakness:
        kind = IdentityKind.SITE_AND_WEAKNESS
        material = ("site+weakness", anchor, weakness)
    elif anchor:
        kind = IdentityKind.SITE
        material = ("site", anchor)
    elif topic:
        kind = IdentityKind.TOPIC
        material = ("topic", *topic, weakness or "")
    else:
        kind = IdentityKind.OPAQUE
        material = ("opaque", record.claim.claim_id)

    return ClaimIdentity(
        key=hash_text("\n".join(material)),
        kind=kind,
        anchor=anchor,
        sites=sites,
        weakness=weakness,
        topic=topic,
    )


@dataclass(frozen=True, slots=True)
class Related:
    """Groups that sit at one site and were not merged, because their weakness labels differ.

    The case this exists for is real and common: one reviewer called a missing signature check
    `CWE-306` in two runs and `CWE-345` in two others, at the same function. Those are the same
    weakness under two labels, and merging them would mean this tool asserting an equivalence
    between two CWE identifiers -- a taxonomy judgement it has no basis to make and no way to
    check.

    So they stay separate and are reported adjacent. A reviewer looking at one site with three
    labels can see in one line what the merge would have been, and decide it themselves.
    """

    anchor: str
    weaknesses: tuple[str, ...]
    identity_keys: tuple[str, ...]
    titles: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor": self.anchor,
            "weaknesses": list(self.weaknesses),
            "identity_keys": list(self.identity_keys),
            "titles": list(self.titles),
        }


def related_groups(
    groups: dict[str, list[DispositionRecord]],
    graph: CallGraph | None = None,
) -> list[Related]:
    """Distinct groups sharing an anchor, which are candidates for a merge this tool will not make."""
    by_anchor: dict[str, list[tuple[str, ClaimIdentity, list[DispositionRecord]]]] = {}
    for key, members in groups.items():
        identity = identity_for(members[0], graph)
        if identity.anchor is None:
            continue
        by_anchor.setdefault(identity.anchor, []).append((key, identity, members))

    out: list[Related] = []
    for anchor, entries in by_anchor.items():
        if len(entries) < 2:
            continue
        out.append(
            Related(
                anchor=anchor,
                weaknesses=tuple(
                    dict.fromkeys(identity.weakness or "(none)" for _, identity, _ in entries)
                ),
                identity_keys=tuple(key for key, _, _ in entries),
                titles=tuple(
                    dict.fromkeys(
                        members[0].claim.title
                        for _, _, members in entries
                        if members[0].claim.title
                    )
                ),
            )
        )
    return out


def group_by_identity(
    records: Iterable[DispositionRecord],
    graph: CallGraph | None = None,
) -> tuple[dict[str, list[DispositionRecord]], list[Merge]]:
    """Group records by content identity, and report every group of more than one.

    Returns the groups keyed by identity, and the merges -- the groups that folded two or more
    claims together. A group of one is not a merge and is not reported as one: the interesting
    output is what was combined, not what was left alone.

    Insertion order is preserved within a group and across groups, so a reviewer reading the
    report sees claims in the order the queue received them.
    """
    groups: dict[str, list[DispositionRecord]] = {}
    identities: dict[str, ClaimIdentity] = {}

    for record in records:
        identity = identity_for(record, graph)
        groups.setdefault(identity.key, []).append(record)
        identities[identity.key] = identity

    merges = [
        Merge(
            identity=identities[key],
            claim_ids=tuple(item.claim.claim_id for item in members),
            titles=tuple(dict.fromkeys(item.claim.title for item in members if item.claim.title)),
            tools=tuple(dict.fromkeys(item.claim.source.tool for item in members)),
            weaknesses=tuple(
                dict.fromkeys(item.claim.weakness for item in members if item.claim.weakness)
            ),
        )
        for key, members in groups.items()
        if len(members) > 1
    ]
    return groups, merges
