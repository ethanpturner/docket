"""Does a content-derived identity merge what a tool's own signature does not?

Pools every run of one reviewer over one application into a single queue and compares two ways of
counting distinct claims: the producer's own signature, and `docket.identity`. The pooled queue is
the case that matters -- a signature that is stable within a run and unstable across runs looks
fine until somebody runs the scanner twice.

Two figures are reported separately, because they answer different questions. The pooled count
says how much shorter the queue gets. The cross-run group count says whether identity survives a
re-run at all, which is the property the tool's own signature does not have.

The resolving subset is reported beside the whole set, because identity degrades to the title when
no cited position resolves, and one of the two reviewers here cites unusable paths in three of its
ten runs. Mixing those in would report a property of that bug as a property of this module.

No model calls, no network. The feeds and the worktree are both on disk.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

from docket import records_for_file
from docket.disposition import DispositionRecord
from docket.identity import IdentityKind, identity_for
from docket.reachability import CallGraph, build_call_graph

SCENARIOS = ("unsigned-webhooks", "rag-support-bot")


def _counts(
    records: list[DispositionRecord],
    graph: CallGraph | None,
    runs_of: dict[str, str],
) -> dict[str, int]:
    """Group the records and count what matters: groups, merges, and cross-run groups."""
    groups: dict[str, list[DispositionRecord]] = defaultdict(list)
    for record in records:
        groups[identity_for(record, graph).key].append(record)

    cross_run = 0
    for members in groups.values():
        runs = {runs_of[member.claim.claim_id] for member in members}
        if len(runs) > 1:
            cross_run += 1

    return {
        "emitted": len(records),
        "signatures": len({record.claim.claim_id for record in records}),
        "groups": len(groups),
        "merges": sum(1 for members in groups.values() if len(members) > 1),
        "cross_run_groups": cross_run,
        "largest": max((len(members) for members in groups.values()), default=0),
    }


def main(runs_root: Path, worktree: Path, commit: str) -> int:
    grand: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for scenario in SCENARIOS:
        repo = worktree / "benchmarks" / scenario / "code"
        if not repo.is_dir():
            print(f"missing {repo}", file=sys.stderr)
            continue
        graph = build_call_graph(repo)

        by_tool: dict[str, list[DispositionRecord]] = defaultdict(list)
        runs_of: dict[str, str] = {}
        runs: dict[str, set[str]] = defaultdict(set)
        for feed in sorted((runs_root / scenario).glob("*/run-*/feed.jsonl")):
            records = records_for_file(feed, repo=repo, commit=commit)
            if not records:
                continue
            tool = records[0].claim.source.tool
            run_name = feed.parent.name
            runs[tool].add(run_name)
            for record in records:
                runs_of[record.claim.claim_id] = run_name
            by_tool[tool].extend(records)

        print(f"\n## {scenario}")
        for tool, records in sorted(by_tool.items()):
            whole = _counts(records, graph, runs_of)
            resolving = [item for item in records if item.resolved_count > 0]
            subset = _counts(resolving, graph, runs_of)
            kinds: dict[str, int] = defaultdict(int)
            for record in records:
                kinds[identity_for(record, graph).kind.value] += 1

            print(
                f"{tool}: {len(runs[tool])} runs, {whole['emitted']} emitted -> "
                f"{whole['signatures']} by signature -> {whole['groups']} by content "
                f"({whole['merges']} merges, {whole['cross_run_groups']} spanning >1 run, "
                f"largest {whole['largest']})"
            )
            print(
                f"  claims citing a position that resolves: {subset['emitted']} -> "
                f"{subset['signatures']} by signature -> {subset['groups']} by content "
                f"({subset['cross_run_groups']} spanning >1 run)"
            )
            for kind in IdentityKind:
                if kinds[kind.value]:
                    print(f"  identity {kind.value}: {kinds[kind.value]} claims")

            for key, value in whole.items():
                grand[tool][key] += value
            for key, value in subset.items():
                grand[tool][f"resolving_{key}"] += value
            grand[tool]["runs"] += len(runs[tool])

    print("\n## pooled across both applications")
    header = (
        f"{'tool':<18} {'runs':>5} {'emitted':>8} {'signature':>10} {'content':>8} {'x-run':>6}"
    )
    print(header)
    for tool, row in sorted(grand.items()):
        print(
            f"{tool:<18} {row['runs']:>5} {row['emitted']:>8} "
            f"{row['signatures']:>10} {row['groups']:>8} {row['cross_run_groups']:>6}"
        )
    print("\nresolving subset only")
    print(header)
    for tool, row in sorted(grand.items()):
        print(
            f"{tool:<18} {row['runs']:>5} {row['resolving_emitted']:>8} "
            f"{row['resolving_signatures']:>10} {row['resolving_groups']:>8} "
            f"{row['resolving_cross_run_groups']:>6}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
