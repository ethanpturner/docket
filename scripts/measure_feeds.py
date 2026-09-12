"""The README's headline number: how often a reviewer's citation points at real code.

Runs docket over the feeds from the scored reviewer runs and reports locator resolution per tool.
No model calls, no network: the feeds and the worktree are both on disk.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

from docket import records_for_file
from docket.resolve import Resolution

SCENARIOS = {
    "unsigned-webhooks": "unsigned-webhooks",
    "rag-support-bot": "rag-support-bot",
}


def main(runs_root: Path, worktree: Path, commit: str) -> int:
    totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    claims: dict[str, int] = defaultdict(int)
    per_tool_runs: dict[str, int] = defaultdict(int)

    for scenario in sorted(SCENARIOS):
        repo = worktree / "benchmarks" / scenario / "code"
        if not repo.is_dir():
            print(f"missing {repo}", file=sys.stderr)
            continue
        for feed in sorted((runs_root / scenario).glob("*/run-*/feed.jsonl")):
            records = records_for_file(feed, repo=repo, commit=commit)
            if not records:
                continue
            tool = records[0].claim.source.tool
            per_tool_runs[tool] += 1
            for record in records:
                claims[tool] += 1
                for item in record.locators:
                    totals[tool]["total"] += 1
                    totals[tool][item.resolution.value] += 1

    print(f"{'tool':<18} {'runs':>5} {'claims':>7} {'locators':>9} {'resolve':>9} {'rate':>7}")
    for tool in sorted(totals):
        row = totals[tool]
        resolved = row[Resolution.RESOLVES.value]
        total = row["total"]
        rate = f"{resolved / total:.0%}" if total else "n/a"
        print(
            f"{tool:<18} {per_tool_runs[tool]:>5} {claims[tool]:>7} {total:>9} "
            f"{resolved:>9} {rate:>7}"
        )
        for value in Resolution:
            if value is not Resolution.RESOLVES and row[value.value]:
                print(f"{'':<18} {value.value}: {row[value.value]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
