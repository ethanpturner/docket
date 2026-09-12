"""The README's second number: what gathering evidence establishes, and what it does not.

Runs `docket assess` over every claim in the scored reviewer runs and reports the distribution of
answers, how many claims ended with a candidate justification, how many ended with nothing
established, and what it cost.

The point of the measurement is not that the tool works. It is the shape of the result: on real
machine-generated claims against real code, how often is any question actually settled? A number
that comes out low is the finding, because it is the same number a human triager is working with
and nobody publishes it.

Usage:

    python scripts/measure_assessments.py RUNS_DIR WORKTREE COMMIT [--record FILE | --replay FILE]

Claims are assessed concurrently because each is independent; the model adapter blocks on I/O and
the recording is serialised behind a lock.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from docket import records_for_file
from docket.assess import assess_record
from docket.evidence import EvidenceRecord
from docket.model import (
    DEFAULT_MODEL,
    OpenAICompatibleModel,
    RecordingModel,
    ReplayModel,
    StructuredModel,
)
from docket.questions import QUESTIONS, Answer
from docket.reachability import build_call_graph

SCENARIOS = ("unsigned-webhooks", "rag-support-bot")


def _assess_all(
    runs_root: Path,
    worktree: Path,
    commit: str,
    model: StructuredModel | None,
    workers: int,
) -> list[tuple[str, EvidenceRecord]]:
    """Every claim in every run, assessed. Returns (tool, record) pairs."""
    jobs: list[tuple[str, Path, object]] = []
    graphs = {}

    for scenario in SCENARIOS:
        repo = worktree / "benchmarks" / scenario / "code"
        if not repo.is_dir():
            print(f"missing {repo}", file=sys.stderr)
            continue
        graphs[scenario] = build_call_graph(repo)
        for feed in sorted((runs_root / scenario).glob("*/run-*/feed.jsonl")):
            for record in records_for_file(feed, repo=repo, commit=commit):
                jobs.append((scenario, repo, record))

    def run(job: tuple[str, Path, object]) -> tuple[str, EvidenceRecord]:
        scenario, repo, record = job
        assessed = assess_record(
            record,  # type: ignore[arg-type]
            repo=repo,
            graph=graphs[scenario],
            model=model,
        )
        return str(record.claim.source.tool), assessed  # type: ignore[attr-defined]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(run, jobs))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", type=Path)
    parser.add_argument("worktree", type=Path)
    parser.add_argument("commit")
    parser.add_argument("--record", type=Path, default=None)
    parser.add_argument("--replay", type=Path, default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    model: StructuredModel | None
    if args.replay is not None:
        model = ReplayModel.from_path(args.replay, model=args.model)
    else:
        live: StructuredModel = OpenAICompatibleModel(model=args.model)
        model = RecordingModel(inner=live, path=args.record) if args.record else live

    started = time.monotonic()
    results = _assess_all(args.runs, args.worktree, args.commit, model, args.workers)
    elapsed = time.monotonic() - started

    by_tool: dict[str, Counter[str]] = {}
    answers: dict[str, Counter[str]] = {spec.question.value: Counter() for spec in QUESTIONS}
    tokens_in = tokens_out = calls = 0

    for tool, record in results:
        counts = by_tool.setdefault(tool, Counter())
        counts["claims"] += 1
        calls += record.model_calls
        tokens_in += record.input_tokens
        tokens_out += record.output_tokens
        if record.candidates:
            counts["with_candidate"] += 1
        if record.established_count == 0:
            counts["nothing_established"] += 1
        counts["questions_established"] += record.established_count
        for finding in record.findings:
            answers[finding.question.value][finding.answer.value] += 1
            if finding.model_failed:
                counts["model_failures"] += 1

    print(f"\nclaims assessed: {len(results)} in {elapsed:.0f}s, {calls} model calls")
    print(f"tokens: {tokens_in} in / {tokens_out} out\n")

    print(
        f"{'tool':<18} {'claims':>7} {'w/ candidate':>13} {'nothing est.':>13} {'q est./claim':>13}"
    )
    for tool in sorted(by_tool):
        row = by_tool[tool]
        per = row["questions_established"] / row["claims"] if row["claims"] else 0
        print(
            f"{tool:<18} {row['claims']:>7} {row['with_candidate']:>13} "
            f"{row['nothing_established']:>13} {per:>13.2f}"
        )

    print(f"\n{'question':<24} {'supports':>9} {'contradicts':>12} {'not est.':>9}")
    for spec in QUESTIONS:
        counts = answers[spec.question.value]
        print(
            f"{spec.question.value:<24} "
            f"{counts[Answer.SUPPORTS_JUSTIFICATION.value]:>9} "
            f"{counts[Answer.CONTRADICTS_JUSTIFICATION.value]:>12} "
            f"{counts[Answer.NOT_ESTABLISHED.value]:>9}"
        )

    failures = sum(row["model_failures"] for row in by_tool.values())
    if failures:
        print(f"\nmodel calls that produced no answer: {failures}")

    if args.json_out:
        args.json_out.write_text(
            json.dumps(
                {
                    "claims": len(results),
                    "elapsed_seconds": round(elapsed, 1),
                    "model_calls": calls,
                    "input_tokens": tokens_in,
                    "output_tokens": tokens_out,
                    "by_tool": {tool: dict(counts) for tool, counts in by_tool.items()},
                    "answers": {key: dict(value) for key, value in answers.items()},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
