"""Build the committed worked example of the triage loop.

Three runs over one small application, showing the only behaviour in this tool that no other
suppression mechanism has: a decision that carries until the code it was made about changes, and
then stops carrying.

1. The queue is new. A reviewer decides both claims.
2. The queue is empty. Both decisions carry; nothing needs a person.
3. One cited function is edited. Exactly that claim comes back as `stale`, with the previous
   decision and the reason attached; the other still carries.

Run from the repository root. Deterministic, offline, no model calls: what the example
demonstrates is the digest comparison, and putting a model in it would make the output vary.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from docket import records_for_file
from docket.baseline import Baseline, entry_for, load_baseline, save_baseline
from docket.decision import Decision
from docket.disposition import Status
from docket.identity import identity_for
from docket.reachability import build_call_graph
from docket.summary import render_summary
from docket.triage import triage

ROOT = Path("docs/eval/loop-example")

APP_BEFORE = '''"""A tiny report service, as the reviewer saw it."""

from pathlib import Path


def _load(name: str) -> str:
    """Read a report by name. The name is not checked against the root."""
    return (Path("reports") / name).read_text(encoding="utf-8")


def render(name: str) -> str:
    """Render a report for a caller."""
    return _load(name)


def audit(action: str) -> None:
    """Write an audit line. Never called from anywhere in this module."""
    Path("audit.log").write_text(action, encoding="utf-8")
'''

# One function changes. `_load` gains the containment check the reviewer's first claim was about;
# `audit` is untouched, so the decision about it must still carry.
APP_AFTER = APP_BEFORE.replace(
    '''def _load(name: str) -> str:
    """Read a report by name. The name is not checked against the root."""
    return (Path("reports") / name).read_text(encoding="utf-8")''',
    '''def _load(name: str) -> str:
    """Read a report by name, refusing anything outside the root."""
    root = Path("reports").resolve()
    candidate = (root / name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("outside the report root")
    return candidate.read_text(encoding="utf-8")''',
)

# Run three re-runs the scanner, which is what a pipeline does: the same two weaknesses, cited at
# the positions they now occupy. The line numbers all moved. Identity is derived from the enclosing
# symbol, so both claims still match the decisions made against the old numbers -- which is the
# property that makes a baseline survive an edit at all.
FINDING = [
    {
        "signature": "scanner-a1",
        "title": "Report name is joined to a path without containment",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "code_paths": ["service.py:7"],
    },
    {
        "signature": "scanner-a2",
        "title": "Audit helper is never called",
        "cwe": "CWE-778",
        "severity": "LOW",
        "code_paths": ["service.py:18"],
    },
]

FINDING_AFTER = [
    {
        "signature": "scanner-b7",
        "title": "Report path is built from caller input",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "code_paths": ["service.py:8"],
    },
    {
        "signature": "scanner-b9",
        "title": "Audit helper has no caller",
        "cwe": "CWE-778",
        "severity": "LOW",
        "code_paths": ["service.py:22"],
    },
]

DECISIONS = {
    "scanner-a1": (
        Status.EXPLOITABLE,
        None,
        "`name` reaches a path join with no containment check, and `render` is called from the "
        "HTTP layer with a caller-supplied value.",
    ),
    "scanner-a2": (
        Status.NOT_EXPLOITABLE,
        "vulnerable_code_not_in_execute_path",
        "`audit` has no caller in this service and is not exported; it is dead code scheduled "
        "for deletion, not a missing control.",
    ),
}


def _write_app(target: Path, source: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    (target / "service.py").write_text(source, encoding="utf-8")


def _run(name: str, *, target: Path, finding: Path, baseline: Baseline, out: Path) -> None:
    records = records_for_file(finding, repo=target, commit=name)
    result = triage(records, repo=target, baseline=baseline)
    out.mkdir(parents=True, exist_ok=True)
    (out / "triage.json").write_text(
        json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (out / "summary.md").write_text(
        render_summary(result, title=f"docket — {name}"), encoding="utf-8"
    )
    print(
        f"{name}: {len(result.new)} new, {len(result.stale)} stale, {len(result.carried)} carried"
    )
    for item in result.stale:
        print(f"    stale: {item.title} — {item.state.detail}")


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    target = ROOT / "target"
    _write_app(target, APP_BEFORE)

    finding = ROOT / "finding.jsonl"
    finding.parent.mkdir(parents=True, exist_ok=True)
    finding.write_text("\n".join(json.dumps(row) for row in FINDING) + "\n", encoding="utf-8")
    finding_after = ROOT / "finding-after-the-fix.jsonl"
    finding_after.write_text(
        "\n".join(json.dumps(row) for row in FINDING_AFTER) + "\n", encoding="utf-8"
    )

    # Run one: everything is new.
    _run("run-1-new", target=target, finding=finding, baseline=Baseline(), out=ROOT / "run-1-new")

    # The reviewer decides both, and the decisions are anchored to the code they were made about.
    graph = build_call_graph(target)
    records = records_for_file(finding, repo=target, commit="run-1-new")
    baseline = Baseline()
    for record in records:
        status, justification, reason = DECISIONS[record.claim.claim_id]
        decision = Decision(
            claim_id=record.claim.claim_id,
            status=status,
            reason=reason,
            decided_by="reviewer@example.com",
            justification=justification,
            decided_at=datetime(2026, 9, 11, tzinfo=UTC),
        )
        baseline.put(
            entry_for(identity_for(record, graph), decision, record, repo=target, graph=graph)
        )
    save_baseline(baseline, ROOT / "baseline.json")

    # Run two: both carry, and the queue is empty.
    _run(
        "run-2-carried",
        target=target,
        finding=finding,
        baseline=load_baseline(ROOT / "baseline.json"),
        out=ROOT / "run-2-carried",
    )

    # Somebody fixes the path traversal. `audit` is untouched.
    _write_app(target, APP_AFTER)

    # Run three: the scanner runs again and cites the new positions. The decision about `_load`
    # is stale because that function changed; the one about `audit` carries, because the only
    # thing that happened to it is that it moved down the file.
    _run(
        "run-3-stale",
        target=target,
        finding=finding_after,
        baseline=load_baseline(ROOT / "baseline.json"),
        out=ROOT / "run-3-stale",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
