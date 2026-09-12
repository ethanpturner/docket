"""Phase 3: the queue, the merge, and the decision that expires when its code changes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from docket import main, records_for_file
from docket.baseline import (
    Baseline,
    BaselineEntry,
    SpanState,
    State,
    anchors_for,
    entry_for,
    load_baseline,
    save_baseline,
    state_of,
)
from docket.decision import Decision
from docket.disposition import Status
from docket.identity import IdentityKind, group_by_identity, identity_for, related_groups
from docket.reachability import build_call_graph
from docket.summary import render_summary, render_terminal
from docket.triage import triage

APP = '''from fastapi import FastAPI, Request

app = FastAPI()


def verify(body: bytes, signature: str) -> bool:
    """Present and never called."""
    return False


@app.post("/events")
async def receive_event(request: Request) -> dict[str, str]:
    body = await request.body()
    payload = body.decode()
    return {"ok": payload[:10]}
'''


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "main.py").write_text(APP, encoding="utf-8")
    return root


Row = dict[str, object]


def _feed(path: Path, rows: list[Row]) -> Path:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def _records(tmp_path: Path, repo: Path, rows: list[Row], name: str = "f.jsonl"):
    return records_for_file(_feed(tmp_path / name, rows), repo=repo, commit="abc123")


# --- identity ------------------------------------------------------------------------------


def test_identity_survives_a_line_shift(tmp_path: Path, repo: Path) -> None:
    """The same weakness cited at two line numbers inside one function is one claim.

    This is the property the tool's own signature does not have, and the reason a baseline keyed
    on a line number would expire on every unrelated edit above it.
    """
    graph = build_call_graph(repo)
    first = _records(
        tmp_path,
        repo,
        [{"signature": "aaa", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:12"]}],
        "a.jsonl",
    )
    second = _records(
        tmp_path,
        repo,
        [
            {
                "signature": "bbb",
                "title": "Handler does not authenticate",
                "cwe": "CWE-306",
                "code_paths": ["main.py:14"],
            }
        ],
        "b.jsonl",
    )
    assert identity_for(first[0], graph).key == identity_for(second[0], graph).key
    assert identity_for(first[0], graph).anchor == "main.py::receive_event"


def test_identity_ignores_the_tools_own_signature(tmp_path: Path, repo: Path) -> None:
    graph = build_call_graph(repo)
    rows: list[Row] = [
        {"signature": "one", "title": "A", "cwe": "CWE-306", "code_paths": ["main.py:12"]},
        {"signature": "two", "title": "B", "cwe": "CWE-306", "code_paths": ["main.py:13"]},
    ]
    records = _records(tmp_path, repo, rows)
    groups, merges = group_by_identity(records, graph)
    assert len(groups) == 1
    assert len(merges) == 1
    assert merges[0].size == 2
    # The merge carries both titles, so a reviewer can see what was folded together.
    assert set(merges[0].titles) == {"A", "B"}


def test_a_different_weakness_at_one_site_is_not_merged(tmp_path: Path, repo: Path) -> None:
    """Two CWEs at one function stay separate and are reported as related.

    Equating two CWE identifiers is a taxonomy judgement, and asserting one silently is how a
    merge hides a finding.
    """
    graph = build_call_graph(repo)
    rows: list[Row] = [
        {"signature": "one", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:12"]},
        {"signature": "two", "title": "Unverified", "cwe": "CWE-345", "code_paths": ["main.py:12"]},
    ]
    groups, merges = group_by_identity(_records(tmp_path, repo, rows), graph)
    assert len(groups) == 2
    assert merges == []
    related = related_groups(groups, graph)
    assert len(related) == 1
    assert set(related[0].weaknesses) == {"CWE-306", "CWE-345"}


def test_an_unresolved_claim_falls_back_to_its_title(tmp_path: Path, repo: Path) -> None:
    graph = build_call_graph(repo)
    # A path outside the worktree: the shape the Mantis sandbox-path defect produced.
    rows: list[Row] = [
        {"signature": "x", "title": "Something", "code_paths": ["/elsewhere/sandbox/main.py:1"]}
    ]
    identity = identity_for(_records(tmp_path, repo, rows)[0], graph)
    assert identity.kind is IdentityKind.TOPIC
    assert identity.anchor is None


# --- the baseline --------------------------------------------------------------------------


def _decided(tmp_path: Path, repo: Path):
    """One decided record, its identity, and a baseline holding it."""
    graph = build_call_graph(repo)
    rows: list[Row] = [
        {"signature": "s1", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:12"]}
    ]
    record = _records(tmp_path, repo, rows)[0]
    identity = identity_for(record, graph)
    decision = Decision(
        claim_id=record.claim.claim_id,
        status=Status.NOT_EXPLOITABLE,
        reason="the route is not mounted in this deployment",
        decided_by="reviewer@example.com",
        justification="vulnerable_code_not_in_execute_path",
    )
    baseline = Baseline()
    baseline.put(entry_for(identity, decision, record, repo=repo, graph=graph))
    return graph, record, identity, baseline


def test_a_decision_carries_while_its_code_is_unchanged(tmp_path: Path, repo: Path) -> None:
    graph, _, identity, baseline = _decided(tmp_path, repo)
    finding = state_of(identity, baseline, repo=repo, graph=graph)
    assert finding.state is State.CARRIED
    assert finding.entry is not None
    assert finding.entry.status == "not_exploitable"


def test_a_decision_goes_stale_when_its_code_changes(tmp_path: Path, repo: Path) -> None:
    """The phase's whole idea: a dismissal expires when the thing it dismissed is rewritten."""
    _, _, identity, baseline = _decided(tmp_path, repo)
    (repo / "main.py").write_text(
        APP.replace('return {"ok": payload[:10]}', 'return {"ok": payload[:99]}'),
        encoding="utf-8",
    )
    finding = state_of(identity, baseline, repo=repo, graph=build_call_graph(repo))
    assert finding.state is State.STALE
    assert "not what the decision quotes" in finding.detail
    # The previous decision is shown, never silently reapplied.
    assert finding.entry is not None
    assert finding.entry.reason == "the route is not mounted in this deployment"


def test_a_moved_span_carries_rather_than_expiring(tmp_path: Path, repo: Path) -> None:
    """Inserting a line above a citation is not a change to the thing that was decided.

    Without this, one formatting pass re-opens every dismissal in the file and the mechanism is
    switched off by the end of the week.
    """
    _, _, identity, baseline = _decided(tmp_path, repo)
    (repo / "main.py").write_text("# a new comment line\n" + APP, encoding="utf-8")
    finding = state_of(identity, baseline, repo=repo, graph=build_call_graph(repo))
    assert finding.state is State.CARRIED
    assert any(state is SpanState.MOVED for _, state in finding.span_states)
    assert "moved" in finding.detail


def test_a_decision_that_anchored_nothing_is_stale_not_carried(tmp_path: Path, repo: Path) -> None:
    """An entry with no anchors cannot be shown to still be about this code.

    Carrying it would be a check that cannot fail, which is the defect this project keeps finding
    in other people's tools and in its own.
    """
    _, _, identity, _ = _decided(tmp_path, repo)
    baseline = Baseline()
    baseline.put(
        BaselineEntry(
            identity_key=identity.key,
            identity_kind=identity.kind,
            identity_basis=identity.basis,
            status="not_exploitable",
            reason="r",
            decided_by="someone",
            decided_at="2026-09-11T00:00:00+00:00",
            anchors=(),
        )
    )
    finding = state_of(identity, baseline, repo=repo)
    assert finding.state is State.STALE
    assert "anchored no resolved positions" in finding.detail


def test_an_absent_file_makes_a_decision_stale(tmp_path: Path, repo: Path) -> None:
    _, _, identity, baseline = _decided(tmp_path, repo)
    (repo / "main.py").unlink()
    finding = state_of(identity, baseline, repo=repo, graph=build_call_graph(repo))
    assert finding.state is State.STALE
    assert "no longer resolves" in finding.detail


def test_a_baseline_round_trips(tmp_path: Path, repo: Path) -> None:
    _, _, _, baseline = _decided(tmp_path, repo)
    path = save_baseline(baseline, tmp_path / "baseline.json")
    again = load_baseline(path)
    assert list(again.entries) == list(baseline.entries)
    assert next(iter(again.entries.values())).anchors


def test_a_file_that_is_not_a_baseline_is_refused(tmp_path: Path) -> None:
    """Silently starting from an empty baseline would re-open every decided claim."""
    path = tmp_path / "nope.json"
    path.write_text(json.dumps({"format": "something/else"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a docket baseline"):
        load_baseline(path)


def test_anchors_record_the_enclosing_symbol(tmp_path: Path, repo: Path) -> None:
    graph = build_call_graph(repo)
    rows: list[Row] = [
        {"signature": "s", "title": "t", "cwe": "CWE-306", "code_paths": ["main.py:12"]}
    ]
    anchors = anchors_for(_records(tmp_path, repo, rows)[0], repo=repo, graph=graph)
    assert len(anchors) == 1
    assert anchors[0].symbol == "receive_event"
    assert anchors[0].symbol_sha256 is not None


# --- the queue -----------------------------------------------------------------------------


def test_triage_merges_and_marks_everything_new(tmp_path: Path, repo: Path) -> None:
    rows: list[Row] = [
        {"signature": "a", "title": "A", "cwe": "CWE-306", "code_paths": ["main.py:12"]},
        {"signature": "b", "title": "B", "cwe": "CWE-306", "code_paths": ["main.py:13"]},
        {"signature": "c", "title": "C", "cwe": "CWE-400", "code_paths": ["main.py:12"]},
    ]
    result = triage(_records(tmp_path, repo, rows), repo=repo)
    assert result.claims_in == 3
    assert len(result.items) == 2
    assert len(result.new) == 2
    assert result.model_calls == 0
    assert all(item.status == Status.UNDETERMINED.value for item in result.items)


def test_a_carried_decision_leaves_the_queue(tmp_path: Path, repo: Path) -> None:
    graph, _, _, baseline = _decided(tmp_path, repo)
    rows: list[Row] = [
        {"signature": "later", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:13"]}
    ]
    result = triage(_records(tmp_path, repo, rows), repo=repo, baseline=baseline, graph=graph)
    assert len(result.carried) == 1
    assert result.needs_a_person == []
    assert result.carried[0].status == "not_exploitable"


def test_a_stale_decision_returns_to_the_queue_as_undetermined(tmp_path: Path, repo: Path) -> None:
    """A stale decision does not carry its old status forward, even for display."""
    _, _, _, baseline = _decided(tmp_path, repo)
    (repo / "main.py").write_text(APP.replace("payload[:10]", "payload[:99]"), encoding="utf-8")
    rows: list[Row] = [
        {"signature": "later", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:13"]}
    ]
    result = triage(_records(tmp_path, repo, rows), repo=repo, baseline=baseline)
    assert len(result.stale) == 1
    assert result.stale[0].status == Status.UNDETERMINED.value
    assert len(result.needs_a_person) == 1


def test_the_summary_shows_a_stale_decisions_previous_reason(tmp_path: Path, repo: Path) -> None:
    _, _, _, baseline = _decided(tmp_path, repo)
    (repo / "main.py").write_text(APP.replace("payload[:10]", "payload[:99]"), encoding="utf-8")
    rows: list[Row] = [
        {"signature": "l", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:13"]}
    ]
    result = triage(_records(tmp_path, repo, rows), repo=repo, baseline=baseline)
    markdown = render_summary(result)
    assert "went stale" in markdown
    assert "the route is not mounted in this deployment" in markdown
    assert "STALE" in render_terminal(result)


# --- the command line ----------------------------------------------------------------------


def test_triage_exits_zero_by_default(tmp_path: Path, repo: Path, capsys) -> None:
    """A tool that arrives blocking a pipeline is uninstalled before anyone reads its output."""
    feed = _feed(
        tmp_path / "f.jsonl",
        [{"signature": "a", "title": "A", "cwe": "CWE-306", "code_paths": ["main.py:12"]}],
    )
    code = main(["triage", str(feed), "--repo", str(repo), "--commit", "abc123", "--no-model"])
    assert code == 0
    assert "new" in capsys.readouterr().out


def test_fail_on_new_is_opt_in(tmp_path: Path, repo: Path) -> None:
    feed = _feed(
        tmp_path / "f.jsonl",
        [{"signature": "a", "title": "A", "cwe": "CWE-306", "code_paths": ["main.py:12"]}],
    )
    argv = ["triage", str(feed), "--repo", str(repo), "--commit", "abc123", "--no-model"]
    assert main(argv) == 0
    assert main([*argv, "--fail-on-new"]) == 1


def test_fail_on_stale_is_opt_in(tmp_path: Path, repo: Path) -> None:
    _, _, _, baseline = _decided(tmp_path, repo)
    baseline_path = save_baseline(baseline, tmp_path / "baseline.json")
    (repo / "main.py").write_text(APP.replace("payload[:10]", "payload[:99]"), encoding="utf-8")
    feed = _feed(
        tmp_path / "f.jsonl",
        [{"signature": "l", "title": "No auth", "cwe": "CWE-306", "code_paths": ["main.py:13"]}],
    )
    argv = [
        "triage",
        str(feed),
        "--repo",
        str(repo),
        "--commit",
        "abc123",
        "--no-model",
        "--baseline",
        str(baseline_path),
    ]
    assert main(argv) == 0
    assert main([*argv, "--fail-on-stale"]) == 1


def test_triage_writes_a_queue_and_a_vex_document(tmp_path: Path, repo: Path) -> None:
    feed = _feed(
        tmp_path / "f.jsonl",
        [{"signature": "a", "title": "A", "cwe": "CWE-306", "code_paths": ["main.py:12"]}],
    )
    out = tmp_path / "out"
    code = main(
        [
            "triage",
            str(feed),
            "--repo",
            str(repo),
            "--commit",
            "abc123",
            "--no-model",
            "--out",
            str(out),
            "--summary",
            str(tmp_path / "summary.md"),
        ]
    )
    assert code == 0
    queue = json.loads((out / "triage.json").read_text(encoding="utf-8"))
    assert queue["summary"]["claims_in"] == 1
    document = json.loads((out / "openvex.json").read_text(encoding="utf-8"))
    assert document["statements"][0]["status"] == "under_investigation"
    assert "docket" in (tmp_path / "summary.md").read_text(encoding="utf-8")


# --- the committed worked example ----------------------------------------------------------

LOOP = Path(__file__).resolve().parents[1] / "docs" / "eval" / "loop-example"


def test_the_loop_example_is_what_the_readme_says() -> None:
    """Re-derive the committed three-run example: new, carried, then one stale and one carried.

    The third run's claims arrive under different scanner signatures from the first run's
    (`scanner-b7` against `scanner-a1`), so a baseline keyed on the producer's own identifier
    would have matched nothing and called both claims new. This test is the pin on that.
    """
    runs = {
        "run-1-new": (2, 0, 0),
        "run-2-carried": (0, 0, 2),
        "run-3-stale": (0, 1, 1),
    }
    for name, (new, stale, carried) in runs.items():
        summary = json.loads((LOOP / name / "triage.json").read_text(encoding="utf-8"))["summary"]
        assert (summary["new"], summary["stale"], summary["carried"]) == (new, stale, carried), name

    third = json.loads((LOOP / "run-3-stale" / "triage.json").read_text(encoding="utf-8"))
    states = {item["title"]: item["baseline"] for item in third["items"]}

    changed = states["Report path is built from caller input"]
    assert changed["state"] == "stale"
    assert "not what the decision quotes" in changed["detail"]
    # The previous decision travels with it, so the reviewer re-decides from their own argument.
    assert changed["previous"]["status"] == "exploitable"
    assert "no containment check" in changed["previous"]["reason"]

    moved = states["Audit helper has no caller"]
    assert moved["state"] == "carried"
    assert "moved" in moved["detail"]
    assert [span["state"] for span in moved["spans"]] == ["moved"]


def test_the_loop_example_claims_arrive_under_new_signatures() -> None:
    """Identity is content-derived, so a re-run's fresh identifiers still match the baseline."""
    first = (LOOP / "finding.jsonl").read_text(encoding="utf-8")
    third = (LOOP / "finding-after-the-fix.jsonl").read_text(encoding="utf-8")
    assert "scanner-a1" in first and "scanner-a1" not in third
    assert "scanner-b7" in third
