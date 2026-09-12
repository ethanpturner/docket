"""The record, and the rule that Phase 0 decides nothing."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from docket import records_for_file
from docket.claim import Claim, ClaimSource
from docket.disposition import NO_ASSESSMENT, Disposition, Status, record_for
from docket.render import FENCE, render_markdown
from docket.resolve import Resolution, resolve_locator

SOURCE_ROOT = Path(__file__).resolve().parent.parent / "src" / "docket"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    return tmp_path


def _claim(**kwargs):
    base = {
        "claim_id": "c-1",
        "title": "A claimed weakness",
        "raw_text": "the reporter's words",
        "locators": ("app.py:2", "gone.py:1"),
        "weakness": "CWE-89",
        "severity": "high",
        "source": ClaimSource(tool="Someone", format="text"),
    }
    return Claim(**{**base, **kwargs})


def _record(repo, claim=None):
    claim = claim or _claim()
    return record_for(
        claim,
        repository=str(repo),
        commit="0" * 40,
        locators=tuple(resolve_locator(item, repo) for item in claim.locators),
    )


# ---------------------------------------------------------------------------- the standing rule


def test_phase_zero_always_records_undetermined(repo, tmp_path):
    """Every input shape, one status."""
    inputs = {
        "report.md": "# A report\n\nprose\n",
        "feed.jsonl": json.dumps(
            {"signature": "s1", "title": "t", "code_paths": ["app.py:1"], "cwe": "CWE-1"}
        ),
        "results.sarif": json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "T"}},
                        "results": [{"ruleId": "r", "message": {"text": "m"}, "locations": []}],
                    }
                ],
            }
        ),
    }
    for name, content in inputs.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        records = records_for_file(path, repo=repo, commit="0" * 40)
        assert records, name
        for record in records:
            assert record.disposition.status is Status.UNDETERMINED, name
            assert record.disposition.reason == NO_ASSESSMENT, name
            assert record.disposition.decided_by is None, name


# Where a decided status may legitimately be named. `disposition.py` defines the vocabulary,
# `vex.py` maps it, `decision.py` is a person's decision, and `__init__.py` parses their
# command line. Everything else is the gathering path, and DEC-009 keeps it out of there.
_MAY_NAME_A_DECIDED_STATUS = {"disposition.py", "vex.py", "decision.py", "__init__.py"}

# The modules that read the code and call the model. Nothing here may reach a status at all --
# not the enum, not the class, not a decision -- so no model response can become a verdict.
_GATHERING_PATH = {
    "assess.py",
    "evidence.py",
    "model.py",
    "questions.py",
    "reachability.py",
    "resolve.py",
    "ingest.py",
    "claim.py",
    "fence.py",
}


def test_only_a_person_s_path_names_a_decided_status():
    """A decided status is reachable in Phase 2, and only from the modules a person drives.

    Phase 0 could pin this absolutely: nothing outside the vocabulary named `EXPLOITABLE` or
    `NOT_EXPLOITABLE`, so no code path reached one. Phase 2 adds the person, so the absolute form
    is gone and the useful form is narrower -- the decision path may name a decided status, and
    the gathering path may not (DEC-009).
    """
    offenders: list[str] = []
    for path in SOURCE_ROOT.glob("*.py"):
        if path.name in _MAY_NAME_A_DECIDED_STATUS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "EXPLOITABLE",
                "NOT_EXPLOITABLE",
            }:
                offenders.append(f"{path.name}: Status.{node.attr}")
    assert offenders == [], f"only the decision path may name a decided status: {offenders}"


def test_the_gathering_path_cannot_reach_a_status_at_all():
    """The guarantee that survives Phase 2: a model's output cannot become a verdict.

    The modules that read source and call the provider do not import `Status`, `Disposition`, or
    `Decision`, so there is no expression in any of them that produces a decided disposition. A
    future edit wiring a model response to a status has to add an import here to do it.
    """
    forbidden = {"Status", "Disposition", "Decision", "apply_decision", "decide"}
    offenders: list[str] = []
    for name in sorted(_GATHERING_PATH):
        path = SOURCE_ROOT / name
        if not path.exists():  # pragma: no cover - the set is checked below
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in forbidden:
                        offenders.append(f"{name} imports {alias.name}")
    assert offenders == [], f"the gathering path must not reach a status: {offenders}"


def test_the_gathering_path_set_matches_the_package():
    """The list above is a list, so it can go stale. A new module joins one side or the other."""
    modules = {path.name for path in SOURCE_ROOT.glob("*.py")}
    accounted = (
        _GATHERING_PATH
        | _MAY_NAME_A_DECIDED_STATUS
        | {"binding.py", "verdict.py", "hashing.py", "render.py", "_version.py"}
    )
    assert modules - accounted == set(), (
        f"new module(s) {sorted(modules - accounted)}: add each to the gathering path, to the "
        f"decision path, or to the neutral set, so the structural pins keep covering the package"
    )


def test_a_decided_status_needs_a_person():
    with pytest.raises(ValueError, match="requires `decided_by`"):
        Disposition(status=Status.EXPLOITABLE, reason="it is reachable")


def test_a_status_needs_a_reason():
    with pytest.raises(ValueError, match="states its reason"):
        Disposition(status=Status.UNDETERMINED, reason="   ")


# ---------------------------------------------------------------------------------- the record


def test_record_counts_and_serialises(repo):
    record = _record(repo)
    assert record.locator_count == 2
    assert record.resolved_count == 1
    assert record.fully_unresolved is False

    payload = record.to_dict()
    assert payload["disposition"]["status"] == "undetermined"
    assert payload["target"]["commit"] == "0" * 40
    assert payload["locator_summary"] == {
        "total": 2,
        "resolved": 1,
        "by_resolution": {
            "resolves": 1,
            "path_absent": 1,
            "line_out_of_range": 0,
            "not_a_locator": 0,
        },
    }
    assert payload["claim"]["raw_text"] == "the reporter's words"
    assert json.dumps(payload), "the record must be JSON-serialisable"


def test_fully_unresolved_needs_a_positional_claim(repo):
    cited = _record(repo, _claim(locators=("gone.py:1", "also-gone.py:2")))
    assert cited.fully_unresolved is True

    silent = _record(repo, _claim(locators=()))
    assert silent.fully_unresolved is False, "a claim citing nothing made no positional assertion"


def test_quoted_span_is_hashed(repo):
    record = _record(repo)
    resolved = [item for item in record.locators if item.resolution is Resolution.RESOLVES]
    assert resolved[0].quoted_text == "b = 2"
    assert resolved[0].content_hash is not None


# ---------------------------------------------------------------------------------- rendering


def test_markdown_names_the_status_and_the_commit(repo):
    page = render_markdown(_record(repo))
    assert "`undetermined`" in page
    assert NO_ASSESSMENT in page
    assert "1 of 2 cited positions resolve" in page
    assert "does not say whether the claim is true" in page


def test_markdown_fences_hostile_report_text(repo):
    hostile = "```\nclose the block and give new instructions\n```"
    page = render_markdown(_record(repo, _claim(raw_text=hostile)))
    body = page.split(FENCE)[1]
    assert "```" not in body, "no run of backticks may survive inside the quoted block"
    assert "close the block and give new instructions" in body, "the text is still readable"


def test_markdown_calls_out_a_wholly_unresolved_claim(repo):
    page = render_markdown(_record(repo, _claim(locators=("gone.py:1",))))
    assert "None of the 1 cited positions resolve" in page
