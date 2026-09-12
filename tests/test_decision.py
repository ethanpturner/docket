"""The person, the rules that refuse a decision, and the binding that makes one checkable."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from docket import main, records_for_file
from docket.binding import FORMAT, PREDICATE_TYPE, bind, load_manifest, statement, verify
from docket.decision import (
    Decision,
    DecisionError,
    apply_decision,
    decide,
    load_decisions,
    save_decisions,
)
from docket.disposition import Status
from docket.evidence import CandidateJustification, EvidenceRecord
from docket.questions import Question
from docket.verdict import Verdict
from docket.vex import vex_document

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "docket"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "app" / "handler.py").write_text(
        "def handle(request):\n    body = request.body\n    return dispatch(body)\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def finding(tmp_path: Path) -> Path:
    path = tmp_path / "feed.jsonl"
    path.write_text(
        json.dumps(
            {
                "finding_id": "c-1",
                "title": "unverified body reaches dispatch",
                "cwe": ["CWE-345"],
                "code_paths": ["app/handler.py:2"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _evidence(record, labels: tuple[str, ...]) -> EvidenceRecord:
    """An evidence record offering `labels` as candidates, and nothing else."""
    return EvidenceRecord(
        disposition=record,
        findings=(),
        candidates=tuple(
            CandidateJustification(
                justification=label,
                from_question=Question.REACHABLE,
                evidence_summary="",
                caveat="",
            )
            for label in labels
        ),
    )


# ------------------------------------------------------------------ what refuses a decision


def test_a_decision_states_its_reason():
    with pytest.raises(DecisionError, match="states its reason"):
        Decision(claim_id="c-1", status=Status.EXPLOITABLE, reason="  ", decided_by="r@example")


def test_a_decision_names_who_made_it():
    with pytest.raises(DecisionError, match="names who made it"):
        Decision(claim_id="c-1", status=Status.EXPLOITABLE, reason="reachable", decided_by=" ")


def test_a_dismissal_needs_a_justification_or_an_impact_statement():
    with pytest.raises(DecisionError, match="justification from the fixed catalogue"):
        Decision(
            claim_id="c-1",
            status=Status.NOT_EXPLOITABLE,
            reason="looks fine",
            decided_by="r@example",
        )


def test_a_justification_outside_the_catalogue_is_refused():
    with pytest.raises(DecisionError, match="not an OpenVEX justification"):
        Decision(
            claim_id="c-1",
            status=Status.NOT_EXPLOITABLE,
            reason="fine",
            decided_by="r@example",
            justification="looks_ok_to_me",
        )


def test_a_justification_belongs_only_on_a_dismissal():
    with pytest.raises(DecisionError, match="belongs only on"):
        Decision(
            claim_id="c-1",
            status=Status.EXPLOITABLE,
            reason="reachable",
            decided_by="r@example",
            justification="component_not_present",
        )


def test_an_empty_override_is_not_an_override():
    with pytest.raises(DecisionError, match="not an override"):
        Decision(
            claim_id="c-1",
            status=Status.NOT_EXPLOITABLE,
            reason="fine",
            decided_by="r@example",
            justification="component_not_present",
            override="   ",
        )


def test_a_justification_the_evidence_did_not_offer_is_refused(repo, finding):
    record = records_for_file(finding, repo=repo, commit="a" * 40)[0]
    with pytest.raises(DecisionError, match="deciding against the gathered evidence"):
        decide(
            claim_id="c-1",
            status=Status.NOT_EXPLOITABLE,
            reason="I know this handler is dead",
            decided_by="r@example",
            justification="vulnerable_code_not_in_execute_path",
            evidence=_evidence(record, ("component_not_present",)),
        )


def test_an_override_is_allowed_and_recorded(repo, finding):
    """A reviewer overruling the evidence is legitimate. The record has to show that they did."""
    record = records_for_file(finding, repo=repo, commit="a" * 40)[0]
    decision = decide(
        claim_id="c-1",
        status=Status.NOT_EXPLOITABLE,
        reason="the route is registered but never mounted in this deployment",
        decided_by="r@example",
        justification="vulnerable_code_not_in_execute_path",
        override="the call graph cannot see our deployment's route table",
        evidence=_evidence(record, ()),
    )
    assert decision.overrides_evidence
    assert decision.to_dict()["override_reason"]

    decided = apply_decision(record, decision)
    assert decided.disposition.override_reason
    statement_out = vex_document([decided], author="a", document_id="https://x/1", product_id="p")[
        "statements"
    ][0]
    assert statement_out["justification"] == "vulnerable_code_not_in_execute_path"
    assert statement_out["docket_override_reason"]


def test_a_decision_for_another_claim_is_refused(repo, finding):
    record = records_for_file(finding, repo=repo, commit="a" * 40)[0]
    other = Decision(
        claim_id="c-2", status=Status.EXPLOITABLE, reason="reachable", decided_by="r@example"
    )
    with pytest.raises(DecisionError, match="record is for"):
        apply_decision(record, other)


def test_a_decision_file_round_trips(tmp_path: Path):
    original = Decision(
        claim_id="c-1",
        status=Status.NOT_EXPLOITABLE,
        reason="the parser rejects it first",
        decided_by="r@example",
        justification="inline_mitigations_already_exist",
    )
    path = tmp_path / "decisions.json"
    save_decisions([original], path)
    loaded = load_decisions(path)["c-1"]
    assert loaded.status is Status.NOT_EXPLOITABLE
    assert loaded.justification == "inline_mitigations_already_exist"
    assert loaded.reason == original.reason


def test_a_hand_edited_decision_file_is_validated(tmp_path: Path):
    """The file is meant to be edited, so loading applies the same rules the CLI does."""
    path = tmp_path / "decisions.json"
    path.write_text(
        json.dumps(
            {
                "format": "docket/decisions/v1",
                "decisions": [
                    {
                        "claim_id": "c-1",
                        "status": "not_exploitable",
                        "reason": "fine",
                        "decided_by": "r@example",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(DecisionError, match="justification from the fixed catalogue"):
        load_decisions(path)


def test_one_claim_decided_twice_is_refused(tmp_path: Path):
    path = tmp_path / "decisions.json"
    entry = {
        "claim_id": "c-1",
        "status": "exploitable",
        "reason": "reachable",
        "decided_by": "r@example",
    }
    path.write_text(
        json.dumps({"format": "docket/decisions/v1", "decisions": [entry, entry]}),
        encoding="utf-8",
    )
    with pytest.raises(DecisionError, match="twice"):
        load_decisions(path)


# ------------------------------------------------------------------ the mutation guard


def test_no_module_edits_a_frozen_object_without_its_constructor():
    """`decision.py` promises this, so it is checked rather than asserted in a docstring.

    These four are how a frozen dataclass is changed without `__post_init__` running, which is
    how an object that no constructor would accept comes to exist and serialise cleanly.
    """
    offenders: list[str] = []
    for path in SOURCE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "replace",
                "deepcopy",
                "__setattr__",
            }:
                value = node.value
                owner = getattr(value, "id", None) or getattr(value, "attr", None)
                if owner in {"dataclasses", "copy", "object"}:
                    offenders.append(f"{path.name}: {owner}.{node.attr}")
    assert offenders == [], f"build a new object through its constructor instead: {offenders}"


# ------------------------------------------------------------------ the binding


def _bound(tmp_path: Path, repo: Path, finding: Path) -> tuple[Path, Path]:
    """A decided, bound claim. Returns the manifest path and the base directory."""
    records = records_for_file(finding, repo=repo, commit="a" * 40)
    decision = Decision(
        claim_id="c-1",
        status=Status.EXPLOITABLE,
        reason="the body reaches dispatch with no verification",
        decided_by="r@example",
    )
    decisions = {"c-1": decision}
    base = tmp_path / "work"
    base.mkdir(exist_ok=True)
    record_path = base / "record.json"
    record_path.write_text(
        json.dumps([record.to_dict() for record in records], indent=2), encoding="utf-8"
    )
    decisions_path = save_decisions([decision], base / "decisions.json")
    decided = [apply_decision(record, decision) for record in records]
    manifest = bind(
        decided,
        decisions,
        base=base,
        artifacts={"record": record_path, "decisions": decisions_path, "finding": finding},
        docket_version="0.3.0",
    )
    manifest_path = base / "binding.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path, base


def test_a_binding_verifies_and_re_reads_the_quoted_span(tmp_path, repo, finding):
    manifest_path, base = _bound(tmp_path, repo, finding)
    result = verify(load_manifest(manifest_path), base=base, repo=repo)
    assert result.overall is Verdict.VERIFIED
    assert any(check.kind == "span" for check in result.checks)
    assert "re-read from the repository" in result.coverage


def test_without_a_repository_the_span_checks_are_unverifiable(tmp_path, repo, finding):
    """Not `verified`. A check that did not run is not a check that passed."""
    manifest_path, base = _bound(tmp_path, repo, finding)
    result = verify(load_manifest(manifest_path), base=base, repo=None)
    assert result.overall is Verdict.UNVERIFIABLE
    assert "NOT re-read" in result.coverage


def test_an_edited_artifact_contradicts_the_binding(tmp_path, repo, finding):
    manifest_path, base = _bound(tmp_path, repo, finding)
    (base / "decisions.json").write_text(
        (base / "decisions.json").read_text(encoding="utf-8").replace("r@example", "someone-else"),
        encoding="utf-8",
    )
    result = verify(load_manifest(manifest_path), base=base, repo=repo)
    assert result.overall is Verdict.CONTRADICTED


def test_edited_code_contradicts_the_binding(tmp_path, repo, finding):
    """The check the digests alone cannot make: the record drifting away from its subject."""
    manifest_path, base = _bound(tmp_path, repo, finding)
    (repo / "app" / "handler.py").write_text(
        "def handle(request):\n    body = verify(request.body)\n    return dispatch(body)\n",
        encoding="utf-8",
    )
    result = verify(load_manifest(manifest_path), base=base, repo=repo)
    assert result.overall is Verdict.CONTRADICTED
    span = next(check for check in result.checks if check.kind == "span")
    assert span.verdict is Verdict.CONTRADICTED


def test_unverifiable_outranks_contradicted(tmp_path, repo, finding):
    """Both wrong and unreadable is reported as unreadable: less was established, not more."""
    manifest_path, base = _bound(tmp_path, repo, finding)
    (base / "decisions.json").write_text("{}", encoding="utf-8")
    (base / "record.json").unlink()
    result = verify(load_manifest(manifest_path), base=base, repo=repo)
    assert result.overall is Verdict.UNVERIFIABLE


def test_a_statement_wraps_the_manifest(tmp_path, repo, finding):
    manifest_path, _ = _bound(tmp_path, repo, finding)
    manifest = load_manifest(manifest_path)
    envelope = statement(manifest, subject_name="binding.json")
    assert envelope["_type"] == "https://in-toto.io/Statement/v1"
    assert envelope["predicateType"] == PREDICATE_TYPE
    assert envelope["predicate"]["format"] == FORMAT
    assert len(envelope["subject"][0]["digest"]["sha256"]) == 64


def test_a_foreign_manifest_is_refused(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"format": "attestrun/2"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a docket binding"):
        load_manifest(path)


# ------------------------------------------------------------------ the command line


def test_decide_bind_verify_end_to_end(tmp_path, repo, finding, capsys):
    work = tmp_path / "cli"
    work.mkdir()
    record_path = work / "record.json"
    assert (
        main(
            [
                "record",
                str(finding),
                "--repo",
                str(repo),
                "--commit",
                "a" * 40,
                "--out",
                str(work),
            ]
        )
        == 0
    )
    (work / "dispositions.json").rename(record_path)

    assert (
        main(
            [
                "decide",
                str(record_path),
                "--claim",
                "c-1",
                "--status",
                "exploitable",
                "--reason",
                "the body reaches dispatch unverified",
                "--decided-by",
                "r@example",
                "--decisions",
                str(work / "decisions.json"),
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "bind",
                str(record_path),
                "--decisions",
                str(work / "decisions.json"),
                "--finding",
                str(finding),
                "--base",
                str(work),
                "--out",
                str(work / "out"),
            ]
        )
        == 0
    )

    manifest = load_manifest(work / "out" / "binding.json")
    assert manifest["claims"][0]["status"] == "exploitable"
    vex = json.loads((work / "out" / "openvex.json").read_text(encoding="utf-8"))
    assert vex["statements"][0]["status"] == "affected"
    assert vex["statements"][0]["action_statement"]

    assert main(["verify", str(work / "out" / "binding.json"), "--base", str(work)]) == 0
    assert (
        main(
            [
                "verify",
                str(work / "out" / "binding.json"),
                "--base",
                str(work),
                "--repo",
                str(repo),
            ]
        )
        == 0
    )


def test_verify_exits_non_zero_when_contradicted(tmp_path, repo, finding):
    manifest_path, base = _bound(tmp_path, repo, finding)
    (base / "decisions.json").write_text("tampered", encoding="utf-8")
    assert main(["verify", str(manifest_path), "--base", str(base), "--repo", str(repo)]) == 1


def test_verify_exits_zero_when_merely_unverifiable(tmp_path, repo, finding):
    """An unknown is not a failure, so it does not fail a build unless asked."""
    manifest_path, base = _bound(tmp_path, repo, finding)
    assert main(["verify", str(manifest_path), "--base", str(base)]) == 0
    assert main(["verify", str(manifest_path), "--base", str(base), "--fail-on-unverifiable"]) == 1


def test_decide_refuses_an_unoffered_justification_at_the_command_line(tmp_path, repo, finding):
    work = tmp_path / "cli2"
    work.mkdir()
    assert (
        main(
            ["record", str(finding), "--repo", str(repo), "--commit", "a" * 40, "--out", str(work)]
        )
        == 0
    )
    code = main(
        [
            "decide",
            str(work / "dispositions.json"),
            "--claim",
            "c-1",
            "--status",
            "not_exploitable",
            "--reason",
            "dead code",
            "--decided-by",
            "r@example",
            "--justification",
            "vulnerable_code_not_in_execute_path",
            "--decisions",
            str(work / "decisions.json"),
        ]
    )
    assert code == 2
    assert not (work / "decisions.json").exists()


# ------------------------------------------------------------------ the committed worked example

WORKED_EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "eval" / "worked-example"


def test_the_committed_worked_example_still_verifies():
    """The example in the README is re-derived here, so it cannot rot into a screenshot.

    Everything it needs is committed -- the finding, the target snapshot, the model recording, the
    record, the decision and the binding -- so this runs with no key and no network.
    """
    manifest = load_manifest(WORKED_EXAMPLE / "binding.json")
    result = verify(manifest, base=WORKED_EXAMPLE, repo=WORKED_EXAMPLE / "target")
    assert result.overall is Verdict.VERIFIED, [
        (check.subject, check.detail)
        for check in result.checks
        if check.verdict is not Verdict.VERIFIED
    ]
    assert manifest["claims"][0]["status"] == "exploitable"


def test_the_worked_example_is_unverifiable_without_its_repository():
    manifest = load_manifest(WORKED_EXAMPLE / "binding.json")
    assert verify(manifest, base=WORKED_EXAMPLE, repo=None).overall is Verdict.UNVERIFIABLE


def test_the_worked_example_s_recorded_verdicts_match_a_fresh_run():
    """The three JSON verdicts committed beside it are what this code produces today."""
    manifest = load_manifest(WORKED_EXAMPLE / "binding.json")
    recorded = json.loads(
        (WORKED_EXAMPLE / "verifications" / "verified.json").read_text(encoding="utf-8")
    )
    fresh = verify(manifest, base=WORKED_EXAMPLE, repo=WORKED_EXAMPLE / "target")
    assert recorded["verdict"] == fresh.overall.value
    assert len(recorded["checks"]) == len(fresh.checks)

    for name in ("unverifiable", "contradicted"):
        payload = json.loads(
            (WORKED_EXAMPLE / "verifications" / f"{name}.json").read_text(encoding="utf-8")
        )
        assert payload["verdict"] == name
