"""The VEX document against the spec's shape, and the command's contract."""

from __future__ import annotations

import json

import pytest

from docket import main, records_for_file
from docket.disposition import Disposition, DispositionRecord, Status
from docket.vex import CONTEXT, JUSTIFICATIONS, STATUS_MAP, vex_document

# OpenVEX v0.2.0: required at the document, and at a complete statement.
DOCUMENT_REQUIRED = {"@context", "@id", "author", "timestamp", "version", "statements"}
STATEMENT_REQUIRED = {"vulnerability", "products", "status"}
VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    return root


@pytest.fixture
def finding(tmp_path):
    path = tmp_path / "feed.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {
                    "signature": "s1",
                    "title": "One",
                    "code_paths": ["app.py:1"],
                    "cwe": "CWE-89",
                    "severity": "high",
                },
                {"signature": "s2", "title": "Two", "code_paths": ["missing.py:9"]},
            )
        ),
        encoding="utf-8",
    )
    return path


def test_vex_document_has_the_required_shape(repo, finding):
    records = records_for_file(finding, repo=repo, commit="c" * 40)
    document = vex_document(
        records,
        author="mailto:security@example.com",
        document_id="https://x/1",
        product_id="pkg:generic/app",
    )
    assert set(document) >= DOCUMENT_REQUIRED
    assert document["@context"] == CONTEXT
    assert isinstance(document["version"], int)
    assert document["statements"]
    for statement in document["statements"]:
        assert set(statement) >= STATEMENT_REQUIRED
        assert statement["status"] in VALID_STATUSES
        assert statement["vulnerability"]["name"]
        assert statement["products"] == [{"@id": "pkg:generic/app"}]
    assert json.dumps(document)


def test_undetermined_maps_to_under_investigation(repo, finding):
    records = records_for_file(finding, repo=repo, commit="c" * 40)
    document = vex_document(records, author="a", document_id="https://x/1", product_id="p")
    assert {s["status"] for s in document["statements"]} == {"under_investigation"}


def test_the_status_map_covers_every_status():
    assert set(STATUS_MAP) == set(Status)
    assert set(STATUS_MAP.values()) <= VALID_STATUSES
    assert len(JUSTIFICATIONS) == 5, "the spec's fixed catalogue, not an open vocabulary"


def test_not_affected_carries_an_argument(repo, finding):
    """The spec requires a justification or an impact statement for `not_affected`."""
    base = records_for_file(finding, repo=repo, commit="c" * 40)[0]
    decided = DispositionRecord(
        claim=base.claim,
        repository=base.repository,
        commit=base.commit,
        locators=base.locators,
        disposition=Disposition(
            status=Status.NOT_EXPLOITABLE,
            reason="the sink is unreachable from any entry point",
            decided_by="reviewer@example.com",
        ),
    )
    statement = vex_document([decided], author="a", document_id="https://x/1", product_id="p")[
        "statements"
    ][0]
    assert statement["status"] == "not_affected"
    assert statement["impact_statement"]


def test_an_empty_document_is_refused():
    with pytest.raises(ValueError, match="at least one statement"):
        vex_document([], author="a", document_id="https://x/1", product_id="p")


# -------------------------------------------------------------------------------------- CLI


def test_cli_writes_json_and_exits_zero(repo, finding, tmp_path, capsys):
    code = main(["record", str(finding), "--repo", str(repo), "--commit", "c" * 40])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 2
    assert {row["disposition"]["status"] for row in payload} == {"undetermined"}


def test_cli_never_gates_by_default(repo, finding):
    """Claim s2 cites a file that does not exist, and the command still exits 0."""
    assert main(["record", str(finding), "--repo", str(repo), "--commit", "c" * 40]) == 0


def test_cli_gates_only_when_asked(repo, finding):
    code = main(
        [
            "record",
            str(finding),
            "--repo",
            str(repo),
            "--commit",
            "c" * 40,
            "--fail-on-unresolved",
        ]
    )
    assert code == 1


def test_cli_writes_each_format(repo, finding, tmp_path):
    for fmt, expected in (("json", "dispositions.json"), ("vex", "openvex.json")):
        out = tmp_path / fmt
        assert (
            main(
                [
                    "record",
                    str(finding),
                    "--repo",
                    str(repo),
                    "--commit",
                    "c" * 40,
                    "--out",
                    str(out),
                    "--format",
                    fmt,
                ]
            )
            == 0
        )
        assert json.loads((out / expected).read_text(encoding="utf-8"))

    out = tmp_path / "md"
    assert (
        main(
            [
                "record",
                str(finding),
                "--repo",
                str(repo),
                "--commit",
                "c" * 40,
                "--out",
                str(out),
                "--format",
                "markdown",
            ]
        )
        == 0
    )
    assert len(list(out.glob("*.md"))) == 2


def test_cli_refuses_a_missing_repository(finding, tmp_path):
    assert main(["record", str(finding), "--repo", str(tmp_path / "nope"), "--commit", "c"]) == 2
