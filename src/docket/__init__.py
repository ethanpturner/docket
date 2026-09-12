"""docket: the record of what was claimed, what was checked, and who decided.

Five commands. The first two decide nothing; the third is where a person does; the last two make
that decision checkable afterwards.

    docket record FINDING --repo PATH --commit SHA [--out DIR] [--format json|markdown|vex]
    docket assess FINDING --repo PATH --commit SHA [--no-model] [--record F | --replay F]
    docket decide RECORD --claim ID --status S --reason R --decided-by WHO [--justification J]
    docket bind   RECORD --decisions F --finding F --out DIR
    docket verify MANIFEST [--repo PATH]

`record` answers the question that needs no model: does this claim point at code that exists?
`assess` adds the five questions OpenVEX allows a dismissal to rest on, answering two of them
mechanically and asking a model the other three. Neither reaches a status.

`decide` is what the first two refuse in favour of. A person sets the status, names themselves,
gives a reason, and selects a justification from the fixed catalogue when the status needs one. A
justification the evidence never offered is refused unless they say they are overriding it, and
that override is recorded rather than smoothed into agreement.

`bind` digests the claim, the record, the model calls and the decision into one manifest; `verify`
re-derives it -- the artifact digests, and the quoted spans re-read from the repository. Without a
repository those span checks are `unverifiable`, and the coverage line says so rather than leaving
a reader to infer it from which flags were passed.

`record` and `assess` always exit 0, because a triage tool that blocks a pipeline on its first run
is uninstalled before anyone reads its output; gating is opt-in through `--fail-on-unresolved`.
`verify` exits non-zero on `contradicted`, which is a statement that something recorded here is no
longer true, and zero on `unverifiable` unless asked otherwise: an unknown is not a failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from docket._version import __version__
from docket.assess import assess_records
from docket.binding import bind as bind_manifest
from docket.binding import load_manifest, statement
from docket.binding import verify as verify_binding
from docket.decision import (
    Decision,
    DecisionError,
    apply_decision,
    load_decisions,
    save_decisions,
)
from docket.disposition import DispositionRecord, Status, record_for, record_from_dict
from docket.ingest import IngestError, load_claims
from docket.model import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OpenAICompatibleModel,
    RecordingModel,
    ReplayModel,
    StructuredModel,
)
from docket.render import render_evidence_markdown, render_markdown
from docket.resolve import resolve_locator
from docket.verdict import Verdict
from docket.vex import JUSTIFICATIONS, vex_document

if TYPE_CHECKING:
    from docket.claim import Claim
    from docket.evidence import EvidenceRecord

__all__ = ["__version__", "main", "records_for_file"]


def records_for_file(finding: Path, *, repo: Path, commit: str) -> list[DispositionRecord]:
    """Every claim in `finding`, checked against `repo`, as Phase 0 records."""
    claims: list[Claim] = load_claims(finding)
    return [
        record_for(
            claim,
            repository=str(repo),
            commit=commit,
            locators=tuple(resolve_locator(locator, repo) for locator in claim.locators),
        )
        for claim in claims
    ]


def _write(directory: Path, name: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    destination.write_text(content, encoding="utf-8")
    return destination


def _emit(
    records: list[DispositionRecord],
    *,
    fmt: str,
    out: Path | None,
    author: str,
    product: str,
) -> None:
    if fmt == "markdown":
        pages = [render_markdown(record) for record in records]
        if out is None:
            print("\n---\n\n".join(pages), end="")
            return
        for record, page in zip(records, pages, strict=True):
            written = _write(out, f"{record.claim.claim_id}.md", page)
            print(f"wrote {written}", file=sys.stderr)
        return

    if fmt == "vex":
        document = vex_document(
            records,
            author=author,
            document_id=f"https://openvex.dev/docs/docket/{records[0].claim.claim_id}",
            product_id=product,
        )
        payload = json.dumps(document, indent=2)
        if out is None:
            print(payload)
            return
        print(f"wrote {_write(out, 'openvex.json', payload)}", file=sys.stderr)
        return

    payload = json.dumps([record.to_dict() for record in records], indent=2)
    if out is None:
        print(payload)
        return
    print(f"wrote {_write(out, 'dispositions.json', payload)}", file=sys.stderr)


def _emit_evidence(
    records: list[EvidenceRecord],
    *,
    fmt: str,
    out: Path | None,
    author: str,
    product: str,
) -> None:
    if fmt == "markdown":
        pages = [render_evidence_markdown(record) for record in records]
        if out is None:
            print("\n---\n\n".join(pages), end="")
            return
        for record, page in zip(records, pages, strict=True):
            written = _write(out, f"{record.disposition.claim.claim_id}.md", page)
            print(f"wrote {written}", file=sys.stderr)
        return

    if fmt == "vex":
        _emit(
            [record.disposition for record in records],
            fmt="vex",
            out=out,
            author=author,
            product=product,
        )
        return

    payload = json.dumps([record.to_dict() for record in records], indent=2)
    if out is None:
        print(payload)
        return
    print(f"wrote {_write(out, 'assessments.json', payload)}", file=sys.stderr)


def _load_record_file(path: Path) -> tuple[list[DispositionRecord], list[dict[str, Any]]]:
    """Records and their raw JSON, from a file `record` or `assess` wrote.

    Both are returned because the raw form carries the assessment -- the five questions and their
    candidate justifications -- which the record objects do not. `decide` needs the candidates to
    know whether a selected justification is an override.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise DecisionError(f"{path} is not a docket record file")
    return [record_from_dict(entry) for entry in data], data


def _candidates_in(raw: dict[str, Any]) -> tuple[str, ...]:
    """The candidate justifications the assessment offered, from the raw record."""
    assessment = raw.get("assessment") or {}
    return tuple(
        str(item["justification"])
        for item in assessment.get("candidate_justifications") or ()
        if item.get("justification")
    )


def _cmd_decide(args: argparse.Namespace) -> int:
    records, raw = _load_record_file(args.record_file)
    index = {
        record.claim.claim_id: (record, entry) for record, entry in zip(records, raw, strict=True)
    }
    if args.claim not in index:
        known = ", ".join(sorted(index)) or "none"
        print(
            f"docket: {args.record_file} holds no claim {args.claim!r} (holds: {known})",
            file=sys.stderr,
        )
        return 2

    _, entry = index[args.claim]
    candidates = _candidates_in(entry)
    decision = Decision(
        claim_id=args.claim,
        status=Status(args.status),
        reason=args.reason,
        decided_by=args.decided_by,
        justification=args.justification,
        impact_statement=args.impact_statement,
        override=args.override,
        decided_at=datetime.now(UTC),
    )
    if (
        decision.justification is not None
        and not decision.overrides_evidence
        and decision.justification not in candidates
    ):
        offered = ", ".join(candidates) if candidates else "none"
        print(
            f"docket: the assessment did not offer {decision.justification!r} as a candidate "
            f"(offered: {offered}).\n"
            f"        Selecting it is deciding against the gathered evidence, which is allowed "
            f"and recorded.\n"
            f"        Pass --override with your reason.",
            file=sys.stderr,
        )
        return 2

    existing = load_decisions(args.decisions) if args.decisions.exists() else {}
    existing[decision.claim_id] = decision
    save_decisions(existing.values(), args.decisions)
    label = decision.justification or "(no justification)"
    note = " [overrides the evidence]" if decision.overrides_evidence else ""
    print(
        f"{decision.claim_id}: {decision.status.value} / {label} by {decision.decided_by}{note}",
        file=sys.stderr,
    )
    print(f"wrote {args.decisions}", file=sys.stderr)
    return 0


def _cmd_bind(args: argparse.Namespace) -> int:
    records, raw = _load_record_file(args.record_file)
    decisions = load_decisions(args.decisions)

    decided: list[DispositionRecord] = []
    for record, entry in zip(records, raw, strict=True):
        decision = decisions.get(record.claim.claim_id)
        if decision is None:
            decided.append(record)
            continue
        # The candidate check runs again here rather than being trusted from `decide`, because a
        # decision file is meant to be hand-edited and the edit is where an override goes missing.
        candidates = _candidates_in(entry)
        if (
            decision.justification is not None
            and not decision.overrides_evidence
            and decision.justification not in candidates
        ):
            offered = ", ".join(candidates) if candidates else "none"
            print(
                f"docket: claim {decision.claim_id}: the decision file selects "
                f"{decision.justification!r}, which the assessment did not offer (offered: "
                f"{offered}). Add an override reason.",
                file=sys.stderr,
            )
            return 2
        decided.append(apply_decision(record, decision))

    artifacts: dict[str, Path] = {"record": args.record_file, "decisions": args.decisions}
    if args.finding is not None:
        artifacts["finding"] = args.finding
    if args.recording is not None:
        artifacts["recording"] = args.recording

    base = args.base or Path.cwd()
    manifest = bind_manifest(
        decided,
        decisions,
        base=base,
        artifacts=artifacts,
        docket_version=__version__,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "binding.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {manifest_path}", file=sys.stderr)

    envelope = statement(manifest, subject_name=args.subject or manifest_path.name)
    envelope_path = args.out / "binding.statement.json"
    envelope_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {envelope_path}", file=sys.stderr)

    product = args.product or f"file://{Path(decided[0].repository).resolve()}"
    document = vex_document(
        decided,
        author=args.author,
        document_id=f"https://openvex.dev/docs/docket/{decided[0].claim.claim_id}",
        product_id=product,
    )
    vex_path = args.out / "openvex.json"
    vex_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {vex_path}", file=sys.stderr)

    if manifest["undecided_claims"]:
        undecided = ", ".join(manifest["undecided_claims"])
        print(f"docket: bound with undecided claims: {undecided}", file=sys.stderr)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    base = args.base or args.manifest.parent
    result = verify_binding(manifest, base=base, repo=args.repo)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for check in result.checks:
            print(f"  {check.verdict.value:<13} {check.subject}: {check.detail}")
        print(f"\n{result.overall.value}")
        print(f"coverage: {result.coverage}")
        print(f"scope: {manifest.get('scope', '')}")

    if result.overall is Verdict.CONTRADICTED:
        return 1
    if result.overall is Verdict.UNVERIFIABLE and args.fail_on_unverifiable:
        return 1
    return 0


def _model_for(args: argparse.Namespace) -> StructuredModel | None:
    """The model for this run, or None when the deterministic questions are all that is wanted."""
    if args.replay is not None:
        return ReplayModel.from_path(args.replay, model=args.model)
    if args.no_model:
        return None
    live: StructuredModel = OpenAICompatibleModel(model=args.model, base_url=args.base_url)
    if args.record is not None:
        return RecordingModel(inner=live, path=args.record)
    return live


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="docket",
        description=(
            "Record the disposition of a security finding: what was claimed, what was checked, "
            "and what nobody has decided."
        ),
    )
    parser.add_argument("--version", action="version", version=f"docket {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    recorder = subparsers.add_parser(
        "record", help="read a finding, resolve its locators, write the record"
    )
    recorder.add_argument("finding", type=Path, help="SARIF, a findings JSON, a feed, or text")
    recorder.add_argument("--repo", type=Path, required=True, help="the worktree to check against")
    recorder.add_argument(
        "--commit", required=True, help="the commit the worktree is at; recorded, never inferred"
    )
    recorder.add_argument("--out", type=Path, default=None, help="write here instead of stdout")
    recorder.add_argument(
        "--format", choices=("json", "markdown", "vex"), default="json", dest="fmt"
    )
    recorder.add_argument(
        "--author",
        default="docket",
        help="the VEX document's author; a machine-readable identity is preferred",
    )
    recorder.add_argument(
        "--product",
        default=None,
        help="the VEX product identifier, ideally a package URL. Defaults to the repository path.",
    )
    recorder.add_argument(
        "--fail-on-unresolved",
        action="store_true",
        help=(
            "exit 1 when a claim cites positions and none resolve. Off by default: a tool that "
            "arrives blocking gets uninstalled before anyone reads a finding."
        ),
    )

    assessor = subparsers.add_parser(
        "assess",
        help="gather evidence for the five questions; still decides nothing",
    )
    assessor.add_argument("finding", type=Path, help="SARIF, a findings JSON, a feed, or text")
    assessor.add_argument("--repo", type=Path, required=True, help="the worktree to check against")
    assessor.add_argument(
        "--commit", required=True, help="the commit the worktree is at; recorded, never inferred"
    )
    assessor.add_argument("--out", type=Path, default=None, help="write here instead of stdout")
    assessor.add_argument(
        "--format", choices=("json", "markdown", "vex"), default="json", dest="fmt"
    )
    assessor.add_argument("--model", default=DEFAULT_MODEL, help="the model to gather with")
    assessor.add_argument("--base-url", default=DEFAULT_BASE_URL, help="an OpenAI-compatible API")
    assessor.add_argument(
        "--record", type=Path, default=None, help="append every model call to this JSONL recording"
    )
    assessor.add_argument(
        "--replay",
        type=Path,
        default=None,
        help="serve responses from this recording and never reach the network",
    )
    assessor.add_argument(
        "--no-model",
        action="store_true",
        help="answer only the two deterministic questions; costs nothing",
    )
    assessor.add_argument("--author", default="docket", help="the VEX document's author")
    assessor.add_argument("--product", default=None, help="the VEX product identifier")

    decider = subparsers.add_parser(
        "decide",
        help="a person sets the status, names themselves, and gives a reason",
    )
    decider.add_argument(
        "record_file", type=Path, metavar="RECORD", help="the JSON `record` or `assess` wrote"
    )
    decider.add_argument("--claim", required=True, help="the claim being decided")
    decider.add_argument(
        "--status", required=True, choices=tuple(item.value for item in Status), help="the verdict"
    )
    decider.add_argument("--reason", required=True, help="why, in your own words; never optional")
    decider.add_argument(
        "--decided-by", required=True, dest="decided_by", help="who is deciding; not authenticated"
    )
    decider.add_argument(
        "--justification",
        default=None,
        choices=JUSTIFICATIONS,
        help="the OpenVEX label, on `not_exploitable` only",
    )
    decider.add_argument(
        "--impact-statement",
        default=None,
        dest="impact_statement",
        help="the spec's free-prose alternative to a justification",
    )
    decider.add_argument(
        "--override",
        default=None,
        help=(
            "your reason for selecting a justification the assessment did not offer. Required to "
            "do so, and recorded: deciding against the evidence is legitimate and must be legible."
        ),
    )
    decider.add_argument(
        "--decisions",
        type=Path,
        default=Path("decisions.json"),
        help="the decision file to write or update",
    )

    binder = subparsers.add_parser(
        "bind", help="digest the claim, the record, the model calls and the decision into one file"
    )
    binder.add_argument("record_file", type=Path, metavar="RECORD", help="the record JSON")
    binder.add_argument("--decisions", type=Path, required=True, help="the decision file")
    binder.add_argument(
        "--finding", type=Path, default=None, help="the inbound finding as received"
    )
    binder.add_argument("--recording", type=Path, default=None, help="the model-call recording")
    binder.add_argument("--out", type=Path, required=True, help="write the binding here")
    binder.add_argument(
        "--base",
        type=Path,
        default=None,
        help="the directory artifact paths are recorded relative to. Defaults to the cwd.",
    )
    binder.add_argument("--subject", default=None, help="the in-toto subject name")
    binder.add_argument("--author", default="docket", help="the VEX document's author")
    binder.add_argument("--product", default=None, help="the VEX product identifier")

    verifier = subparsers.add_parser(
        "verify", help="re-digest the artifacts and re-read the quoted spans"
    )
    verifier.add_argument("manifest", type=Path, help="the binding to check")
    verifier.add_argument(
        "--repo",
        type=Path,
        default=None,
        help=(
            "the worktree to re-read the quoted spans from. Without it those checks are "
            "`unverifiable`, and the coverage line says so."
        ),
    )
    verifier.add_argument(
        "--base",
        type=Path,
        default=None,
        help="the directory artifact paths are relative to. Defaults to the manifest's directory.",
    )
    verifier.add_argument("--json", action="store_true", help="machine-readable output")
    verifier.add_argument(
        "--fail-on-unverifiable",
        action="store_true",
        dest="fail_on_unverifiable",
        help="exit 1 when a check could not run. Off by default: an unknown is not a failure.",
    )

    args = parser.parse_args(argv)

    if args.command in ("decide", "bind", "verify"):
        handlers = {"decide": _cmd_decide, "bind": _cmd_bind, "verify": _cmd_verify}
        try:
            return handlers[args.command](args)
        except (DecisionError, ValueError) as error:
            print(f"docket: {error}", file=sys.stderr)
            return 2
        except OSError as error:
            print(f"docket: {error}", file=sys.stderr)
            return 2

    if not args.repo.is_dir():
        print(f"docket: {args.repo} is not a directory", file=sys.stderr)
        return 2
    try:
        records = records_for_file(args.finding, repo=args.repo, commit=args.commit)
    except (IngestError, OSError) as error:
        print(f"docket: {error}", file=sys.stderr)
        return 2

    if not records:
        print("docket: the file holds no claims", file=sys.stderr)
        return 0

    product = args.product or f"file://{args.repo.resolve()}"

    if args.command == "assess":
        assessed = assess_records(records, repo=args.repo, model=_model_for(args))
        _emit_evidence(assessed, fmt=args.fmt, out=args.out, author=args.author, product=product)
        return 0

    _emit(records, fmt=args.fmt, out=args.out, author=args.author, product=product)

    if args.fail_on_unresolved and any(record.fully_unresolved for record in records):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
