"""docket: the record of what was claimed, what was checked, and what nobody decided.

Phase 0 ships the part that needs no model. Given a finding and a repository at a pinned commit,
it answers one question mechanically: does this claim point at code that exists? Everything else
is recorded as received and left undetermined.

The command:

    docket record FINDING --repo PATH --commit SHA [--out DIR] [--format json|markdown|vex]

It always exits 0. A triage tool that blocks a pipeline on its first run gets uninstalled before
anyone reads its output, so gating is opt-in through `--fail-on-unresolved`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from docket.disposition import DispositionRecord, record_for
from docket.ingest import IngestError, load_claims
from docket.render import render_markdown
from docket.resolve import resolve_locator
from docket.vex import vex_document

if TYPE_CHECKING:
    from docket.claim import Claim

__version__ = "0.1.0"

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

    args = parser.parse_args(argv)

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

    _emit(
        records,
        fmt=args.fmt,
        out=args.out,
        author=args.author,
        product=args.product or f"file://{args.repo.resolve()}",
    )

    if args.fail_on_unresolved and any(record.fully_unresolved for record in records):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
