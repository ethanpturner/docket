"""Binding a decision to the material it was made from, so a reader can check it later.

A disposition is worth something only if somebody can tell, months afterwards, what it was decided
against. The claim as it arrived, the commit, the spans that were quoted, the model calls that were
made, and the reviewer's own words are all separate files by the time a decision exists, and any
of them can be edited without the others noticing. A binding is the digest chain that makes that
editing visible.

**Two kinds of check, and they are not equally strong.** Re-digesting the recorded artifacts
answers "are these the same files", which is worth having and is only a statement about bytes on
this machine. Re-deriving the quoted spans from the repository answers "does the code still say
what the record quotes", which is a statement about the thing the decision was actually about. The
second is the one that catches a record drifting away from its subject while every file around it
stays byte-identical, and it is the reason a repository is worth passing to `verify` even though
it is optional.

**A missing repository is `unverifiable`, never `verified`.** Verification without the worktree
checks the artifacts and says so; it does not report success over a check it did not run. This is
the same rule the disposition vocabulary exists for, one level up, and the coverage bound is
printed on every verification rather than left for a reader to infer from which flags were passed.

**Nothing here is signed.** The manifest is emitted in in-toto Statement shape so that `cosign` or
any other signer can place a signature over it without learning anything about docket, and the
README records the two commands. Emitting an unsigned envelope and calling it an attestation would
be the same category error as recording an unchecked dismissal as a checked one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from docket.hashing import content_hash, verify_hash
from docket.resolve import Resolution, resolve_locator
from docket.verdict import Verdict

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from docket.decision import Decision
    from docket.disposition import DispositionRecord

__all__ = [
    "FORMAT",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "Binding",
    "Check",
    "bind",
    "load_manifest",
    "statement",
    "verify",
]

FORMAT: Final = "docket/binding/v1"
STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE: Final = "https://github.com/ethanpturner/docket/binding/v1"

SCOPE: Final = (
    "This manifest records that the listed artifacts had the listed digests when the decision was "
    "made, and that the quoted spans were the bytes at the cited positions of the named commit. It "
    "does not claim the decision is correct, and it does not claim anything about material it was "
    "not told to digest."
)


@dataclass(frozen=True, slots=True)
class Check:
    """One thing verification looked at, and what it found."""

    subject: str
    verdict: Verdict
    detail: str
    kind: str = "artifact"
    """`artifact` for a digested file, `span` for a quoted position re-read from the repository."""


@dataclass(slots=True)
class Binding:
    """The result of verifying one manifest."""

    manifest_path: str
    checks: list[Check] = field(default_factory=list)
    repository_checked: bool = False

    @property
    def overall(self) -> Verdict:
        return Verdict.combine([check.verdict for check in self.checks])

    @property
    def coverage(self) -> str:
        """What this verification did and did not cover, in the words a reader needs."""
        artifacts = sum(1 for check in self.checks if check.kind == "artifact")
        spans = sum(1 for check in self.checks if check.kind == "span")
        if self.repository_checked:
            return (
                f"{artifacts} artifact digests re-computed and {spans} quoted spans re-read from "
                f"the repository."
            )
        return (
            f"{artifacts} artifact digests re-computed. The quoted spans were NOT re-read: no "
            f"repository was given, so nothing here establishes that the code still says what the "
            f"record quotes."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest_path,
            "verdict": self.overall.value,
            "coverage": self.coverage,
            "checks": [
                {
                    "kind": check.kind,
                    "subject": check.subject,
                    "verdict": check.verdict.value,
                    "detail": check.detail,
                }
                for check in self.checks
            ],
        }


def _artifact(base: Path, path: Path, role: str) -> dict[str, Any]:
    """One digested file. An unreadable file records `null`, never a placeholder digest.

    A synthetic value would compare unequal on every later verification and report `contradicted`
    for a file that was simply missing, which is the collapse this project exists to refuse.
    """
    try:
        digest: str | None = content_hash(path.read_bytes())
        size: int | None = path.stat().st_size
    except OSError:
        digest, size = None, None
    try:
        name = str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        name = str(path)
    return {"role": role, "path": name, "sha256": digest, "size": size}


def _spans(records: Iterable[DispositionRecord]) -> list[dict[str, Any]]:
    """Every resolved position the record quotes, with the digest of what was there.

    Only resolved locators appear. An unresolved one has no bytes to re-derive, and listing it
    with a null digest would put a check in the chain that can never do anything but abstain.
    """
    out: list[dict[str, Any]] = []
    for record in records:
        for item in record.locators:
            if item.resolution is not Resolution.RESOLVES or item.content_hash is None:
                continue
            out.append(
                {
                    "claim_id": record.claim.claim_id,
                    "locator": item.locator,
                    "path": item.path,
                    "start_line": item.start_line,
                    "end_line": item.end_line,
                    "sha256": item.content_hash,
                    "truncated": item.truncated,
                }
            )
    return out


def bind(
    records: list[DispositionRecord],
    decisions: dict[str, Decision],
    *,
    base: Path,
    artifacts: dict[str, Path],
    docket_version: str,
) -> dict[str, Any]:
    """The manifest for a decided set of claims.

    `artifacts` maps a role -- `finding`, `assessment`, `recording`, `decisions` -- to the file
    that holds it. Roles are named rather than positional so that a manifest missing one is
    legible: a binding with no `recording` is a decision made without a model, which is a fact
    about the decision and not an omission to paper over.
    """
    if not records:
        raise ValueError("a binding needs at least one record")
    undecided = [
        record.claim.claim_id
        for record in records
        if record.claim.claim_id not in decisions and not record.disposition.is_decided
    ]
    return {
        "format": FORMAT,
        "bound_at": datetime.now(UTC).isoformat(),
        "docket_version": docket_version,
        "scope": SCOPE,
        "target": {
            "repository": records[0].repository,
            "commit": records[0].commit,
        },
        "claims": [
            {
                "claim_id": record.claim.claim_id,
                "status": record.disposition.status.value,
                "justification": record.disposition.justification,
                "decided_by": record.disposition.decided_by,
                "overrides_evidence": record.disposition.override_reason is not None,
            }
            for record in records
        ],
        "undecided_claims": undecided,
        "artifacts": [
            _artifact(base, path, role) for role, path in sorted(artifacts.items()) if path
        ],
        "quoted_spans": _spans(records),
    }


def verify(manifest: dict[str, Any], *, base: Path, repo: Path | None = None) -> Binding:
    """Re-digest the artifacts, and re-read the quoted spans when a repository is given."""
    binding = Binding(manifest_path=str(base), repository_checked=repo is not None)

    artifacts = manifest.get("artifacts") or []
    spans = manifest.get("quoted_spans") or []
    if not artifacts and not spans:
        binding.checks.append(
            Check(
                "(nothing recorded)",
                Verdict.UNVERIFIABLE,
                "the manifest digests no artifacts and quotes no spans",
                kind="artifact",
            )
        )
        return binding

    for entry in artifacts:
        name = f"{entry.get('role', '?')}: {entry.get('path', '?')}"
        recorded = entry.get("sha256")
        if recorded is None:
            binding.checks.append(
                Check(
                    name,
                    Verdict.UNVERIFIABLE,
                    "no digest was recorded; the file was unreadable when the binding was made",
                )
            )
            continue
        path = base / str(entry["path"])
        try:
            data = path.read_bytes()
        except OSError as error:
            binding.checks.append(Check(name, Verdict.UNVERIFIABLE, f"cannot be read: {error}"))
            continue
        if verify_hash(str(recorded), data):
            binding.checks.append(Check(name, Verdict.VERIFIED, "digest matches"))
        else:
            actual = content_hash(data)
            binding.checks.append(
                Check(
                    name,
                    Verdict.CONTRADICTED,
                    f"contents moved: {actual[:19]}... != {str(recorded)[:19]}...",
                )
            )

    for entry in spans:
        name = f"span: {entry.get('claim_id', '?')} {entry.get('locator', '?')}"
        if repo is None:
            binding.checks.append(
                Check(
                    name,
                    Verdict.UNVERIFIABLE,
                    "no repository given; the quoted bytes were not re-read",
                    kind="span",
                )
            )
            continue
        # Re-resolving the recorded locator rather than reading the path directly: one code path
        # produces a quotation and one code path checks it, so the truncation cap and the
        # repository-containment rule cannot drift apart between recording and verification.
        again = resolve_locator(str(entry.get("locator", "")), repo)
        if again.resolution is not Resolution.RESOLVES or again.content_hash is None:
            binding.checks.append(
                Check(
                    name,
                    Verdict.UNVERIFIABLE,
                    f"the cited position does not resolve at this worktree "
                    f"({again.resolution.value}); nothing was re-read to compare",
                    kind="span",
                )
            )
            continue
        if again.content_hash == entry.get("sha256"):
            binding.checks.append(
                Check(
                    name,
                    Verdict.VERIFIED,
                    "the code at the cited position is byte-identical to what was quoted",
                    kind="span",
                )
            )
        else:
            binding.checks.append(
                Check(
                    name,
                    Verdict.CONTRADICTED,
                    "the code at the cited position is not what the record quotes",
                    kind="span",
                )
            )

    return binding


def statement(manifest: dict[str, Any], subject_name: str) -> dict[str, Any]:
    """Wrap a manifest as an in-toto Statement v1, unsigned.

    The subject is the digest of the manifest's own canonical bytes. attestrun's Statement points
    at a recorded command's output, because that is the thing its verification re-derives; there
    is no command here, and the thing a signature should cover is the whole digest chain. Signing
    it with `cosign attest-blob` binds an identity to that chain without either tool changing.
    """
    if manifest.get("format") != FORMAT:
        raise ValueError(f"not a docket binding (expected format {FORMAT!r})")
    payload = canonical_bytes(manifest)
    digest = content_hash(payload).split(":", 1)[1]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": manifest,
    }


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    """The manifest's bytes for hashing: sorted keys, compact separators, UTF-8.

    Canonical rather than as-written, so that a manifest re-serialised by another tool still
    hashes the same. A digest over incidental whitespace would report `contradicted` for a
    reformatting, which is the false positive this project spends its effort avoiding.
    """
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_manifest(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != FORMAT:
        raise ValueError(f"{path} is not a docket binding (expected format {FORMAT!r})")
    return data
