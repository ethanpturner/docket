"""Reading a finding from whatever produced it.

Four shapes, one output. SARIF is the universal case; Mantis and Codex Security are the two
agentic reviewers this tool was measured against first; plain text is the bug bounty email, where
there is no structure to read and pretending otherwise would invent locators nobody cited.

**Nothing is inferred that was not written down.** A report that names no file yields a claim with
no locators, not a claim with a guessed one. A tool that gives no severity yields `None`, not
`medium`. The disposition record's value is that it distinguishes what was claimed from what was
checked, and a defaulted field destroys that distinction at the first step.

**Every ingest preserves the source's text verbatim.** `Claim.raw_text` is what a reviewer reads
and what the record quotes. It is carried, never summarised, and never parsed for instructions.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from pathlib import Path

from docket.claim import Claim, ClaimSource
from docket.hashing import hash_text

__all__ = ["IngestError", "detect_format", "load_claims"]


class IngestError(ValueError):
    """The file is not a finding in any format this tool reads."""


def _claim_id(prefix: str, *parts: str) -> str:
    """A stable identifier: the source's own where it has one, otherwise a content digest.

    The digest form means two ingests of one report produce one identifier, and two claims that
    differ anywhere produce two. A counter would produce neither property.
    """
    digest = hash_text(" ".join(parts)).split(":", 1)[1]
    return f"{prefix}-{digest[:16]}"


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


# --------------------------------------------------------------------------------------------
# SARIF 2.1.0


def _sarif_locators(result: dict[str, Any]) -> tuple[str, ...]:
    """Every physical location a result cites, as `path` or `path:start-end`.

    SARIF's `region` is optional and its `endLine` defaults to `startLine`; a location with
    neither yields a bare path, which resolves against the file's existence alone.
    """
    locators: list[str] = []
    for location in result.get("locations") or []:
        if not isinstance(location, dict):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        uri = _text(artifact.get("uri")) if isinstance(artifact, dict) else ""
        if not uri:
            continue
        region = physical.get("region")
        if isinstance(region, dict) and isinstance(region.get("startLine"), int):
            start = region["startLine"]
            end = region.get("endLine")
            end_line = end if isinstance(end, int) else start
            locators.append(f"{uri}:{start}-{end_line}" if end_line != start else f"{uri}:{start}")
        else:
            locators.append(uri)
    return tuple(locators)


def _from_sarif(payload: dict[str, Any], origin: Path) -> list[Claim]:
    claims: list[Claim] = []
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver")) or {}
        source = ClaimSource(
            tool=_text(driver.get("name")) or "unknown",
            version=_text(driver.get("version")) or None,
            format="sarif",
        )
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            message = _text((result.get("message") or {}).get("text"))
            rule = _text(result.get("ruleId"))
            title = message.splitlines()[0] if message else rule
            claims.append(
                Claim(
                    claim_id=_claim_id("sarif", origin.name, rule, message),
                    title=title,
                    raw_text=message,
                    locators=_sarif_locators(result),
                    weakness=rule or None,
                    severity=_text(result.get("level")) or None,
                    source=source,
                )
            )
    return claims


# --------------------------------------------------------------------------------------------
# Agentic reviewer JSON


def _agentic_claim(row: dict[str, Any], origin: Path, tool: str, fmt: str) -> Claim:
    """One row of a normalised agentic feed.

    Mantis spells `cwe` as a string and Codex Security as a list; both are carried as written,
    joined for display, never mapped to a canonical taxonomy. The row's own signature is the
    identifier where it has one, because that is the identity the producing tool assigned.
    """
    cwe = row.get("cwe")
    weakness = ", ".join(str(item) for item in cwe) if isinstance(cwe, list) else _text(cwe) or None
    signature = _text(row.get("signature")) or _text(row.get("finding_id"))
    title = _text(row.get("title"))
    paths = row.get("code_paths")
    locators = tuple(str(item) for item in paths) if isinstance(paths, list) else ()
    return Claim(
        claim_id=signature or _claim_id(fmt, origin.name, title),
        title=title,
        raw_text=json.dumps(row, indent=2, sort_keys=True),
        locators=locators,
        weakness=weakness,
        severity=_text(row.get("severity")) or None,
        source=ClaimSource(tool=tool, format=fmt),
    )


def _from_codex_findings(payload: dict[str, Any], origin: Path) -> list[Claim]:
    """Codex Security's native `findings.json`, whose locations carry start and end lines."""
    claims: list[Claim] = []
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        locators: list[str] = []
        for location in finding.get("locations") or []:
            if not isinstance(location, dict):
                continue
            path = _text(location.get("path"))
            if not path:
                continue
            start, end = location.get("startLine"), location.get("endLine")
            if isinstance(start, int):
                tail = f"{start}-{end}" if isinstance(end, int) and end != start else str(start)
                locators.append(f"{path}:{tail}")
            else:
                locators.append(path)
        identity = finding.get("identity")
        cwe = identity.get("cwe") if isinstance(identity, dict) else None
        severity = finding.get("severity")
        level = severity.get("level") if isinstance(severity, dict) else severity
        summary = _text(finding.get("summary"))
        claims.append(
            Claim(
                claim_id=_text(finding.get("findingId"))
                or _claim_id("codex", origin.name, summary),
                title=summary.splitlines()[0] if summary else _text(finding.get("ruleId")),
                raw_text=json.dumps(finding, indent=2, sort_keys=True),
                locators=tuple(locators),
                weakness=_text(cwe) or _text(finding.get("ruleId")) or None,
                severity=_text(level) or None,
                source=ClaimSource(tool="Codex Security", format="codex-security"),
            )
        )
    return claims


# --------------------------------------------------------------------------------------------
# Plain text


def _from_text(raw: str, origin: Path) -> list[Claim]:
    """A report with no structure: one claim, no locators, nothing extracted.

    A bug bounty email names files in prose, and a regular expression over prose would produce
    locators the reporter did not cite, which the record would then present as their claim. The
    honest reading of an unstructured report is that it cites nothing mechanically checkable, and
    a reviewer adds locators by hand.
    """
    first = ""
    for line in raw.splitlines():
        if line.strip():
            first = line.strip().lstrip("# ").strip()
            break
    return [
        Claim(
            claim_id=_claim_id("text", origin.name, raw),
            title=first,
            raw_text=raw,
            locators=(),
            source=ClaimSource(tool="unknown", format="text"),
        )
    ]


# --------------------------------------------------------------------------------------------


# Keys that identify a row of a normalised agentic feed. A one-line feed is a valid JSON object,
# so the shape rather than the parse is what tells it apart from a document.
_FEED_ROW_KEYS: Final = frozenset({"signature", "code_paths", "finding_id"})


def _is_feed(raw: str) -> bool:
    """Whether every non-empty line is a JSON object, which is what JSON Lines means."""
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return False
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(row, dict):
            return False
    return True


def detect_format(path: Path) -> str:
    """Which ingest reads this file, decided by content rather than by extension.

    A `.json` file is four different formats here, so the extension answers nothing; the shape
    does. An unrecognised JSON document is an error rather than a text claim, because silently
    treating structured input as prose would drop every locator in it.
    """
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if not stripped:
        return "empty"
    if not stripped.startswith("{"):
        return "text"

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # A multi-line JSON Lines feed starts with `{` and is not itself valid JSON.
        if _is_feed(raw):
            return "feed"
        raise IngestError(
            f"{path}: starts like JSON but is neither a JSON document nor JSON Lines"
        ) from None

    if isinstance(payload, dict):
        if "$schema" in payload or ("version" in payload and "runs" in payload):
            return "sarif"
        if "findings" in payload and "documentType" in payload:
            return "codex-findings"
        # A one-line feed: valid JSON, and a finding row rather than a document.
        if _FEED_ROW_KEYS & set(payload):
            return "feed"
    raise IngestError(
        f"{path}: a JSON object that is not SARIF and not a findings document. Supported: "
        f"SARIF 2.1.0, Codex Security findings.json, JSON Lines feeds, plain text."
    )


def load_claims(path: Path) -> list[Claim]:
    """Read every claim in `path`.

    The format is detected from the content. A file holding no claims returns an empty list
    rather than raising: an empty scan is a real result, and it should produce a record saying so.
    """
    fmt = detect_format(path)
    raw = path.read_text(encoding="utf-8")

    if fmt == "empty":
        return []
    if fmt == "text":
        return _from_text(raw, path)
    if fmt == "sarif":
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise IngestError(f"{path}: SARIF must be a JSON object")
        return _from_sarif(payload, path)
    if fmt == "codex-findings":
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise IngestError(f"{path}: a findings document must be a JSON object")
        return _from_codex_findings(payload, path)

    claims: list[Claim] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise IngestError(f"{path}:{number}: not a JSON object per line ({error})") from error
        if not isinstance(row, dict):
            raise IngestError(f"{path}:{number}: each line must be a JSON object")
        # The two reviewers' feeds differ only in how they spell their own identity.
        is_codex = _text(row.get("signature")).startswith("codex-security/")
        tool = "Codex Security" if is_codex else "Mantis"
        fmt_name = "codex-security" if is_codex else "mantis"
        claims.append(_agentic_claim(row, path, tool, fmt_name))
    return claims
