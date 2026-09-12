# docket

Records the disposition of a security finding: exploitable, not exploitable, or undetermined, with
the evidence behind it.

A triage queue asks one question all day. Somebody asserted a weakness. Is it real? There are three
honest answers and every tool records two of them. The third, *nobody has established either way*,
is the one an auditor asks about, the one a maintainer spends their week on, and the one that
currently gets written down as a pass.

```
docket record findings.sarif --repo ./app --commit 9f2c1ab --format vex
```

## What Phase 0 does

Given a finding and a repository at a pinned commit, it answers the part that needs no model: does
this claim point at code that exists?

- **Reads** SARIF 2.1.0, Codex Security's `findings.json`, JSON Lines feeds from agentic reviewers,
  and plain text. A report with no structure yields one claim with no locators, because prose names
  a file and does not cite one.
- **Resolves** every cited `path`, `path:line`, or `path:start-end` against the worktree: `resolves`,
  `path_absent`, `line_out_of_range`, or `not_a_locator`. It quotes the cited span and hashes it.
- **Records** the claim as received, the resolutions, and a disposition. In Phase 0 that disposition
  is always `undetermined`, reason `no assessment performed`.
- **Emits** OpenVEX beside the record, so a scanner that already consumes VEX can act on it.

## What it refuses to do

**It does not decide whether a finding is real.** There is no code path in Phase 0 that produces any
status but `undetermined`, and `tests/test_disposition.py` walks the syntax tree to pin that. A
resolving locator means the citation is checkable, not that the code is vulnerable. A failing one
means the citation is broken, not that the weakness is absent.

**It does not guess a path.** A claim citing `app.py` when the repository holds `src/app.py` is
`path_absent`. Searching for a plausible match would turn a broken citation into a working one and
hide the failure the check exists to surface.

**It does not interpret an inbound report.** The text is carried verbatim, quoted inside a fence that
it cannot close, and never read as instructions. A report is evidence that a claim was made. It is
not evidence of the weakness it describes.

## The three-valued vocabulary

The vocabulary is not invented here. OpenVEX already has it, and tools like Grype already consume
VEX documents as a filter.

| docket | OpenVEX | Meaning |
|---|---|---|
| `exploitable` | `affected` | the evidence supports the claim |
| `not_exploitable` | `not_affected` | the evidence contradicts it, and the reason is named |
| `undetermined` | `under_investigation` | nobody has established either |

OpenVEX requires a `justification` or an `impact_statement` on any `not_affected` statement. That is
the same discipline this tool applies anyway: a dismissal states its argument. A status with no
reason is refused at construction.

## Measured

Run over the sixteen scored runs of two agentic reviewers against two applications, at
`trace@c5b0590`. Every locator each tool cited, checked against the code it reviewed:

| Tool | Runs | Claims | Locators cited | Resolve | Rate |
|---|---:|---:|---:|---:|---:|
| Codex Security 0.1.26 | 3 | 9 | 34 | 34 | 100% |
| Mantis @ `d13c93f` | 10 | 72 | 164 | 140 | 85% |

The 24 that do not resolve are one failure mode and one arithmetic error. Twenty-two are Mantis
citing the absolute path of its own scratch directory rather than a repository-relative path, in
three of its ten runs; every locator in those runs is unusable. Two cite line 36 of a 35-line file.

Per claim rather than per locator, 22 of Mantis's 72 claims cite nothing that resolves, so a reviewer
reading those has no position to start from. Codex Security has none.

Reproduce it with `scripts/measure_feeds.py RUNS_DIR WORKTREE COMMIT`. No model calls, no network.

## Status

Phase 0. The record and the resolver are here; a person sets a status, and nothing yet helps them.
Later phases gather evidence for that decision and sign the result. The gathering will use a model
and the deciding will not.

Install from a clone: `uv sync`, then `uv run docket --help`.

MIT.
