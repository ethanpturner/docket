# Checks that cannot come out false

**Audited:** 2026-09-14, across this repository and its three siblings. Detector at
`scripts/audit_unfailable.py`; findings for the other repositories are on their own pages.

Six defects of one class turned up across two repositories in two days, and three of them were
here, in a tool that was three days old. That is the reason for this page. The defects were not
subtle and they were not caught by review:

- a `not_affected` status required a justification or an impact statement, and the emitter fell
  back to the reviewer's `reason`, which is always present, so the requirement could never fire
  (`DEC-009`);
- two of the five evidence questions were shown to a gatherer as the negation of the label they
  were filed under, so evidence that a claim was **real** was recorded as grounds to dismiss it
  (`DEC-008`);
- a baseline entry that anchored no positions could only ever return `carried` (`DEC-014`).

Each passed review. Each passed CI. Each established nothing. The common shape is that the failing
branch was unreachable, so the check agreed with itself every time it ran.

## The taxonomy

| | What it looks like |
|---|---|
| **A** | A filter naming a value nothing assigns. |
| **B** | A metric whose numerator or denominator cannot vary, usually because its input is authored rather than captured. |
| **C** | A guard whose failure branch is unreachable, most often because a fallback always satisfies it. |
| **D** | A claim true of one path and silent about the others, with no test that would fail if the enforcement were removed. |
| **E** | A polarity disagreement: a question, a label and the field it is stored in pointing in different directions. |
| **F** | A test that cannot fail: no assertion, only assertions over literals, or a subject mocked to produce the thing asserted. |

A, C and F have mechanical instances a parser can settle, and that is what the detector finds.
B, D and E are read by a person.

## The detector

```
uv run python scripts/audit_unfailable.py /path/to/repo [--json]
```

It reads source rather than importing it, so it runs against any of the four repositories. It
finds enum members nothing assigns outside tests, exception types nothing raises, and test
functions whose assertions compare only literals. It is a worklist and not a verdict: a member
named only by a JSON payload, an exception raised by a subclass, and a test whose whole purpose is
that a constructor does not raise are all reported and all fine.

Across the four repositories it raised seven candidates. Four were confirmed, two were cleared as
deliberate and documented, and one was a false positive — a false-positive rate of one in seven
on this corpus, with two more that a reader has to judge rather than the tool.

## Confirmed here

### C — `SpanTooLargeError` was never raised, and its name and docstring disagreed

`src/docket/resolve.py` defined `SpanTooLargeError(ValueError)`, exported it in `__all__`, and
never raised it. Nothing caught it either. Its docstring read *"Raised when a file cannot be read
as text"*, which is not what its name says, and is a second symptom of the same thing: nobody had
exercised it, so nobody had noticed that the two disagreed.

Both conditions it seems to name are handled without it. A file that cannot be read as UTF-8 text
makes `_read_lines` return `None` and the locator resolves as `path_absent`. A cited range longer
than `MAX_QUOTED_LINES` still resolves, and the record carries `truncated: true`. So the class was
a public name promising an error mode the module does not have, and a caller writing
`except SpanTooLargeError` would have written a handler that never runs.

**Removed** (`DEC-016`). The two behaviours it described are the ones the module already had, and
both are tested.

### D — a tidying hook silently broke the example that proves the binding works

Found by running the audit rather than by the detector, and worth more than the thing it was
looking for. `pre-commit`'s `end-of-file-fixer` appended a newline to
`docs/eval/worked-example/record.json`, whose content hash pins the bytes of the spans the binding
cites. The worked example then failed to verify.

The failure is the shape this page is about, one level up: `pyproject.toml` already excludes that
directory from the formatter, and the comment there says why — *"formatting it would break the
example it exists to support"*. The same reasoning applies to every hook that rewrites bytes, and
only the formatter had been given it. The exclusion was true of one path and silent about the
others, which is taxonomy D exactly.

**Fixed:** a top-level `exclude` in `.pre-commit-config.yaml` covering both committed examples,
with the reason stated beside it and a pointer to the matching exclusion in `pyproject.toml`. Two
tests fail if it regresses (`test_the_committed_worked_example_still_verifies` and
`test_the_worked_example_s_recorded_verdicts_match_a_fresh_run`), which is how it was caught.

## Cleared here

| Candidate | Why it is not a finding |
|---|---|
| `Status.EXPLOITABLE` / `NOT_EXPLOITABLE` unreachable from the gathering path | That is the guarantee, not a defect. `tests/test_disposition.py` pins it in two directions: the gathering modules may not import `Status`, `Disposition` or `Decision`, and a third test asserts the module list covers the package so a new file joins one side or the other. |
| Every `Verdict` member | `docs/eval/worked-example/verifications/` holds one of each — `verified`, `unverifiable`, `contradicted` — re-derived by CI. |
| Every `Resolution` member | `tests/test_resolve.py` constructs an input for each. |
| Every `State` and `SpanState` member | The loop example produces `new`, `carried` and `stale` across three runs; `moved` is covered by a test that inserts a line above a citation. |
| Every `Answer` member | The Phase 1 measurement produced all three over 81 claims, and the recording is committed. |
| The published figures | Every one is computed over captured feeds from real tool runs, committed under `docs/eval/`. Changing a feed changes the number. See below. |

## The published figures are falsifiable

This is the question worth asking of any measurement page, and the answer here is yes for all of
them. The locator-resolution rates, the per-question answer counts, the cost per claim and the
deduplication figures are all computed from feeds captured by running two reviewers, committed
verbatim. A different feed produces a different number. The scripts that compute them
(`scripts/measure_feeds.py`, `scripts/measure_assessments.py`, `scripts/measure_dedupe.py`) read
those files and nothing else, and the model calls replay from a committed recording rather than
being re-run until the number improves — 21 of 177 calls returned nothing and are published as
`not_established` for exactly that reason.

## What the detector does not find

The three branches a parser cannot settle are the ones that produced the worst of the six defects.
`DEC-008`'s polarity bug is the case in point: every enum member was assigned, every branch was
reachable, every test passed, and the tool was recording the opposite of what it had found. What
caught it was a measurement whose shape was implausible — 28 `supports` and 0 `contradicts` on a
question no real codebase answers one way.

So the standing check is not this script. It is: for every published number, what input would
change it; and for every invariant asserted in prose, which test fails if the enforcement is
deleted.
