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

## What the detector does not find, and what the actual remedy is

**The detector's yield was one in seven, and it would not have caught any of the three defects
that prompted this sweep.** In all three, every enum member was assigned, every branch was
reachable, and every test passed. `DEC-008`'s polarity bug is the case in point: the tool was
recording the opposite of what it had found, and what caught it was a measurement whose shape was
implausible — 28 `supports` and 0 `contradicts` on a question no real codebase answers one way.

So the detector is a worklist, and **the coverage test is the remedy.**

`tests/test_vocabulary_coverage.py` is ported from the sibling attestation project, which was the
only one of the five repositories this sweep found nothing in and the only one already testing for
the class. It fails unless **every member of every vocabulary this tool can emit was produced by
something**, scored from what the code emitted rather than from what an enum declares.

- **47 members** across eleven vocabularies: `Status`, `Verdict`, `Resolution`, `State`,
  `SpanState`, `Question`, `Answer`, `Reachability`, `IdentityKind`, `FailureReason`, plus the
  OpenVEX justification catalogue and the status map.
- **Members are harvested, never named.** Nothing in the test writes `Resolution.PATH_ABSENT` and
  calls it covered. The committed examples are read, and the public functions are run over the
  committed example targets — the resolver over locators the target does and does not satisfy, the
  call graph over all eighteen functions it defines, the identity function over a record and its
  degraded forms, the baseline over the loop example's own entries, the VEX emitter over a record
  carried to each status, and the replay seam asked for a request no recording holds. Whatever
  comes back is what counts. Naming a member would reintroduce the check that cannot fail.
- **Eight are allow-listed with a reason the test reads**, in two kinds kept apart on purpose.
  `deliberate` is a value the design refuses to produce, and `IdentityKind.OPAQUE` is the only
  one: it is reached solely by a claim carrying no resolved position, no weakness and no usable
  title, which is a finding with nothing in it. The other seven are `unstaged` — producible, but
  needing conditions this corpus cannot create for free: six provider failures and one file
  deletion between runs. The split means debt reads as debt rather than hiding behind a principle.
- **Three companion tests keep the allow-list honest.** One fails if an allow-listed member starts
  being produced, so an exemption cannot outlive its reason. One fails on a typo that would
  silently exempt nothing. One walks the package for `StrEnum` subclasses, so a new vocabulary
  joins the check or fails it.

The precedent for the allow-list is the sibling model-lineage project's `SignatureState.VALID`:
unreachable, correct, and correct *because* reachability would have made the tool claim what
detection cannot establish. That entry is a recorded decision. An unreached member with no entry
is an oversight, and this test is the difference between the two.

### What adding it surfaced that the hand pass missed

Four things, and the hand clearing above had declared these vocabularies covered:

1. **The VEX emitter had never been exercised for two of its three statuses.** The committed
   documents hold `affected` only, because the worked example's claim was upheld.  `not_affected`
   and `under_investigation` — the two labels carrying this tool's whole argument about
   uncertainty — were emitted by nothing committed.
2. **`FailureReason.NOT_RECORDED` was unproduced**, though it is the one failure reason that costs
   nothing to reach and the one that makes offline replay mean anything.
3. **Two of three `Reachability` verdicts were unproduced** by the harvest as first written,
   because it asked about four hand-picked lines. Walking all eighteen functions reaches them.
4. **Two of the first allow-list entries were wrong.** `Status.EXPLOITABLE` and
   `Resolution.NOT_A_LOCATOR` are produced, and the reverse test said so immediately.

The first two are the useful ones: both are values a reader of the enum would assume the tool
emits, and neither was reachable from anything committed.

### The standing questions

For every published number: what input would change it. For every invariant asserted in prose:
which test fails if the enforcement is deleted. The coverage test answers the second for
vocabularies. Nothing automates the first.
