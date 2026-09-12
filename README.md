# docket

Records the disposition of a security finding: exploitable, not exploitable, or undetermined, with
the evidence behind it.

A triage queue asks one question all day. Somebody asserted a weakness. Is it real? There are three
honest answers and every tool records two of them. The third, *nobody has established either way*,
is the one an auditor asks about, the one a maintainer spends their week on, and the one that
currently gets written down as a pass.

```
uvx --from git+https://github.com/ethanpturner/docket docket triage findings.sarif \
    --repo . --commit "$(git rev-parse HEAD)" --no-model
```

No configuration, no account, no API key, and no network beyond fetching the tool. On a queue of
forty claims that run takes **0.08 seconds**, because the two questions it answers are a path
lookup and a call graph. Everything below is what the other four commands add.

## The queue

`docket triage` is the loop. It reads a finding set, merges it by content, assesses one claim per
group, and compares each against the decisions already made.

```
docket triage findings.sarif --repo ./app --commit 9f2c1ab \
    --baseline .docket/baseline.json --out .docket/out
```

```
40 claims -> 21 after merging (18 merges)
  new     3
  stale   1
  carried 17
```

**It exits 0 whatever it finds.** A security tool that arrives blocking a pipeline is uninstalled
before anybody reads its first finding. Gating is opt-in and each flag names a condition a team
agreed to care about: `--fail-on-new`, `--fail-on-stale`, `--fail-on-status`. (`DEC-015`.)

### Merging, and what it refuses to merge

A claim's identity is derived from its content: the innermost cited symbol, and the normalised CWE.
Not the producer's own signature, which identifies the prose rather than the weakness — across ten
runs of one reviewer, 72 emitted claims carried 41 distinct signatures and **not one repeated
across runs**. Not the line number either, which is a position in a revision.

Every merge is reported with its basis and the titles it folded together, because a merge is a
claim this tool makes and a reviewer needs to be able to reject it.

**Two CWE identifiers at one site are not merged.** The same reviewer called one missing signature
check `CWE-306` in two runs and `CWE-345` in two others. Merging those would mean asserting an
equivalence between two entries in somebody else's taxonomy, which this tool has no basis to make
and no way to check, so they are reported adjacent and the call is a person's. (`DEC-013`.)

### The baseline expires

A decided claim carries forward so it does not come back. Every other suppression file in this
category stops there, and the dismissal then outlives the code it was reasoning about: somebody
rewrites the function, and the finding that would now be real is filtered out by a decision made
about different code.

A decision here is anchored to the bytes it cites **and** to the enclosing function's own digest.

| State | Meaning |
|---|---|
| `carried` | every span the decision rests on still reads the same |
| `stale` | a span changed or stopped resolving, so the decision is **not** applied |
| `new` | no decision exists for this identity |

A span whose bytes moved while its function is byte-identical has moved, not changed, and the
decision carries with a note — otherwise one formatting pass re-opens every dismissal in the file
and the mechanism gets switched off inside a week. An entry that anchored no positions is stale
rather than carried, because carrying it would be a check that cannot fail. (`DEC-014`.)

A stale claim returns carrying the previous status, the previous reason, and a sentence naming what
changed. The reviewer is usually about to reach the same conclusion, and making them reconstruct
their own argument from nothing is how this feature would get turned off.

## Checking the citation

Given a finding and a repository at a pinned commit, `docket record` answers the part that needs no
model: does this claim point at code that exists?

- **Reads** SARIF 2.1.0, Codex Security's `findings.json`, JSON Lines feeds from agentic reviewers,
  and plain text. A report with no structure yields one claim with no locators, because prose names
  a file and does not cite one.
- **Resolves** every cited `path`, `path:line`, or `path:start-end` against the worktree: `resolves`,
  `path_absent`, `line_out_of_range`, or `not_a_locator`. It quotes the cited span and hashes it.
- **Records** the claim as received, the resolutions, and a disposition. In Phase 0 that disposition
  is always `undetermined`, reason `no assessment performed`.
- **Emits** OpenVEX beside the record, so a scanner that already consumes VEX can act on it.

## What it refuses to do

**It does not decide whether a finding is real.** No code path in either command produces any status
but `undetermined`, and two tests walk the syntax tree to pin that, one per phase. A
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

OpenVEX requires a `justification` or an `impact_statement` on any `not_affected` statement, and
`fixed`, its fourth label, is not a disposition this tool reaches: a record binds one claim to one
commit, and `fixed` asserts something about a version it never examined (`DEC-012`). A status with
no reason, and a dismissal with no argument, are both refused at construction.

## Gathering evidence

`docket assess` answers five questions about a claim. They are not questions we chose. OpenVEX
fixes the set of reasons a dismissal may rest on at five justification labels, so those are the
only dismissals a downstream consumer can read, and the evidence worth gathering is whatever bears
on them.

| Question | Bears on | Answered by |
|---|---|---|
| Is the cited file present at this commit? | `component_not_present` | the resolver |
| Does the cited span contain the construct described? | `vulnerable_code_not_present` | a model |
| Is the cited code reachable from an entry point? | `vulnerable_code_not_in_execute_path` | a call graph |
| Can attacker-controlled input reach it? | `vulnerable_code_cannot_be_controlled_by_adversary` | a model |
| Is there a control on the path the claim missed? | `inline_mitigations_already_exist` | a model |

Two are mechanical and free. `--no-model` answers those two and costs nothing. The other three get
one model call each, and the model's schema has no field for a verdict, a status, a severity, a
confidence, or a recommendation: a response carrying one is refused rather than trimmed.

An answer is three-valued for the same reason a disposition is. Evidence supports the
justification, contradicts it, or settles neither, and the third is the common case.

**Nothing here selects a justification.** What the record gains is a list of *candidates*: the label
a reviewer could select, the evidence behind it, and the reason it might still be wrong. Every one
carries `is_decision: false`.

**`no_caller_found` is never reported as `unreachable`.** A call graph built from Python source
loses every dynamic call, so an absence of edges is an absence of evidence, and converting one into
the other would reproduce the collapse this tool exists to prevent one level down.

Every model call is recorded at the seam — provider, the model as returned, a hash of the canonical
request, the request, the response — so an assessment re-derives months later with no key. A replay
refuses on a miss rather than reaching for the provider, and a test runs the whole path with the
environment variable unset.

## Measured: do the citations hold up?

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

## Measured: what gathering establishes

The same 81 claims, assessed: 177 model calls costing **$0.97**, or
**$0.012 per claim**. Every call is in `docs/eval/recordings/`, and the table below
re-derives from it in under a second with the API key unset.

| Tool | Claims | Ended with a candidate | Questions settled |
|---|--:|--:|--:|
| Codex Security | 9 | 0 of 9 | 3.56 of 5 |
| Mantis | 72 | 26 of 72 | 2.83 of 5 |

| Question | Answered by | Supports a dismissal | Contradicts one | Not established |
|---|---|--:|--:|--:|
| Is the cited file present? | `resolver` | 22 | 59 | 0 |
| Does the span contain the construct? | `model` | 1 | 52 | 28 |
| Is it reachable from an entry point? | `call graph` | 1 | 56 | 24 |
| Can attacker input reach it? | `model` | 0 | 33 | 48 |
| Is there a control the claim missed? | `model` | 2 | 10 | 69 |

**Coverage.** 21 of the 177 calls produced no usable answer and left their question
`not_established`. Most are gateway timeouts rather than refusals: the live gathering stalled
repeatedly in five-minute blocks, and the run was stopped with its tail unanswered. A timed-out
question is recorded as unestablished, which is what it is, and the figure is stated here rather
than quietly reduced by re-running until it looked better.

**Read the last column first.** The common outcome is that nothing was established. On the two
questions the OpenVEX spec itself warns are hard to prove, 48 and 69 of 81 claims end with no
answer either way. That is the state of most machine-generated findings against real code, and it
is the number a human triager is already working with.

Dismissal candidates are rare and getting rarer: 26 of 72 Mantis claims and none of Codex
Security's 9 end with a label a reviewer could select.

### The number that is not a result

An earlier version of this measurement reported **28 `supports` and 0 `contradicts`** on *Can
attacker input reach it?*, over these same 81 claims. No real codebase answers a reachability
question one way 28 times out of 28. It now reads 0 and 33.

Two of the five questions read, on the reviewer's page, as the negation of the label they bear on.
The gatherer was shown the page's question and asked whether its findings supported *the
justification*, so it answered the question it could see: it described a handler reading the HTTP
request body, answered `supports`, and that was filed as evidence the code is beyond an attacker's
reach. The clearest statement that a claim was reachable was being turned into a reason to dismiss
it.

No disposition was ever wrong, because this tool makes none. The candidates a reviewer reads first
were backwards, which is the same failure one step earlier. `DEC-008` records it, every question now
carries an affirmative `proposition` that is the only thing a model is shown, and the pre-fix figure
is kept here as the finding that produced the entry rather than as a result.

## Measured: does merging by content beat the tool's own label?

The same sixteen runs, pooled per reviewer per application, so that a signature stable inside one
run and unstable across runs is measured on the case that exposes it. Reproduce with
`scripts/measure_dedupe.py RUNS_DIR WORKTREE COMMIT`; no model calls, no network.

| Tool | Runs | Emitted claims | Distinct by its own signature | Distinct by content | Groups spanning >1 run |
|---|--:|--:|--:|--:|--:|
| Mantis @ `d13c93f` | 10 | 72 | 41 | **35** | 5 |
| Codex Security 0.1.26 | 3 | 9 | 9 | **7** | 2 |

Restricted to claims that cite a position which resolves — excluding the 22 Mantis claims caught by
its scan-root path defect, which have no site and fall back to their titles:

| Tool | Emitted | By signature | By content |
|---|--:|--:|--:|
| Mantis | 50 | 30 | **24** |
| Codex Security | 9 | 9 | **7** |

**The second column is the result, not the third.** Content identity does shorten the queue, by
about 15%. What it does not do is make ten runs collapse into one queue, and the reason is not a
weakness in the merge rule: **only 5 of the 35 groups appear in more than one of the five runs.**
Thirty of them were reported once and never again.

Deduplication cannot fix non-determinism. The pairwise signature agreement of 0.00 measured earlier
was not an artefact of unstable labelling that better identity would wash out — after normalising
away the prose, the line numbers and the tool's own identifiers, the underlying findings still
mostly differ from run to run. A queue fed by a re-run of this reviewer is mostly new claims, and
that is a fact about the reviewer.

One thing the merge did surface. At a single function, `deploy_notifier/main.py::receive_event`,
the same reviewer attached **five different CWE identifiers across five runs** — 306, 345, 400, 664
and 703. Those are reported together and merged into nothing, because equating them is a taxonomy
judgement this tool declines to make.

## The loop, end to end

Three runs over one small service, committed under
[`docs/eval/loop-example/`](docs/eval/loop-example/) and re-derived by two tests on every CI run.

| Run | What happened | Queue |
|---|---|---|
| 1 | The scanner reports two claims. Nobody has decided them. | 2 new |
| 2 | A reviewer decided both; nothing in the code moved. | 2 carried, **nothing needs a person** |
| 3 | Somebody fixed the path traversal. The scanner ran again. | **1 stale, 1 carried** |

The third run is the point. The path-traversal decision comes back, because the function it was
about was rewritten, carrying the reviewer's own earlier reason. The dead-code decision carries,
because `audit` only moved down the file.

And the third run's claims arrive under **different scanner signatures** from the first run's —
`scanner-b7` where run one had `scanner-a1`, citing different line numbers. A baseline keyed on the
producer's identifier would have matched neither and called both claims new.

## In CI

```yaml
- uses: ethanpturner/docket@main
  with:
    finding: semgrep.sarif
    baseline: .docket/baseline.json
```

Defaults: `--no-model`, and every gate off. It writes a Markdown summary to the job summary, the
OpenVEX document to `.docket/out/`, and exits 0. A full workflow is in
[`.github/workflows/example-triage.yml.txt`](.github/workflows/example-triage.yml.txt); there is a
`Dockerfile` for anyone who would rather pin an image.

## Deciding, and binding the decision to what it was made from

`record` and `assess` refuse to reach a status. `decide` is what they refuse in favour of.

```
docket decide record.json --claim C --status not_exploitable \
  --justification vulnerable_code_not_in_execute_path \
  --reason "the handler is registered but never mounted in this deployment" \
  --decided-by you@example.com
```

Four rules refuse a decision, and each one exists because the field it guards is the field a
triage queue currently leaves empty:

- **A status with no reason** is an assertion without an argument.
- **A decided status with no decider** is a verdict nobody is accountable for.
- **A dismissal with neither a justification nor an impact statement.** OpenVEX requires one; an
  earlier version satisfied that by falling back to the reviewer's reason, which made the check
  unfailable, because a reason is always present. `DEC-009` removed the fallback.
- **A justification the assessment did not offer** — unless the reviewer says they are overriding
  the evidence, and why. Overruling five narrow questions answered against one commit is
  legitimate and common. The record has to show that it happened: six months later, "the tool
  found this and a person agreed" and "a person decided this over the tool's objection" are
  different facts about how much checking was done, and a bare justification label cannot tell
  them apart. The override travels into the VEX document as `docket_override_reason`.

`bind` then digests the finding as received, the record, the model calls, and the decision into
one manifest, and `verify` re-derives it.

```
docket bind record.json --decisions decisions.json --finding finding.jsonl --out ./out
docket verify out/binding.json --repo ./app
```

**Two checks, and they are not equally strong.** Re-digesting the artifacts answers *are these the
same files*. Re-reading the quoted spans from the repository answers *does the code still say what
the record quotes*, which is the question that catches a dismissal going quietly stale while every
file around it stays byte-identical. Without a repository the span checks are `unverifiable`, and
the coverage line says so rather than leaving a reader to infer it from which flags were passed.

`verify` exits non-zero on `contradicted` — something recorded here is no longer true — and zero
on `unverifiable`, because an unknown is not a failure. Nothing is signed: the manifest is emitted
in in-toto Statement shape so `cosign attest-blob --type <predicate> --predicate binding.json`
signs it and `cosign verify-blob-attestation --bundle ... --trusted-root ...` checks it offline,
without either tool learning anything about docket.

## The worked example

One real claim, carried the whole way, committed under
[`docs/eval/worked-example/`](docs/eval/worked-example/). Everything it needs is in the repository,
so it replays with no key and no network, and three tests re-derive it on every CI run.

The claim is Codex Security's, against the `unsigned-webhooks` application at `trace@c5b0590`:
*unsigned requests can publish forged deployment notifications*, citing five positions.

| Step | Result |
|---|---|
| `record` | 5 of 5 cited locators resolve |
| `assess` | 4 of 5 questions contradict a dismissal; 1 not established |
| `decide` | `exploitable`, by a named person, with their reason |
| `bind` | 4 artifacts digested, 5 quoted spans recorded |
| `verify` | `verified` |

The unanswered question is the interesting part. *Can attacker-controlled input reach it?* was
never answered, because that gathering call timed out during the measurement run — so the reviewer
read `main.py` themselves and said so in the reason, rather than letting silence read as a pass.
That is the whole product in one line.

The three verdicts are committed in
[`verifications/`](docs/eval/worked-example/verifications/):

| Run | Verdict | Exit |
|---|---|---|
| With the repository | `verified` | 0 |
| Without the repository | `unverifiable` — the spans were not re-read | 0 |
| With one cited line edited | `contradicted` — the code is not what the record quotes | 1 |

The third is the check the artifact digests cannot make. Every file in the binding was still
byte-identical; the code had moved.

## Status

Phase 3. `triage` is the loop: merge a queue by content, compare it against what was already
decided, and say what needs a person. `record` checks a claim's citations, `assess` gathers
evidence for the five questions and decides nothing, `decide` is where a person does, and `bind`
and `verify` make that decision checkable afterwards without a key.

```
uv tool install git+https://github.com/ethanpturner/docket   # or: pipx install git+...
uvx --from git+https://github.com/ethanpturner/docket docket --help
```

From a clone: `uv sync`, then `uv run docket --help`. No runtime dependencies, on any path.

MIT.
