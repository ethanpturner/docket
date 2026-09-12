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

Phase 2. `record` checks a claim's citations, `assess` gathers evidence for the five questions and
decides nothing, `decide` is where a person does, and `bind` and `verify` make that decision
checkable afterwards without a key.

Install from a clone: `uv sync`, then `uv run docket --help`.

MIT.
