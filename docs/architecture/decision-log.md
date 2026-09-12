# Decision log

Numbered decisions, newest last. Every entry states what was decided, why, what was rejected, what
it costs, and what it leaves open. A decision is changed by a later entry, never by an edit.

---

## DEC-001 — A disposition has three values, and they map onto OpenVEX

**Date:** 2026-09-11
**Status:** Accepted

### Decision

A disposition is `exploitable`, `not_exploitable`, or `undetermined`, and the record emits an
OpenVEX document where those map to `affected`, `not_affected`, and `under_investigation`. A
`not_affected` statement carries the reviewer's reason as `impact_statement`, or a label from the
spec's fixed five-item justification catalogue once a later phase selects one.

### Why

The third value is the product. "We looked and it is fine" and "nobody looked" are different facts
about a system, reached by different work, and no triage tool distinguishes them; the second is
recorded as the first because the queue has no field for it.

OpenVEX already has that field. `under_investigation` is a first-class status in the spec, and
scanners such as Grype already consume VEX documents to filter their own output. So the refusal to
assert false certainty ships as a value in a format that is already read, rather than as a new
artifact someone must be persuaded to adopt. That distinction decides whether a three-valued verdict
is a feature or a curiosity: uncertainty survives as an input to somebody else's suppression and
dies as a deliverable.

### Alternatives considered

- **A confidence score.** Rejected. A number invites a threshold, a threshold hides the difference
  between a checked dismissal and an unchecked one, and no reader can tell which 0.3 means.
- **Two values with a nullable "reviewed" flag.** Rejected as the same three values, spelled so that
  the default reads as a dismissal.
- **A vocabulary of our own.** Rejected. It would need adopting before it could be used, and the
  adoption is the hard part.

### Tradeoffs

VEX is built around CVE identifiers and most inbound claims have none, so `vulnerability.name` falls
back to the claim's own identifier with the CWE in `description`. That is an honest use of the field
and a slightly unusual one; a consumer keying strictly on CVE names will not match.

### Open questions

Which of the five VEX justification labels a later phase may select automatically, and which require
a person. `inline_mitigations_already_exist` and
`vulnerable_code_cannot_be_controlled_by_adversary` are the two the spec itself flags as hard to
prove.

---

## DEC-002 — The tool never asserts exploitability

**Date:** 2026-09-11
**Status:** Accepted

### Decision

`docket` records a disposition; it does not reach one. Phase 0 produces `undetermined` and there is
no code path to another status. In later phases a model gathers evidence — the cited span, the
entry points, the reachable path — and a person sets the status, which the record names them for.
A decided status without a `decided_by` is refused at construction.

### Why

The category this tool enters is one practitioners already distrust. The complaint is not that the
tools find nothing; it is that "about 1 in every 10 to 20 comments is actually useful" and that they
"latch on and tunnel hard" without validating. A tool that adds a fourth opinion inherits that
complaint on its first run.

The value on offer is different: the record of what was checked. That value survives being wrong
about a particular bug and does not survive being another guess.

### Alternatives considered

- **Suggest a disposition for the reviewer to confirm.** Rejected. A suggested status is an anchored
  one, and the anchor arrives with none of the accountability the record exists to create. It also
  makes the tool's own accuracy the thing under discussion.
- **Assert only where the evidence is mechanical** (a cited path that does not exist implies the
  claim is wrong). Rejected: a broken citation means the citation is broken. The weakness may be
  real and cited badly, which is common in machine-generated findings.

### Tradeoffs

Phase 0 is less immediately impressive than a tool that answers the question. What it produces is a
filter and a record rather than a verdict, and that is a slower sell.

### Open questions

Whether a later phase should be allowed to pre-fill a status that a reviewer must actively change,
as distinct from suggesting one. Today the answer is no.

---

## DEC-003 — An inbound report is untrusted text

**Date:** 2026-09-11
**Status:** Accepted

### Decision

A finding's prose is carried verbatim into the record, quoted inside a fence it cannot close, and
never parsed for instructions, never mined for locators it did not cite, and never treated as a
statement of fact about the system. Locators are attacker-controlled strings used to build
filesystem paths, so a locator escaping the repository root is `path_absent` and the file is not
opened.

### Why

A bug bounty report is written by a stranger and an agentic scanner's output is written by a model
reading a codebase that may itself contain planted text. Both arrive as prose that will be read by a
person and, in later phases, by a model. Text shaped like an instruction, inside a document a
reviewer is reading to decide something, is the ordinary attack.

The quotation must stay faithful, because a disposition's worth depends on it: a record that
summarises what was claimed cannot be checked against what was claimed. So the text is neutralised
only where it would act as a delimiter, and never altered otherwise.

### Alternatives considered

- **Extract locators from prose with a pattern.** Rejected. It produces citations the reporter did
  not make, which the record then attributes to them.
- **Strip suspicious content.** Rejected: it alters the quotation, and "suspicious" is a judgement
  the tool is not making.
- **Sanitise by escaping everything.** Rejected as unreadable; the reviewer has to read this.

### Tradeoffs

A plain-text report yields a claim with no mechanically checkable position, so Phase 0 tells a
reviewer very little about it. That is accurate rather than unhelpful: an unstructured report cites
nothing a machine can check, and pretending otherwise is where the invented locator comes from.

### Open questions

Whether a later phase offers a reviewer a way to add locators by hand and record that they were
added by a person rather than claimed by the reporter. It should; the field does not exist yet.

---

## DEC-004 — Evidence is gathered against the five VEX justifications, not in free form

**Date:** 2026-09-11
**Status:** Accepted

### Decision

Phase 1 asks five fixed questions, one per OpenVEX justification label, and records an answer to
each. A question's answer is three-valued in the same way a disposition is: the evidence supports
the justification, contradicts it, or establishes neither.

### Why

A reviewer dismissing a claim has to give a reason, and OpenVEX fixes the set of acceptable
reasons at five. So the evidence worth gathering is not "an analysis of this claim" — it is
whatever bears on those five, because those are the only dismissals a downstream consumer can
read. Free-form analysis produces prose a person must re-read and convert into a decision anyway,
and the conversion is where the reasoning gets lost.

Fixing the questions also fixes the *shape* of the model's job, which is what keeps it from
drifting into judgement. A gatherer asked "is this exploitable" answers that question. A gatherer
asked "does the cited span contain the construct the claim describes" answers that one.

### Alternatives considered

- **One open-ended analysis per claim.** Rejected: unanswerable questions become confident prose,
  and there is no field in which "I could not tell" survives.
- **A question per CWE class.** Rejected: it scales with the taxonomy rather than with the
  decision, and the output maps onto nothing a consumer reads.

### Tradeoffs

Five questions do not cover every reason a claim might be wrong — a claim can be incoherent, or
describe behaviour that is intentional. Those fall through as `not_established` on all five, which
is accurate but unhelpful, and a reviewer gets no more than Phase 0 gave them.

### Open questions

Whether a sixth question about intentional behaviour earns its place, given it maps onto no VEX
justification and would therefore produce a candidate nothing can consume.

---

## DEC-005 — The deterministic questions run first, and a model is asked only what is left

**Date:** 2026-09-11
**Status:** Accepted

### Decision

Question one is answered by the resolver and question three by an AST call graph over the
repository. Only the three questions that require reading the claim *and* the code reach a model,
one call each. Running with no model at all is a supported mode that answers two of the five.

### Why

Cost and honesty point the same way. A call graph is free, repeatable, and cites a line number a
reviewer can open; a model reading the same question is neither. Where a mechanical answer exists
it is strictly better evidence, so the mechanical answer is the one recorded and the model is
never asked to confirm it.

One call per question rather than one per claim means a provider failure loses one answer instead
of the assessment, and it keeps each prompt small enough that the evidence in it is the evidence
the answer rests on.

### Alternatives considered

- **One model call covering all five questions.** Cheaper and rejected: a single response mixes
  the evidence for five separate conclusions, and one refusal or truncation loses all of them.
- **Model-only, no static analysis.** Rejected: it replaces a checkable citation with an opinion
  about the same fact.

### Tradeoffs

Three calls per claim is roughly three times the cost of one. Measured at $0.008 per claim, which
is not the constraint.

### Open questions

Whether question three should also ask a model about framework registration the call graph cannot
see. Today it does not, and `no_caller_found` carries that gap as a stated caveat instead.

---

## DEC-006 — `no_caller_found` is not `unreachable`

**Date:** 2026-09-11
**Status:** Accepted

### Decision

The call graph reports `reachable_from`, `no_caller_found`, or `not_determinable`, and never
reports unreachability. `no_caller_found` supports the `vulnerable_code_not_in_execute_path`
justification as a *candidate* and carries, on the record and on the page, the reasons it may be
wrong: dynamic dispatch, framework registration, reflection, and callers outside the repository.

Where a claim cites several positions, every resolved position is examined and any reachable one
contradicts the justification. The first citation does not decide it.

### Why

A static call graph over Python loses every dynamic call, and the losses are not exotic: a
decorator registering a handler, a dispatch table, `getattr`, an entry point in another package.
Reporting "unreachable" from an absence of edges would be the same error the disposition exists to
prevent — nobody looked, recorded as looked and found nothing — one level down.

Examining every cited position rather than the first is the same rule applied to ordering: a claim
that cites one reachable handler and three module-level lines has not established anything about
the execute path, and letting the order of a tool's output decide the answer would make the
assessment depend on something with no meaning.

### Alternatives considered

- **Report `unreachable` when the graph is complete.** Rejected: the graph is never complete, and
  a completeness test would itself be a guess.
- **Suppress the candidate entirely.** Rejected: a reviewer investigating an orphaned function is
  doing useful work, and the candidate with its caveat is what tells them so.

### Tradeoffs

An over-connected graph — names matched across modules rather than resolved through imports —
produces `reachable_from` where a precise analysis might not. That direction withholds a dismissal
candidate rather than offering a bad one, which is the safe way to be wrong here.

An earlier version treated every module-level function in `app.py`, `main.py`, or `cli.py` as an
entry point. It marked private helpers reachable because of the file they sat in, and it was
removed: the error ran in the safe direction and was still wrong, and it suppressed the signal the
analysis exists to produce.

### Open questions

Whether to resolve names through imports. It would sharpen `reachable_from` and make
`no_caller_found` more common, which is the answer that needs the most care.

---

## DEC-007 — Every model call is recorded at the seam, and a replay never reaches the network

**Date:** 2026-09-11
**Status:** Accepted

### Decision

The seam writes one JSON object per call — provider, the model *as the provider returned it*, a
hash of the canonical request, the request, and the response — and a replay serves from that file
keyed by the hash. A request the recording does not hold is a failure the caller sees, never a
call to a provider.

### Why

An evidence record whose model calls cannot be re-derived is a claim about a claim. The recording
is what makes the assessment an input to something else rather than a memory of a run: a reader
with the file and the repository reproduces every answer months later with no key and no account,
and a test does exactly that with the environment variable unset.

Refusing on a miss is the part that makes it mean anything. A replay that silently falls back to
the network produces a result that looks reproduced and is not, and the difference is invisible in
the output — which is the same failure mode as a dismissal nobody checked.

The model identifier is part of the request hash because the same prompt to a different model is a
different request, and replaying one as the other would mislabel the evidence while appearing to
verify it.

### Alternatives considered

- **Record the HTTP exchange.** Rejected: it pins a wire format that will change, and a provider's
  response envelope is not the evidence.
- **Cache by prompt text alone.** Rejected: two models answering the same prompt are two results.

### Tradeoffs

A recording holds the claim's text and the cited source, so it inherits whatever was in them. It
is an artifact to handle like the report itself, not a log to publish carelessly.

### Open questions

Whether a recording should be signed. The manifest shape in the sibling attestation project is the
obvious fit, and Phase 2 is where it belongs.

---

## DEC-008 — A gatherer judges one proposition, and never the question on the reviewer's page

**Date:** 2026-09-11
**Status:** Accepted

### Decision

Each of the five questions carries two texts. `asks` is the question a reviewer reads. `proposition`
states the OpenVEX justification affirmatively, and it is the only one a model is ever shown. The
model reports whether what it found in the code supports that proposition, contradicts it, or
settles neither.

### Why

Because the first version did not do this and produced exactly backwards evidence on real claims.

Two of the five questions are phrased as the negation of the label they bear on. The page asks
"Can input an attacker controls reach the cited code?" and the label it bears on is
`vulnerable_code_cannot_be_controlled_by_adversary`. Shown both the question and the label, the
model answered the question it could see: it described an HTTP handler reading `await
request.body()` directly, answered `supports`, and the code recorded that as support for the
justification that the code is beyond an attacker's reach — a dismissal candidate produced from the
clearest available statement that the claim is reachable. `vulnerable_code_not_present` was
inverted the same way.

The measurement is what caught it. Across 81 real claims the question came back 28 `supports` and
0 `contradicts`, and no real codebase answers a reachability question one way 28 times out of 28.
A one-directional instrument is either measuring nothing or measuring itself, and this one was
generating dismissal candidates in the direction that ends a reviewer's work.

### Alternatives considered

- **Rephrase the human-facing questions to match their labels.** Rejected: "Is the cited code
  unreachable by an adversary?" is a worse question on a page a person reads at triage time, and
  it optimises the human surface for the model's convenience.
- **Invert the mapping for the two affected questions.** Rejected: a sign flip in a lookup table
  is invisible at the call site, and the next question added would need someone to remember which
  kind it is. The proposition makes `supports` mean one thing everywhere.
- **Ask the model for a free-text conclusion and classify it here.** Rejected: it moves the same
  ambiguity into a classifier nobody can inspect.

### Tradeoffs

Two texts per question is redundancy, and they can drift. A test asserts every proposition is
affirmative and contains no question mark, which catches the obvious drift and not a subtle
rewording.

The pre-fix recording is kept out of the published set rather than deleted, and the figure it
produced is reported in the README as the finding that caused this entry, not as a result.

### Open questions

Whether the three model-answered questions should each be asked twice with the proposition negated,
and disagreement between the two treated as `not_established`. That would catch this class of error
without a human noticing a suspicious distribution, at three times the cost.

---

## DEC-009 — A dismissal selects a label or writes the statement; the reason is not a fallback

**Date:** 2026-09-11
**Status:** Accepted. Supersedes the fallback in DEC-001.

### Decision

A `not_exploitable` disposition carries a `justification` from the fixed five-label catalogue, or
an `impact_statement` the reviewer wrote, and it is refused at construction without one of them.
`DEC-001` had the emitter fall back to the reviewer's `reason` as the impact statement; that
fallback is removed.

Both fields may be present, and on a decided dismissal both usually are: the label is what a
consumer acts on, the statement is what a person reads.

### Why

The fallback made the rule unfailable. A `reason` is required on every disposition, so "a
dismissal has a justification or an impact statement" was satisfied by a field that is always
populated, and no input could ever violate it. A check that cannot come out false is not a check,
and this project has now found four of them in two days -- a report section filtered on a status
nothing set, a compliance rate scored against authored recordings, a fence that covered only the
material it was pointed at, and this.

There is a second, sharper reason. OpenVEX highly discourages `impact_statement` for automated
consumers and exists to make dismissals machine-readable; the whole argument for shipping in VEX
rather than a vocabulary of our own is that the machine-readable field is what makes the record
consumable. A fallback that silently fills the prose field on every dismissal produces documents
that satisfy the spec and carry nothing a scanner can key on. Asking the reviewer for one more
flag is the entire difference.

### Alternatives considered

- **Keep the fallback and warn.** Rejected: a warning on the common path is read once.
- **Infer a justification from the assessment's candidates.** Rejected, and it is the tempting
  one. A candidate is evidence that a label *could* apply; selecting it is the decision, and
  `DEC-002` puts that with the person. Inferring it would put the tool's name on the reviewer's
  judgement.
- **Require the label and drop `impact_statement` entirely.** Rejected: the spec permits prose,
  and there are real dismissals no label fits -- "this is intentional behaviour" is not among the
  five.

### Tradeoffs

One more flag on the command that a reviewer runs most. Measured against the alternative, which
is a corpus of dismissals whose reasons are unreadable to the thing consuming them.

### Open questions

Whether a sixth justification for intentional behaviour should be proposed upstream. It would be
the honest home for a large class of real dismissals, and it does not exist.

---

## DEC-010 — A person may decide against the evidence, and the record says that they did

**Date:** 2026-09-11
**Status:** Accepted

### Decision

Selecting a justification the assessment did not offer as a candidate is refused *unless* the
reviewer supplies an override reason, which is recorded on the decision, on the record, and in the
emitted VEX as `docket_override_reason`. The rule is enforced when the decision is made and again
when a decision file is read, because the file is meant to be hand-edited and the edit is where an
override goes missing.

An assessment with no candidates at all -- `--no-model`, or a claim that only went through
`record` -- offers nothing, so every justification against it is an override. That is the correct
reading rather than an inconvenience.

### Why

A reviewer overruling the gathered evidence is legitimate and common. The evidence is five narrow
questions answered against one commit; a person who knows the deployment knows things a call graph
cannot see, and the assessment's own caveats say so. A tool that refused the override would be
asserting its evidence is complete, which is the claim it spends every other page denying.

What must not happen is that the override is invisible. Six months later, "the tool found this and
a person agreed" and "a person decided this over the tool's objection" are different facts about
how much checking happened, and a bare `justification` field cannot tell them apart. The override
field is the only place that difference survives.

### Alternatives considered

- **Allow any justification silently.** Rejected: it makes the candidate list decorative and the
  record unable to distinguish the two cases above.
- **Refuse the override outright.** Rejected as above; it would also push reviewers into the
  `impact_statement` field to get around the check, which loses the label as well as the trace.
- **Record the override but not require a reason.** Rejected: a flag with no argument is the same
  unexplained assertion the tool exists to replace, one level in.

### Tradeoffs

A reviewer in a hurry types a short override reason, and a short bad reason is recorded as
faithfully as a good one. This tool records who decided and why; it does not grade the answer.

### Open questions

Whether an override should also be counted -- a rate of decisions made against the evidence, per
reviewer or per corpus, would say something about whether the gathering is worth its cost. The
field is there for it and nothing computes it yet.

---

## DEC-011 — A binding re-derives the quoted code, not only the file digests

**Date:** 2026-09-11
**Status:** Accepted

### Decision

`docket bind` digests the artifacts -- the finding as received, the record, the model recording,
the decision file -- and separately records every resolved locator with the digest of the bytes
that were quoted from it. `docket verify` re-computes the artifact digests, and, when given a
repository, re-resolves each locator and compares the code that is there now against what the
record quotes. Without a repository those span checks are `unverifiable`, never `verified`, and
the coverage line states which checks ran.

Verification exits non-zero on `contradicted` and zero on `unverifiable`, unless
`--fail-on-unverifiable` is passed.

### Why

Re-digesting the artifacts answers "are these the same files", which is a statement about bytes on
one machine. It does not catch the failure that actually matters here: a record whose files are
all intact while the code it describes has moved underneath it. A dismissal that was correct
against one commit and is quietly wrong against the next is the specific way a triage record rots,
and the only check that sees it is re-reading the cited position.

Re-resolving the recorded locator rather than opening the recorded path is deliberate: one code
path produces a quotation and one code path checks it, so the truncation cap and the
repository-containment rule cannot drift apart between recording and verification.

The exit codes follow the adoption argument the whole tool is built on. A scanner that arrives
failing builds is uninstalled before anyone reads a finding, so `contradicted` -- something
recorded here is no longer true -- fails, and an unknown does not.

### Alternatives considered

- **Re-execute something, as the sibling attestation project does.** There is no command here.
  The decision is a person's, and re-running it is not a thing a machine can do; digesting what it
  was made from is.
- **Require the repository.** Rejected: the common case is verifying a record somebody sent you,
  and refusing to say anything about the artifacts without a checkout would make the tool useless
  exactly when it is most needed. The `unverifiable` verdict and the coverage line are the honest
  version.
- **Sign the manifest here.** Rejected for now. The manifest is emitted in in-toto Statement shape
  so `cosign attest-blob` can sign it and `verify-blob-attestation` can check it offline, and
  neither tool needs to know anything about docket. Emitting an unsigned envelope and calling it
  an attestation would be the category error this project is about.

### Tradeoffs

The span check is only as good as the locators the claim cited. A claim citing nothing has no
spans, so its binding is artifact digests alone, and the coverage line says `0 quoted spans` --
accurate, and thinner than a reader might assume from the word "verified".

### Open questions

Whether to record the commit's own object identifier and check it, rather than trusting the
`--commit` string a caller passed. It would turn "the code at this position" into "the code at
this position of this commit", and it needs a git dependency this package does not have.

---

## DEC-012 — `fixed` is not a disposition this tool reaches

**Date:** 2026-09-11
**Status:** Accepted

### Decision

OpenVEX has four status labels and docket emits three. `fixed` is not offered as a disposition.

### Why

A record binds one claim to one commit. `fixed` asserts that *some other* version of the product
contains a remedy, and this tool has examined exactly one version, so it would be emitting a
statement about something it never looked at.

There is also no gap to fill. A claim that was real and has been remedied at the commit under
examination is `not_affected` with `vulnerable_code_not_present`, which is both true and more
precise. A claim remedied in a later release is a statement about that release, and belongs in a
VEX document issued for it.

### Alternatives considered

- **Offer `fixed` with the remediating commit as a field.** Rejected: the tool would be recording
  a claim about a commit it did not resolve, quote, or assess. Every other status on the record is
  backed by something that was read.

### Tradeoffs

A team tracking remediation wants `fixed` and will have to issue that statement from wherever they
track releases. This is a narrower tool than their workflow needs, which is the accurate thing for
it to be.

### Open questions

Whether a later phase that takes two commits -- the one the claim was made against and the one it
was fixed in -- should emit `fixed` over both. That version would have looked at both, which is
the condition this entry actually rests on.
