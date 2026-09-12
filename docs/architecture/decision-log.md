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
