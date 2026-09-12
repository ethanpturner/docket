# Phase 0: the part that needs no model

2026-09-11

## What this is

`docket` starts from a job people are demonstrably paying humans to do this year. Log4j's
maintainers published their own triage economics: 32 reports over sixteen months produced 3
published vulnerabilities, then 17 reports in a single month and 20 the next, with a maintainer
capping himself at a fifth of his Log4j time. Filippo Valsorda, on the same problem: the bottleneck
is not finding potential issues but assessing which ones are real. And under SOC 2 the dismissal is
not free either — each one becomes a written artifact, because somebody has to mark it not
exploitable and say why.

Nothing writes that record. Trackers store an outcome and not the reasoning, and none of them tells
*not exploitable* apart from *nobody looked*.

## Why Phase 0 is the locator check

The temptation with a triage tool is to start with the interesting half: read the code, decide
whether the bug is real. That half needs a model, costs money per finding, and lands the tool in the
category practitioners already distrust — "about 1 in every 10 to 20 comments is actually useful" is
the going rate for AI code review, and a fourth opinion inherits that reputation on day one.

The uninteresting half turns out to be worth shipping alone. A claim cites `src/app.py:42`. Either
that file is in the repository at this commit with at least 42 lines, or the claim is about a
codebase other than the one in front of you. No model, no network, no cost.

Measured over the sixteen scored runs of two agentic reviewers, that check is not a formality.
Mantis's cited locators resolve 140 times out of 164. The 24 failures are almost all one bug: in
three of its ten runs it cited the absolute path of its own scratch directory instead of
repository-relative paths, so every locator in those runs is unusable and 22 of its 72 claims cite
nothing a reviewer can open. Codex Security resolves 34 of 34.

That is a filter with an honest denominator, and it arrives before anyone spends a model call.

## The decisions, and the one that took the longest

Three entries, and DEC-001 is the one that decides whether this is a tool or a curiosity.

The obvious design is a three-valued verdict of our own, since that discipline is the through-line of
every project in this portfolio. The evidence says a three-valued verdict as a *deliverable* dies:
OpenVEX is a whole specification built around exactly this, including a literal `under_investigation`
status, and after three and a half years its spec repository has a couple of hundred stars. What
keeps VEX alive is that Grype consumes it. Uncertainty survives as an input to somebody else's
suppression and dies as something you hand a person.

So the vocabulary is not invented here. It is OpenVEX's, and docket fills in the field everybody
leaves blank. That single choice is the difference between asking the world to adopt a new artifact
and writing into one it already reads.

DEC-002 is the rule that keeps the tool from becoming what it replaces: it never asserts
exploitability. Phase 0 asserts nothing at all, and the test that pins it walks the syntax tree
looking for any construction of a decided status outside the module that defines the vocabulary, so
a future edit has to name what it is doing.

DEC-003 came out of the fence work in `trace` two days ago and transplanted without modification. An
inbound report is a document written by a stranger that reports claims about a system. That is the
same object `trace` learned to register as untrusted and gate at a checkpoint, and the same rules
apply: carry it verbatim, quote it inside something it cannot close, extract nothing from
instruction-shaped text, and never guess a path from prose.

## What surprised me

Two things.

The first is how much of this already existed. The resolver is `trace`'s DEC-151 citation-fidelity
check with a different front end; the hashing is its DEC-019 module with three functions instead of
six; the fencing is its `input_package` rule. Phase 0 is mostly a re-pointing of work done for a
different reason.

The second is the failure mode the measurement found. I expected the unresolved locators to be
hallucinated filenames, which is the thing everyone worries about with machine-generated findings.
They are not. They are a sandbox path leaking into the output — a plumbing bug in the harness, not a
fabrication by the model. A reviewer triaging by hand would have read three runs' worth of findings,
found nothing at any cited position, and concluded the tool was inventing things. The record says
something narrower and more useful.

## Open

The record is here and nothing helps a person set a status. That is Phase 1: gather the evidence for
the decision, with a model doing the gathering and no part of it doing the deciding. Signing the
record is Phase 2, and `attestrun`'s manifest is the right shape for it.

One thing to watch. The `--fail-on-unresolved` flag exists and is off, on the evidence that a tool
arriving already blocking gets uninstalled before anyone reads a finding. The pressure to turn it on
by default will come from whoever installs it first, and the answer should stay no.
