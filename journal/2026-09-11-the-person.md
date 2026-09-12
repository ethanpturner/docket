# The person, and what it costs to let them in

Phase 2, the same day as Phases 0 and 1.

Everything before today refused to decide. That refusal is cheap to write and it is the whole
argument for the tool, so the phase that ends it is the one that could quietly undo it. Most of
the work was not the decision — it was making sure that letting a person in did not let anything
else in with them.

## What the refusal was actually protecting

Phase 0 pinned its golden rule structurally: no module outside the vocabulary named
`Status.EXPLOITABLE` or `Status.NOT_EXPLOITABLE`, so no code path reached a decided status. It was
a good test and it had to go, because Phase 2's entire job is to reach one.

The temptation was to delete it and write a sentence in a docstring saying a person decides. What
replaced it is narrower and, I think, stronger: the decision path may name a decided status, and
the *gathering* path may not reach one at all. `assess.py`, `model.py`, `questions.py`,
`evidence.py`, `reachability.py`, `resolve.py`, `ingest.py`, `claim.py` and `fence.py` do not
import `Status`, `Disposition` or `Decision`, so there is no expression anywhere in them that
produces a verdict. A future edit wiring a model response to a status has to add an import to one
of those files to do it.

I mutation-tested both new pins rather than trusting that they passed. Adding
`from docket.disposition import Status` to `assess.py` fails the gathering test; adding a
`dataclasses.replace` to `render.py` fails the mutation test. A guard that has never been seen to
fail is a guard nobody has checked.

The third test is the one I nearly left out: a list of module names in a test file goes stale the
moment somebody adds a module. So a third test asserts the two lists plus a neutral set cover the
package, and it failed within the hour — I added `_version.py` and it caught it.

## The unfailable check, again

`Disposition` gained a rule that a `not_exploitable` status carries a justification or an impact
statement. Then two Phase 1 tests failed, and the reason was instructive.

`vex.py` had been falling back to the reviewer's `reason` as the impact statement. `reason` is
required and non-empty on every disposition. So "a dismissal has a justification or an impact
statement" was satisfied, always, by a field that can never be absent. The check could not come
out false.

That is the fourth one of these I have seen in two days: a report section filtered on a status
nothing in the pipeline could set; a compliance rate scored against recordings nobody had
captured; a fence whose coverage claim was true of the material it was pointed at and silent about
the rest; and now this. The shape is the same every time — the code agrees with itself, the test
agrees with the code, and nothing in the loop is attached to the outside world. I do not have a
general defence to propose. What I notice is that all four were found by trying to *measure*
something rather than by reading the code, and three of the four were found by a tool or a person
outside the project.

Removing the fallback is `DEC-009`, and it supersedes the fallback `DEC-001` designed. The
argument for removing it is not only that the check was vacuous: OpenVEX discourages
`impact_statement` for automated consumers, and the entire reason for shipping in VEX rather than
a vocabulary of our own is that the machine-readable field is what makes the record consumable. A
fallback that fills the prose field on every dismissal produces documents that pass the spec and
carry nothing a scanner can key on.

## The override is the feature

`DEC-010` is the entry I would defend hardest. Selecting a justification the assessment did not
offer is refused unless the reviewer says they are overriding the evidence and why.

Refusing the override outright was the obvious alternative and it is wrong, because it would
assert that five narrow questions answered against one commit are complete — the claim the tool
spends every other page denying. A person who knows the deployment knows things the call graph
cannot see. Allowing it silently is also wrong, for a subtler reason: six months later, "the tool
found this and a person agreed" and "a person decided this over the tool's objection" are
different facts about how much checking happened, and a bare `justification` field cannot tell
them apart.

So the override is a field, it is required to select an unoffered label, it is checked again when
a decision file is loaded because the file is meant to be hand-edited, and it travels into the
emitted VEX as `docket_override_reason`. An assessment with no candidates at all — `--no-model`,
or a claim that only went through `record` — offers nothing, so every justification against it is
an override. That reads as harsh and it is exactly right: selecting `vulnerable_code_not_present`
when nobody looked at the code is the decision that most needs a trace.

## Two checks, unequal

`bind` digests the artifacts and separately records every quoted span. `verify` re-computes the
digests and, given a repository, re-resolves each locator and compares the code that is there now.

The second check is the one worth having. The first answers *are these the same files*, which is a
statement about bytes on one machine. Only the second catches a record drifting away from its
subject while every file around it stays byte-identical — which is precisely how a triage record
rots. The worked example demonstrates it: edit one cited line, and every artifact digest still
matches while the verdict goes to `contradicted`.

Re-resolving the recorded locator rather than opening the recorded path was a late change and a
good one. One code path produces a quotation and one code path checks it, so the truncation cap
and the containment rule cannot drift apart between recording and verification.

Verification without a repository returns `unverifiable`, never `verified`, and prints what it did
not do. That is the same rule the disposition vocabulary exists for, one level up.

## The worked example, and the claim I picked

I wanted the example to be a real claim against real code with real model calls, replaying from
committed recordings and no key. It is: Codex Security's finding that unsigned requests can
publish forged deployment notifications, five cited positions, all five resolving.

Four of the five questions contradict a dismissal. The fifth — *can attacker-controlled input
reach it?* — is `not_established`, because that model call timed out during the measurement run
two hours ago. I nearly picked a cleaner claim.

Keeping it is better, and it is the reason the example teaches anything. The reviewer's recorded
reason says they read `main.py` themselves rather than treating silence as a pass. A tool whose
examples all show five green answers would be teaching the wrong lesson about what triage looks
like.

Committing the target snapshot meant excluding it from ruff, which matters more than it sounds:
formatting a byte-identical copy of somebody else's code would break the span digests that pin it.
The exclusion is load-bearing, so it carries a comment saying so.

## Loose ends

`docket_version` was hardcoded to `0.1.0` in the record class while the package said `0.2.0`.
Records have been claiming a version that did not write them since Phase 0. Fixed by putting the
version in one module both can import, which is a small thing that would have become a confusing
thing in a record whose whole purpose is provenance.

`fixed`, OpenVEX's fourth label, is refused with its own entry (`DEC-012`). A record binds one
claim to one commit; `fixed` asserts something about a version this tool never examined.

Open, and recorded rather than solved: nothing counts overrides, though the field is there for it,
and a rate of decisions-against-the-evidence would say something real about whether the gathering
is worth its cost. And the binding trusts the `--commit` string a caller passes rather than
checking a git object, which would turn "the code at this position" into "the code at this
position of this commit" and needs a dependency this package does not have.
