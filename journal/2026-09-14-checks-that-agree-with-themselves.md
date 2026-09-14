# 2026-09-14 — Checks that agree with themselves

Six defects of one class had turned up across two repositories in two days, three of them here, in
a tool three days old. That is a rate, not luck, so today was an audit of all four repositories for
the class rather than another feature.

## What the class is

A check whose failing branch cannot be reached. It runs, it passes, and it establishes nothing. The
three found here earlier were a guard satisfied by a fallback that is always present, a pair of
questions asked in one direction and recorded in the other, and a baseline state that could only
return one value. What they have in common is that the code agreed with itself: no input existed
that would have made any of them disagree.

That is a different failure from a bug. A bug produces a wrong answer that somebody eventually
sees. This produces a right-looking answer forever.

## The detector, and what it is worth

`scripts/audit_unfailable.py` finds the third of the taxonomy a parser can settle: enum members
nothing assigns, exception types nothing raises, tests whose assertions compare only literals. It
reads source rather than importing it, so the same script ran against all four repositories.

Seven candidates across four repositories. Four confirmed, two cleared as deliberate and
documented, one a false positive — `whence`'s `Relation.DISTILLED_FROM`, which is assigned through
a string-to-relation map the parser cannot follow. One in seven is a workable rate for a worklist.

Here it found one: `SpanTooLargeError`, defined, exported, never raised, and carrying a docstring
that described something other than its name. `DEC-016` removes it. The docstring mismatch is the
part worth keeping in mind — nothing had ever exercised the class, so nothing had forced the name
and the description to agree, which is the same absence one level down.

## What it is not worth

The detector would not have found any of the three defects that prompted it. Every enum member in
the polarity bug was assigned. Every branch was reachable. Every test passed. The tool was
recording the opposite of what it had found, and what caught it was a number whose shape was
implausible: 28 `supports` and 0 `contradicts` on a question no real codebase answers one way.

So the audit's real output is not the script. It is two questions to ask of anything published:
for every number, what input would change it; for every invariant asserted in prose, which test
fails if the enforcement is deleted. Both are on `unfailable-checks.md`, with the answers for this
repository, so the next pass does not redo the clearing.

## The sibling worth copying

`attestrun` raised zero candidates, and it is the only one of the four that already checks for this
class deliberately. Its evaluation refuses to pass unless every verdict in the vocabulary is
produced by at least one scenario, and the comment beside it names the failure exactly: scoring the
registry's declared strings would check a list of words in a YAML file against itself. A tool that
has only ever returned `verified` has not been tested.

That check belongs here, and it is now here. **The detector's yield was one in seven and it would
not have caught any of the three defects that prompted the sweep, so `tests/test_vocabulary_coverage.py`
is the actual remedy and the script is a worklist.**

It covers 47 members across eleven vocabularies and harvests rather than names them: the committed
examples are read, and the resolver, call graph, identity function, baseline, VEX emitter and
replay seam are each run over the committed targets. Eight members are allow-listed with a reason
the test reads, split into `deliberate` (one: an identity for a claim with nothing in it) and
`unstaged` (seven: six provider failures and a file deletion). Three companion tests stop the
allow-list rotting — one fails when an exemption stops being true, one on a typo, one when a new
vocabulary appears.

Writing it found four things the morning's hand pass had cleared. The VEX emitter had never been
exercised for `not_affected` or `under_investigation` — the two labels that carry this tool's
entire argument about uncertainty, emitted by nothing committed. `FailureReason.NOT_RECORDED` was
unproduced, though it costs nothing to reach and is what makes offline replay mean anything. Two
of three reachability verdicts were unproduced until the harvest walked all eighteen functions
instead of four chosen lines. And two of my own allow-list entries were simply wrong, which the
reverse test said immediately.

That is the argument for the test in one paragraph: the hand pass was careful, done the same day,
by someone looking for exactly this, and it still cleared six vocabularies that had two holes in
them.
