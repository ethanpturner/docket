# The five questions

Phase 0 answered one thing mechanically: does a claim point at code that exists. Phase 1 had to
answer more without becoming the thing the tool exists not to be — a fourth opinion about whether
a bug is real.

The shape came from OpenVEX rather than from us. A dismissal in VEX needs a justification, and the
spec fixes the set at five labels. That turns "gather evidence about this claim" into five
questions with answerable shapes, and it settles an argument that would otherwise have run for
days about what the model should be asked. It also does something better: a gatherer asked *does
the cited span contain the construct the claim describes* answers that question, where a gatherer
asked *is this exploitable* answers the one it was asked. Fixing the questions is most of what
keeps the model from drifting into judgement.

## Two of the five need no model

Question one was already answered in Phase 0 by the resolver. Question three — is the cited code
reachable — turned out to be answerable with `ast` and about two hundred lines: an approximate call
graph keyed on bare function names, plus a list of decorator fragments that mark a framework entry
point.

The verdict vocabulary is where the care went. The graph reports `reachable_from`,
`no_caller_found`, or `not_determinable`, and it never reports `unreachable`. Every dynamic call is
invisible to it — a decorator registering a handler, a dispatch table, `getattr`, a caller in
another package — so an absence of edges is an absence of evidence. Naming that verdict
`unreachable` would have reproduced, one level down, exactly the collapse the disposition exists to
prevent.

## The bug the fixture found

The first version treated every module-level function in `app.py`, `main.py`, or `cli.py` as an
entry point. The test fixture has a `helper` that is called and an `orphan` that is not, both at
module level in `app.py`, and both came back `reachable_from`.

It is worth being precise about the direction of that error. `reachable_from` *contradicts* the
dismissal, so over-marking entry points withholds a candidate rather than offering a bad one —
the safe way to be wrong. It was still wrong, and worse, it suppressed the one signal the analysis
exists to produce. The filename rule is gone. What survives is decorators and three conventional
names.

A second version of the same mistake survived longer: `_reachability_finding` examined only the
first resolving locator. A claim citing four positions, one inside a handler and three at module
level, got whichever answer the tool's output order happened to produce. Now every resolved
position is examined and any reachable one contradicts the justification, which is both more
accurate and conservative in the right direction.

## What the model is allowed to return

Three questions need someone to read the claim and the code together. Those get one model call
each, and the schema has no field for a verdict, a status, a severity, a confidence, or a
recommendation. `additionalProperties` is false and a response carrying a decision-shaped key is
refused rather than trimmed — the question comes back `not_established` with the offending field
named. A gatherer that answers with a verdict has not answered, and that is worth seeing.

The claim's text reaches the model fenced, and everything outside the markers is a string this tool
wrote. That rule came from the sibling project, where it was learned the expensive way: it is not
enough to fence the quoted text if the file name, the section heading, and the parsed metadata
travel in the part of the prompt that reads as instruction.

## The bug the measurement found

The reachability errors above were caught by a fixture. This one was caught by the distribution,
and it would not have been caught any other way.

Two of the five questions are phrased, on the reviewer's page, as the negation of the label they
bear on. The page asks *Can input an attacker controls reach the cited code?* and the label it
bears on is `vulnerable_code_cannot_be_controlled_by_adversary`. The first version showed the
gatherer that question and asked whether its findings supported *the justification*. The model
answered the question it could see. It described a handler reading `await request.body()` directly,
answered `supports`, and the code filed that as support for the proposition that the code is beyond
an attacker's reach.

So the clearest available statement that a claim is reachable was being converted into a candidate
for dismissing it. `vulnerable_code_not_present` was inverted the same way.

Nothing in the tests caught it, because every test used a stub whose answer was whatever the test
supplied. The distribution caught it: across 81 real claims the question came back 28 `supports`
and 0 `contradicts`. No real codebase answers a reachability question one way 28 times out of 28.
A one-directional instrument is either measuring nothing or measuring itself.

The fix is to stop asking two things at once. Every question now carries two texts: `asks`, which a
person reads, and `proposition`, which states the justification affirmatively and is the only thing
a gatherer is ever shown. `supports` now means one thing everywhere. `DEC-008` records it, and the
pre-fix figure is kept in the README as the finding that produced the entry rather than as a result.

The uncomfortable part is what it says about the phase's own design rule. The tool is built so that
a model cannot set a status, and that held — no disposition was ever wrong, because none was ever
made. But a candidate justification is the thing a reviewer reads first, and it was being generated
backwards. Refusing to decide is not the same as being harmless.

## What it cost, and what it found

Every claim from the sixteen scored reviewer runs, assessed: 81 claims, 177 model calls, $0.97,
about $0.012 per claim. Every call is recorded, and the published table re-derives from the
recording in under a second with the key unset.

The live gathering was worse behaved than the cost suggests. It stalled repeatedly in five-minute
blocks — the adapter's own timeout, tripping on a gateway that would accept a request and then
answer nothing — and the run was stopped with its tail unanswered. 21 of the 177 calls produced no
answer and left their question `not_established`. That is recorded in the coverage line rather
than fixed by re-running until the number looked better, which is the same rule the disposition
applies to itself: an unanswered question is unanswered.

The finding is not that the tool works. It is the distribution: how often any question is actually
settled on real machine-generated claims against real code. That number is the one a human triager
is already working with, and nobody publishes it.

## Open

Whether to resolve names through imports rather than matching them across modules. It would sharpen
`reachable_from` and make `no_caller_found` more common, which is the answer that needs the most
care before it gets easier to reach.

Whether a recording should be signed. The attestation project's manifest is the obvious shape and
Phase 2 is where it belongs.
