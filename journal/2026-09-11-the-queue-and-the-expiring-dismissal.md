# The queue, and the dismissal that expires

Phase 3. The queue, deduplication, the baseline, and the CI path — the phase whose job is not to
add a capability but to make the previous three installable.

## What the adoption research said, and what it changed

Seven structural properties separate security tools that get adopted from ones that are admired.
docket already cleared two: it consumes SARIF, which pipelines already produce, and it emits VEX,
which Grype already consumes. This phase was aimed at the rest, and two of them changed the design
rather than the packaging.

**Exit zero.** The most-installed scanner in this category exits 0 by default even when it finds
something. That reads as a bug until you notice it is why the tool is installed at all. So `triage`
never fails a build unless asked, and the three gates are separate flags naming separate policies
(DEC-015).

**A tool with no baseline file does not survive its second week.** That one sent me somewhere more
interesting than a suppression list.

## The dismissal that expires

Every suppression mechanism in this category suppresses forever. The fingerprint goes in the file,
the finding never returns, and — this is the part nobody writes down — it never returns after
somebody rewrites the function the dismissal was reasoning about either. The argument dies and the
suppression outlives it.

DEC-011 had already bound a decision to the bytes at the positions it cites, for a different
reason. Which means "is this dismissal still about the code it was made about" is a digest
comparison, not a judgement. So the baseline carries a decision only while those bytes read the
same, and returns the claim to the queue when they change, carrying the reviewer's own previous
reason (DEC-014).

That is the one thing in this tool no other tool in the category does, and it cost almost nothing
to build because the previous phase had already paid for it.

**The tests found the rule too weak.** My first version compared the cited span alone. A test with
a rewritten function body and an untouched `def` line passed when it should have failed: the
citation matched, the function around it had been replaced, and the decision carried. A claim
citing a handler's `def` line is not a claim about that line. Both digests are checked now.

The second correction came from the moved-span test. Inserting one line above a citation pushed it
onto the decorator, where no function encloses it, so a positional symbol lookup found nothing and
reported a rewrite that had not happened. The symbol is looked up by name now, because position is
precisely the thing that moved.

## Deduplication, and the number that is not the one I expected

The brief was to derive identity from content rather than the producer's signature, on the evidence
that signatures never repeat across runs. That part worked: 72 emitted Mantis claims go to 41 by
signature and 35 by content.

The measurement that matters is the other column. **Only 5 of those 35 groups appear in more than
one of the five runs.** Thirty were reported once and never again.

I had been reading the 0.00 signature agreement as a labelling artefact — the same findings wearing
different identifiers each run, which better identity would wash out. It is not. After normalising
away the prose, the line numbers and the tool's own identifiers, the findings themselves still
mostly differ between runs. Deduplication cannot fix non-determinism, and a queue fed by a re-run
of this reviewer is mostly new claims.

Two design decisions came out of looking at the groups rather than the totals.

The first: keying on the *set* of cited sites split claims from themselves, because one run cites
`{main.py, main.py::receive_event}` and the next cites `{main.py::receive_event}`. The key is the
innermost single site now.

The second I declined to fix. The missing-authentication weakness still splits into two groups,
because the reviewer called it CWE-306 in two runs and CWE-345 in two others. Merging those means
asserting that two entries in MITRE's taxonomy are the same entry — a judgement this tool cannot
check and has no standing to make. They are reported adjacent instead, and a person decides. On one
function the report shows five different CWE identifiers across five runs, which is worth seeing.

## The unfailable check, again

`state_of` on an entry with no anchors could only ever return `carried`: nothing to compare, so
nothing to contradict. That is the fifth instance of this shape in two days across this project and
its siblings — a rendered section filtering on a status nothing set, a compliance metric scored
against authored recordings, a fence covering only excerpt bodies, a `not_affected` requirement
satisfied by a field that is always present, and now this. It reads `stale`.

The pattern is specific enough to name: a check whose negative branch is unreachable is worse than
no check, because the absent check is at least visible.

## Open

Whether `--fail-on-stale` should be the one gate defaulting on, since a stale decision is the only
condition here that represents something a person already examined and that has since changed.
Whether a symbol rename should preserve identity, which needs more than a name. And whether the
related-groups report should learn a CWE family map, which I think is a trap.
