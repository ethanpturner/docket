# The path that named nothing

`docket`'s first measurement was meant to produce a rate. It produced a bug report instead.

Resolving 164 locators from ten Mantis runs left 24 unresolved, and 22 of those were one thing: in
three of the ten runs, every finding cited the absolute path of the scan root with the leading slash
stripped, and carried no line numbers. Seven runs of the same command, same model, same effort, same
workflow, same target, were clean. The difference is not in the configuration.

Reading the harness source at the tested commit found the mechanism in three lines. The tool that
writes findings passes the scan root as the fallback path for the whole report. The writer takes
that fallback whenever the model omits a per-finding `filepath`. And `canonical_filepath` returns
the basename only when a path is absolute *and not a directory* — the scan root is a directory, so
it falls through to `raw.lstrip("/")`. The result is a string that looks like a path, is not one,
and is never flagged.

Upstream fixed it five days after the commit measured, in a near-complete rewrite of the reference
harness, so the report is a record rather than an issue. Filing a fixed bug is noise.

Two things worth keeping. The first is that this is exactly the class of defect Phase 0 exists to
find, and it needed no model call to find it: a claim that points at nothing, presented
indistinguishably from a claim that points at code. The second is the shape of the failure. Every
field was populated. Nothing errored. A consumer that does not resolve locators would see a clean
run of findings, and a reviewer opening one would find a directory.

Written up at `docs/upstream/mantis-sandbox-paths.md`, with the version boundary stated, because
anyone replaying those recorded runs will hit it.
