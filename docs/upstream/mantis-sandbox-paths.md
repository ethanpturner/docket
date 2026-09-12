# Mantis findings that cite the scan root instead of a file

**Not filed upstream.** The defect is real at the commit measured and is already fixed at
`google/mantis` HEAD. `d13c93fb` (2026-09-03), the commit this was measured against, is the commit
immediately before `dd5d7935` (2026-09-08), "Near complete rewrite of ADK reference harness", which
rewrites the two functions responsible. An issue reporting it would report a fixed bug. The record
is kept here because it is the first finding `docket` produced, because it pins the version boundary
for anyone replaying these runs, and because the failure was silent at both commits.

`google/mantis` accepts issues but states in `CONTRIBUTING.md` that it takes no external pull
requests or code contributions.

## Summary

In three of ten runs, every finding's `filepath` is the absolute path of the scan root with the
leading slash removed, and `line_numbers` is empty. A reviewer reading those findings has no file
and no line to open, and nothing in the output marks the value as unusable.

## Environment

| | |
|---|---|
| Mantis | `d13c93fb8e9779801711daea0d65fffa133c3b2d` |
| Harness | the ADK reference harness under `reference/` |
| Model | `openai/gpt-5.6-sol` via `api.openai.com` |
| Effort | `medium` |
| Sandbox | `static-only` |
| Targets | two FastAPI applications, 9 and 13 files, at `ethanpturner/trace@c5b0590` |

The invocation, identical across all ten runs apart from the run directory:

```
python scripts/launch.py <target> \
  --workflow reference/workflow.pilot.json \
  --sandbox static-only \
  --model openai/gpt-5.6-sol \
  --reasoning-effort medium \
  --db <run>/out/knowledge.db
```

`workflow.pilot.json` is `workflow.json` with the reproducer, repro-classifier, chainer and patcher
nodes removed. The three affected runs share their model, effort, workflow, sandbox mode and target
with the seven clean ones. Nothing in the configuration distinguishes them.

## What happens

In the `findings` table of `knowledge.db`, and in every export derived from it:

```
filepath     private/tmp/.../scratchpad/reviewers/scaled/runs/unsigned-webhooks/mantis/run-3/target
line_numbers []
```

A clean run of the same target, same command:

```
filepath     deploy_notifier/main.py
line_numbers [34, 36, 41, 45]
```

The emitted value is the scan root, which is a directory, rendered as an absolute path with the
leading `/` removed. It is neither a repository-relative path nor a valid absolute one, and it names
no file.

## What should happen

`filepath` names a file in the reviewed repository, relative to its root, as the harness's own test
suite asserts (`reference/test_suite.py`, "Specific filepath attribution under repo-scoped run",
which expects `src/auth.py`). Where a finding carries no file, the field should be empty rather than
carrying a directory path, so a consumer can tell the difference between "this file" and "no file".

## Frequency

Three of ten runs are affected. Within them, every finding is affected.

| | |
|---|---:|
| Runs affected | 3 of 10 |
| Emitted findings citing the scan root | 22 of 72 |
| Distinct findings citing the scan root | 11 of 41 |
| Cited locators that do not resolve for this reason | 22 of 164 |

Affected: `unsigned-webhooks` run 3, `rag-support-bot` runs 3 and 5.

## Mechanism

Two lines, both in the reference harness at `d13c93fb`.

`reference/tools/research_tools.py:156` passes the scan root as the fallback filepath for every
finding in the report:

```python
write_findings(ctx.db_path, ctx.target_file, findings, run_id=ctx.run_id)
```

`reference/core/database.py:607` takes that fallback whenever the model's structured finding omits
`filepath`:

```python
raw_fp = finding.get("filepath") or filepath or ""
```

`reference/core/database.py:57-58`, in `canonical_filepath`, then converts it:

```python
if raw == tf_clean:
    return os.path.basename(raw) if (os.path.isabs(raw) and not os.path.isdir(raw)) else (raw.lstrip("/") if os.path.isabs(raw) else raw)
```

The ternary takes the basename only when the path is absolute **and not a directory**. The scan root
is a directory, so control falls to the else branch and returns `raw.lstrip("/")`.

Reproduced directly against that commit, with no model and no network:

```python
>>> from core.database import canonical_filepath
>>> d = tempfile.mkdtemp()
>>> canonical_filepath(d, target_file=d)
'var/folders/.../T/tmpudn2fabr'
>>> canonical_filepath("app.py", target_file=d)
'app.py'
```

The trigger is that the model omitted `filepath` and `line_numbers` on its findings in those three
runs. The harness had no per-finding path to canonicalise and substituted the scan root.

## Impact

A finding whose locator cannot be opened cannot be triaged, scored, deduplicated against another
run, or carried into any downstream format. The failure is silent: the field is populated, the value
is a plausible-looking path, and nothing in the record marks it as a fallback. A consumer that
resolves locators sees a path that does not exist; a consumer that does not resolve them sees
nothing wrong at all.

## Status at HEAD

`dd5d7935` rewrites both functions and closes this. `write_findings` now detects when the
finding's filepath is the scan directory, its basename, or `.`, falls back to the path component of
the first `code_paths` entry, and only falls back to `filepath` when that is not a directory.
`canonical_filepath` no longer has the `lstrip("/")` branch: absolute paths are relativised against
the jail directory, the target directory, or the working directory, and a path that relativises to
`.` returns the empty string.

Simulating HEAD's `canonical_filepath` on the failing input returns `''` rather than a stripped
absolute path. That was established by reading `reference/core/database.py` at HEAD and running its
logic, not by re-running the harness.

## How this was found

`docket record` resolves every locator a finding cites against the repository at a pinned commit and
reports whether it resolves. Over these ten runs it resolved 140 of 164 cited locators; the 22
described here and two citing a line one past the end of a file are the remainder. See
`scripts/measure_feeds.py`.
