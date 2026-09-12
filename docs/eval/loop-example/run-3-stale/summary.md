## docket — run-3-stale

**0 new, 1 stale, 1 carried, from 2 claims.** 0 merge(s). Commit `run-3-stale`. Nothing here is decided by this tool.

### Decisions that went stale (1)

The code these were decided against has changed, so they are back in the queue.

#### 1. Report path is built from caller input

- **Where** `service.py::_load`
- **Weakness** CWE-22
- **Evidence** 2 of 5 questions settled, no candidate justification
- **Was** `exploitable`, decided by reviewer@example.com on 2026-09-11
- **Their reason** `name` reaches a path join with no containment check, and `render` is called from the HTTP layer with a caller-supplied value.
- **Why it is back** the code at service.py:7 is not what the decision quotes

<details>
<summary>Carried, no action needed (1)</summary>

| Claim | Status | Decided by | When |
| --- | --- | --- | --- |
| Audit helper has no caller | `not_exploitable` | reviewer@example.com | 2026-09-11 |

</details>
