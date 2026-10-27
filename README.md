# Agent-Platform

Standalone Python 3.12+ CLI for read-only repository and authorized Issue inspection.
Git must be installed. No runtime Python dependencies. `inspect` is fully offline;
`issues` additionally requires an installed, operator-authenticated GitHub CLI `gh`.
The bounded pipe reader supports POSIX systems (Linux/macOS).

Install from this checkout with `pip install .` (in a virtual environment), or
`uv tool install .`. Then invoke the installed command from a target repository:

```sh
agent-platform --help
cd /path/to/target-repository
agent-platform inspect
```

Run from the working-tree root, including linked worktree roots. Nested
directories and bare repositories are rejected. Symlinks resolve to canonical
paths. Origin must use `https://github.com/OWNER/REPO[.git]`,
`git@github.com:OWNER/REPO[.git]`, or `ssh://git@github.com/OWNER/REPO[.git]`.
Credentials, custom ports, query strings and other hosts are rejected.

Success emits one JSON object (sorted keys), for example:

```json
{"branch": "main", "linked_worktree": false, "repository": "owner/repo", "root": "/path/to/target-repository"}
```

`branch` is null for detached HEAD. Repository spelling is preserved; `.git`
is removed. Root is an absolute canonical path. Errors emit a fixed safe message
to stderr and no JSON. Exit codes: 2 non-working-tree (also argparse usage),
3 nested invocation, 4 missing/untrusted origin, 5 timeout, 6 Git execution,
output-limit or query failure, 7 unsafe/unresolvable path or value. Unborn HEAD
currently fails with code 6. Git queries each have a five-second deadline and
8 KiB limit per output stream; excess output kills the child. Inherited Git
environment overrides and global/system config are excluded. Local Git config
still applies, including URL rewrites; the effective origin is validated.

Inspection never contacts GitHub, invokes Codex, modifies a target repository,
or starts background work. No commit, push, PR creation or automatic merge.

Read-only Issue discovery (MVP.1):

```sh
cd /path/to/target-repository
agent-platform issues --trusted-actor maintainer-login
agent-platform issues --issue 42 --trusted-actor maintainer-login --trusted-actor another-login
```

The same repository-root rules apply. `issues` uses only explicit `gh api` GET
requests to github.com for this repository's identity, Issues and Issue events.
It does not query collaborators, credentials, comments, administration endpoints
or other repositories. Configure `gh` authentication yourself before invocation;
the CLI never runs login commands. `gh` and Git must be on the system executable
path (`os.defpath`). Only HOME/config locations and GH_TOKEN/GITHUB_TOKEN are
passed for gh authentication; host, debug, proxy, pager and repository overrides
are excluded. Authentication values and raw stderr are never printed.

Supply `--trusted-actor LOGIN` for each maintainer/authorized collaborator whose
ready-label actions you trust. **This is your local operator assertion of their
authority**, not a server-side permission lookup. Logins match without case.
Without an allowlist, the result has no eligible candidates and no gh calls occur.
The caller and command arguments are trusted: this is not an authorization
service. Policy is never read from the target checkout, Issue prose or comments.

An eligible candidate must be a genuine open Issue with `agent:ready`, without
`agent:working` or `needs:human`, and have an explicit scope. MVP.1 deliberately
requires a `## Scope` section containing at least one single-line bullet (`-`,
`*` or `1.`) beginning with Implement, Add, Fix, Remove, Update, Create, Document
or Test, followed by at least 31 characters describing the work. Scope headings
and verbs are case insensitive. Placeholder words TODO, TBD, whatever, something
and "figure it out" reject the scope. For example:

```markdown
## Scope
- Implement root validation with regression tests for nested directories.
```

This conservative format checks explicitness, not semantic safety. Issue text
remains untrusted data and is never executed or used to form commands.

Complete paginated event history must show consistent ready-label transitions
ending in a labeled event by an allowlisted actor. Missing actors/events,
duplicate IDs, out-of-order timestamps, same-second ready transitions and label
state inconsistencies fail closed. The full event history and relevant Issue
snapshot are read twice; repository identity is also checked twice. Any mismatch
returns no candidates. This is a bounded snapshot, not an atomic authorization:
changes after validation remain possible. Future execution must independently
revalidate admission and scope at launch.

Limits: 20 items/page, three pages/list or history pass, 128 GETs and a 60-second
request budget per invocation; each gh process has a five-second deadline and
2 MiB limit per stdout/stderr stream. Pagination links must refer to the same
endpoint and expected query; only locally constructed numbered pages are queried.
A full terminal page without a next link is conservatively ambiguous. Any limit
or API/authentication/network/JSON error discards all results; no partial success,
automatic retries, claiming, checkpoint, mutex or task execution is introduced.

Success emits one JSON object with `repository` (canonical GitHub spelling),
`status`, `reason` and `candidates`, sorted by Issue number. Listing includes
eligible Issues only; `--issue N` reports that exact Issue, including a reason
when ineligible, and never substitutes another. Each candidate has `number`,
`title` (200 printable characters maximum, URLs, supplied auth tokens and GitHub token patterns
redacted), `trusted_actor` (null unless trusted), `eligible` and `reason`.
Bodies and events are never returned. Output is bounded by the page limits.

```json
{"candidates": [{"eligible": true, "number": 42, "reason": "eligible", "title": "Fix root validation", "trusted_actor": "maintainer-login"}], "reason": "eligible_issues", "repository": "owner/repo", "status": "eligible"}
```

Exit 0 means eligible candidates; 9 means no work (including missing allowlist
or an ineligible exact Issue); 8 means unavailable/ambiguous API with an empty
`candidates` list, `status: unavailable` and a fixed safe stderr diagnostic.
Missing/inaccessible exact Issues are unavailable, not substituted. Existing
local inspection/usage codes 2–7 still apply. No result authorizes Codex execution.

Development:

```sh
uv sync --locked
uv run ruff check .
uv run pytest
git diff --check
uv run agent-platform --help
```

Tests use local temporary repositories, fake gh responses and controlled
subprocesses only; they never call live GitHub or providers. CI
runs Ruff and pytest on Python 3.12. See AGENTS.md for contributor guardrails.
