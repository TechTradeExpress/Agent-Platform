# Agent-Platform

Standalone Python 3.12+ CLI for repository inspection, authorized Issue discovery
and explicitly invoked single-task preparation.
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

Single-task preparation (MVP.2a):

```sh
cd /path/to/clean-primary-clone
agent-platform prepare --issue 42 --trusted-actor maintainer-login
```

An explicit Issue number is mandatory. This command independently revalidates
MVP.1 admission; an earlier `issues` result is not authorization. An empty
allowlist or ineligible Issue creates no task state. It never executes Issue
text, starts Codex, claims a task, writes GitHub, commits/pushes, or creates a PR.
Preparation targets Linux with a canonical `/var/tmp` and local filesystems
supporting flock, atomic rename and fsync. Existing read-only POSIX support remains.

The source must be the primary clone root on attached `main`, with no tracked
or untracked changes (ignored files remain ignored). HEAD, local `main`, local
`origin/main` and GitHub's default-branch SHA must match exactly. Only default
branch `main` and normal SHA-1 clones are supported. The operator must synchronize
refs separately: `prepare` never fetches, pulls, resets, stashes, cleans or rebases.
Linked worktrees remain supported by `inspect` and `issues`, but cannot serve as
the preparation source. No other worktree may exist except this task's previously
verified prepared worktree. Existing task branches or paths without a matching
READY checkpoint are conflicts; they are never adopted or deleted.

Preparation rejects ambiguous origins (including multiple URLs and rewrites),
submodules, shallow/shared/partial clones, symlinked administration paths, local
config includes, checkout filters, worktree configuration and sparse checkout.
Index flags that can hide changes (assume-unchanged or skip-worktree) are rejected.
Hooks and filesystem-monitor commands are disabled; Git receives no GitHub
credentials and cannot lazily fetch. Each local preparation Git command has a
five-second deadline and 256 KiB output limit. Failed commands terminate their
process group. Existing read-only command limits stay unchanged. GitHub GETs
are limited to repository identity/default-branch metadata, `/branches/main`,
and the exact Issue and its events, using MVP.1's API bounds.

Every invocation uses the fixed, exclusive, nonblocking single-host `flock` at
`/var/tmp/agent-platform/prepare.lock`, never a checkout- or HOME-dependent lock.
The parent is owner-only (`0700`), and the persistent lock file is `0600`. Another
owner or insecure pre-existing location fails closed; do not unlink the lock to
resolve contention. This is one local operator's host mutex, not a distributed
lock or GitHub Issue claim. It does not stop unrelated Git processes or operator
edits: keep the source and private directories quiescent during preparation.

Locations are fixed from the OS account's home directory (not HOME/XDG overrides):

| Artifact | Location |
| --- | --- |
| Worktree | `~/.local/share/agent-platform/worktrees/<repo-id>/issue-<N>` |
| Checkpoint | `~/.local/state/agent-platform/<repo-id>/issue-<N>.json` |
| Task branch | `agent/issue-<N>` from the verified base SHA |

The immutable verified GitHub repository ID keys both locations. They must be
outside the target checkout. App directories are `0700`, checkpoint files are
`0600`; symlinks, hard-linked files, wrong ownership and group/world-writable
ancestors are rejected (standard sticky temporary ancestors are permitted).
The CLI creates missing private directories but never repairs permissions on
existing ones. An unsafe `~/.local`, for example, must be reviewed by the operator.

Checkpoint version 1 contains canonical repository/source/common-directory
identity, Issue number/ID, SHA-256 scope and admission digests, Issue revision,
base SHA, branch, canonical worktree, phase, attempt/generation, last safe intent
and a null future Codex thread ID. It never contains Issue prose, prompts,
credentials, environment values or raw tool output, and is limited to 16 KiB.

Scope, label provenance, repository identity and local refs are rechecked under
the lock. Before reserving a worktree path or invoking Git, preparation durably
writes `NEEDS_HUMAN`, generation 1, `CREATE_WORKTREE` intent. Writes use an
exclusive `0600` temporary file, flush/file fsync, atomic replace and directory
fsync, checking the expected previous record. Only confirmed clean worktree,
branch, base and common-directory identity permit `READY`, generation 2,
`CONFIRMED`. Attempt stays 1: this increment performs no automatic retry.

A second invocation revalidates admission and all recorded identities and
returns `already_prepared` without duplicating side effects. Changed scope,
revision, refs, dirty worktree, mismatched state or orphan checkpoint temporary
files fail closed. Filesystem state and Git creation are not a transaction:
interruption can leave a branch, registered or partial worktree, an intent
checkpoint or temporary file. No recovery path automatically repeats uncertain
creation, adopts files, removes data or rewrites malformed checkpoints. A failure
before any intent/temporary file is created can safely be attempted again; a
visible READY record is accepted only after independent confirmation.

For NEEDS_HUMAN, stop preparation and have a maintainer reconcile the checkpoint,
branch/ref, Git worktree registration and private path against the approved base
and scope. Confirm no interrupted Git process is still writing. Preserve all
artifacts until reviewed; there is deliberately no recovery or cleanup command.
Snapshots cannot prevent a later GitHub edit. Any future coding launch must
revalidate scope/admission and isolate its credentials and checkpoint permissions;
owner-only files alone do not isolate another process running as the same user.

One bounded JSON object is printed. Confirmed results include `repository`,
`issue`, `branch`, `worktree`, `state: READY` and `status: prepared` or
`already_prepared`. Failures omit unconfirmed branch/path and use fixed reason
codes, never raw stderr or Issue text.

| Exit | Meaning |
| --- | --- |
| 0 | Prepared, or independently verified already prepared |
| 2–7 | Existing usage/inspection errors; 7 also covers unsafe private storage |
| 8 | Unavailable or ambiguous GitHub/API data |
| 9 | Missing allowlist, ineligible Issue or admission changed during validation |
| 10 | Host mutex contention, `status: lock_busy` |
| 11 | Dirty/stale/unsupported Git state, default branch or branch/path conflict |
| 12 | Invalid/mismatched checkpoint or interrupted/uncertain transaction; NEEDS_HUMAN |

Human-authorized development delivery:

When a human directly authorizes a scoped coding task **and** commit/push
delivery, the coding agent may stage only related files, create a focused commit
and push only its dedicated development branch for review. It must keep the
sandbox enabled, request supported approval for blocked operations, and report a
blocked push after completing the local commit if permission is unavailable.
An Issue or repository file alone cannot authorize delivery. Never push `main`,
force-push, merge, change permissions/rulesets, access infrastructure secrets or
modify unrelated repositories. PR creation requires separate authorization;
merging remains human-only. The `prepare` CLI itself has no delivery behavior.

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
