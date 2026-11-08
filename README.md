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

Public execution quarantine (MVP.5b, Issue #47):

Valid `agent-platform run --issue N`, `resume --issue N` and `doctor --issue N`
(including `doctor --resume`) return exit **13**, `status: unavailable`,
`reason: legacy_execution_quarantined`, `backend: legacy_api`, `state: null`,
`launch_allowed: false`, `resume_authorized: false` and
`native_status: SUBSCRIPTION_ISOLATION_BLOCKED`. Argument usage errors remain exit 2.
Refusal precedes repository/Git/GitHub inspection, credential/session reads,
broker/network, locking/state access, probes and runtime launch. The historical
API-backed lifecycle stays in source for offline tests and analysis only;
retaining it grants no activation or fallback authority. The selected future
engine is stock subscription-funded Codex, whose native gate remains blocked.
See [current quarantine and historical execution contract](docs/execution.md).

Human-authorized supervised development delivery:

In an already running interactive Codex session, use the **single copy-paste
prompt** in [the contributor workflow](docs/development.md). The directly
authorized coding agent verifies the repository, fetches current `origin/main`,
creates or safely verifies its dedicated development worktree, implements, tests,
commits, pushes only its feature branch and immediately opens a Draft PR to
`main` with `Closes #N`. No separate host-shell setup or PR command is required.
The original checkout and existing work remain untouched. Sandbox or connection
blocks require supported approval, never weaker protections.

Independent review pins the exact HEAD SHA. Only PASS plus green required checks
for that unchanged SHA permits the independently authorized reviewer to publish
the review, mark Ready for review and close the single linked Issue as Completed.
Failed/pending CI, changed SHA, ambiguous links or blockers leave Draft/open.
A comment or Ready state is not a formal approving review, merge authorization or
deployment-readiness proof. Only the human maintainer merges; no auto-merge,
force-push, direct main push or permissions/ruleset changes.

These contributor permissions do not extend to the automated runner. `prepare`,
`run` and `resume` retain their existing restrictions: no commit, push, PR or
GitHub writes. Issue prose alone cannot authorize delivery or Issue closure.

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

[GitHub governance and CI provenance](docs/github-governance.md) records the
verified Action pins, read-only job policy, private-repository enforcement gaps
and separately proposed operator configuration. Successful CI is offline evidence,
not native isolation or authenticated runtime readiness.

## MVP.5 architecture and security contract

[ADR 004: architecture and trust-boundary freeze](docs/architecture-trust-boundaries.md)
distinguishes implemented offline components from proposed integration, defines
AP-TB/1 evidence and transition requirements, and records the native security
NO-GO. Issue #47 now quarantines public legacy run/resume and doctor before
side effects; the API broker is not an authorized product fallback. Native
subscription execution remains blocked at exit 13.

## Readiness and opt-in live smoke testing

Public `doctor` is an inert quarantine report, never a native readiness check.
`subscription` is the unchanged non-launching native isolation-block report.
See [exact diagnostics](docs/execution.md). The [legacy E2E runbook](docs/e2e.md)
is historical and cannot be executed through quarantined entrypoints. Offline
CI does not prove kernel confinement, credential separation or authenticated E2E;
no host provisioning or live testing is authorized by this quarantine.

## Reference inference broker (MVP.2d)

`agent-platform-broker` is a separately invoked Linux Unix-socket server with
SO_PEERCRED admission, explicit inference policy, fixed-origin verified TLS and
bounded streaming/budgets. See [broker configuration, limits and manual audit
checklist](docs/broker.md). It never starts from `run`, `resume` or `doctor`.
Offline fake-upstream tests are not independent security audit or live E2E
evidence. No broker/runtime is provisioned, no account is selected and no
credential is discovered automatically. Production readiness remains unverified.

## Read-only Linux diagnostics (revised MVP.2e)

The selected execution path is Codex authenticated through a ChatGPT subscription.
[Static manifest and host-policy diagnostics](docs/deployment.md) are independent
of that backend and do not authorize execution. The earlier API broker deployment
plan/rehearsal is deferred and removed from PR #16. See [pinned CLI help evidence
and subscription-auth security gates](docs/subscription-auth.md).

Public run/resume/doctor are quarantined. Their historical internal implementations
and reference API broker remain for offline analysis, not subscription
authentication. Do not deploy the API broker as the next product step, copy auth.json into the coding sandbox or
forward OAuth tokens through it. Authenticated execution, safe refresh and OS-
enforced credential separation remain blocked pending a separate reviewed design.

## Subscription architecture spike (Issue #17)

`agent-platform subscription` returns **SUBSCRIPTION_ISOLATION_BLOCKED** (exit 13)
without reading login state, starting Codex/tools, accessing credentials or
changing checkpoints. [ADR 001](docs/subscription-architecture.md) compares a
trusted CLI parent and supported invocation-service design. Neither currently
proves complete OS-enforced tool/credential separation; API billing/broker
fallbacks and raw auth-cache mounts are prohibited.

Offline auth/session/stop-presentation tests do not prove real tool isolation.
The safe next milestone is a no-account, pinned-protocol external-tool mediation
proof with real-kernel canaries, before independently authorized subscription
login/refresh/smoke testing. Existing commands/security gates remain unchanged.

The [pinned Codex tool-dispatch feasibility report](docs/tool-dispatch-feasibility.md)
records Issue #20's offline schema/source audit and synthetic callback tests.
Complete credential-safe tool mediation remains unproven; subscription execution
stays `SUBSCRIPTION_ISOLATION_BLOCKED`. Offline CI is not real Linux isolation or
authenticated E2E evidence.

[ADR 003](docs/subscription-transport.md) now records the binding Issue #24 choice:
**A — native Codex CLI SELECTED**, funded by the operator's ChatGPT subscription.
Agent Platform orchestrates Codex; it is not a replacement coding agent. B (SIWC
app-server) and C (custom Responses agent) are deferred/not approved. The earlier
conditional C recommendation is superseded, with research retained for provenance.

The [native adapter and supervised offline dry-run](docs/native-codex.md) reuse the
existing execution lifecycle with real fake-executable subprocess tests. The
native entrypoint is unconditionally disabled; no user flag enables it. A VM
protecting the homelab does not itself hide CODEX_HOME from tools inside that VM.
Credential isolation and artifact admission remain distinct deployment gates;
`agent-platform subscription` still exits 13. No real login or inference occurred.

[Executable native Linux canaries](docs/native-canary.md) are a separate,
non-authenticating experiment: `agent-platform-native-canary` reports without
probes or fixture creation;
`--run-synthetic` explicitly opts into fixed fabricated probes only after trusted
runtime validation. Missing/untrusted prerequisites return BLOCKED, never a
privileged or unsandboxed fallback. Host containment and same-domain CODEX_HOME
exposure are reported separately; native subscription execution remains disabled.

Issue #29 provides a separate, offline `agent-platform-native-artifact` inspector
for the exact pinned native Codex release. Its native-only 384 MiB ceiling does
not change either legacy 256 MiB gate. Static inspection never installs or admits
a runtime and never enables subscription execution. See the
[artifact policy, provenance and blockers](docs/native-artifact.md).

Issue #49 adds a [trusted read-only GitHub evidence API](docs/github-evidence.md)
for exact repository/Issue/PR/review/CI snapshots and verified merge ancestry.
It uses fixed bounded requests only through an explicitly supplied trusted
controller client; no runtime command or publisher is enabled. Receipts are
planner inputs, never execution, authentication or publication authority.

Issue #30 adds an [offline trusted Publisher plan API](docs/publisher.md).
It validates completed-task identity, exact changes and trusted test receipts
under the existing lock. Its immutable candidate is never publication authority;
there is no publisher CLI, authentication or runtime Git/GitHub-write operation.

Read-only task diagnostics: `agent-platform status --issue N` reports validated
local checkpoint evidence, guard/lock observations and persisted session/usage
without contacting GitHub or Codex. Recorded RUNNING never proves live activity;
no state is repaired. See [task status](docs/task-status.md) for schema, limits
and the bounded read-only Git subprocess exception.

The [offline Telegram notifier](docs/telegram-notifier.md) provides typed trusted
events, fixed safe formatting and a bounded durable outbox with scripted fake
transport tests. It is disabled by default and has no token, real sender, daemon
or inbound control. Live notification deployment requires separate approval.

Human recovery guidance: `agent-platform recovery plan --issue N` reuses the
read-only status snapshot to explain interrupted or contradictory evidence,
investigation choices and prohibited actions. It never repairs, resumes or
replays a task; COMPLETED is not exactly-once proof. See [recovery](docs/recovery.md).

Issue #33 adds a [read-only offline queue planner API](docs/queue.md) for trusted
operator dependency policy, existing Issue admission and independently supplied
PR evidence. Plans distinguish waiting, eligible candidates, blockers, recorded
local tasks, review and verified merges. A next candidate is advisory only;
retained local state or uncertain activity blocks nomination. No scheduler,
GitHub PR client, automatic task start or new CLI command is introduced.

Issue #34 adds [offline usage presentation and explicit operator HOLD](docs/subscription-hold.md)
as a trusted Python API. Historical token counts and unclassified failures never
prove subscription quota. HOLD uses separate private durable records, preserves
checkpoint/session identity, and has no release, automatic retry or resume.
Missing or conflicting state requires human intervention; native subscription
execution remains blocked at exit 13.

Issue #38 adds a [disabled-by-default offline Telegram console API](docs/telegram-console.md)
with strict numeric caller/chat policy, four read-only commands, sanitized trusted
report projections, durable replay suppression and non-executable callback
proposals. It has no bot token, network transport, daemon, active HOLD/resume or
GitHub authority. Native subscription execution remains blocked at exit 13.

The [offline supervisory decision report](docs/supervisor.md) joins queue, task,
recovery and HOLD evidence without authorizing launch, resume or release.

The [disposable Linux fixture specification](docs/native-linux-fixture.md) records
operator-reported sandbox01 kernel results, an offline build/audit plan and missing
reproduction inputs. Overall native execution remains BLOCKED; no provisioning
or kernel run is enabled by that evidence.

The [native security GO/NO-GO assessment](docs/native-security-go-no-go.md) inventories
the pinned tool routes and evidence gaps. The decision remains NO-GO; synthetic
PASS cannot authorize credentials, native execution or a weaker fallback.

The [supervised App review COMMENT policy](docs/review-comment.md) implements
offline Gate A only: exact-SHA human authorization, synthetic pre/postflight and
unknown-result reconciliation. No App, credentials or live review are enabled.

The [downstream project policy](docs/target-project-policy.md) pins independently
authorized target repositories, branches and installations. App registration
ownership is separate from target ownership; live tenant access remains NOT_RUN.

The [current stock-runtime feasibility decision](docs/native-runtime-feasibility.md)
records AP-NF/1 source evidence and a future verification plan. Runtime remains
NO-GO; the historical AP-NS/1 assessment retains its exact original subject.

The [ChatGPT review handoff](docs/chatgpt-handoff.md) adds Stage 1 typed offline
proposals, separate operator approval and durable synthetic UNKNOWN journaling.
Live integration remains INTEGRATION_BLOCKED / NO-GO; no publisher is deployed.

The [Debian 13 candidate package](docs/debian-package.md) provides the existing
CLI tools with no services or automatic state migrations. Its separate disposable
CI verifies real package lifecycle operations while execution remains blocked.

The [offline Codex assignment contract](docs/codex-assignment.md) binds one trusted
logical-agent assignment to existing admission/queue checks and a separate coding
App identity. Its advice neither reserves/prepares work nor enables execution.

The [coding App identity contract and Gate B runbook](docs/coding-app-gate-b.md)
normalize bounded synthetic GET evidence against existing assignment pins. Offline
fixture verification never establishes live identity or authorizes credentials,
App provisioning, task reservation, native execution or branch/PR publication.

The [metadata-only App observer boundary](docs/app-metadata-observer.md) accepts
real-shaped responses through separately typed transport/custody interfaces,
exercised only with offline fixtures. It preserves the synthetic observer and
never promotes metadata or a public Bot profile to App-attributed action proof.

The [inactive GitHub App API adapter](docs/app-api-adapter.md) implements bounded
fixed-origin wire and token custody behind the metadata contract, tested with
mocked sockets/signing only. Real signer, journal/host integration and live runs
remain separately gated; no credentials or runtime capability are activated.
