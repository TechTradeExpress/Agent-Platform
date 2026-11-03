# Trusted read-only GitHub evidence collector — Issue #49

`agent_platform.github_evidence` is a synchronous trusted-caller Python API, not
a CLI command, collector daemon, scheduler, authorization service or Publisher.
No client is created by runtime dispatch, queue, status, recovery or Telegram.
No real account/collector request was exercised for its acceptance tests; injected
fake gh responses traverse the real bounded transport and synthetic Git repos.
The existing public run/resume/doctor quarantine and native/subscription exit-13
block remain unchanged. Stock subscription-funded Codex remains the future engine.

## Policy and authority boundary

The operator/controller supplies an immutable version-1 conceptual policy:

- Existing `publisher.Admission`: exact repository ID/canonical name, Issue
  ID/number, scope digest/revision, separately trusted admission digest and current
  main SHA. `Policy` is never deserialized from a target file, Issue, model text,
  CI output, cached JSON or chat. The scope/revision is verified against current
  Issue bytes using the existing preparation encoding. Blocking labels reject.
- Exact PR number, expected source HEAD and base commit, and `purpose` of
  `reviewed` or `merged`. Fork/missing source repositories are conservatively
  rejected; both sides must match the pinned canonical repository ID/name and
  target `main`. For reviewed PRs base must equal pinned current main.
- For `reviewed`, one to eight explicit `Principal(identifier, login)` reviewer
  pins and `Check(app_id, app_slug, name)` requirements. These are operator policy,
  not permissions inferred from a body's PASS claim, collaborator label, check
  display name or server ruleset. The governance APIs' known 403 limitation is
  not bypassed. Completeness/appropriateness of the required-check policy still
  needs independent operator review.
- Reviewed PRs additionally pin the current synthetic merge-result SHA. Its
  REST commit must have parents exactly `[expected base, expected head]`, and
  the PR metadata must name that exact merge-result SHA. Matching successful
  App checks are required at **both** HEAD and that base-bound merge result;
  old HEAD-only CI cannot establish an updated-base integration result.

A reviewer must be a distinct GitHub ID/login from the PR author. Only the latest
submitted review per actor is considered; same-actor same-second ambiguity blocks.
Any latest CHANGES_REQUESTED review blocks. Every observed allowlisted reviewer's
latest review must be a `COMMENTED` review at the exact HEAD, with first line:

```text
Agent-Platform review v1: PASS FULL_HEAD_SHA
```

This intentionally narrow marker is a new reader contract, not a claim that older
free-form review prose meets it. Unrecognized/old-SHA/APPROVED/dismissed/missing
reviews cannot replace the required COMMENT evidence. A marker by the implementer
or an unpinned actor is not authority. Identity is checked using the API's actor
ID/login and caller policy, never the body alone. This cannot prove independence
of people/accounts/sessions beyond the supplied principal boundary. No review,
Ready transition, Issue closure or formal APPROVE is published by this API.

## Read-only transport and complete snapshot

Explicit `GitHub(policy)` uses the existing operator-managed gh authentication
only on requested calls. It never runs login, discovers/provisions tokens,
inspects Codex/auth/session stores or forwards a client to tools. `collect` takes
an explicit API object; no network client is selected automatically. The separate
[governance credential roles](github-governance.md) remain design requirements,
not a deployed credential/OS attestation. A possibly broader existing credential
is not restricted cryptographically by Python; independently provisioned least
privilege and process isolation would be required for live integration.

REST paths are fixed within the pinned repository, constructed only from validated
numeric/SHA pins, with explicit GET, fixed github.com host and sanitized bounded
gh subprocesses. Allowed paths are metadata, `branches/main`, exact `issues/N`,
`issues/N/events`, `pulls/P`, `pulls/P/reviews`, exact HEAD/merge-result
`commits/SHA/check-runs` and `commits/SHA/status`, plus the exact merge-result
`commits/SHA` for parent verification. No arbitrary route, ref, URL, method,
model-selected query, admin or writer endpoint is accepted.

Two literal, code-owned GraphQL **queries**, transported as POST to `graphql`,
obtain native `closingIssuesReferences` and `reviewThreads`. Owner/name/PR/cursor
are separate validated variables, never query syntax; arbitrary documents,
mutations or query kinds cannot be supplied. This transport POST is not a GitHub
mutation. The GraphQL repository and PR IDs, number and head/base OIDs must match
REST/policy on every page. REST PR body must contain exactly one standalone
`Closes #N` and no additional closing references; that prose is insufficient
without exactly one matching native same-repository Issue link/ID/state.

Every thread must be present and resolved. An explicitly complete empty thread
connection is acceptable; a missing/null connection or omitted/partial page is
not equivalent to no findings. Unresolved outdated threads also block. All
observed check runs must be completed/successful at their requested SHA; required
names additionally match pinned App IDs/slugs. The Checks API's default latest
filter is used; complete results and count consistency are required. Duplicate
IDs, mismatched URLs/SHAs, wrong Apps, missing counts and future completion times
reject. Legacy combined statuses may veto (pending/failure/incomplete), but cannot
substitute for required App check authority. No statuses is explicitly distinct
from missing required checks. CI facts do not establish that a workflow's commands
or reviewed code are safe; independent source/governance review remains necessary.

The transport reuses existing REST HTTP/JSON/Link validation. A Link must stay
on the same fixed host/path/query with the expected next page; it is never
executed/followed as an arbitrary URL. Counted wrappers require `total_count` to
match the complete collected set. Limits shared by REST and GraphQL:

| Bound | Contract |
| --- | --- |
| Requests / elapsed API budget | At most 128 requests, 60 seconds; no retry/backoff |
| Per subprocess | At most 5 seconds, 2 MiB per stream, fixed argv, shell disabled |
| Each list/connection | 20 items/page, at most 3 pages / 60 items |
| REST terminal page | A full page without provable continuation is conservatively ambiguous and rejected |
| GraphQL completeness | totalCount/nodes/pageInfo, unique IDs and nonrepeating bounded cursors; errors/partial data reject |
| Review/PR body | At most 64 KiB each; only hashes/fixed facts leave collection |
| Receipt handoff age | Caller supplies current integer time, at most 300 seconds from observation; clock reversal/expiry rejects |

Each collection reads two complete evidence passes. Each pass brackets its
Issue/history, PR and repository/main observations with rereads; relevant remote
facts must be identical within/across passes. HTTP 403/429/5xx, request/time/output
limits, malformed/duplicate-key JSON, missing data, count/pagination truncation,
unknown provenance or drift discard the whole receipt with fixed
`EvidenceError("github_evidence_unavailable")`. No raw response body, stderr,
path, author or diagnostic prose is exposed by `diagnostic()`.

This is a bounded stable snapshot, not an atomic GitHub transaction or proof that
remote state cannot change immediately after a reread. A cached assertion cannot
be promoted to a live API result by loading a file. The trusted transport is still
part of the TCB; code compromised within that process can fabricate responses or
types. The 300-second upper bound never replaces fresh collection before effects.

## Local facts, actual merge and retained state

Collection requires a canonical clean primary main source, canonical matching
origin/common directory and local HEAD/main/origin-main equal to the pinned remote
main. It reuses bounded read-only `prepare.source_snapshot`/Git helpers. It never
fetches, updates refs, checks out, stages, commits, prepares a task or reads a
coding worktree's files, checkpoints, auth stores or native sessions.

The existing fixed host mutex is acquired with `create=False` and held across
collection and local checks. Missing/busy/unsafe/replaced mutex blocks; no private
store or lock is initialized. Source identity and all refs are reread before
return. The mutex serializes cooperating local controllers, not outside Git
writers or GitHub. Reading may affect access times; byte snapshots are not an
OS immutability proof.

For `merged`, the Issue and PR must actually be closed and GitHub must report
`merged=true`, valid merge SHA and timestamp. Both the exact PR base and actual
merge object must be commits available locally and ancestors of pinned main.
A closed Issue or an unmerged PR's speculative merge_commit_sha is never enough.
Reviewed receipts currently require an open Issue as well as an open PR. A Ready
PR whose Issue was already closed is not automatically promoted or reopened;
this strict reviewed mode is unavailable until the caller obtains appropriate
separate facts (actual merged evidence only after merge).
The merged mode records a verified merge fact, **not** an independent PASS/CI claim;
no historical review or check is fabricated. Squash merge association relies on
GitHub's PR/merge evidence, not ancestry alone. Missing local objects, unrelated
commits, stale main or inconsistent open/merged state block without fetch/repair.

## Immutable receipt and planner handoff

`Receipt` contains immutable policy, observation time, API provenance, digests
of bounded remote/local facts, exact review/check tuples and an existing
`queue.PullRequest`. `api_provenance` distinguishes `github_api_snapshot` from
explicitly synthetic test transport; local ancestry is reported separately.
Digests are correlation/integrity values, not signatures, authenticated account
identity, GitHub authorization, independent audit or exactly-once proof.

Trusted-controller-only integration (not a new runtime entrypoint):

```python
from agent_platform import github_evidence

# policy is directly trusted operator policy, never target/model JSON.
receipt = github_evidence.collect(
    canonical_primary_root, policy, api=github_evidence.GitHub(policy)
)
pr_pin = receipt.queue_receipt(now=trusted_current_time)
# Supply pr_pin via queue.capture(..., pull_requests=(pr_pin,)).
# Existing queue admission/local/lock/merge checks still apply independently.
```

For reviewed receipts, `publisher_admission(now=...)` returns the **separately
trusted caller's original admission pin** after expiry checks and observed scope/
revision matching; it does not reauthenticate ready-label authorization. Issue
history is completely collected/reread as drift evidence, not reinterpreted as
operator authority. The diagnostic explicitly says admission is not
reauthenticated. Refresh full admission through the existing trusted admission
boundary before any future effect. It cannot grant eligibility or execution.

`publisher.plan(source, admission_pin, separately_trusted_test_evidence)` still
requires exact COMPLETED checkpoint, full tree/change inventory and genuine
checkpoint/tree-bound local TestEvidence. A successful remote CI job cannot be
split into invented ruff/pytest/diff_check PASS receipts. This collector does not
manufacture TestEvidence, inspect checkpoints to create it, bypass any planner
check or return publish authorization. Merged receipts cannot supply a Publisher
admission handoff. All diagnostics retain launch_allowed=false and
publish_authorized=false; no token, HTTP client or privileged socket is serialized.

## Acceptance evidence and limits

`tests/test_github_evidence.py` uses fake gh responses plus synthetic local Git.
It covers accepted reviewed/merged planner inputs, principal/marker/version/SHA
pins, native linkage, complete threads, both CI SHAs/merge parents, conflicting
reviews/statuses, successful pagination and truncated/foreign/replayed pages,
403/429/5xx, malformed JSON, resource limits, source/ref/lock/remote drift,
redaction, expiry, no writes/runtime and retained edits. These tests provide
VERIFIED_OFFLINE evidence only; real collector authentication, least-privilege
account scope, OS credential separation and production readiness are NOT_RUN /
REQUIRES_INDEPENDENT_REVIEW. The PR records actual local and exact-HEAD CI results,
including known dev01 failures. No offline PASS activates native execution,
credentials, Publisher, Telegram, scheduling, recovery or another Issue.

Protocol references (official sources, not live integration proof):
[GraphQL calls](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql),
[PullRequest and review-thread fields](https://docs.github.com/en/graphql/reference/pulls),
[Check runs](https://docs.github.com/en/rest/checks/runs),
[combined statuses](https://docs.github.com/en/rest/commits/statuses).

## Issue #59 Gate A compatibility

The [offline supervised COMMENT policy](review-comment.md) reuses the bounded
remote snapshot checks for prepublication facts. The internal prepublication
branch creates no Receipt and does not assert an existing PASS; public collect
still requires the observed exact-SHA COMMENT marker and all existing rules.
Principal syntax additionally permits the canonical `[bot]` suffix, with numeric
ID and case-insensitive author-login independence preserved. No writer, token
handling or automatic review/Ready/Issue transition enters this collector.
