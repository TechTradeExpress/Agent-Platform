# Supervised Issue queue planning — Issue #33

`agent_platform.queue` is a bounded, read-only Python API for the trusted control
plane. It reports waiting, eligible_candidate, blocked, active, under_review,
done and unknown entries. `next_candidate` is **advice for human approval**,
never task selection, preparation or execution permission. `launch_allowed` is
always false. There is no scheduler, timer, watcher, retry loop or CLI entrypoint.

The API follows the existing offline Publisher boundary. A file-taking CLI
would need a separately reviewed way to authenticate dependency policy and PR
receipts; repository JSON, Issue descriptions and model output cannot supply
that authority. Existing `issues`, `status` and `recovery plan` commands retain
their contracts. This milestone does not add GitHub PR endpoints to the runtime.

## Trusted inputs and workflow

The manually invoking operator or trusted control plane supplies:

1. A canonical primary source checkout, not the coding worktree.
2. An immutable `Policy` containing up to eight `Entry` objects. Each entry pins
   the existing `publisher.Admission` schema: repository ID/name, Issue ID/number,
   scope digest/revision, provenance digest and base SHA. Explicit `Dependency`
   references and priority (0 first through 100 last) come only from trusted
   operator policy. They are durable caller-held policy, never inferred from
   checkboxes, text, labels or branch names. Dependencies have a canonical
   repository and Issue number; cross-repository dependencies are blocked.
3. An explicit trusted-actor tuple and supplied bounded admission API for
   `capture`. In offline use that API serves separately trusted snapshots; tests
   use fake GitHub responses. No client is initialized automatically. A trusted
   caller may explicitly supply the existing `issues.GitHub` GET-only client;
   its unchanged request, time, output and pagination budgets apply. No new
   endpoint is queried. Missing data or exhausted budgets produce a fixed
   refusal, never a partial snapshot.
4. Optional immutable `PullRequest` receipts from a **separately trusted,
   independently reviewed collector**. The collector must obtain native Issue
   linkage (not closing keywords or model claims), exact linked Issue identity,
   source/target repository identity, target branch, reviewed HEAD and stable
   current HEAD, full PR state, merge timestamp/commit and default-branch SHA.
   Ambiguous linkage or multiple PRs for one Issue must be reconciled before
   supplying a receipt. Issue #49 now provides an
   [explicit read-only collector](github-evidence.md); queue itself still creates
   no client and trusts only separately supplied receipts.

These typed objects are trusted caller assertions, not cryptographic
attestations. A frozen dataclass does not authenticate its creator. Do not load
policy, snapshots, expected HEADs or PR receipts from the untrusted worktree,
chat, saved plan or model output. The digest is a correlation value, not a
signature or capability. A controller capable of fabricating trusted objects is
outside this offline validation boundary, as with `publisher.plan`.

Conceptual integration inside the trusted controller:

```python
from agent_platform import queue

# operator_policy and trusted_pr_receipts come from the boundaries above.
# bounded_admission_api is explicit: a trusted snapshot reader or existing GET API.
snapshot = queue.capture(
    bounded_admission_api,
    operator_policy,
    ("operator-selected-maintainer",),
    pull_requests=trusted_pr_receipts,
)
report = queue.plan(canonical_primary_root, snapshot)
assert report["launch_allowed"] is False
# Display report to a human. Do not dispatch its next_candidate to prepare/run.
```

`capture` reuses `issues.validate_candidate`: open-Issue scope, blocking labels,
complete trusted ready-label provenance and stable Issue/history rereads. It
compares the exact resulting receipt with the operator's admission pin. A
shared pure `prepare.admission_record` encoder preserves the existing receipt
format without duplicating admission policy. Two complete queue passes plus
repository/default-branch rereads reject inconsistent snapshots, including
changes between independently stable per-Issue reads. Excluded Issues retain
only a fixed admission blocker; raw text and history are discarded.

## Dependency and local evidence

A closed Issue alone is `blocked`, not done. `done` requires matching trusted PR
and admission identities, exactly one linked Issue, target main in the same
repository, an unchanged expected HEAD, closed/merged state, merge timestamp and
exact pinned default-branch SHA. The merge object must be a commit actually
present locally, and a bounded read-only `git merge-base --is-ancestor` must
confirm it belongs to that exact main. Missing objects, changed HEADs, stale
pins and contradictory open-Issue/merged-PR state cannot satisfy dependencies.
Squash/rebase merges rely on the collector's reviewed-HEAD/merge association;
local ancestry alone does not establish that association or prove correctness.

An unmerged open PR is under_review. Unsatisfied known dependencies are waiting;
missing, cross-repository, self and cyclic dependencies block. Duplicate Issues,
duplicate dependencies/PR receipts and oversized input are rejected. Candidate
ordering is stable priority then Issue number, independent of API ordering.
Entries display dependencies before dependents, with priority/Issue ties and a
deterministic unresolved-cycle tail. Observations bind their exact admission pin;
replacing a policy without recapturing evidence cannot reuse old eligibility.
Dependency evaluation is recursive and bounded by the eight-entry limit; only
verified done dependencies can enable an open admitted candidate.

Every `plan` takes the existing fixed host mutex with `create=False` and holds it
through local inspection, graph evaluation and stable rereads. It never creates
a lock file or state directory. A missing/busy/unsafe mutex blocks nomination.
The existing source inspection requires canonical clean main, matching local
origin/main and the pinned base. No fetch is performed. Empty local state also
requires the sole registered primary worktree. Unexpected worktrees block.

The planner scans the existing private nonsecret checkpoint namespace across
repository IDs, bounded to 128 directories/files and eight distinct local tasks.
Unknown filenames, unsafe paths, symlinks, corrupt records, temporary writes and
orphan guards cannot count as idle. For current-repository records it reuses
`task_status._observe` under the same lock and `recovery._classification`,
including checkpoint generation, worktree/guard identity and all-ref checks.
Other-repository records also block, rather than being silently ignored. No
credentials, native session stores or raw event logs are opened.

**Any retained local checkpoint blocks nomination**, including READY, PAUSED and
COMPLETED and tasks outside the queued set. A completed checkpoint is not human
reconciliation or exactly-once proof. The `active` queue status means a recorded
local task reserves/requires investigation of the executor; it never asserts
live activity. `local_tasks` reports its phase and recovery classification with
`live_activity=unknown`. This conservative milestone has no archive/cleanup or
reconciliation writer. Human review of retained state, with separately authorized
intervention if needed, remains necessary before another task can be nominated.
Unknown or changing evidence discards partial candidates. No guard is deleted,
checkpoint repaired, process signalled or task restarted.

## Output and freshness

The version-1 JSON-ready report is at most 16 KiB (including its plan digest).
It contains entries with Issue number/status/fixed reason/priority/dependency
statuses, candidate ordering, an optional single advisory next_candidate,
bounded local-task evidence and fixed authorization/isolation statements.
It contains no titles, prose, paths, actors, URLs, raw exceptions, Git output,
prompts, logs, credentials or quota-reset guesses. The SHA-256 of canonical
report JSON is stable for identical evidence; it grants no authority.

`freshness=stable_snapshot_not_live` means only that supplied GitHub admission
was stable when captured and local evidence was stable during planning. It is
not a live GitHub observation or TTL promise. Remote changes after capture are
unknowable offline. Before **every** actual manually authorized start, refresh
trusted Issue admission, dependency PR/HEAD/merge evidence, default-branch SHA
and local lock/recovery checks. Queue eligibility, trusted scope, operator
approval, isolation readiness and actual execution permission remain separate.
Native Codex/subscription execution remains blocked; no plan bypasses that gate.

## Evidence and remaining work

`tests/test_queue.py` traverses the real admission implementation with fake gh
responses and synthetic repositories/checkpoints. Coverage includes sequential
merged chains, independent priorities, cycles/self/missing/cross-repository
references, duplicates, closed/unmerged Issues, PR identity/HEAD/merge/ancestry,
untrusted/missing history, pagination ambiguity, changing API snapshots, stale
scope/provenance pins, every local phase, guards/temporary writes, foreign and
out-of-queue tasks, busy/missing locks, identity aliases, mutation during planning,
size limits, redaction and read-only/no-network/no-model checks.

Offline PASS does not verify live GitHub linkage collection, present remote
freshness, process quiescence, production isolation or authenticated inference.
A practical next milestone is independent review of the operator-held policy
and PR-evidence collector boundary, followed by separately approved supervised
integration. Issue #34, Telegram operator console #38, real notification delivery,
scheduling, publication and runtime activation are outside this change.
