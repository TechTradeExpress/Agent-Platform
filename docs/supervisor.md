# Offline supervisory decision report — Issue #50

`agent_platform.supervisor.report(root, evidence, now=...)` joins trusted admission
and queue/PR evidence with local task status, recovery classification and explicit
operator HOLD. It is a bounded, read-only Python API, not a CLI command, scheduler,
HOLD writer, release mechanism or runtime integration. Schema version 1 always
returns `launch_allowed=false`, `resume_authorized=false`, `safe_to_replay=false`,
`mutations_allowed=false` and `publish_authorized=false`.

Stock Codex CLI funded by the operator's ChatGPT subscription remains the selected
future engine. Native/subscription execution remains
`SUBSCRIPTION_ISOLATION_BLOCKED`, exit 13; public legacy run/resume/doctor remain
quarantined. The supervised interactive developer session is separate. This report
never invokes either engine, probes login/session stores or contacts GitHub.

## Trusted inputs and identity

The frozen `Evidence` value contains an exact `publisher.Admission`, an existing
`queue.Snapshot`, an integer `observed_at` and an optional independently trusted
`recovery.RecoveryReference`. `root` is the canonical primary checkout, not the
coding worktree. Tests construct synthetic Git repositories and private stores.
The report requires the existing non-creating fixed host mutex; it never creates
that prerequisite, a checkpoint, directory or HOLD.

The trusted controller supplies these values in-process, never by deserializing
model output, repository JSON, Issue prose, Telegram assertions or a saved report.
Admission binds repository ID/name, Issue ID/number, scope digest/revision,
admission provenance digest and exact base SHA. Queue observations must match
those pins. PR evidence binds the same admission, destination main/repository,
single Issue, current/expected head SHA and default-branch SHA. Closed is not
merged: the existing queue evaluator also requires verified merge facts and local
commit ancestry. Missing or conflicting dependency evidence blocks.

PR receipts retain the [Issue #49 collector](github-evidence.md) trust boundary.
That collector's independent reviewer ID/login matching, exact reviewed SHA and
required check identity rules are unchanged. This module does not implement
another review validator, accept a model PASS, infer approval from queue status,
or turn a merge receipt into publication authority. The controller must supply
receipts from the authenticated collector with its existing policy; the report
cannot authenticate a fabricated in-memory value. SHA-256, frozen dataclasses and
caller assertions establish consistency, not cryptographic identity or human
consent. No GitHub client, token or privileged socket enters this API or a worker.

`observed_at` must be the **oldest** observation used for the entire queue and PR
snapshot, not a refreshed timestamp on an old receipt. Explicit trusted `now`
must be an integer, no earlier than observation and at most 300 seconds later.
The controller must reject expired collector receipts before composition and must
not re-date them. This age check is caller-attested, not a live GitHub revalidation
or a signed timestamp. There is no automatic refresh or polling. Reuse is only
correlation; every report invocation rereads local state and verifies age again.

For an existing checkpoint, an independent reference binds exact admission,
generation, execution UUID, session UUID and checkpoint digest. A missing or
conflicting reference never adopts a newer/recent session. Native session files
are not opened; recorded session lineage is evidence only.

## Snapshot consistency and decisions

One `state.host_lock(create=False)` covers two complete observations, using the
existing under-lock queue/status/HOLD readers rather than acquiring nested locks.
Each observation includes canonical source/base/common-directory identity,
registered worktrees, all-ref/checkpoint/guard checks from task status, bounded
cross-repository checkpoint inventory, queue evaluation without the local-task
status override, recovery classification, HOLD contents and file fingerprint.
The HOLD binding must describe exactly the same task status and checkpoint
lineage. The second complete observation must equal the first. The lock pathname
must still identify the originally opened descriptor, and the in-process evidence
digest must remain unchanged. All existing private-directory, no-symlink,
single-link/owner/mode, bounded-file and orphan-transaction checks remain in use.

This is a stable **observed snapshot**, not an atomic snapshot of GitHub, the
kernel and uncooperative same-UID processes. The lock only serializes cooperating
control-plane clients. A process could mutate and restore data between reads;
file metadata and hashes are not OS isolation or authenticated liveness evidence.
No observed snapshot authorizes a later action. Future activation would require
separately designed mandatory launch-time validation under a held lock.

| Observation | Report interpretation |
| --- | --- |
| Valid active HOLD, with or without recorded task | HOLD retained; `NEEDS_HUMAN`, activity unknown; never release/idle/start |
| No HOLD, including an otherwise empty store | `hold_missing_not_release`; missing means unknown, never released |
| Invalid/conflicting HOLD or changed checkpoint/session binding | `BLOCKED`; preserve all artifacts, do not rewrite to follow new lineage |
| PAUSED, READY, STARTING, RUNNING or NEEDS_HUMAN checkpoint | Retained task requires reconciliation, not launch/resume permission |
| COMPLETED checkpoint retained | Completion requires reconciliation; not exactly-once or idle proof |
| Orphan guard/temporary transaction, unsupported state, foreign/ambiguous inventory, stale refs/base, unsafe paths | `BLOCKED` or `NEEDS_HUMAN`; no repair, cleanup or replay |
| Stale/contradictory Issue/PR/queue pin | Queue blocked; local task presence cannot hide stale remote evidence |
| Evidence changes during observation | `BLOCKED`; partial successful projections are discarded |
| Missing/unreadable mutex | `BLOCKED`, exit 12, no mutex creation |
| Busy mutex | `BLOCKED`, exit 10, no checkpoint read |

All coherent reports still require human reconciliation because live process
activity and external effects remain unknown. Exit 12 means unresolved supervisory
decision, **not** the runtime's exit-13 gate changing. There is deliberately no
success/ready/idle decision, next-candidate nomination or release status. Queue
`eligible_candidate` is displayed only as historical advisory evidence, not a
supervisor selection. Report output has fixed reasons, numeric Issue identity,
sanitized bounded queue/local projections and recorded phase/recovery labels;
Repository ID/base SHA and input/queue correlation digests bind the report to
the supplied evidence without exposing paths, session/execution UUIDs, logs, prose
or authentication data.
Reports are below 16 KiB and include a deterministic correlation digest. Repeated
identical evidence yields the same report, without persistent replay state or
side effects. Unknown effects remain unknown.

## Separately authorized future HOLD release and enforcement

**Proposal only; none of the following is implemented or authorized here.** A
future release design must authenticate an independently authorized human action
outside model/Telegram assertions, bind one repository/Issue, exact current scope,
base/head, generation, checkpoint digest and session UUID, and verify fresh
admission and independent review identities. It must establish process quiescence
independently; a free lock, missing file or recorded terminal phase is insufficient.
Unknown external effects require authoritative reconciliation, not retry.

Release must be distinct from launch/resume approval, with explicit one-use intent,
crash-safe atomic persistence, anti-replay semantics and uncertain-write recovery.
Never delete a HOLD to imply release or overwrite it to follow changed sessions.
Missing/corrupt/conflicting records must fail closed. Every future execution entry
and resume boundary must enforce a current authenticated decision under the same
lock, reread exact lineage and preserve all native isolation gates. Tests would
need interruption before/after durable replacement, races, expired authority,
changed sessions and unknown child lifetime. No timer, quota prose, callback,
absent HOLD, old PASS or this report can supply that authority. Such state writers,
mandatory enforcement, signals and release operations require another explicitly
authorized Issue and independent review; #50 adds none.

## Evidence limits and verification

Synthetic tests cover all recorded phases, HOLD absence/corruption/conflict,
checkpoint/session reference drift, orphan transactions, stale Issue/head/base
pins, bounded age, replaced/busy/missing locks, cross-read mutations of HOLD,
checkpoint, guard, refs, worktree registration and inventory, redaction and writer/
network/runtime tripwires. Fixture setup may create state; the report never does.
Read-only Git commands are expected; credential/network/runtime commands are not.
[Recovery](recovery.md), [queue](queue.md), [HOLD](subscription-hold.md) and
[architecture](architecture-trust-boundaries.md) remain the underlying contracts.
Offline PASS is `VERIFIED_OFFLINE` only, not live process evidence, authenticated
subscription execution, tool/credential isolation, production readiness or an
independent review. #28 disposable kernel tests and #51 native GO/NO-GO remain
separate and blocked from execution on dev01 by this task.
