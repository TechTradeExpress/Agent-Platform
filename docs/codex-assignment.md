# Single-agent Codex assignment — Issue #69

**AP-CA/1, VERIFIED_OFFLINE only.** This milestone implements a typed assignment
and read-only **eligibility advice**, the offline-advice option in Issue #69.
It does not reserve or prepare a task. No CLI, worker launch, live App probe,
GitHub writer, scheduler, polling or background service is added. Native and
public legacy run/resume/doctor remain blocked at exit 13. No separately billed
API authentication fallback, App credentials or infrastructure changes occur.

```text
ChatGPT/human planning (Issue text is untrusted data)
  -> independently authenticated operator/controller assignment pins
  -> AP-CA/1 stable offline admission and existing queue/local-state checks
  -> OFFLINE_ELIGIBLE_ADVICE (reserved=false, prepare_authorized=false)
  -> Codex execution adapter BLOCKED / exit 13
  -> future trusted coding-App publisher BLOCKED / separate Gate B
```

## Trusted contract and reuse

`codex_assignment.CodexAssignment` is frozen and serializable with `asdict()`.
It is **direct trusted-caller input**, never decoded from Issue/model JSON,
labels/assignees, repository YAML or cached files. Serialization/hashes correlate
bytes, not authenticated authority. This module has no policy/credential loader.
Constructors and nested pins are revalidated at each entry.

| Pin | Contract |
| --- | --- |
| schema_version/runtime | Exactly integer 1 and codex; no API engine or arbitrary adapter selector. |
| admission | Existing publisher.Admission: canonical numeric repository ID/full owner/name; exact Issue ID/number; approved scope SHA-256/revision, independent admission digest; full 40-hex base SHA. |
| base_branch | Explicit flat approved branch. The current advice path supports main only because prepare/queue still require it; other branches BLOCK, never fall back. |
| agent_id | Explicit operator-pinned logical agent, bounded ASCII identifier. GitHub assignees/App names cannot choose it. |
| assignment_id | Unique SHA-256 replay identity; not a GitHub identifier or secret. |
| authorization_sha256 | Reference to the independent operator authorization, not a model PASS or signature by itself. |
| issued_at/expires_at | Integer lifetime <=300 seconds; future, expired, stale or conflicting evidence blocks. Expiry never clears retained uncertainty. |
| coding_app/reviewer_app | Existing #59 AppIdentity pins: App ID/slug, registration owner ID/login/type, installation ID and bot ID/login. App IDs, slugs, installations and bot IDs/case-insensitive logins must be distinct. |
| installation / owner | Existing #62 InstallationIdentity. Its account ID/login/type is the intended target owner, checked against repository metadata; App registration owner is independent. Derived owner/owner_type properties avoid competing owner sources. |
| allowed_repository_ids | Derived one-repository tuple from Admission, not a model-selected allowlist. Identity observations must match it exactly. |

A configured coding name is provisional. All IDs in tests are fabricated; none
identify an installed App. `IdentitySnapshot` binds the exact assignment digest,
observation time and existing nonsecret InstallationFacts. It requires fabricated
coding-App/bot and installation-account metadata, selected single-repo scope,
minimal effective coding permissions, installation-token kind and bounded expiry.
These facts contain **no token** and prove no live authentication. Missing facts
return IDENTITY_UNVERIFIED; inconsistent/unknown facts BLOCK. Every outcome says
live_app_identity=NOT_RUN and publish/launch/resume/prepare authority=false.

TargetProject is a **later PR-specific** review context, not an assignment model.
AP-CA/1 therefore reuses its validated primitives without inventing a future PR
number/HEAD. Optional `for_project()` checks later #62 pins: exact admission,
owner/branch, coding bot as expected PR author, reviewer bot and reviewer
publication context. It grants no Receipt/runtime/queue conversion authority.
An actual future PR author's identity must be observed from GitHub, not inferred
from the assignment or bot name. Existing target merged/queue handoffs remain
blocked where #62 already blocks them; no domain migration is implemented.

## Bounded read-only admission

`advise(root, assignment, inventory, expected_agent=..., actors=...,
identity=..., api=..., now=...)` accepts explicit synthetic adapters only. There
is no default network client. Reader provenance labels are test contracts, not
an OS sandbox or authentication; supplied callbacks are trusted code.

The endpoint inventory is repository metadata, branches/main, the one pinned
Issue and its events. The existing issues.GitHub pagination/HTTP validation,
issues.validate_candidate, prepare.admission_record, queue.capture and queue.plan
are reused. Limits: <=128 reads/60 seconds, <=2 MiB per returned observation,
20 items/page, <=3 pages; no retry or arbitrary HTTP/GraphQL routing. Transport
callbacks must enforce their own per-call bounds; post-call checks do not isolate
malicious same-process code. No new live endpoint or credential access is added.

Require canonical repository ID/name/owner/default branch, current base, open
Issue ID/number, exact scope bytes/revision/digest, explicit scope and complete
trusted ready-label provenance. The assignment is additional independent
operator authority: a ready label alone is never sufficient. Missing scope,
closed/foreign Issue, PR-shaped object, working/needs-human labels, stale base,
untrusted ready actor, incomplete pagination or drift blocks. Other stable labels
are data, not authorization or task-selection signals. Assignees may be empty or
exactly the pinned coding bot; unexpected/multiple assignees block as conflicting
observations. A matching assignee still supplies no assignment authority.
Repository/raw Issue/assignee observations are bracketed and hashed; changed
observations reject the whole result. No Issue prose, link or raw error is returned.

A fresh queue capture is passed to the existing planner; it acquires the fixed
host mutex **without creating it**, checks canonical clean main/source identity,
all refs/worktrees and the full existing checkpoint/guard/temporary inventory,
and rereads local evidence. Any retained local task, even COMPLETED, unknown or
foreign state, busy/missing/replaced mutex or unsafe store blocks advice. Coding
edits and recovery files are retained. No checkpoint, worktree, session or lock
is initialized or changed by this API. The advice path creates no new reservation
ledger and does not call prepare, execution, native runtime or Publisher.

## One logical agent, replay and crash limits

The trusted controller supplies one complete global `Inventory` for the expected
agent: <=8 assignment pins, <=128 retained intent records, explicit epoch,
observation time and completeness. No subset can be inferred from target data.
Exactly one assignment may be eligible in that view. Multiple simultaneous
assignments, including across repositories or expired competing assignments,
BLOCK rather than auto-prioritize. The existing local queue must also be idle;
there can be no already prepared/retained task.

Retained intents bind assignment ID/digest, repo/Issue ID, timestamp and state.
UNKNOWN, RESERVED or PREPARED anywhere in that agent's history blocks another
nomination even after expiry. FINISHED permits a different task only; reused ID,
digest or same repo+Issue identity blocks replay even with a new assignment ID.
Missing/partial/stale/contradictory evidence blocks. Bounded history is never
automatically evicted, reset or repaired; a new epoch/installation cannot justify
discarding unresolved history. Controller honesty/completeness is a trust input,
not something a bool or digest authenticates.

This is **offline advice**, not an atomic claim or crash-durable admission intent.
Repeated advice for the same unchanged snapshot is deterministic and consumes no
operation. Two callers cannot prepare anything through this API. It does not
prove exclusion across dishonest/incomplete caller snapshots, create a global
reservation or authorize later prepare. The controller must durably retain real
intents outside model/worker access and supply complete history after a crash;
lost continuity means BLOCKED/NEEDS_HUMAN, not a new empty Inventory. That durable
producer/lease/launch design is NOT_IMPLEMENTED here. Unknown effects never become
retry permission. There is no automatic recovery write, retry, release or cleanup.
Every result retains reserved=false and prepare_authorized=false.

## Coding App versus reviewer App

| Domain | Future minimal permission/role | Boundary |
| --- | --- | --- |
| Coding App | Metadata read, Contents write, Pull requests write for a separately approved feature-branch/Draft-PR publisher | No Issues/Actions/Checks/Admin/organization writes or merge authority. No live writer in this milestone. |
| Reviewer App | Existing #59 Metadata read and Pull requests write, code restricted to COMMENT | Separate App/bot from actual PR author; no code/content writer or formal APPROVE. |
| Read-only collector | Existing independently scoped Issue/PR/check observations | Do not broaden either writer to collect evidence or give clients to worker. |
| Human/operator controller | Authenticates assignment and exact downstream publication approvals; retains replay/uncertainty history | No authority from Issue/model/labels; sole maintainer may hold human roles. Human alone merges. |
| Codex worker | Future bounded implementation only, currently BLOCKED | No App key/JWT/token, privileged GitHub client, approval/journal write access or API fallback. |

GitHub Contents write is repository-scoped, **not feature-branch-only**. PR write
is broader than COMMENT. Code allowlists cannot protect an unprotected main or
prove permission confinement. A bot ID is a posting identity, not independent
human review or reasoning assurance. AP-SM/2 source review delegation does not
authorize downstream operational mutations or product exact-payload approval.
#49 reviewer identity, #59, #62, AP-CH/1 and UNKNOWN-before-POST remain unchanged.

## Future Gate B — design checklist, not authorization

1. Obtain a separate explicit target-specific operator decision after independent
   review/human merge. Verify supported installation/actor observation capabilities
   and current canonical target identity; no default downstream tenant is inferred.
2. Independently register/install separate coding/reviewer Apps with observed real
   IDs, one selected repository, appropriate minimal permissions and no unnecessary
   webhooks. This milestone performs none of those operations.
3. Establish independently audited key/JWT/short-lived installation-token custody
   outside ChatGPT, Codex, worktrees and workers. No PAT/OAuth impersonation or
   token forwarding workaround. Verify actual App/install/account/bot facts.
4. Verify effective protected-main/branch rules, no worker/main/force/merge writer,
   and restricted branch publisher design. Missing/unknown server enforcement is
   BLOCKED, never a claim of feature-only permission from Contents write.
5. Design durable single-agent claim/replay/UNKNOWN handling across repositories,
   epochs, rotations and crashes; independently verify completeness, identity,
   isolation and concurrency. This offline advice cannot be a launch receipt.
6. Independently demonstrate subscription/credential/tool isolation before any
   execution scope. Native/legacy gates remain exit 13; no separately billed API
   fallback. Later live publication requires its own exact authorized scope,
   durable intent before effects and observed actual bot author/branch/PR identity.
7. Require #49 exact-SHA CI/reviewer/Issue/thread evidence, separate authenticated
   downstream approval and human-only merge. No autonomous start/Ready/closure,
   merge, service, polling or deployment follows from offline PASS.

## Offline evidence

`tests/test_codex_assignment.py` uses fabricated Apps and fake gh transport plus
synthetic Git, admission, mutex and retained state. It covers exact positive
advice; serialization without authority; repo/owner/Issue/scope/base/branch drift;
coding/reviewer collision and wrong effective identity/permission; stale/expired
facts, untrusted labels/assignees; replay, lost history and simultaneous tasks;
existing prepared work, busy/missing lock; API failures, pagination ambiguity,
redaction and forbidden runtime/writer/state mutations. Live identities, credentials,
publication, production isolation and durable claim authority remain NOT_RUN.


Issue #74's [AP-AM/1 metadata contract](app-metadata-observer.md) is separate from
this synthetic assignment/writer identity contract. The operator-reported real
App has Metadata read only; no public Bot profile or metadata result satisfies
AP-CA/1's writer, admission, queue, authorization or durable-claim requirements.
Do not synthesize an assignment or reviewer receipt from it. See the updated
[operator milestone](coding-app-gate-b.md#operator-reported-mvp8b-milestone-and-mvp8c).
