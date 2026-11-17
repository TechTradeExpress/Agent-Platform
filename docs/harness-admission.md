# HAR-02: worker-pinned offline harness admission

**AP-HAR/1 companion / SOURCE_ONLY / OFFLINE_ONLY / HOST_NOT_RUN.**
[Issue #132](https://github.com/TechTradeExpress/Agent-Platform/issues/132)
implements the pure typed binding checks proposed by
[ADR 008](multi-harness-architecture.md), not a scheduler or production admission
service. Its stacked base is the exact published HAR-01 PR #139 HEAD
`733160b8db95de9a6eefebc5394bcc339705fa87`, tree
`8e9ad754ec811c82cda8b54ec2458a14deb92668`. The maintainer keeps HAR-01–07
unmerged until the full series completes review/CI. Any future HAR-02 Draft must
target `feature/issue-131-multi-harness-adr`, not main, until separately reconciled.
This delivery is local-only: no push, PR or GitHub mutation.

`harness_admission.py` is explicitly SOURCE_ONLY in the closed Debian manifests.
Neither Control, Worker P0/P1 nor Publisher imports or ships it. No entrypoint,
JSON loader, vendor adapter/parser, executable chooser, CLI invocation, IPC,
credential read, provider request, host change, reservation or persistent ledger
is added. The Codex adapter below only adapts existing **assignment data**.

## Input and trust boundary

All inputs are exact frozen/slots dataclass instances from trusted callers.
Strings/dicts decoded from an Issue, worktree, model, environment, serialized
example or report are rejected. Subclasses, missing/extra fields, unknown versions,
unknown/multi-valued IDs and bool/float epochs do not become authority. Revalidate
nested constructors at entry and bracket the full input digests against drift.
`HarnessId` has exactly `codex` and `claude_code`; no aliases or provider/model
names. Typed construction checks syntax/consistency, **not authentication**.

| Type / closed version | Meaning |
| --- | --- |
| `Binding` / embedded AP-HID/1 + AP-HCAP/1 | Worker and enrollment/boot reference, scalar HarnessId, selection epoch 1..2^63-1, approved matrix digest, configuration/executable-manifest/parser/instructions/isolation SHA-256 pins |
| `WorkerSelection` / AP-HSEL/1 | Exactly the HAR-01 record: issuer/approval/continuity references, previous digest, selected/drained state. Initial epoch requires zero previous digest; later epochs require nonzero previous digest. This module does not create/advance selections or validate a history chain |
| `CapabilitySnapshot` / AP-HCAP-SNAPSHOT/1 | Exact immutable HAR-01 capability row, full binding and schema. No extra/missing/reordered/duplicated capabilities or optimistic statuses. Document consistency only, not host/CLI proof |
| `SelectionApproval` / AP-HSEL-APPROVAL/1 | Separately supplied trusted-caller pins for the exact selection, capability snapshot, issuer, approval and continuity witness, bounded freshness; provenance must be `synthetic_operator_snapshot` |
| `TaskAuthorization` / AP-HAR-AUTHORIZATION/1 | Complete external task-authorization digest, stable task-identity digest, explicit attempt/agent/worker/enrollment mapping, selection digest, model/account policy, closed required capabilities and expiry. Origin is exactly AP-HAR-TASK/1 or AP-CA/1; `synthetic_task_authorization` only |
| `HarnessAssignment` / AP-HASSIGN/1 | Exact HAR-01 wire shape, bound to the full worker binding and selection digest, immutable attempt/task/model/account pins |
| `RetainedAttempt` / AP-HAR-INTENT/1 | Global history: assignment reference/digest, complete task authorization and stable task identity digests, worker/enrollment/selection/epoch, fixed state, observation time |
| `Inventory` / AP-HAR-INVENTORY/1 | Exactly one current selection for the expected worker, exact capability/approval snapshots, complete global retained history, independent generation digest and observation time; `synthetic_harness_inventory` only |

Opaque task authority must cover **all** existing repository/Issue/scope/revision,
base/head, role, App/installation/reviewer, policy, freshness and human approval
constraints. `task_identity_sha256` correlates stable repository + Issue identity
across attempts, workers and changed authorization digests. It is not a task
selector or target authorization API. The external trusted producer must retain
and validate the complete source facts. Generic HAR-02 does not inspect a repo,
read GitHub, authenticate an operator, prove completeness or replace AP-CA/1's
stricter identity/queue checks. Agent identity is separate from worker identity;
no mapping is guessed from a hostname, PATH, model or installed tool.

Nonsecret issuer/approval/witness strings and provenance labels are **not signed
receipts or live evidence**. Every current producer is fabricated/offline. Future
production use needs separately reviewed authenticated producers and independent
continuity; a caller boolean, hash, local fsync or restored DB cannot supply them.

## Selection, assignment and result

`bind(selection, authorization)` has **no harness parameter**. It copies the
already selected worker binding only if selection digest, worker/enrollment and
explicit task authorization agree, and rejects a drained selection. The task
cannot request another harness. Installation discovery, model/provider choice,
PATH search, CLI fallback and account rotation are absent.

`advise(assignment, authorization, inventory, *, expected_worker,
expected_selection_sha256, expected_generation_sha256, now, legacy=None)` is a
pure snapshot comparison. Expected selection and generation pins come from a
**separate trusted current continuity source**, not values read back from the
same untrusted inventory. Without them a stale/rolled-back view is not admissible.
All timestamps are explicit integer inputs; no system clock or host observation.
Selection/task approval lifetime is at most 300 seconds; future/stale snapshots,
expired grants, wrong boot, selection/epoch/config drift and mismatched approval
or capabilities return BLOCKED. Revalidate at every future phase; this result is
not a reusable ticket for acknowledgement, exec, resume or result acceptance.

Success means only `OFFLINE_BINDING_MATCH / binding_snapshot_only`. It never
means a task is executable, actually admitted, entitled, isolated, authenticated
or ready. The [closed result schema](harness-admission.schema.json) and
[fabricated assignment/result fixtures](harness-admission.examples.json) retain
all five authority flags false, runtime exit 13, HOST_NOT_RUN, LIVE_NO_GO,
SUBSCRIPTION_ISOLATION_BLOCKED and Gate #73 BLOCKED. Invalid inputs return only
fixed reason codes; no raw exception, native output, session/account ID, path,
credential or task prose. Digests correlate sorted compact JSON plus newline.

The capability snapshot must equal the exact pinned HAR-01 matrix/row and the
separately approved snapshot digest, including its binding. It is not a user
allowlist and cannot promote REQUIRED_UNVERIFIED or BLOCKED to support. A required
capability must already have OFFLINE_CONTRACT evidence; otherwise
`capability_unverified`. Codex's existing historical event parser has that narrow
evidence; Claude's parser does not. An empty required list permits **binding-only
comparison** for either ID; it proves no feature and can never enable execution.
Both engines' complete tool/auth isolation and real execution remain BLOCKED.

## Concurrency, replay and switch discipline

Inventory requires one scalar selection, explicit completeness, <=4096 retained
records, unique attempt references/digests and task authorization digests. There
is no eviction or automatic reset at capacity. Any RESERVED, PREPARED, RUNNING or
UNKNOWN attempt for that logical worker blocks a new attempt, even from an old
boot/epoch or after a purported lease timeout. Unrelated work on another worker
does not grant this worker more than one attempt. Global history rejects replay
of attempt reference, assignment digest, authorization digest **or stable task
identity**, including FINISHED records, across workers and renamed attempts.
Unrelated FINISHED history may permit a new binding snapshot, never a retry grant.
Future timestamps, collisions or ambiguous history block rather than collapse.

Re-reading unchanged advice consumes nothing and remains deterministic. Two
callers receiving MATCH have **zero reservations**, not two runnable assignments.
This module enforces snapshot consistency, not distributed concurrency. A durable
single-writer compare-and-swap reservation, replay retention, independently
anchored anti-rollback, leases/fencing, child-death verification and reconciliation
remain NOT_IMPLEMENTED. Missing real evidence stays BLOCKED, never an empty fresh
inventory. A restored inventory plus a restored local anchor is not continuity.

Operator rotation must follow ADR 008: quiesce, reject new jobs/resume, reconcile
all intents and uncertain effects, independently prove process death, re-attest
new pins, obtain approval and atomically increment the epoch with continuity.
Here any changed selection/epoch or QUIESCING/RECONCILING/BLOCKED state invalidates
the old assignment. No switch/rollback/release method exists. Switching back
requires a new epoch and new approvals, never the old assignment or native session.
No fallback to the other engine, including after capability/account uncertainty.

## AP-CA/1 compatibility and migration

Existing `codex_assignment.py`, its typed constructors, original advise/queue and
identity validation, digest, runtime='codex', integer schema_version=1 and all
existing tests are unchanged. Unknown future versions stay rejected. No legacy
serialized JSON is imported, and no harness is inferred from omitted new fields.

`bind_codex(legacy, selection, authorization)` validates the exact original
`CodexAssignment`, requires AP-CA/1 origin, Codex selection, exact legacy digest,
agent mapping, stable repo/Issue identity digest and unchanged issued/expiry times.
The entire original admission/target/App/reviewer policy remains bound by that
digest; it is not reserialized with fields dropped. The caller supplies a new,
explicit selection authorization. Common `advise` with AP-CA/1 origin additionally
requires that same original `legacy` object and repeats the adapter checks.
A raw AP-CA label/digest without the object does not pass the compatibility path.

A binding MATCH does **not** replace legacy eligible advice or chain it into
execution. Source JSON hashes are not authenticated authority; existing legacy
UNKNOWN/checkpoints retain their original namespace and block migration pending
independent reconciliation. No checkpoint rewrite, journal reset, native session
copy or cross-harness/host resume is delivered. Native `run`/`resume` retain their
unconditional pre-I/O BLOCKED / exit 13 gate, flags and complete isolation policy.
HAR-03's Claude adapter/parser is not implemented or stubbed as a successful one.

## Offline verification and remaining gates

Tests cover both ID bindings, all selection pins and epochs, wrong worker/boot,
unknown versions/subclasses/serialized dicts, missing/dual selection, operator
approval mismatch, snapshot freshness/continuity/drift, capability rejection,
retained UNKNOWN/concurrency, finished/global/stable-task replay, legacy migration
and pre-I/O native gates. Fixtures use fake references/digests, not real host
observations. Packaging tests assert closed SOURCE_ONLY classification, P0/P1
archive exclusion for both roles/revisions 3–6, and deny role/Publisher imports.

Run Ruff, HAR-01/HAR-02/AP-CA contracts, unchanged native quarantine tests,
packaging tests, full pytest and diff checks. Disposable OS lifecycle, real
operator authentication, independent anchor durability, race/process isolation,
Claude protocol/instruction loading, vendor eligibility and all actual host or
paid-turn tests are NOT_RUN. No harness/tool is installed or invoked here.
Publisher/App credentials, accounts and services remain untouched. Follow-ups and
separate approval stay required; HAR-01–07 remain unmerged for series review.
