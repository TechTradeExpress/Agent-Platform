# CP-05 initial Draft publisher — AP-DP/1

`draft_publisher.publish` implements the complete first-publication transaction
against injected synthetic GitHub, admission and journal ports. There is no CLI,
production HTTP client, token/key loader, signer, listener, service or runtime
integration. All results have init-disabled `live_authorized=false`.
`PUBLISHED_OFFLINE_FIXTURE` proves a simulated transaction, never live authority.
CP-01, CP-02, CP-03, AP-SM/2 and the #73 gate remain independent prerequisites.
Native SUBSCRIPTION_ISOLATION_BLOCKED and public legacy exit 13 are unchanged.

## Inputs and authority

Candidate bytes are inert CP-03 data. `validate` independently compares them to a
separately supplied frozen Policy and constructs a frozen Request. The authenticated
Admission port must approve that exact Request, including candidate digest, immutable
Git HEAD/tree, repository/Issue/scope/base/ref, App/registration owner/installation/account/bot/target owner, fixed
Draft title/body and expiry. No candidate claim or local PASS grants authority.
Policy, Request, Observation, PullRequest, Intent, State and Result are version-bound,
frozen slotted data contracts. There is no policy/authority JSON loader.
The authorization reference is never returned or logged. Frozen Python types and
hashes do not authenticate callers: all ports and policy originate inside the
separately trusted controller. The synthetic fixtures deliberately fabricate them.
No existing publisher.plan receipt is converted into write authorization.

## Transaction and immutable effects

Immutable State snapshots admit only VALIDATED -> CLAIMING -> ACTIVE, then
ACTIVE -> UNKNOWN -> ACTIVE per effect, and ACTIVE -> COMPLETE. Invalid local
transitions refuse; persistent replay authority belongs exclusively to Journal.
The fixed sequence is validation, fresh admission, exclusive journal claim,
complete remote observation, dependency-ordered object creates, atomic absent-ref
creation, remote canonical-object/ref verification, Draft creation, two independent
PR observations and confirmed terminal result. Every write uses a new immutable
AP-DP/1 Intent with monotonic sequence, exact request and payload SHA-256 digests.
The journal must durably persist and independently read back UNKNOWN before the API
call. Exact observed results are independently confirmed before the next step.
Unreachable object uploads count as writes and receive their own intents.

The API surface contains only observe, create_object, read_object, create_ref,
create_draft and read_pr. These are a fixed GitHub domain interface for simulation,
not arbitrary HTTP endpoints. The implementation supplies canonical objects as
bytes; it never executes Git, shell, hooks, filters or target code. A future wire
adapter must map those objects to reviewed GitHub payloads without changing their
hashes or bytes. CP-03 still supports only flat ASCII trees, at most 128 paths,
130 objects, 16 KiB descriptor, 256 KiB/object and 1 MiB total candidate data.
It is not a complete production Git validator. PR text is fixed and below 8 KiB.

Each remote observation checks canonical repository and owner, open Issue and
scope, App/installation and verified bot attribution, exactly one explicitly selected
repository, active installation, matching installation account/target owner, pinned
registration owner and no event subscriptions, exact Metadata read/Contents write/PR write grants, independently
verified governance, current main SHA, feature ref and complete all-state PR
inventory for the Issue OR ref. Extra permissions, missing evidence, existing
refs or any prior open/closed PR block. Mutable admission is refreshed before
every write. Atomic create-if-absent is mandatory; GET then update is prohibited.
There are no updates, force push, delete, COMMENT, APPROVE, Ready, Issue closure
or merge operations. Publication does not close the Issue.

Before PR creation every remote canonical object is reread and compared to the
CP-03-validated bytes, including exact tree and sole base parent. The returned
PR number is insufficient: independent PR reads verify same-repository HEAD/base,
current SHAs, author numeric ID/login and App, Draft/open state, exact fixed text
with sole `Closes #N`, and sole native Issue ID association. A body reference alone
is insufficient. Duplicate inventory or drift after an effect stops the sequence.

## UNKNOWN, exclusivity and recovery

The injected Journal owns an exclusive session for the entire call, with an
independently protected continuity anchor and separate stable repository/Issue and repository/ref guards
across App, authorization and namespace rotation. Claim is atomic and never drops
history. All attempts, even successful ones, remain non-replayable. The publisher
provides no automatic reconciliation, retry, reset, cleanup or rollback. It never
adopts an existing branch or PR. Losing claim/UNKNOWN/result confirmation returns
UNKNOWN_NEEDS_HUMAN; an uncertain journal claim also requires human reconciliation.
Candidate/policy or admission refusal before claim returns BLOCKED. A failure after any
confirmed partial effect returns UNKNOWN_NEEDS_HUMAN, retaining prior facts.
Process death leaves durable UNKNOWN/claim history; BaseException propagates.
Human reconciliation must inspect remote and local facts without automatically
repeating writes or deleting unreachable objects, branches or PRs.

The library enforces cooperative 5-second call and 60-second overall deadlines,
with expiry at most 300 seconds from the supplied trusted current time. A late
return stops subsequent effects. It cannot interrupt a blocked injected function.
The trusted adapter must enforce actual socket/read deadlines, ordinary response
limits of 64 KiB, complete pagination at most 3 pages of 20, no redirects/retries,
and separately bounded canonical artifact reads within CP-03 byte ceilings. Typed
snapshots are complete trusted-adapter outputs, not raw unbounded HTTP documents.
No live adapter or durable journal implementation is supplied by CP-05. In-memory
fixtures assert ordering and simulate persistence across invocations; they cannot
prove power-loss durability, mutual exclusion or independent anti-rollback.
Results contain only fixed codes/status, write count, optional verified PR number,
version and false live authority; no raw exception, URL, path or authorization.

## Gates before a live pilot

Live remains NO-GO. Require separately authorized independent CP-01 control01
host/UID/IPC/network/credential isolation evidence, including negative probes and
reboot; actual authenticated exact-payload human admission, fencing, revocation,
clock and #73 evidence; independently anchored durable exclusive replay history
resistant to deletion/rollback and rotation; power-loss/crash reconciliation proof;
reviewed GitHub wire schema, pagination and atomic create semantics; actual App/bot
attribution, single-repository installation and effective grant evidence; protected
main/no-bypass and human-only merge enforcement. Contents and PR write grants are
broader than this interface and cannot be made safe by an allowlist alone.
Also require independently collected exact-tree tests, candidate profile adequacy,
credential custody and bounded request/response proofs. No synthetic PASS satisfies
these gates or authorizes App activation, real credentials or control01 access.

Offline tests exercise end-to-end effects, candidate/path/tree/SHA identity failures,
App/Issue/grant mismatch, base/ref drift, existing/duplicate PRs, durable UNKNOWN and
result-confirmation failures, timeouts/crash/replay, author/PR/API mismatches, deadlines
and absence of arbitrary or prohibited write methods. Full existing tests preserve
legacy/native quarantine. No real GitHub App, control01, worker02 or Proxmox is used.

## Review repair: retained claim and synthetic route contract

A confirmed claim is retained history even when zero GitHub writes completed.
After entering CLAIMING, every unsuccessful return requires reconciliation,
including a failed first observation or admission revocation after claim. Such
results are UNKNOWN_NEEDS_HUMAN with completed_writes=0; BLOCKED is reserved for
candidate/policy rejection or admission refusal before claim. A repaired external
observation does not release, reset or reuse the claim on another invocation.

`RouteOperation`, frozen `Route`, `allowed_routes` and `route_allowed` provide a
pure synthetic method/origin/path profile. Routes bind the validated candidate's
repository, Issue, installation, base/feature ref, exact object IDs and optionally
a separately observed PR number. The fixed origin is https://api.github.com.
Only the enumerated GETs and initial object/ref/Draft POSTs are represented.
PR enumeration has exactly state=all, per_page=20 and pages 1–3. Unknown verbs,
URLs, paths, query fields or route metadata refuse by default; main/tag writes,
merge, reviews/APPROVE, deletion, updates/force and repository settings are absent.
Ref/Draft metadata pins exact feature ref and HEAD; Draft must be true. The
synthetic transaction fixture checks its write/object/PR routes against this
profile. It does not make HTTP requests.

Every Route has init-disabled semantics_verified=false. This is deliberately
route metadata, not an HTTP body encoder, authenticated permission gate or a
complete observation adapter. Git object wire encoding, native Issue association
queries, effective App/grant evidence, pagination completeness, response schemas
and atomic create-if-absent semantics still require separately reviewed official
API/schema evidence before any future live adapter. In particular no generic
GraphQL endpoint, arbitrary body, network sender or live-safe claim is introduced.
The profile cannot grant authority or replace admission, journal continuity,
independent remote observations or the existing live NO-GO gates.

## PUB-01 worker-local handoff proposal

[Issue #104 / AP-PH/1](publisher-handoff.md) adds byte-only intake and a separate
synthetic existing-Draft update model. It proposes worker-local separately
privileged publishers without deploying or replacing CP-02 control01 custody.
CP-03 update refusal, CP-05 create-only behavior and all live gates remain.
Official CAS/permission evidence and effective App merge denial remain BLOCKED.
