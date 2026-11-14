# CP-02 — per-worker GitHub App and supervised publisher contract

Issue #88, 2026-11-10. **DESIGN_ONLY / OFFLINE_ONLY / LIVE_NO_GO**.
This is a proposed contract, not an accepted wire schema, executable publisher,
credential service or worker adapter. All examples below are fabricated and
non-authorizing. Completion permits independent contract review only.

Packaging specialization: [ADR 007 / AP-PKG/1](debian-role-package-architecture.md)
records the approved direction of PUB-02's **worker-local**, separately confined
App signer/Publisher rather than treating the Control-only custody placement
below as the only future topology. This applies solely to each worker's own
App and operator-initiated exact feature/Draft operation. Untrusted Codex/tools
still receive no credential or handle; Control credentials stay on Control.
The original CP-02 protocol, AP-AL/AP-AS interfaces and synthetic publication
gates are unchanged. PR #109 must be reviewed/merged before #111 packages its
implementation; no host activation or live evidence follows from this ADR.

## Baseline and governing boundaries

Historical CP-02 source base: `e19c0b3b124ac5689d0c31c60a5ea5e7330c11af`.
The original local CP-02 commit was
`88e1d6c6278b0025483d68f3e0a4fe6943e0eea5`. This integration uses
`origin/main` at `1e77100e04f29fb0475a2bcc18100726f6d86692`.
[ADR 006 / AP-WP/0.1](worker-pool-identity-architecture.md),
[AP-SM/2](solo-maintainer-policy.md), [development](development.md),
[AP-TP/1](target-project-policy.md), [Gate B](coding-app-gate-b.md),
[governance](github-governance.md), [AP-AL/1](app-api-adapter.md),
[AP-AJ/1](custody-journal-and-host-isolation.md) and
[AP-AS/1](app-signer-ipc.md) retain their existing invariants.

CP-01 / #87 originated as a local candidate at
`2e14c76a3a9c73133461e8a212ebe4882e6a3b2c`.
[PR #89](https://github.com/TechTradeExpress/Agent-Platform/pull/89) has since
been merged by the maintainer; [CP-01](control-plane-host-contract.md) is now on
main and included through this merge. Its inclusion does not complete host,
independent assurance or live activation gates.

The maintainer published CP-02 from a laptop as
[Draft PR #90](https://github.com/TechTradeExpress/Agent-Platform/pull/90).
This human-controlled source delivery is not a deployed production GitHub App
publisher and proves no worker App publication capability. Issue #88 remains
OPEN pending final review. These remote-state facts are operator-reported;
this local integration performs no network verification or publication.
Deployment still requires CP-01 independent assurance and all gate completion.
Issue #73 remains an open operator governance/custody/live-identity gate. Its
historical publisher01 proposal supplies no control01 admission or current proof.
ADR 006's publisher01 denotes the proposed Control Plane role; CP-01/CP-02 use
control01 for the proposed host. No rename, host observation or migration follows.

| Capability | Existing support | CP-02 status |
| --- | --- | --- |
| Human-invoked source contributor and separate ChatGPT review | Documented AP-SM/2 workflow; direct human instruction controls actual scope | Unchanged; Draft #90 was published by the maintainer; this update stops at one local integration commit |
| `publisher.plan` | Offline inspection, `publish_authorized=false` | No commit/ref/PR writer added |
| #49 / #59 / #62 evidence and COMMENT | Trusted-caller/synthetic interfaces, exact-SHA/project rules | No live client or new Receipt bridge |
| AP-AL / AP-AJ / AP-AS | Inactive bounded libraries; explicit journal and injected signer/IPC | Not a deployed composition; claims-only signer bridge stays blocked |
| Existing techtradeexpress-agent | Operator-reported Metadata read only | Unchanged; never promoted or repurposed |
| Per-worker Apps, controller, publisher, authenticated approvals | NOT_IMPLEMENTED | Proposed only; host and live GitHub tests NOT_RUN |
| Native/subscription and public legacy execution | SUBSCRIPTION_ISOLATION_BLOCKED / exit 13; legacy quarantine | Unchanged; no API billing fallback |

No App registration/install/permission change, real key/token access, host access,
service, scheduler, automatic Ready/Issue closure or merge is authorized here.

## Target enrollment, identities and symmetric roles

Agent Platform is organization- and project-aware, not a source-repository-only
product. Trusted human enrollment explicitly pins each project's authorization
reference, canonical repository numeric ID and full name, target owner ID/login/
type, approved default/base branch and governance, Issue ID/number/scope revision,
allowed operations/paths, required CI App/check identities, source provenance,
expiry and revocation policy. Default is deny; no implicit All repositories,
source-organization membership or authority inherited from another project.
Registration owner, installation account, repository owner, task actor and human
approver are separate facts. Registration owner may differ from target owner;
installation account must match that target owner. Repo transfers, renames,
permission or membership changes require fresh enrollment evidence and approval.

Proposed worker01 and worker02 each use a **distinct registered GitHub App**:
different App ID, bot numeric ID/case-insensitive login, and independently pinned
installation ID/account per target. Names in ADR 006 are illustrative, not real
identity evidence. Two installations of one App are insufficient. Verify App/bot
association from independently authenticated attributable evidence; a slug or
public Bot profile alone is insufficient. New-App attribution bootstrap remains
a separately approved evidence problem, never permission to make a test write.
Observe actual PR/review authors after publication; no guessed bot IDs.

Either worker may implement task A and review task B. Role belongs to the immutable
assignment, not hostname or App name. Retain every contributor's machine, agent,
execution/session/context lineage and actual PR author across role/App/installation
rotation. A contributor cannot review its candidate. If both workers contributed,
review is BLOCKED pending a separately approved independent path.

Each enrollment selects exactly one repository for an operation. Organization-wide
reuse requires independently authorized per-target contexts and retained isolation;
never broaden existing single-repository AP-CI/AP-AM profiles to fit a multi-repo
installation. Project-aware pre-PR assignment/intent types are future work:
TargetProject currently requires PR/HEAD pins. Do not fabricate a PR, strip project
pins or convert target Receipts into main-only queue/prepare/runtime authority.

## Candidate operation, permission and actor matrix

All rows describe **future capabilities**, not deployed grants. Endpoint-specific
permissions, payloads and concurrency guarantees need fresh official-API/schema
verification and independent review before implementation or provisioning.
Contents write is repository-wide, **not feature-branch scoped**. PR write is
broader than Draft creation or COMMENT. Code allowlists do not replace effective
GitHub base protection, bypass inventory and human-only merge enforcement.

| Operation | Candidate grant / scope | Posting actor and trusted executor | Required restriction |
| --- | --- | --- | --- |
| Canonical source/Issue/PR/check evidence | Separate reader: Metadata, Contents, Issues, PR, Checks, Actions and statuses read as required | Read-only collector on control01 | Exact target, bounded complete stable reads; no writer grant for convenience |
| Stage/validate proposed Git objects | No GitHub write | Separate credential-free control01 validator | Treat artifacts as data; no hooks, filters, repo code or model commands |
| Create/update feature ref to exact commit | Metadata read + Contents write, one selected repository | Implementer's assigned App through narrow publisher | Approved feature ref, expected old SHA/absence, fast-forward only, never base/tag/delete/force |
| Create one Draft PR | Metadata read + Pull requests write, same repository | Same implementer App | Exact ref/HEAD/base/Issue/body; Draft only; no duplicate/fork or automatic update |
| Publish technical review COMMENT | Metadata read + Pull requests write, one repository | Other worker's distinct App through review publisher | Exact PR/HEAD/body and authenticated human approval; COMMENT only |
| Ready / linked Issue Completed | Not a CP-02 capability; Issues write excluded | Existing separately authorized AP-SM/2 source reviewer only | No product transition or permission inferred |
| Merge protected base | No worker/App capability | Human maintainer only | Server enforcement and separate manual human decision |
| Register/install App, change grants/rules, rotate credentials | No publisher capability | Separately authorized human administrator | Never delegated to workers or this contract |

Minimal implementer writer candidate: exactly Metadata read, Contents write and
Pull requests write, selected repository only, no events/webhooks, Administration,
Workflows or Issues write. Reviewer operation capability exposes only COMMENT;
provisioning must resolve whether a role-restricted token/extra writer separation
can safely reduce the per-worker App's grant union. A role field does not reduce
GitHub permissions. #59/#62's exact metadata/PR-write synthetic profile cannot
silently accept a broader coding token. Token issuance restrictions supplement,
never hide, installation-wide grant/membership observations. Existing AP-AM/AP-AL
metadata-only routes and token lifecycle are not extended into this publisher.
If a required permission or effective base/no-bypass control is unknown, STOP;
no grant broadening, PAT fallback or protection bypass to obtain GO.

## Proposed control01 compartments and credential custody

| Separate process/UID domain | Allowed assets and fixed calls | Denied edges |
| --- | --- | --- |
| Untrusted worker/tools | Credential-free assignment/result channel, local candidate artifacts | No production/admin endpoint, password, PEM, JWT, token, signer handle, journal FD or writer client |
| Noncredential ingress | Authenticated bounded typed messages to controller | No custody/signer/publisher socket or controller-ledger write |
| Trusted controller / admission | Independently authenticated human policy, scope, leases, fencing, replay and approval records | No target code execution; cannot derive authority from worker PASS |
| Credential-free validator / observer | Canonical independent source/CI facts, fixed artifact validation | No writer token, signer capability or executable worker instructions |
| Fixed signer | Approved App/key/purpose and exact custody peer, AP-AS admission | No network, generic bytes/path signing or worker/ingress access |
| Custody | Private short-lived JWT/token lifecycle and complete AP-AJ history | No raw credential output, shared worker UID or generic proxy |
| Operation-specific publisher | Private admitted operation session and minimum target token in trusted memory | No metadata-adapter reuse, merge, arbitrary method/path/body, shell or Git helper |
| Redacted audit/output | Validated facts, digests, fixed outcomes and evidence references | No credentials, raw HTTP/errors, auth headers, secret paths or active handles |
| Root/operator | Explicit reviewed provisioning, incident response and independent continuity custody | No administrative credential placement on workers |

Publisher token delivery, custody session ownership and peer admission are
NOT_IMPLEMENTED and need a new reviewed operation-scoped protocol. No worker
supplies token/key paths, arbitrary endpoints, signing claims or a callable proxy.
Use separate principal/code/config/state/IPC boundaries, both-end pinned peer
PID/UID/GID and lifetime, no inherited FDs, dump/proc/memory/env leaks or shared
secret-bearing UID. Proposed admission/signer have no INET; custody/publisher only
explicit fixed verified GitHub HTTPS routes/peers, no redirects/proxy/DNS fallback.
Future listener/egress policies and bounded credential teardown need independent
negative probes, including reboot. CP-01 remains the prerequisite host contract;
this table grants no socket ACL, account, unit or network access.

LoadCredential gives a readable copy to its unit UID; same-UID 0700/env filtering
is not isolation. Whole-worker VM containment does not protect CODEX_HOME tokens
from tools inside it. Root/hypervisor compromise remains trusted-domain risk.
Local SQLite/hash/inode checks do not prove independent rollback/deletion defense.
Admission/continuity producer, safe signer bridge and live composition remain
BLOCKED; no automatic setup, loader, listener, service or repair is supplied.

## Immutable publication descriptor and bounded protocol

Proposed versioned descriptor fields are closed, canonical and independently
validated; this is **not a currently accepted serialized schema**:

- Project/enrollment and actual human authorization reference; canonical repo/
  owner/base/Issue/scope pins; operation enum and exact destination.
- Assignment/job/attempt, worker/agent/context/contributor lineage, role, lease,
  boot/enrollment epoch, one-use nonce, fencing generation and issued/expiry.
- App/bot/registration owner, installation/account, effective permissions and
  selected membership; trusted observer/evidence digests and observation times.
- Exact feature ref, expected previous full SHA or typed ABSENT, current base SHA,
  allowed path/change inventory, object format, canonical tree, parent and proposed
  commit bytes/hash, author/committer fields and source/test receipts.
- For PR create: typed pre-PR phase, exact head/base repositories/refs/commit,
  deterministic title/body digest with sole intended `Closes #N`, Draft=true.
  Bind the resulting actual PR ID/number/author in a new phase, never invent it.
- For COMMENT: existing PR ID/number, full HEAD/base/merge SHA, analysis/body
  digests, contributor exclusions, decision, check identities and thread evidence.
- Stable replay guard, journal namespace/store/independent anchor, operation ID,
  dependencies, policy/code versions, payload budgets and expiration.

A digest or saved descriptor correlates bytes; it does not authenticate a human.
Approve each immutable effect through a separate authenticated controller boundary;
product review retains AP-CH/1 exact-payload human approval. No model or bot can
approve its own output. Changed tree/parent/ref/body/actor/base/expiry requires new
approval after reconciliation; it cannot clear an earlier UNKNOWN.

Proposed sequence, each step fail-closed:

1. Independently refresh target authority, open Issue/scope, governance, App and
   installation facts. Verify complete stable reads and no revocation/lease/fence
   conflict. Acquire exclusive per-target/task/ref authority; local host lock
   rules remain unchanged, not replaced by a distributed lease assertion.
2. Validate candidate data in a credential-free boundary. Recompute Git object
   IDs using pinned format; reject malformed objects, unexpected paths, submodules,
   unsafe links and unsupported modes. Initial publication has exactly one parent
   equal to approved current base; later approved feature updates require exact
   expected tip parent and proven base ancestry. No merge/foreign parent, hidden
   refs, pack tricks, target hooks/config/filters or repository execution in the
   credential domain. Independently collected tests bind exact tree and inventory;
   worker-supplied PASS does not mint trusted receipts.
3. Re-read canonical base/ref and all mutable admission facts immediately before
   each write. Persist and independently confirm durable UNKNOWN intent **before**
   object upload, ref write or PR creation, including unreachable-object effects.
   Journal/fence uncertainty blocks before I/O. Objects/ref/PR are separate effects,
   not one atomic transaction; each needs its own approved intent and result.
4. Create feature ref only if absent; update only the expected tip, fast-forward,
   never force. The proposed transport must provide verified atomic expected-ref
   comparison; a GET followed by unconditional PATCH is insufficient. If unavailable,
   update is unsupported/NO-GO, not emulated with a race. Revalidate base stability
   after effect; drift stops subsequent steps even if the ref write succeeded.
5. Verify actual object/tree/parents and remote feature tip equal approved commit.
   Before Draft create, independently prove no existing conflicting open/closed PR
   or retained creation intent for the task/ref; incomplete enumeration blocks.
   Create exactly the approved same-repo Draft. Verify actual returned and re-read
   PR ID, author/App attribution where available, head/base, Draft/open state and
   single native Issue association. Drift or missing attribution is UNKNOWN/BLOCKED;
   never declare success solely from an HTTP response or body closing reference.
6. Persist confirmed results, actual actor/object/ref/PR facts and evidence times;
   return only bounded redacted outcomes. No subsequent operation follows a failed,
   late, uncertain or unconfirmed write. No automatic Issue closure or Ready.

Proposed ceilings: descriptor 16 KiB, COMMENT body 8 KiB, PR text 8 KiB, candidate
inventory 128 paths/1 MiB total object data, 64 KiB per ordinary response, at most
3 pages of 20 objects for enumeration, 5 seconds per request and 60 seconds per
operation; expiry <=300 seconds, no queued work. These are future limits, not
changes to existing component caps. Truncation, duplicate/unknown fields, extra
pages, count drift, oversized/unsupported candidate or deadline means STOP, never
partial approval, cap increase or retry. A future API proof must reconcile actual
response sizes/atomic semantics with these ceilings before code or live GO.

API-observed posting actor is distinct from Git commit author/committer fields
(which can be forged), signature provenance and the claimed contributing agent.
Keep each in audit evidence; a worker App publishing a human-authored commit does
not establish bot authorship, human consent or independent review.

## Independent review and AP-SM/2 reconciliation proposal

Other-worker review requires a fresh session, isolated worktree and auth/context
storage, no implementation transcript or writable implementation checkout, no
worker-to-worker channel, and independent canonical retrieval of exact commits,
diff, current base, Issue association, complete findings/threads and CI. Treat
implementer summaries as supplementary untrusted input. Contributor inventory must
be complete; an editing reviewer becomes a contributor and invalidates eligibility.

Require exact current HEAD plus current base-bound merge-result successful CI,
actual checkout SHAs, exact merge parents `[base, head]`, pinned required check
Apps, one same-repo linked open Issue and no unresolved findings/blocking threads.
Old PASS, failed/pending/missing checks, changed HEAD/base or incomplete evidence
blocks publication; no inferred green from display names or run head_sha alone.
A new HEAD needs new independent review; base drift needs new CI/reassessment.
Prepublication facts are not a #49 reviewed Receipt: that requires an actually
observed identity-qualified exact-SHA PASS COMMENT and all collector gates.

The reviewer App must differ from the actual PR author on numeric ID and login,
and from every contributor's assigned App. COMMENT uses exact commit_id and
human-approved immutable body; observe actual author and destination after send.
State analysis provenance as AI-assisted other-worker technical review; it is not
independent human review, formal APPROVE/REQUEST_CHANGES or proof of reasoning
independence. Separate model contexts can share errors. A single human maintainer
is supported; no fictitious second human or final-SHA human consent is recorded.

**Proposed future policy change only:** permit a separately reviewed worker-review
handoff with authenticated provenance as a technical-analysis input. This requires
explicit AP-SM/2 and AP-CH/1 reconciliation before use. It does not replace today's
human-requested separate ChatGPT source review, relabel Codex as ChatGPT, create a
product Receipt from a source COMMENT or import source delegation downstream.
Current AP-SM/2 conditional COMMENT -> Ready -> single Issue Completed remains
unchanged for its authorized source interactions. CP-02 product capability stops
at Draft and separately authorized COMMENT; no automatic transitions or scheduler.
The human alone decides and performs final protected-base merge.

## Bootstrap, replay, recovery and audit

Bootstrap cycle: supervised Codex can implement and commit locally while credentials
are withheld, but it cannot push or bootstrap its own trusted publisher. A local
commit, developer Git identity or old gh setup grants no writer authority.
The maintainer used a separate laptop to publish Draft #90. That supervised
source-delivery path does not deploy or authorize a production App publisher.
This update is local-only; no further publication is authorized here. Compare
human-controlled choices for future separately approved delivery:

| Candidate path | Benefit | Preconditions and remaining risk |
| --- | --- | --- |
| Human publishes reviewed exact local commit from a separate trusted workstation | Breaks cycle without worker credentials or publisher dependency | Explicit delivery approval; immutable artifact/commit/base verification; no executing transferred hooks/config; actual human push/PR attribution |
| Human transfers inert candidate to a separately reviewed minimal trusted publisher on control01 | Establishes eventual App-mediated route | CP-01, authority/continuity, governance and publisher implementation/identity gates first; cannot use this route to approve/deploy itself |
| Keep local-only pending gates | No live authority introduced | Preserve work and record delivery blocked; this is the boundary for the current local integration update |

Never copy administrator PAT/gh login, PEM/JWT/token or signing handle onto a
worker, even temporarily. Never upgrade techtradeexpress-agent for bootstrap.
Preserve #87's original commit/worktree and actual provenance: its source was
merged through PR #89. CP-02 is delivered as Draft #90, with #88 still open for
final review. Any changed candidate needs fresh exact-SHA review evidence and
separate human authorization for subsequent publication or manual merge.
Source delivery transitions to App mediation only after individually reviewed gates and a fresh human-approved
exact target/action, never merely because the publisher source was merged.

Proposed publisher ledger is separate from task checkpoints and existing AP-AJ
metadata-token journal; do not reuse/extend those schemas implicitly. Retain full
history and a stable repository+task+feature-ref creation guard, then repository+
PR guard, across project/App/installation/namespace/credential rotations. Atomically
map pre-PR intent to observed PR without creating a replay gap. Serialize competing
attempts with authenticated fencing; a stale process cannot dispatch after lease
loss. Local locks alone do not establish remote fencing or independent continuity.

Each effect is UNKNOWN-before-attempt -> CONFIRMED only with exact remote evidence.
Timeout/crash/restart, lost response, duplicate PR, ref/base drift, journal write
failure or partial effect stays UNKNOWN/NEEDS_HUMAN. No blind retry, automatic
replay, reset, eviction, namespace escape, force update, cleanup or presumed
revocation from expiry. A successful ref with failed PR remains a published ref
and uncreated/uncertain PR, never overall success; preserve it without deletion.

An explicitly incident-authorized operator stops new admissions and reconciles
read-only canonical remote objects/refs/PRs/reviews, authors, exact payload and
ledger/independent anchor. Absence in one read or free lock cannot prove no effect.
Confirmed existing exact PR is recorded, not duplicated; unknown effects remain
blocked. Revocation/rotation/uninstall, rollback of code, restore or any new write
requires separate incident approval. Restore must retain replay/UNKNOWN lineage
and independent continuity; never restore old DB+anchor as fresh permission.
AP-AJ's local durability is insufficient for independent anti-rollback assurance.

Audit retains schema/code/policy hashes, real human delegation/approval reference,
canonical project/task/actor pins, exact tree/parent/commit/ref/base/PR/review IDs,
contributor/context lineage, check/merge-parent facts, sanitized evidence digests,
observation/expiry times, nonce/fence, independent anchor and actual transition
results. No secrets, raw logs/HTTP, paths to credentials or invented acceptance.
A journal confirmation is not exactly-once GitHub execution or live OS proof.

## Synthetic acceptance examples and future evidence

These bounded, testable examples are **DESIGN_ONLY**, not executed publisher tests.
There is no CP-02 validator to exercise. Use one fabricated target P/repo R,
base B, feature F absent, canonical one-parent commit C/tree T, Issue I open,
implementer worker01/App A/installation IA and reviewer worker02/App Z/installation
IZ, independently pinned selected-R grants, fresh authenticated approvals, complete
empty operation guard and green exact-HEAD/base-merge evidence. Symbols denote
fixed full IDs/digests in a future harness, not production values. Change only the
listed input per negative case; expect zero effect attempts unless stated.

| Case / changed synthetic input | Required outcome |
| --- | --- |
| Valid F ABSENT -> C, approved immutable Draft descriptor | One object/ref effect per intent, one Draft at C by A; confirmed facts; no merge/Ready/Issue close |
| Roles reversed on a different task with clean contributor lineage | Same constraints; worker02 implements, worker01 COMMENTs using its distinct App |
| Valid independent COMMENT, observed PR author A, poster Z | One exact-C COMMENT after durable UNKNOWN and human payload approval; no APPROVE |
| Wrong repo/target owner or project Q approval used for P, same Issue/PR numbers | DENY; no cross-project scope or guard reuse |
| Wrong App, bot association, installation/account or selected membership | DENY even if names/token appear valid; no permission broadening |
| Swapped role, contributor reviewing, same-worker context or both workers contributed | DENY; no eligible pool reviewer; identity rotation does not erase history |
| Ref main/default/release/tag, force/delete, unexpected parent/path/tree/hash | DENY before object/ref upload; no branch convention bypass |
| Arbitrary URL/method, generic signer input, APPROVE/merge/settings request | DENY; no generic client dispatch |
| Worker asks for token/key/signer handle or includes executable instructions | DENY; no credentials/handles or command execution |
| Model PASS/JSON digest or Issue text substituted for authenticated human approval | DENY; no effect, even with syntactically valid descriptor |
| Stale HEAD/base, changed ref versus expected SHA, expired approval/fence | STOP; atomic mismatch produces no ref update; changed facts invalidate subsequent writes |
| Failed/pending/missing CI, wrong check App/checkout/merge parents, unresolved thread | DENY COMMENT; no stale PASS promotion |
| Existing exact/conflicting PR or incomplete enumeration | Record observed exact match only after reconciliation; no duplicate create; conflict BLOCKED |
| Replay of confirmed nonce/intent, rotation to new App/project journal view | DENY additional send; stable guard/history retained |
| UNKNOWN after PR/ref/COMMENT timeout or crash; missing/rolled-back ledger/anchor | STOP across restart; no retry/reset; operator read-only reconciliation |
| Ref confirmed, PR response lost | Retain confirmed ref plus UNKNOWN PR; no delete, duplicate POST or claimed Draft success |
| Oversized/truncated/duplicate fields/pages, deadline exceeded | STOP bounded operation, no cap widening or partial result authority |

Existing component suites provide only their own offline evidence: publisher plan,
project isolation, review COMMENT, GitHub evidence, App wire/adapter, custody and
signer tests. Local Ruff/pytest/diff outcomes belong in the delivery record;
they do not execute these proposed examples or demonstrate publisher correctness.
Host/UID/proc/FD/network/MAC/reboot/rollback tests: **HOST_NOT_RUN**. Real App
identity, selected membership, effective protections, atomic-ref API behavior,
Draft/COMMENT attribution, duplicate/replay/crash pilot: **LIVE_NOT_RUN / BLOCKED**.
No green-CI or live security claim follows from local validation.

## Individually gated implementation milestones and GO/NO-GO

Each milestone needs its own human scope, independent exact-version review and
appropriate evidence; order is dependency guidance, never permission to start:

1. Review CP-01 candidate and complete effective principal/credential/IPC/network/
   storage/continuity design, with independently authorized negative host evidence.
2. Resolve #73 per-target effective protected-base/no-bypass/human-only merge
   governance and real App/installation/actor proof; explicitly enroll each project.
   No governance means no Contents-write pilot.
3. Implement authenticated controller/admission, durable one-use/fencing and
   independent continuity with loss/rollback/crash reconciliation. Review pre-PR
   project-aware types without weakening blocked legacy conversions.
4. Implement credential-free canonical object/test validation and operation-scoped
   custody/signer/publisher composition with fixed routes, verified atomic ref
   semantics, budgets, durable stable guards and full synthetic adversarial tests.
5. Review independent other-worker handoff and explicit AP-SM/2/AP-CH/1 policy
   reconciliation; implement contributor exclusion and exact-CI COMMENT boundaries.
6. Separately authorize bootstrap delivery and App registration/selected install/
   least grants/key provisioning only on an approved trusted management path.
   Demonstrate worker credential denial; never transfer administrator credentials.
7. Separately authorize one disposable target publisher pilot with exact payload,
   observed actor/ref/Draft/COMMENT outcomes and controlled failure/recovery evidence.
   Host containment and publisher pilot do not admit native subscription execution.

Missing/unknown gate, stale evidence, widened permission, unresolved UNKNOWN,
self-review or ineffective base protection is **NO-GO**. All-offline PASS still
means **LIVE_NO_GO**. Any later live GO is capability/target/version-specific,
requires fresh explicit human authorization and independent security assurance,
and never grants native execution, automatic scheduling/transitions or merge.
Stock subscription-authenticated Codex remains the intended engine; complete
trusted-Codex/untrusted-tool separation remains independently BLOCKED. Preserve
SUBSCRIPTION_ISOLATION_BLOCKED / exit 13 and public legacy quarantine unchanged.

## PUB-01 worker-local handoff proposal

[Issue #104 / AP-PH/1](publisher-handoff.md) adds byte-only intake and a separate
synthetic existing-Draft update model. It proposes worker-local separately
privileged publishers without deploying or replacing CP-02 control01 custody.
CP-03 update refusal, CP-05 create-only behavior and all live gates remain.
Official CAS/permission evidence and effective App merge denial remain BLOCKED.
