# ADR 008: one active harness per worker

**Contract:** AP-HAR/1. **Status:** PROPOSED / DESIGN_ONLY / SOURCE_ONLY /
OFFLINE_ONLY / HOST_NOT_RUN. **Issue:** [HAR-01 #131](https://github.com/TechTradeExpress/Agent-Platform/issues/131),
within [HAR-00 #130](https://github.com/TechTradeExpress/Agent-Platform/issues/130).
Reference source: main `5c4bae6549afcbd39f32f2da4afe3f26df9188d1`.

This is a proposed architecture amendment, not a runnable selection mechanism.
It proposes extending the **engine cardinality/selection** decisions of
[ADR 003](subscription-transport.md), [ADR 004](architecture-trust-boundaries.md)
and [ADR 005](native-runtime-feasibility.md) from Codex-only to one of two stock,
first-party harnesses. It does not declare that amendment approved or either
engine safe. Current Codex-only implementations and their quarantines remain
unchanged until separately reviewed follow-ups. No custom inference engine,
subscription relay, SDK substitution or API-billed fallback is proposed.

`LIVE_NO_GO`, `SUBSCRIPTION_ISOLATION_BLOCKED`, Gate #73 BLOCKED, public/native
exit 13, `INSTALL_INERT`, `HOST_NOT_RUN` and human-only merge remain unchanged.
No host, provider CLI, login, account, credential, Publisher or service is accessed
by this design. Offline contract tests establish document consistency only.

## Context and audit of existing boundaries

| Existing contract / source | Design consequence; no implementation change here |
| --- | --- |
| [AP-CA/1](codex-assignment.md), `src/agent_platform/codex_assignment.py` | `CodexAssignment` accepts only runtime `codex`, schema 1; admission binds target, role and App pins. Its inventory epoch is a digest, not the new monotonic selection counter. Preserve freshness (maximum 300 seconds), complete inventory and retained UNKNOWN intents. No permissive JSON loader or inferred harness. |
| `src/agent_platform/native_codex.py` | Preparation/execution are blocked before I/O. Existing fixed argv, including `--ignore-rules`, does **not** prove root AGENTS.md loading. A future instruction-loading contract requires a new verified invocation; do not silently remove a flag. |
| `src/agent_platform/codex.py` | The 0.164.0 event parser owns canonical UUID and turn/exit consistency rules. Its historical loopback broker is quarantined, never a fallback. A parser pin is not equivalent to the separately managed 0.166.0 binary pin. |
| `src/agent_platform/subscription.py` | Auth is not inspected; limits remain unavailable, no guessed reset or automatic resume. Native account ownership is separate from task authority. |
| [PKG-03R](codex-upstream-provisioner.md), `provisioning/codex_upstream.py` | Official release lock, archive/binary identity and AP-CODEX-INSTALL/1 remain Codex-specific. No generic installer, new artifact pin or Claude installation is delivered. |
| [PKG-07 / worker doctor](worker-doctor.md), `packaging/worker-provisioning/worker_doctor.py` | A verified absolute managed executable is installation evidence, not execution binding. Preserve personal Codex and distinguish caller PATH, coding-user scope and trusted absolute-exec proof. No CONFIGURED promotion from inventory. |
| [ADR 006](worker-pool-identity-architecture.md) | Worker enrollment/boot, agent, attempt, role, account and App are distinct identities. Retain symmetric worker roles, one job per worker, fencing and contributor lineage. A different harness is not an independent human or permission to self-review. |
| [ADR 007](debian-role-package-architecture.md), `packaging/build_deb.py` | Exactly two packages: Control and Worker. Closed P0/P1 manifests do not gain harness payloads implicitly. Future adapters/installers require explicit classification and review. No Codex or Claude .deb is added. |
| [Contributor workflow](development.md), [AP-SM/2](solo-maintainer-policy.md), root [AGENTS.md](../AGENTS.md) | Direct human supervised-development authority is separate from product-runtime authority, regardless of contributor harness. This task's delivery is local-only. |
| [PUB-02](draft-publisher.md), `src/agent_platform/worker_publisher.py` | Separate operator-only one-shot job, signer and per-worker App pins. Harness output is a candidate artifact, never a publication grant, credential client or signer handle. Preserve UNKNOWN-before-effect and human-only merge. |

## Decision and identity vocabulary

`HarnessId` is the case-sensitive, closed AP-HID/1 enum **`codex` |
`claude_code`**. No aliases, arbitrary names, `auto`, provider/model name, PATH
lookup, feature detection, CLI override or unrecognized value selects an engine.
Adding an ID requires a new major contract and independent review. A model is a
separately pinned setting of the selected harness; an account reference identifies
its vendor-native protected owner, not a worker or GitHub App.

A worker has **exactly one committed selected harness**, represented by one
scalar, even while it is drained or blocked. Before initial enrollment there is
no valid selection and admission is BLOCKED. Zero ready engines is safe; two
active engines is invalid. Installed alternate tooling is read-only inventory,
never a second selected engine. Workers are symmetric: no worker01/Codex or
worker02/Claude mapping, inferred or hard-coded. One active job per worker remains
the initial limit; no automatic failover on quota, crash or missing tooling.

The [closed JSON Schema](harness-contract.schema.json) defines proposed records
AP-HSEL/1 (selection), AP-HASSIGN/1 (binding), AP-HSESSION/1 (lineage) and
AP-HEVENT/1 (redacted event). [Examples](harness-contract.examples.json) are
fabricated, non-authorizing fixtures. [AP-HCAP/1](harness-capabilities.json) is
the closed capability matrix. These documents are **not an ingestion API**;
there is no production validator, loader, IPC, scheduler or execution path.

Every object rejects additional properties; every field is required. Unknown
schema/capability revision, omitted/null fields, duplicate JSON keys, floats or
booleans as integers, excessive values and unrecognized enum values fail closed.
Records are at most 16 KiB UTF-8 and depth 8; a future stream allows at most
10,000 events, 16 KiB per line and 1 MiB aggregate, with lower component limits
winning. JSON has no NaN/Infinity. The schema checks shape; the semantic rules
below, provenance and independent anti-replay evidence are also mandatory.

## Capability matrix and evidence

AP-HCAP/1 has exactly the two ID rows and a closed set of capability columns.
Values mean `OFFLINE_CONTRACT` (existing narrower synthetic parser evidence),
`REQUIRED_UNVERIFIED` (future requirement) or `BLOCKED` (not admitted). None is a
GO state. Capability evidence is scoped to an exact executable/source pin,
protocol/parser revision, platform, immutable config and instruction digest.
Required UNKNOWN/unverified support blocks admission; intersection of positive
facts is necessary but never sufficient. No runtime negotiation, probing or
optimistic defaults; a new column/revision requires explicit compatibility review.

Codex parser evidence concerns the existing 0.164.0 offline contract only, not
compatibility with the PKG-03R 0.166.0 executable or all stock tools. Claude's
exact release, binary hash, event protocol, session ID grammar, cancellation,
resume and complete tool isolation remain **UNVERIFIED / NOT_RUN**. HAR-03 must
pin and audit an official protocol before implementing a separate parser.

Issue #131 describes AGENTS.md support starting with Claude Code 2.1.277.
This design adopts **2.1.277 or newer as a minimum compatibility requirement**,
not a verified support claim or approved binary pin. HAR-04/HAR-06 must select a
newer exact reviewed release where appropriate and retain official documentation
and actual loading evidence. No vendor documentation fetch, CLI diagnostic or
provider request was performed here. Future verification references supplied by
the Issue are [Claude memory](https://code.claude.com/docs/en/memory#agentsmd)
and [legal/compliance](https://code.claude.com/docs/en/legal-and-compliance);
their current contents and applicability remain unverified in this offline task.

## Trusted selection and immutable assignment

AP-HSEL/1 is a proposed nonsecret record issued by the trusted controller only
after independent, authenticated operator approval for that worker. Root-owned
installed policy validates enrollment/boot, approval scope and all pins; neither
an Issue, checkout, model output, environment variable nor a self-signed worker
record is an issuer. `issuer_ref` is a public reference, **not authentication**.
Human approval and issuer verification must be external to these JSON bytes.

`binding` fixes logical worker, enrollment/boot reference, one `harness_id`,
monotonic `selection_epoch` (1..2^63-1), AP-HCAP revision, and SHA-256 digests of
configuration, executable provenance, parser, root instructions and isolation
profile. A configuration digest covers exact vendor-native arguments, model
settings, fixed absolute executable, library/runtime closure and denied alternate
config/tool routes. The executable digest refers to a verified installation
manifest, not an executable path alone. No absolute home paths or secrets enter
public records. Account and model policy references are separately bound in the
assignment; the configuration must permit that exact combination.

The selection store needs a single-writer, durable compare-and-swap generation
and independently anchored continuity, bound to the worker enrollment. Duplicate
records, missing history, restored/decreased/reused epochs, unknown issuer or
conflicting selection block. Hashes/local fsync alone cannot prevent rollback.
A new boot invalidates old assignments until explicit reconciliation. Expiry or
revocation fences admission; neither proves old processes dead. Epoch exhaustion
blocks rather than wrapping. Durable storage/anchor implementation is deferred.

AP-HASSIGN/1 **references** the already committed selection digest and copies
its complete binding. The scheduler chooses an eligible worker under existing
authority, not a harness for each task. Any task-requested engine switch is
rejected. `task_authorization_sha256` binds the complete existing target/project,
repo/Issue/scope/base/head, role, App, deadline and admission constraints; it is
not permission to omit them. `assignment_ref` identifies a fresh attempt,
`model_policy_sha256` and `account_policy_ref` bind approved native settings and
account policy without carrying account secrets. A public reference proves no
current login, vendor entitlement or quota.

Compare every pin at admission, acknowledgement, before effects, resume and
result acceptance. Fresh independently verified selection/config/installation,
auth-isolation and target authority must still match. Drift after observation is
not solved by hashing: a future launcher needs no-follow descriptor identity,
verified ownership/capabilities, revalidation and a supported exec binding without
path re-open races; otherwise BLOCKED. Never execute PATH/aliases or a personal
installation. Repeated/stale assignment delivery cannot create another intent.
Retain one-use/fencing history and all UNKNOWN outcomes across boots and restores.

## Operator-approved change protocol

1. Independently authorize a maintenance intent against the old selection digest,
   epoch, worker and proposed new exact pins. Enter QUIESCING with CAS; reject new
   assignments and resume. Selection still names the old engine.
2. Drain/reconcile every in-flight, retained and UNKNOWN intent, background child,
   tool effect and session. Verify process-tree death and reconcile external
   effects under separate incident authority. Timeout, cancellation response,
   terminal event or expired lease alone does not prove quiescence. Any UNKNOWN
   leaves RECONCILING/BLOCKED and prohibits a new active engine.
3. Re-attest the proposed official executable, parser/config/instruction pins,
   vendor/account eligibility, complete auth/tool isolation and resource controls.
   Obtain fresh independent operator approval over the exact reconciled evidence
   and replacement record. Installation or inventory alone is insufficient.
4. Atomically commit the new selection with **epoch + 1**, previous-record digest
   and independently advanced continuity witness; invalidate old assignments.
   A crash before/after commit requires read-only reconciliation, no auto retry,
   presumed rollback or dual selection. Failure stays drained/BLOCKED.
5. New tasks get new assignments and new native sessions. Old sessions/edits stay
   retained in their original harness namespace. Switching back is another
   approved change with another increment; never restore an earlier epoch.

These are future transition requirements, not commands. Selection state is
`SELECTED`, `QUIESCING`, `RECONCILING` or `BLOCKED`; SELECTED means configured
choice only, never ready or authorized to launch. Initial selection has epoch 1
and an all-zero previous digest; later epochs require the actual prior record
and continuity witness. There is no automatic Codex-to-Claude session conversion,
account rotation, re-enrollment workaround or failover.

## Sessions, resume, errors and events

The controller owns canonical attempt/lineage and event sequencing. Each adapter
owns only its pinned vendor-native parser/ID grammar and maps bounded observations
to AP-HEVENT/1. Do not feed Claude JSON through `codex.Events`, normalize unknown
native events into success or guess Claude UUID semantics. Public `session_ref`
is an opaque controller reference; `native_session_sha256` correlates a protected,
validated native identifier without exporting it or its private storage path.
It does not authorize resume. Native IDs/checkpoints remain with the protected
native owner; never copy auth/session stores into a tool worker or report.

AP-HSESSION/1 binds assignment digest, full selection binding and exact lineage.
A parentless initial attempt uses a zero parent digest. Resume requires a new,
freshly admitted immutable assignment, the exact prior checkpoint digest and
unchanged worker/enrollment, harness, epoch, executable/parser/config/instructions,
model/account policy and task scope, plus a reconciled PAUSED state. Otherwise
NEEDS_HUMAN/new task, not latest-session search, fork, cross-host or cross-harness
resume. No import/migration of native Codex sessions into Claude Code is proposed.

| Canonical state / reason | Rule |
| --- | --- |
| STARTING / NONE | Durable launch intent, not proof of a process; unavailable today |
| RUNNING / NONE | Correlated native lifecycle observation, not proof of continued liveness |
| COMPLETED / NONE | Exact parser terminal event **and** matching successful exit, bounded complete stream; not publication authority or proof of descendant death |
| PAUSED / NATIVE_TURN_FAILED | Exact known failed-turn/exit combination supported by that parser; no generic retry/resume |
| NEEDS_HUMAN / PROTOCOL_INVALID, OUTCOME_UNKNOWN, CANCEL_UNCONFIRMED, RESOURCE_LIMIT or AUTH_UNVERIFIED | Malformed/unknown/truncated/reordered/oversized output, inconsistent exit, uncertain cancel/death, budget or account uncertainty; retain intent, never automatic replay |
| BLOCKED / BINDING_MISMATCH, SELECTION_UNVERIFIED, CAPABILITY_UNVERIFIED or ISOLATION_UNVERIFIED | Admission denied before effects; a late discovery with possible effects instead requires NEEDS_HUMAN / OUTCOME_UNKNOWN |

The schema closes state/reason combinations. Event `seq` starts at 1, increments
exactly once and never wraps; one terminal state ends a stream. Codex's detailed
thread/turn transitions and exact native exit rules remain the stricter parser
contract; HAR-03 must supply equivalent explicit Claude rules before admission.
No fabricated RUNNING event from text. Duplicated/session-swapped events, success
after terminal, missing native session binding or incomplete state history block
or retain UNKNOWN as appropriate. Canonical lifecycle is not vendor protocol.

Events carry only full binding, assignment/session references, sequence, state,
fixed reason and `usage=UNAVAILABLE`. No raw stdout/stderr, prompts, commands,
transcripts, home paths, native/account IDs, tokens or arbitrary exception strings.
A future trusted usage format requires a new revision, never guessed counts,
reset times or API-spend fallback. Stable observations produce canonical sorted,
compact JSON with one trailing newline, no time/host-dependent fields. Digests
are SHA-256 of those exact bytes; strict decoding precedes hashing. Public logs
must not expose protected native records just to make a digest reproducible.

## One canonical AGENTS.md

The repository-root AGENTS.md is the **single canonical policy/contributor
instruction document** for both harnesses. No duplicated CLAUDE.md,
CLAUDE.local.md, import tree or symlink is added. A future vendor-mandated shim
would need separate review, only reference AGENTS.md, contain zero independent
policy and have a regression test against divergence; it is not approved here.

Future trusted bootstrap must pin root AGENTS.md at the exact approved commit,
its bytes/digest, and the complete bounded instruction-source manifest. It must
verify the actual supported load on the exact pinned official CLI (e.g. the
vendor's documented `/context all` diagnostic when separately authorized),
including project ancestors, nested overrides, local files, home/global configs,
plugins and hooks. No credentials/private homes are inspected in this task.
An inaccessible or unknown competing source means NOT_RUN/BLOCKED, not absence;
do not delete personal files or assume an isolated working directory proves load.
Do not mechanically copy unsupported Codex ignore flags to Claude.

Only an approved root instruction source is permitted by the initial design;
nested AGENTS.md or competing Claude instruction sources in the proposed effective
scope block pending explicit review. Runtime tool execution never gets to alter
trusted bootstrap/policy. A changed instruction digest invalidates admission;
loading a modified file mid-session requires reconciliation and a fresh approved
configuration. AGENTS.md is behavioral guidance, not an OS isolation boundary,
credential grant or substitute for direct human authorization and installed policy.
Prompt injection from Issues, checkout or CLI output cannot amend that authority.

## Migration and packaging

1. HAR-02 introduces an explicitly versioned, worker-pinned admission/envelope only
   after review. Existing AP-CA/1 objects remain **Codex-only** and unchanged;
   missing harness fields in new schemas reject, rather than default to Codex.
   A legacy record may be compared through a trusted explicit Codex compatibility
   boundary only when its complete original authorization/digest and all new pins
   are independently verified. No reserialization that drops target/App/deadline
   constraints and no dispatch/resume bridge delivered by this ADR.
2. Retained legacy intents/checkpoints keep their namespace and parser. Inventory
   them read-only; uncertain or incompatible records stay quarantined. Do not
   reset journals, erase edits or rewrite epochs to make migration succeed.
3. HAR-03 adds offline Claude fixtures and a separate strict parser; Codex parser
   negatives stay intact. No generic permissive event parser or executable launch.
4. HAR-04 designs separately pinned official Claude acquisition and per-harness
   inventory. PKG-03R locks/ownership/capabilities/SHA-256 checks remain unchanged;
   personal installations remain intact. Inventory success never fills missing
   execution binding or changes doctor BLOCKED/NOT_RUN to CONFIGURED.
5. Keep exactly Control and Worker packages, fixed private imports and closed
   SOURCE_ONLY manifests. This ADR/schema/test-only material changes no builder,
   package payload, APT relation, service, workflow, App permission or Publisher.
   Any later promotion requires explicit manifest/lifecycle review.

## Threat model and required negative evidence

Assume hostile Issue/checkout/model output and alternate installed tools; trust
only independently admitted controller/operator and separately protected bootstrap.
Root/hypervisor compromise, provider binary compromise, shared-host rollback,
unproven complete tool mediation and native account eligibility remain unresolved.
Two CLIs, VM isolation or a signed/hashed record alone do not close those threats.

| Attack / uncertainty | Required denial or retained uncertainty; follow-up evidence |
| --- | --- |
| Unknown/case-changed ID, dual selection, model name as ID, task-requested engine, fallback after quota | Closed schemas, single scalar ID, no default/failover; HAR-02 negative tests |
| Forged issuer/approval, missing inventory, replay, epoch rollback, simultaneous switches, restored anchors | External authenticated authority, CAS/fencing/independent continuity; missing witness blocks. HAR-02 offline fault tests then separately approved durable tests |
| Drift between assignment/ack/exec/result, PATH shadow, swapped inode/library/config/AGENTS | Full immutable binding plus supported descriptor/exec proof and exact source manifest; otherwise BLOCKED. HAR-02/04/07 |
| Hooks, plugins, nested agents, hidden config, malicious repository instructions, alternate executable/network ingress | Complete route inventory and immutable denial/separate credential-free tool domain, not prompt instructions. HAR-05/07; all real probes NOT_RUN |
| Cross-harness/host/epoch/account resume, stale native session or poisoned stream | Namespaced lineage and exact checkpoint, independent parsers, fresh admission; no copy/latest/replay. HAR-02/03 |
| Unknown/duplicate/reordered JSON/event, bad exit, unbounded output, fake quota or successful terminal with surviving child | Bounded strict parser, NEEDS_HUMAN and retained UNKNOWN, separate process-death proof. HAR-03/07 |
| Credentials/auth storage/FD/proc/tool leaks, native session export, API/OAuth mediation | No auth-bearing data in canonical events; protected native owner separate from tools, fixed egress, no API fallback. HAR-05/07 |
| Fake PASS/inventory/doctor, different harness used for self-review, App confused with account | Installation/configuration/evidence/authority remain separate; contributor lineage survives engine change. HAR-06 and existing review/Publisher gates |

The accompanying tests exercise only shape, consistency and representative
negative **synthetic document fixtures**, not authenticated selection, persistence,
races, provider compatibility, kernel isolation, CLI loading or live sessions.
Those properties stay HOST_NOT_RUN/BLOCKED until independently proven.

## Sequenced follow-ups and STOP criteria

| Order / Issue | Required outcome before dependent work |
| --- | --- |
| HAR-01 [#131](https://github.com/TechTradeExpress/Agent-Platform/issues/131) | This proposed ADR/closed contract; independent review and human decision, no runtime |
| HAR-02 [#132](https://github.com/TechTradeExpress/Agent-Platform/issues/132) | Versioned worker-pinned admission, retained Codex compatibility, durable switch/epoch design; no automatic launch |
| HAR-05 [#135](https://github.com/TechTradeExpress/Agent-Platform/issues/135) | May proceed after HAR-01 alongside HAR-02: vendor/native-account eligibility and full tool/auth isolation decision; absence of supported boundary is STOP |
| HAR-06 [#136](https://github.com/TechTradeExpress/Agent-Platform/issues/136) | May proceed after HAR-01: harness-neutral supervised workflow and separately approved exact-build instruction-loading/personal-use checklist; independent review remains separate |
| HAR-03 [#133](https://github.com/TechTradeExpress/Agent-Platform/issues/133) | After selection/binding contracts and applicable HAR-05 decisions: pinned Claude protocol and deterministic offline parser fixtures |
| HAR-04 [#134](https://github.com/TechTradeExpress/Agent-Platform/issues/134) | After relevant policy/compatibility decisions: reviewed exact official artifact/inventory design and tests; no activation |
| HAR-07 [#137](https://github.com/TechTradeExpress/Agent-Platform/issues/137) | Only after prerequisite decisions/proofs: trusted invocation/session E2E **design**, separately authorized disposable experiments and then independent review; no implied live GO |

The operator's stated context is individual first-party subscriptions on a private
homelab, not a hosted multi-tenant inference service. This is context, not a legal
or vendor entitlement finding. Keep vendor billing/accounts separate; no consumer
login relay, app OAuth mediation, borrowed subscription inference SDK or API
fallback. Supervised personal CLI use and product orchestration have distinct
eligibility and isolation questions, owned by HAR-05. No login or credential
inspection is authorized by this ADR.

STOP for unsupported complete auth/tool separation, unverified Claude version or
AGENTS load, unclear subscription eligibility, missing continuity/process-death
proof, unknown protocol/capability, conflicting policy or any privilege/host change
needed beyond the assigned scope. Return specific BLOCKED/NOT_RUN evidence to
the human; never select the other harness to get around a gate.
