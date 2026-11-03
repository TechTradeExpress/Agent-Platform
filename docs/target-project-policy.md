# Downstream project and installation isolation — Issue #62

Specification **AP-TP/1**, 2026-11-03. Agent Platform manages **explicitly authorized
downstream project repositories**. Its own source repository and supervised
dev01 development workflow are not product tenant defaults. No source-repository
owner, author login or `main` branch is a universal product identity.

This milestone extends [#49 evidence](github-evidence.md) and
[#59 Gate A COMMENT policy](review-comment.md) **offline only**. No downstream
repository was accessed, App created/installed, key/token handled, live COMMENT
posted or service deployed. Synthetic consistency is VERIFIED_OFFLINE; actual App
identity, installation, credential isolation and downstream access are NOT_RUN.
Gate B is still NOT_AUTHORIZED. Native runtime remains NO-GO /
SUBSCRIPTION_ISOLATION_BLOCKED / exit 13; public run/resume/doctor quarantine stays.

## Trusted target authorization

`github_evidence.TargetProject` is an immutable, version-1 **trusted caller input**:

| Pin | Meaning |
| --- | --- |
| authorization_sha256 | Operator's independent project authorization reference; never obtained from repository/Issue/PR/model configuration |
| admission | Exact canonical GitHub repository ID and owner/name, Issue ID/number, scope/revision/admission digest and current base commit |
| owner, owner_type | Expected target repository/installation-account ID, login and Organization/User type |
| base_branch | Explicit approved default **and** base branch; flat ASCII alphanumeric/hyphen/underscore subset, <=64 characters; reserved HEAD aliases rejected |
| head_sha, pull_request, checks | Exact source HEAD, target PR number and nonempty required check name/App ID/slug pins |
| source_root | Explicit absolute normalized primary source root for this target's local evidence, not a discovered path or task worktree |
| author, reviewers | Exact target PR author and independent reviewer ID/login pins; observed author and policy reviewers must match |
| publication_context_sha256 | Trusted binding of App registration, selected installation and expected author; rotation requires a new explicit project context |
| journal_guard_sha256 | Stable independently controlled target-PR guard domain, preserved through installation/token/authorization rotation |

Within this profile, Admission is a consistency-field carrier, not proof that
the existing main-only prepare admitted a non-main project. It cannot be exported
as runtime authority.

`Policy.project` must match every duplicated admission/head/PR/check/reviewer field exactly.
A wrong project cannot become authoritative because GitHub returned it. There is
no tenant-file loader, auto-discovery, model-selected URL, default repository,
configuration migration or automatic registration. The controller authenticating
operator configuration remains a separate Gate B responsibility. Frozen values,
source hashes and digests are not authenticated authorization or tenancy isolation.

All remote repository identities remain canonical ID **and** full-name comparisons.
REST repository metadata and PR head/base repositories also require the pinned
owner ID/login/type. Native Issue links require the same target repository and
exact Issue ID/number/state; body `Closes #N` alone is insufficient. Identical PR
or Issue numbers in two repositories have no shared authority. Fork heads,
foreign Issue links, missing/ambiguous linkage, current author mismatch,
unresolved threads/latest blocking reviews and incomplete pagination still block.

## Registration owner and installation account are separate

| Object | Scope and checks |
| --- | --- |
| AppIdentity | Global App ID/slug/bot ID/login and **registration** owner ID/login/type. Existing `installation_id` is retained as a compatibility echo, not the installation-account identity. |
| InstallationIdentity | Explicit chosen installation numeric ID and its **account** ID/login/type. ID must match the compatibility echo; account must equal TargetProject owner. |
| InstallationFacts | Synthetic authoritative-observation contract: exact App pins, explicit installation identity, configured project digest, one selected repository ID, minimal effective permissions, installation-token kind and current expiry. |

An App registered by organization A can be installed in approved projects owned
by organizations B and C. Registration owner is **not required to equal** target
owner. Installation account must equal target owner, including numeric ID, login
and type. Synthetic tests also distinguish a User repository owner from an
Organization App owner. App, bot, installation, account, repository selection and
permission claims are independently pinned; a matching name cannot replace ID.
`project_sha256` in InstallationFacts is a **trusted adapter/configuration binding**,
not an invented GitHub REST response field or authentication proof.

Both `Policy.project` and `Envelope.installation` must be present in this profile.
Mixed/partial migration blocks. Policy, installation and App pins participate in
the envelope/body-context digest and human authorization; changing one cannot
reuse the old decision or cached project receipt. `Receipt.for_project` rejects installation, author or reviewer context changes; renewed evidence is required. Actual PR author is observed from that target PR and
compared with expected bot on numeric ID and case-insensitive login. No author
account or source-repository organization is hardcoded. A distinct posting actor
still cannot establish independent technical reasoning or human consent.

Effective installation facts still require exactly Metadata read and Pull requests
write, selected one repository, short-lived installation kind (<=1 hour), no PAT/
user token, wider repository set, extra grant, expiry or implicit refresh. PR write
is broader than COMMENT; only the code-level operation is COMMENT-only. No live
credential implementation is added; facts and provenance labels are synthetic
trusted assertions, not verified tokens or an OS boundary.

## Branch-aware read-only evidence

For explicit projects, the reader's allowed branch endpoint is exactly
`/branches/{approved branch}`. REST default branch, branch commit, PR base ref/SHA,
HEAD and base-bound synthetic merge commit must match policy. Parent order is
exactly `[base, head]`. Required check App identities and successful complete checks
at **both** HEAD and merge result are unchanged. GraphQL documents remain the two
existing literal read queries; repository/PR variables and every connection's
IDs/head/base stay pinned. No new host, generic endpoint or GraphQL mutation.

The collector's project-only `_project_source` performs bounded **read-only** local
identity checks for the approved branch. Wrong source root blocks before Git
inspection. Require canonical primary root/common `.git`, matching unambiguous
origin, clean tree/index, no unsupported config/includes/filters/extensions,
submodules, index flags, alternates/grafts/shallow/commondir or unsafe metadata
aliases; local HEAD, `refs/heads/<branch>` and `refs/remotes/origin/<branch>` must
all equal the pinned base. All refs, source identity and the non-creating fixed
host lock are reread. This separate evidence inspector retains preparation's
rejection checks; it does **not modify** `prepare.source_snapshot` or grant
checkout/worktree/runtime authority. No fetch or ref update occurs in collection.

Synthetic `main` and `trunk` collectors both return fresh immutable reviewed
Receipts only after actual fake API-observed eligible PASS COMMENT and complete
checks. Public `collect()` still has no prepublication PASS bypass. The COMMENT
publisher still uses two full remote fact passes before/after a simulated POST,
with current typed human approval, identity and expiry checks. It does not inspect
local source files; a source-root pin in its digest is not local liveness proof.

## Per-project journal, authorization and evidence isolation

`Envelope.journal_scope` hashes the full project policy plus chosen App and
installation. The journal must report that exact `scope_sha256` and the stable
project `guard_sha256`, completeness and human-pinned epoch. Another project's
journal, even with the same epoch string and PR number, cannot be selected.
Readers match the entire policy; writer metadata matches project and installation;
approval binds the entire envelope. `Receipt.for_project(project, now=...)`
requires exact project equality and the existing <=300-second freshness bound.
No path, broad client or credential is placed in a worker or serialized diagnostic.

**Namespace isolation cannot reset replay protection.** The operation key remains
repository numeric ID + PR number, independent of App, installation, token, HEAD,
project approval and namespace. Providers must atomically retain a **shared target-PR
guard record** across all views/epochs/installations of that target. The stable
guard-domain pin identifies that authoritative ledger. A namespace change may
select a new scoped view, never a fresh empty guard history. UNKNOWN intent binds
the original envelope/authorization digests and prevents another POST after
rotation. Missing/corrupt/migrated/lost ledger or unverifiable completeness blocks;
no resetting, eviction, automatic cleanup, reauthorization or retry is implemented.

The injected synthetic journal contract is still `identity`, epoch-aware `read`
and CAS. Tests use distinct scoped views of the same retained guard map to prove
rotation cannot escape UNKNOWN. Different repositories have different operation
keys and may have separate namespace/installation policies without mixing records.
Cross-project swapped or forged Intent records fail digest checks. Hashes and a
provider's completeness flag cannot prove production durability: a Gate B provider
must enforce this shared-guard invariant, fsync/atomicity, lost-state detection,
principal isolation and bounded access independently. No durable/live multi-tenant
store is implemented, and relabelling a new empty store is not a migration plan.

Unknown write reconciliation, exact remote review/body/actor verification,
COMMENT-only requests, no blind retry, all existing 401/403/429/5xx/timeout handling,
no automatic Ready/Issue closure and human-only merge remain unchanged. A new
installation under UNKNOWN cannot establish another send by creating a new grant.
Token refresh/rotation must not change destination, install/account or permissions;
read-only reconciliation never renews publication permission.

## Compatibility and deliberately blocked paths

| Profile / operation | Result |
| --- | --- |
| Complete existing #49/#59 typed legacy policy, `project=None`, `installation=None` | Prior trusted-caller fixed-main profile remains supported; Gate A retains its same-owner Organization constraint. This is backwards API compatibility, not a newly inferred downstream authorization. |
| Explicit TargetProject + matching InstallationIdentity | New branch/owner/installation-aware synthetic COMMENT and reviewed read-only collector path. No source-repo owner/author constants. |
| Partial new fields, unknown project/version, missing owner/account/namespace or malformed ref | BLOCKED; no fallback to legacy/default branch or inferred authority. |
| Explicit-project merged collection | BLOCKED in Policy construction; no historical merge/CI claim manufactured. Legacy merged evidence remains unchanged. |
| Explicit-project `Receipt.queue_receipt` / `publisher_admission` | BLOCKED for **all branches**, including main. `pull_request=None`; no silent loss of project/branch/installation authority into old planner types. |
| Runtime prepare/run/resume, queue nomination/execution, checkpoint migration for these projects | Unsupported by this milestone. Existing main-based prepare/Admission/queue schemas and all native exit-13 barriers remain unchanged. |
| Forks, non-default approved base, slash/dot/revision-style refs, linked task worktree as primary source | Safely unsupported; no permissive fallback. |
| Live App/downstream/ChatGPT integration | NOT_RUN / Gate B NOT_AUTHORIZED; #60 not begun. |

Policy/envelope/context hashing now includes optional project, installation and
registration-owner-type fields. Saved old digests/receipts/approvals are not
silently refreshed. Direct construction of the complete legacy API shape remains
compatible, but a previous saved operation whose digest does not match must be
preserved for human reconciliation. No checked-in tenant configuration or saved
payload becomes trusted just because it fits the dataclass schema.

**Proposed follow-up only, not a new Issue or implementation:** design a versioned
project/branch-aware admission, queue/merged-receipt and runtime checkpoint domain;
carry target authorization, branch, installation/guard identity and exact source
roots through every handoff before any execution integration. Fresh independent
review and explicit human scope are required. Do not bypass blocked Receipt
handoffs by stripping project fields or fabricating legacy Admission/queue objects.

## Operator migration / verification checklist (offline now)

1. Authenticate operator approval independently of target/model content. Pin each
   authorized downstream project's canonical repo/owner IDs and types, branch,
   source root, admission/scope, PR/head/base/merge and CI App identities. Do not
   default to Agent Platform, TechTradeExpress, su-17 or main as product policy.
2. Separately pin global App registration owner and chosen installation account.
   Verify installation account equals target owner and the effective scoped facts
   allow exactly that repository with minimal permissions. Actual live App IDs,
   token custody and attribution remain Gate B work; use fabricated values only
   in this milestone's tests. No downstream API or repository access was performed.
3. Approve exact canonical envelope and independent-analysis digest through the
   existing ManualAuthorization boundary. Reader policy, writer facts, journal
   scope/guard and epoch must all match this project. Reject foreign receipts,
   identical-number collisions, stale facts and mismatched check Apps.
4. Reconcile **every** retained/UNKNOWN operation before any namespace, token,
   installation or project-authorization migration. Preserve target-PR guard
   history across rotation. Missing history is not fresh state; no manual Grant
   alone can make an uncertain write safe to repeat. This API has no reset path.
5. Use only the supported read-only branch path; do not hand target receipts to
   main-only runtime/queue APIs. Record those unsupported paths as BLOCKED and
   seek separate authorization for the proposed domain redesign.
6. Treat synthetic PASS as VERIFIED_OFFLINE. Source-repository development review
   under the implementing account does **not** satisfy #49's distinct GitHub
   principal requirement merely because its COMMENT is called an independent
   technical review. No formal APPROVE or separate actor is invented here.
7. Gate B still requires explicit maintainer authorization after independent review
   and human merge, credential/controller/durability audit and a separately approved
   disposable downstream pilot. #60 needs its own later handoff; no connector,
   scheduling, live service, permissions change, token minting or native launch
   follows from this policy or a merged source PR.

`tests/test_project_isolation.py` uses two freshly fabricated local Git repositories
and scripted metadata/App/journal views. It covers main/trunk and cross-owner
positive cases; swapped approvals/readers/writers/journals/receipts, source roots,
repo/Issue/PR/head/base/merge/check/author/owner/account mismatches; UNKNOWN rotation,
missing checks/thread conditions, unsafe refs/config and blocked runtime handoffs.
Earlier #49/#59 adversarial tests are retained. All results are offline only;
real per-installation credentials, production tenant isolation and crash durability
remain NOT_RUN / REQUIRES_INDEPENDENT_REVIEW.
