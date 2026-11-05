# ChatGPT review handoff — Issue #60 Stage 1

Specification **AP-CH/1**, 2026-11-05. **VERIFIED_OFFLINE only. Live integration:
INTEGRATION_BLOCKED / NO-GO.** Gate B, Stage 2, real bot identity, live approval
UX, publisher01 deployment and a disposable downstream pilot are **NOT_RUN**.
No connector, account, key, token, JWT, service or live review transport is added.
The source repository's interactive development/Draft PR delivery is distinct
from the downstream product workflow. Native and public legacy execution retain
exit 13. No production OpenAI API or billed inference is used.

## Solo-maintainer product roles

[Solo Maintainer Policy v1](solo-maintainer-policy.md) explicitly supports one
human maintaining a downstream project and approving its review. The operator,
project owner/maintainer and PR author MAY be the same person; a second human is
not an architectural prerequisite. The required separation is among the actual
PR author GitHub principal, a separate ChatGPT technical-analysis process,
explicit authenticated human authorization of the immutable payload, and the
App posting principal. Multiple AI tools are not two independent humans.

The bot must remain distinct from the actual author by numeric ID and
case-insensitive login. It cannot authorize its own review; ChatGPT cannot
authorize its own output. Human approval remains a separate authenticated action,
not model/Issue text or self-reported approval. Body, canonical repository/Issue,
SHAs, identities, evidence, digest and expiry remain immutable and independently
validated through the existing #49/#59/#62/AP-CH/1 rules. Distinct bot identity
neither proves a separate human nor guarantees independent reasoning. No source
same-actor exception enters the collector; no automatic Ready, closure or merge.

Source development instead uses the separate AP-SM/1 manual acceptance record.
A connected `su-17` COMMENT on a `su-17` PR is labelled AI-assisted technical
review, not a #49-qualified independent GitHub review. The earlier #68 review at
`c176fb7d149d3532c0d7de452d6821db0ffdaaa8` is stale after repair; fresh final-HEAD
technical review, both CI revisions and separate explicit human acceptance/merge
are required. No product Receipt is manufactured from that source review.

AI-assisted analysis and green CI do not establish production security assurance.
Credential, isolation, privileged-execution, GitHub-permission and trusted
controller changes retain additional security-verification gates under AP-SM/1.
Unavailable assurance leaves the live capability BLOCKED / NOT_RUN, without
requiring a second human for ordinary offline development. Gate B, real approval
boundary, deployment and live pilot remain separately gated and NOT_RUN.

## Capability decision and sources

Official documentation was read on 2026-11-05. Documentation establishes general
product interfaces, not this account's permissions or installed integrations.

| Capability | Evidence and decision |
| --- | --- |
| Custom ChatGPT MCP read/write tools | [OpenAI custom MCP guide](https://developers.openai.com/api/docs/guides/custom-mcp-server) documents SSE/streaming HTTP, authentication choices and workspace restrictions. SUPPORTED generally; availability for this account and a publisher connection UNKNOWN / NOT_RUN. |
| Tool confirmation | The same guide documents default confirmation for writes and remembered choices within a conversation. SUPPORTED generally; confirmation is not independently authenticated approval of this exact review. |
| Server authentication | [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth) documents server-side authentication. This does not establish a trusted reviewer, GitHub App installation, or our operator approval boundary. |
| Workspace actions | [GPTs and sharing](https://learn.chatgpt.com/docs/enterprise/gpts-and-sharing) describes workspace controls and distinguishes domain permission from user authorization. Account access UNKNOWN. |
| Existing connected GitHub tool selecting a different posting App actor | UNSUPPORTED by this implementation; no verified documented per-call identity selection. App registration cannot be assumed to change the existing connector's actor. No OAuth impersonation workaround. |
| Work-compatible invocation of this publisher | UNKNOWN; no verified callable publisher tool, authenticated exact-payload approval receipt or installed integration. INTEGRATION_BLOCKED. |
| Manual transfer of analysis to a future trusted operator controller | Design supported offline below; authenticated controller and actual end-to-end human UX NOT_IMPLEMENTED / NOT_RUN. |
| Automatic Ready, Issue closure, merge or scheduled monitoring | UNSUPPORTED; outside Stage 1. |

The Issue discussion selects **Variant A: manual trusted Publisher**; MCP is
not selected for this phase and remains only a possible later front end. The
chosen Stage 1 interaction is an **untrusted typed proposal plus a separate
trusted operator decision**, simulated entirely in-process. No claim is made
that ChatGPT currently invokes it. A documented generic MCP write capability
cannot establish that the approved actor/approval bridge exists here. A future
integration needs independent account/workspace capability evidence, code and
credential-domain review, #59 Gate B approval and separate Stage 2 consent. No
custom server installation, token forwarding or secret paste is a fallback.

## Narrow schema and trust domains

`chatgpt_handoff.Handoff` is an immutable, versioned Python value. There is no
HTTP server, tool router, arbitrary URL field, payload-to-policy loader, JSON
approval decoder or CLI activation. Unknown/partial versions fail closed.

| Field | Contract |
| --- | --- |
| schema_version | Exactly integer 1; booleans and unknown versions reject. |
| envelope | Existing #59 Envelope, requiring complete #62 TargetProject and InstallationIdentity; no legacy/implicit destination fallback. |
| envelope.policy | Canonical numeric repository ID and full owner/name; PR, linked Issue ID/number/scope/revision; full 40-hex HEAD/base/merge SHA; approved default/base branch and check App/name pins. |
| envelope.author/app/installation | Expected actual author ID/login; global App ID/slug/registration owner/bot ID/login; separate installation ID/account/type. App registration owner may differ from repository owner. |
| envelope.summary/body | #59 bounded ASCII review text, generated exact PASS/FAIL marker and full context. Summary <=4096 characters, <=1024 per line; body <=8192 bytes. Existing secret-pattern rejection remains conservative, not universal secret detection. |
| evidence | 1–8 typed opaque kind/SHA-256 references: analysis, diff, ci, collector. Exactly one analysis; no duplicate references. No dereferencing model URLs or paths. References identify artifacts; hashes are not source authenticity. |
| created_at/expires_at | Integer trusted time, lifetime <=300 seconds, no future creation or expired submission. |
| digest / body_sha256 | Canonical publisher.digest of full dataclass content / generated body string. The latter hashes the existing JSON string encoding, not raw UTF-8 bytes. |

`OperatorApproval` is **not part of the model payload**. An independently trusted
human-input controller must directly supply the handoff digest and existing
`ManualAuthorization`: exact envelope digest, independent analysis digest, unique
human decision digest, operator ID/login, approved/expiry time and journal epoch.
Approval must occur within the proposal lifetime and expire no later than it.
Changing evidence, expiry, summary, destination, identities, checks or revisions
invalidates the approval. No code turns a PASS, model function call, Issue comment,
JSON `approved=true`, saved plan or a conversation confirmation into this value.

Python types/frozen values and hashes provide consistency only. Trusted caller
code could fabricate them; the model must not run in that controller domain.
Authenticating the human, proving analysis independence and checking retained
artifact provenance remain unimplemented external gates. The GitHub bot is a
posting principal, never proof of independent reasoning. A forged PASS cannot
satisfy independent authorization merely because it has the correct format.

## One validation and COMMENT path

`submit()` revalidates proposal/approval and delegates to existing #59 `publish()`.
No duplicate weaker GitHub verifier is introduced. Defaults provide no reader,
writer or journal; absent or non-synthetic adapters block. Provenance labels are
not authentication or an OS sandbox: injected callbacks remain trusted test code.
No new GitHub writer capability, credential lookup or runtime wiring is supplied.

#59 performs complete stable #49 pre/post snapshots, exact repository/author/bot,
selected installation and minimal permissions, current HEAD/base/merge parents,
single native same-repository open Issue link, both CI revisions with pinned
check Apps, resolved threads and no blocking review. Changed/unknown facts block;
no approval is automatically updated. The only request remains COMMENT at the
fixed PR reviews endpoint, full commit_id and authorized body. No APPROVE, generic
HTTP, Ready, close, merge or Git writes are available from this adapter.

Public #49 `collect()` is unchanged and still requires an API-observed eligible
exact-SHA PASS COMMENT. Prepublication checks cannot manufacture that Receipt.
Tests run the unchanged collector after synthetic publication. A future operator
must run reviewed-mode collection while the Issue is open before considering
any separately authorized acceptance transition. Target receipts still cannot
enter the legacy queue/admission/runtime path. See [#62](target-project-policy.md).

## Durable uncertainty and isolation

`handoff_journal.SyntheticJournal` is an explicit bounded append-only disk test
adapter for the #59 journal contract. It opens **only an existing fixture file**;
it cannot initialize, reset, migrate, delete or repair a ledger. Initialization
exists only in test fixtures. It uses nonblocking exclusive flock, canonical
bounded records, owner/mode/link/path checks, exact externally pinned inode and
full-file digest, append and fsync. Max file size is 256 KiB; capacity exhaustion
blocks instead of evicting history. No raw body, analysis or credentials are stored.
The journal is separate from task checkpoints, sessions and the runtime lock.

Each target-PR has a stable operator-controlled guard domain and authoritative
ledger. Scope binds project+App+installation. The retained operation key remains
repo ID+PR across HEAD, author, App and installation changes. A rotated scoped
view reads the **same ledger** and refuses an old intent in another scope; it
cannot create a new empty namespace. Different projects require independent
operator ledger mappings/pins, scopes and approvals. Copying another project's
journal or authorization blocks even when PR numbers collide.

UNKNOWN is appended and fsynced before the fake writer is called. Only complete
response verification and stable postflight can append VERIFIED. 401/403/429/5xx,
exception, lost response, head drift, partial persistence or fsync failure cannot
retry or advance. Reopening after a simulated crash retains UNKNOWN. Only #59's
explicit read-only reconciliation API may verify the original exact remote
review; it cannot POST or renew approval. The new handoff submit API itself has
no reconciliation/reset/retry operation.

The trusted fixture/controller must retain the inode and latest full-file digest
**outside the proposal and ledger**. The adapter's updated `sha256` is correlation
state to be retained by that controller, not an authenticated receipt. A crash
between fsync and durable external-pin update deliberately leaves reopening
BLOCKED / NEEDS_HUMAN. A stale pin, truncation, lost file, changed inode, corrupt
record, partial tail or contention blocks. Never recompute a missing pin from the
remaining file, reuse an old genesis pin, select a new path or refresh it from
model data to obtain an empty history. New instances with stale pins block even
when a competing operation was legitimate; human reconciliation is required.

This demonstrates fail-closed disk/restart semantics under a trusted synthetic
fixture. It does **not** implement a production continuity-pin authority, audited
power-loss guarantees, safe same-UID adversarial isolation or a live multi-tenant
service. POSIX modes do not isolate Codex from credentials. Production storage
and path races/ownership/backup/rollback protection need independent Gate B review
and an OS-separated controller. Loss of external evidence never permits a retry.

## Future publisher01 manual operator procedure — do not execute

This is a design checklist, not a deployable command or permission to connect to
the VM. No publisher01, Proxmox or external project was accessed in Stage 1.
The [Issue discussion](https://github.com/TechTradeExpress/Agent-Platform/issues/60)
records a historic target selection of TechTradeExpress/Diatonic-Orchestrator
and operator-reported publisher01 network checks. Those statements are not fresh
trusted admission, an infrastructure audit, or Gate B evidence. No existing
content there is a disposable fixture; a future pilot needs a separately approved
synthetic Issue/branch/PR and must never execute that project's infrastructure.
No historical IP, SHA or installation is hardcoded as operational policy here.

1. Obtain separate explicit human authorization for #59 Gate B, the integration
   method and a disposable downstream target. Record independent code/security
   review, account-specific capability evidence and Stage 2 consent. Stop if the
   supported method or exact-payload approval bridge is unverified.
2. An authorized administrator prepares a dedicated unprivileged publisher service
   account on publisher01, isolated from coding workers and dev01. No root/sudo,
   shared CODEX_HOME, worker-writable controller or worker-accessible secret socket.
   No daemon, webhook, timer or scheduled polling. Account creation/deployment and
   credential provisioning are separate authorized operations, not this procedure.
3. Independently provision/audit the narrow controller, real fixed-endpoint writer,
   read-only collector principal and durable authoritative ledger/continuity store.
   App private key/JWT/installation token stays in the operator credential domain;
   ChatGPT/Codex receives neither credentials nor a generic privileged client.
   Pin selected installation/repository and minimal #59 permissions. Keep separate
   per-project read credentials, ledger mapping, rate/concurrency budgets and
   installation scope. The current synthetic adapter is not that live deployment.
4. Human manually invokes the reviewed controller under that account for **one**
   exact target operation; no ambient selection or background follow-up. Obtain
   independent analysis via the approved channel as untrusted proposal data.
   Display canonical repo ID/name, PR/Issue, complete head/base/merge, branch,
   actual author, App registration owner, installation account, bot, CI pins,
   complete body, evidence references/digests, expiry and retained intent status.
5. Authenticate the operator independently of ChatGPT/tool payloads. The human
   verifies analysis provenance/independence and the entire displayed immutable
   request, then authorizes that digest once with short expiry. Decline, lost
   approval, remembered app approval or uncertain identity blocks. ChatGPT's
   default tool confirmation cannot substitute for this boundary.
6. Re-read all #59/#62 facts and ledger continuity; commit UNKNOWN durably before
   the single authorized COMMENT attempt. Never refresh/rotate to bypass UNKNOWN.
   Verify actual response and reread, then collect #49 reviewed evidence while
   the Issue is open. Record nonsecret correlation IDs/result hashes, exact SHA,
   actual bot ID/login/state and observed CI; no raw errors/tokens in output.
7. Stop after COMMENT. Report actual outcome, including uncertain partial effects.
   No automatic Ready, Issue closure or merge. A separately authorized independent
   reviewer owns acceptance transitions; the human maintainer alone merges.
   On failure preserve ledger/pins and reconcile read-only; never blind retry,
   erase history, broaden permissions or install another App to escape ambiguity.

## Offline evidence

`tests/test_chatgpt_handoff.py` consumes the existing two fabricated downstream
projects (distinct owners/repository IDs/installations; main and trunk; App owner
different from target owner). Tests cover successful handoff plus unchanged
collector, separate approval and cross-project isolation, model/JSON PASS denial,
changed evidence/body/expiry, stale HEAD/base, author/bot/repo/installation mismatch,
foreign Issue, missing/wrong-App CI, unresolved threads, forged/duplicate review,
API failures, lost POST response, retained UNKNOWN across restart and App rotation,
lost/corrupt/partial/truncated store and fsync uncertainty. Existing #49/#59/#62
regressions remain required. Offline results cannot activate integration or runtime.
