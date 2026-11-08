# Coding App identity and future Gate B

The #71 sections below preserve the **historical synthetic writer-profile design**,
not instructions to upgrade the current App. Current operator-reported progress
and MVP.8c's separate metadata contract are recorded in the final section. The
current App stays Metadata read only; no write permission is authorized.

Issue #71 is offline preparation only. AP-CI/1 verifies fabricated observations,
never a live installation, task authorization or permission to execute. The
baseline is PR #70's squash `ba3d8162a97d297f1da7fe492aab4f5d1a2889a6`;
its two successful post-merge workflows were independently checked before work.

## Threat and permission design

This design precedes the synthetic adapter. Five distinct trust zones remain:

| Zone | Responsibility / boundary |
| --- | --- |
| Human / ChatGPT planning | Human authorizes a target-specific assignment; ChatGPT helps plan. Issue text, labels, assignees, model PASS and serialized contracts supply no authority. |
| Trusted operator custody | Owns App keys, JWT creation and short-lived installation-token handling outside Codex, dev01 and all worktrees. No custody implementation exists here. |
| Isolated observation component | Future read-only, independently trusted observer supplies authenticated observations and complete replay history. Must not expose credentials or clients to the worker. This Issue supplies only injected fakes. |
| Untrusted Codex worker / target worktree | Cannot access custody, observer credentials, controller state or publisher. No execution is enabled. |
| Future trusted branch/PR publisher | Separate authorization and durable intent gates; repository-scoped Contents write must never be treated as feature-branch-only permission. No writer exists here. |

Coding App and reviewer App IDs, installations and bot principals stay distinct
under AP-CA/1 and #62. Registration owner may differ from installation account /
target owner. A single maintainer is supported; distinct GitHub principals do not
establish independent humans or independent reasoning. AP-SM/2 source review
transitions confer no downstream product authority. #49, #59 COMMENT-only,
AP-CH/1 exact-payload authenticated human approval and UNKNOWN journaling remain.

The minimal candidate App/installation grants are exactly Contents write,
Metadata read and Pull requests write, with selected-repository access to exactly
one explicitly authorized repository and no webhook subscriptions. This is a
future writer's permission envelope, **not authority to use those writes**.
Private source `main` was reported `protected=false`; that observation is not a
current guarantee. Contents write covers the repository, including main absent
effective controls. Live branch writing is NO-GO until independently verified
server governance and credential/worker separation prevent unauthorized main
writes. Local branch conventions do not provide this protection.

## AP-CI/1 evidence map and limitations

`coding_app_identity.observe` accepts an existing trusted `CodexAssignment`,
`IdentitySnapshot`, expected logical agent and a versioned `Observation` challenge.
It reuses AP-CA/1 identity validation, not a second admission/authorization path.
No TargetProject is fabricated before a PR exists; AP-CA/1's `for_project` remains
the later #62 binding check. It does not replace admission, queue or state checks.

| Fixed GET | Declared auth domain | What the response establishes in the fake model |
| --- | --- | --- |
| `/app` | App JWT | App numeric ID, slug, registration owner/type and configured grants/events |
| `/app/installations/{pinned id}` | App JWT | Installation belongs to that App, target account/type, selected mode, grants, unsuspended state |
| `/installation/repositories?page=1&per_page=20` | Installation token | Exactly one accessible repo numeric ID/name/owner/default branch; total count agrees and no continuation |
| `/repos/{pinned repo}/issues/comments/{pinned comment id}` | Installation token | Existing comment's actual Bot user ID/login plus `performed_via_github_app` association to the pinned App and exact Issue URL |

Sources: GitHub's [App endpoints](https://docs.github.com/en/rest/apps/apps),
[installation endpoints](https://docs.github.com/en/rest/apps/installations),
[Issue comment endpoint](https://docs.github.com/en/rest/issues/comments#get-an-issue-comment)
and official [OpenAPI schema](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json)
(`issue-comment.user` and nullable `performed_via_github_app`). These establish
schema/endpoint contracts, not evidence of any actual installation here.

`GET /app` does not expose an actual bot principal. A slug plus `[bot]`, a guessed
numeric ID or a user profile alone does not prove an App-to-bot association. The
conservative adapter requires a separately pinned, **already existing** same-Issue
comment with both Bot author and App association. Missing/null bot evidence is
IDENTITY_UNVERIFIED. No comment is created to bootstrap this proof. A new App
without suitable evidence remains unverified; obtaining alternate proof or
producing an artifact requires a separately reviewed, explicitly authorized plan.
Comment body text, timestamps and author-association labels supply no authority.
This proof shows historical attribution, not future PR authorship. Availability of
that private Issue-comment evidence under the minimal candidate grants has not
been demonstrated live. A forbidden response remains a blocker; do not add
permissions or perform a write to make verification pass.

Auth domain, challenge correlation and snapshot freshness in the fake envelope
are observer assertions, not GitHub response fields. HTTP 200 (including on
public resources) does not prove authentication. Effective token kind, selected
scope, permissions and expiry come from the existing nonsecret InstallationFacts
assertion; these GETs cannot introspect a bearer token's actual restrictions.
The future custody/observer boundary must independently prove those assertions.
No token, JWT, key, Authorization header or secret path is an input/output.

Two complete sequential reads must agree on normalized security facts. Each
response is bounded to 64 KiB; eight requests maximum, five-second request budget,
30-second total budget. Any Link/continuation is rejected, never followed: this
contract only accepts one selected repository fitting the first page. Non-200,
malformed/duplicate-key JSON, wrong routes/auth, missing facts or drift fail closed
without retries. Only fixed diagnostics and canonical normalized digests escape.
Unknown API fields are discarded, not echoed or hashed into retained evidence.

The observation binds exact assignment digest (including scope/base/agent), a
fresh 64-hex challenge, snapshot and <=300-second expiry. A separately trusted
complete bounded history rejects previously observed challenges. Incomplete/lost
history blocks; it is not reconstructed or evicted here. This pure read-only API
does not consume a challenge or provide durable anti-replay; repeated advice is
not an operation. Persisting/consuming history remains a future controller duty.
Different simultaneous assignments require different challenges and independent
binding. This is not AP-CA/1 reservation or a durable claim.

Results are immutable AP-CI/1 facts with finite `VERIFIED_OFFLINE_FIXTURE`,
`IDENTITY_UNVERIFIED` or `BLOCKED`, fixed reason, exact pins/digests and expiry.
Every result has reserved/prepare/launch/resume/publish flags false, live identity
NOT_RUN and runtime exit code 13. No result can become live VERIFIED or authorize
AP-CA/1 advice, prepare, native execution or publishing. No CLI, network client,
credential loader, state writer, scheduler or live transport is supplied.

## Historical #71 future writer Gate B procedure — NOT EXECUTED

Each step requires a real human's separate explicit target-specific approval;
this runbook, an Issue or model output cannot authorize it. Stop if assurance is
missing. Record decisions and redacted observations; never paste keys or tokens.

1. Approve one canonical repository ID/name, owner, intended branch/Issue scope,
   separate coding/reviewer principals and the exact proposed permission set.
   Independently inspect current branch rules and bypass actors. Establish an
   effective protected-main policy first; if unavailable, live writer NO-GO.
   No settings changes are authorized by this Issue.
2. Choose and approve the physical trust host, OS principals, key/token custodian,
   isolated read-only observer and future publisher boundary. Demonstrate the
   worker cannot read credentials, mutate observer/history or call privileged
   clients. Verify startup/reboot persistence does not automatically launch work
   or expose credentials; verify ownership, storage, service and network policy
   after reboot. These checks are open; publisher01 is not presumed ready. No
   dev01/worktree custody or deployment follows from this document.
3. Only under new approval, operator registers a private coding App with no
   unnecessary webhooks/events; exactly Contents write, Metadata read and Pull
   requests write, no administration/workflows/Issues write. Install on exactly
   the approved selected repository, not all repositories. Record actual App ID,
   slug, registration owner/type, installation ID and account/type separately.
4. Custodian alone establishes reviewed key storage/rotation, generates short-lived
   App JWT and an installation token restricted to that repository and minimal
   grants. Worker never sees them. Record only kind, scope, grant facts and expiry.
   No implementation or command in this Issue performs these steps.
5. Under a separately approved read-only probe implementation, authenticate the
   App endpoints with JWT and repository/comment endpoints with installation
   credentials. Capture actual bot numeric ID/login/type and App association from
   pre-existing trustworthy API evidence. Stop if unavailable; do not guess or
   create an unsolicited test comment. Verify actual later PR author separately.
6. Independently re-read all pins, selected membership, effective permissions,
   token expiry, suspension and assignment scope. Retain sanitized normalized
   facts/digests with observation time, expiry, human authorization reference and
   provenance (API evidence vs custody assertion). Never retain raw responses,
   Authorization headers, secret URLs, keys or token material in repository/CI.
7. On error/drift/unknown outcome stop, preserve evidence, revoke affected token
   or uninstall/revoke/rotate only under the operator's separately authorized
   incident procedure. Rotation invalidates old observations and approval pins;
   do not reuse a digest, discard unresolved intent or bypass UNKNOWN guards.
   Re-observe and reauthorize exact identities before any future operation.

## Historical #71 readiness ledger

| Capability | State after offline PASS / next independently authorized evidence |
| --- | --- |
| Synthetic observer and AP-CA/1 fixtures | Offline contract only; run focused and full tests |
| Actual private coding App / selected installation | NOT_RUN; operator approvals and actual observed IDs required |
| Credential custody / token kind, effective permissions | BLOCKED; approved host and secure independently verified custody required |
| Actual Bot author / App association | NOT_RUN; API observations required, never inferred from name |
| Human assignment / exact review-payload authorization | NOT_RUN; authenticated target-specific approval remains separate |
| Protected-main and future branch/PR publication | NO-GO; effective server governance, isolation and separately reviewed writer required |
| Durable single-agent assignment claim | NOT_IMPLEMENTED; AP-CA/1 advice and observation challenge are not claims |
| Native subscription / worker isolation | BLOCKED at exit 13; no paid API fallback, no invocation through Agent Platform |
| Live observer Gate B / physical host / reboot checks | NOT_RUN; separately authorized implementation, probe and recorded verification required |
| Reviewer App / COMMENT publisher | Separate product Gate B remains blocked; may remain unprovisioned |

The next operator action is to approve the exact target/governance and host/custody
verification plan, **not execute this library**. Offline tests and AI review do not
establish production security assurance. Human-only merge and all existing native,
legacy, admission, state, queue, review and publication gates remain unchanged.


## Operator-reported MVP.8b milestone and MVP.8c

Issue #74 summarizes the human operator's tracker #73 observations. Codex has not
repeated the App probe, accessed publisher01 or inspected any credentials:

- Private organization-owned App **TechTradeExpress Agent**, ID **5660901**, slug
  `techtradeexpress-agent`, registration owner `TechTradeExpress`.
- Installation **179693483**, selected mode, organization account, unsuspended,
  exactly Metadata read. Installation-wide enumeration showed only
  `TechTradeExpress/Agent-Platform`, repository ID **1436076348**; token revocation
  was reported successful. No token or key is retained in source evidence.
- Public profile `techtradeexpress-agent[bot]`, ID **353883253**, type Bot. This is
  **not** an authenticated App-attributed action or performed_via_github_app proof.
- Signing PEM is held on publisher01 under root-owned 0600 custody; publisherapp
  has no direct read access. This Issue does not retrieve/sign with it or access
  the VM. VM 102 backup was consciously deferred; loss/rotation risk remains.
- Repository is now reported public. Main ruleset **26772477** is reported active,
  no bypass, requiring PR plus checks/lifecycle and linear history, prohibiting
  force-push/deletion; squash-only merging and auto-merge off. This supersedes the
  historical unprotected/private observation above, but governance must be freshly
  verified before future write authority. Contents write remains repository-scoped.

[AP-AM/1](app-metadata-observer.md) adds the separately typed live-response metadata
boundary with only offline mocked transport/custody. It accepts Metadata read,
not AP-CI/1's future writer grants, and does not require or fabricate an Issue
comment. All successful results remain metadata-only / bot-attribution-unverified.
AP-CI/1's existing synthetic status and strict action-evidence requirements remain
unchanged; AP-CA/1 still cannot accept this as a coding writer identity or claim.

Current readiness: operator reports one manual metadata probe complete; MVP.8c
live adapter/run is **NOT_RUN**, credential-host confinement/reboot/recovery is
not established by offline tests, native and legacy execution stay exit 13,
durable assignment claim is NOT_IMPLEMENTED and all publication remains BLOCKED.
Metadata-only grants cannot produce an App-authored Issue comment; public Bot
lookup cannot substitute. The next step is separately approved trusted-host
adapter/custody review and a bounded metadata-only run, following the new handoff.
Do not register a second App or upgrade permissions merely to satisfy old fixtures.

MVP.8d's [AP-AL/1 inactive API adapter](app-api-adapter.md) now implements the bounded
wire/token-lifecycle layer behind AP-AM/1, with offline mocks only. Signer, durable
exclusive custody journal and trusted-host isolation/wiring still require separate
review and live authorization. LoadCredential is not a process-isolation boundary.
No App probe, credential access, publisher01 deployment or permission change is
performed; the metadata-only and native/public exit-13 boundaries remain intact.

MVP.8e adds the [explicit SQLite journal and host isolation blueprint](custody-journal-and-host-isolation.md),
not activation. Local commit/lock evidence cannot prove external deletion/rollback
protection or a trustworthy custody UID. Independent continuity, storage/reboot and
credential-loss decisions remain operator gates. Signer/IPC (8f) and independent
host activation/pilot (8g) require separate scope and human approval.
