# Supervised GitHub App COMMENT policy — Issue #59, Gate A

Specification **AP-RC/1**, 2026-11-03. Gate A implements an **offline-only** policy
and dependency-injected synthetic client. Gate B (App registration, installation,
key custody, token minting, verified live transport/journal and disposable pilot)
is **NOT_AUTHORIZED / NOT_RUN**. No App identity or numeric IDs are invented here.
Working name `agent-platform-reviewer` is a proposal, not an installed principal.

[ADR 004](architecture-trust-boundaries.md), [review workflow](development.md),
[read-only collector](github-evidence.md) and [governance](github-governance.md)
remain binding. Native execute/subscription and public legacy run/resume/doctor
remain blocked at exit 13; the native security decision remains NO-GO. Gate A
adds no ChatGPT integration, scheduler, Telegram control, Ready/Issue transition,
merge, branch writer, native runtime or inference provider.

## Authority chain and bounded envelope

The implementing account creates a Draft PR. An independent reviewer performs
technical analysis of its exact diff and CI. A human checks that analysis and
explicitly authorizes one immutable payload. The App is only a future **posting
principal**. A different ID/login, App installation, model PASS or typed object
cannot prove independent reasoning or authenticate a human decision.

`review_comment.Envelope` binds the existing `github_evidence.Policy` (repository
ID/name, Issue ID/number/scope/revision/admission pin, PR, exact main/base/HEAD,
base-bound synthetic merge SHA and required App checks), expected PR author
ID/login, App ID/slug, installation ID, owning organization ID/login and bot
ID/login. Policy has exactly that bot as reviewer. Every ID comes from separately
trusted operator policy; test IDs are fabricated. App owner must match the pinned
repository owner; the current API organization identity is checked as well.

`Decision` is PASS or FAIL. Both create **COMMENT**, never APPROVE or
REQUEST_CHANGES. Gate A deliberately applies the same green-CI/resolved-thread
preconditions to both; it does not yet publish FAIL through a red/ambiguous
preflight. FAIL's marker cannot satisfy the collector's PASS contract. The body
is generated with exactly one first line:

```text
Agent-Platform review v1: PASS FULL_40_HEX_HEAD_SHA
```

For FAIL only the decision word changes. Generated context lines additionally
bind repository/PR/Issue, base/merge and a policy/author/App context digest, so
a same-HEAD review from a different base/check/identity context is not silently
reused. No caller can select an HTTP event,
URL, method, GraphQL mutation, pending-review submission or inline comments.
Summary is 1–4096 ASCII characters, <=1024 per line, no CR/control/escape bytes;
complete body <=8192 bytes. Duplicate markers and common secret/auth/private-key
patterns are rejected. This conservative screen is **not a general secret
scanner**: opaque variable-length secrets cannot be identified reliably by regex.
The human must review/redact the exact content; never paste a credential to test
redaction. Bodies/raw errors are never returned in diagnostics or journal entries.

`ManualAuthorization` binds the canonical envelope SHA-256, an independently
performed analysis digest, a unique human decision ID/digest, operator principal
and explicit approved/expiry times (<=300 seconds), plus the explicitly approved
journal epoch. It is a direct trusted
in-process input, never loaded from Issue/PR/model JSON, target files, a saved
plan, ChatGPT conversation or Telegram. Envelope hashing binds its deterministic
body as well as destination, identities, decision and scope. Types and hashes
provide consistency, **not cryptographic approval or independent identity**.
The separately trusted human-input/controller boundary remains a Gate B obligation.
Canonical constructors and nested policy constraints are revalidated at entry;
new HEAD/base/body/check/App/actor pins invalidate old authorization.

## Synthetic interfaces, not credential access

`publish(envelope, authorization, reader=..., writer=..., journal=..., now=...)`
has no default client/store, CLI or environment credential lookup. Gate A accepts
only explicit `synthetic_snapshot`, `synthetic_review_transport` and
`synthetic_journal` provenance. Other/absent adapters block before publication.
These labels are a test contract, **not a network sandbox or authentication**:
callbacks are trusted code and could lie or perform effects if compromised.
There is no live writer, token broker, App installer or filesystem journal here;
production use cannot be obtained by simply changing a label.

- Reader: fixed `get` and two connection-query interfaces; reuses #49's complete
  pagination, repository/Issue/link/thread and HEAD/merge CI validation. Up to
  128 reads / 60 seconds, bounded 2 MiB responses; page size 20, maximum 3 pages.
  Unknown route/query/cursor, truncation, count drift, HTTP or decoding failure
  blocks. No arbitrary URL or HTTP forwarding is exposed by this policy.
- Writer: `identity(timeout=5, limit=4096)` returns **nonsecret synthetic**
  `InstallationFacts`, not a token. It must match expected App/installation/bot,
  organization, selected **one repository ID**, exactly metadata:read and
  pull_requests:write, token_kind=installation and current lifetime <=1 hour.
  User tokens/PATs, broader permissions, all-repository selection, expiry or drift
  block. This is mock metadata validation, not demonstrated authentication.
- Sole write interface: `comment(CommentRequest, timeout<=5, limit=65536)`.
  Publisher constructs POST `/repos/{pinned repo}/pulls/{pinned PR}/reviews`,
  event COMMENT, explicit `commit_id` and exact authorized body. A future trusted
  transport must independently enforce those pins and byte/time limits before
  sending or parsing, without redirects/retries or generic API methods. No such
  live implementation is supplied by Gate A.
- Journal: typed `identity()` returns its epoch/completeness; `read(key, epoch=...)`
  and atomic `compare_and_swap(key, expected, replacement, epoch=...)` enforce
  the human-pinned epoch. Missing/incomplete/replaced identity blocks.
  Tests use explicit in-memory synthetic state. No host/task checkpoint, mutex,
  HOLD, session, Git ref or authorization file is created or changed. Trusted
  future storage must be durable, independently owned and unavailable to Codex;
  loss/corruption/uncertain initialization is **not an empty new journal**.

GitHub documents PR-write permission for creating reviews and installation-token
attribution/expiry. PR write grants **more than COMMENT**; code allowlisting is
not an API-enforced comment-only permission. References:
[create review](https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request),
[App permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps),
[installation authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation).
The future read-only evidence principal may need distinct read grants for checks,
statuses and metadata; do not broaden the review writer to obtain collector access.
The existing authenticated developer's GitHub CLI is **not** a writer fallback.

## Preflight, state machine and unknown results

Preflight reads two full stable #49 snapshots, including a single genuine linked
**open** Issue and the sole `Closes #N` body reference, same-repo PR, expected
current author, Draft/open/not merged state, current main/base/HEAD, no unresolved
threads/findings/latest CHANGES_REQUESTED, and successful checks at both HEAD and
the synthetic merge result with exact `[base, head]` parents and pinned check Apps.
Identity metadata is checked before/after. Current authorization time includes
elapsed monotonic time; expiry during preflight prevents sending. Repository owner
and actual/expected bot versus author compare both numeric ID and login (case
insensitive for independence). A matching name with another ID, or matching ID
with another name, cannot establish the bot principal.

The shared internal `_read(..., _before_comment=True)` validates prepublication
facts **without claiming a PASS review already exists**. Public `collect()` never
selects this branch and still requires `_review()`'s exact-SHA observed PASS.
The collector's principal syntax now accepts the narrow canonical `[bot]` suffix;
ID/login independence, latest-review ambiguity, CI, source/link and receipt rules
remain intact. A prepublication snapshot is not a reviewed collector Receipt.

The retained journal key is repository ID + PR, independent of new App, HEAD,
body or authorization ID. It cannot evade an uncertain earlier attempt by changing
those pins. Intent stores only envelope/authorization digests, UNKNOWN/VERIFIED
and optional positive review ID. No body, token or private analysis enters it.

| State / event | Allowed result and effects |
| --- | --- |
| No intent; invalid/absent human approval or preflight | BLOCKED, no COMMENT or intent initialization |
| No intent; already exact authorized bot review | Reread/verify; CAS to VERIFIED, no POST |
| No intent; approved fresh snapshot, no existing bot review | Atomic CAS to UNKNOWN **before** the sole possible POST; CAS failure prevents sending |
| POST returned | Require actual user.id/login, type Bot, COMMENTED, exact commit/body/PR URL, valid review ID/time; then two full rereads and identity recheck |
| Complete matching postflight | CAS UNKNOWN→VERIFIED; PUBLISHED_SYNTHETIC (offline simulation only) |
| Timeout/401/403/429/5xx, malformed/mismatched receipt, postflight drift, cancellation/crash or uncertain persistence | Keep UNKNOWN/uncertain state, NEEDS_HUMAN; no retry, delete, overwrite or compensating GitHub operation |
| Rerun with UNKNOWN | NEEDS_HUMAN/reconciliation_required; never calls COMMENT again |
| `reconcile_only=True` | Remote **read-only** full revalidation; exactly one matching review may confirm VERIFIED, none/conflict/drift stays unknown; never POST |
| VERIFIED rerun | Full current reread and exact review-ID comparison; ALREADY_VERIFIED_SYNTHETIC, no POST |
| Changed payload, new HEAD/App/grant or corrupt journal | Block/preserve existing intent; no implicit reset/new namespace to escape uncertainty |

Read-only reconciliation may use the original expired grant as an immutable audit
pin; it **cannot renew publication permission**. Current installation metadata
must still be valid. Unknown no-review outcomes do not prove no write happened:
remote visibility, outages and deletion can be ambiguous. No automatic replay is
provided. A retained confirmed old operation is also not silently replaced for a
new HEAD; separately designed human reconciliation is required. Gate A does not
provide a reset/delete/retry API. Future controllers must share one serialized
journal, never recreate it after loss. An empty in-memory test store proves no
cross-crash durability; no such production claim is made.

GitHub observations are not atomic with POST; commit_id fixes what was reviewed,
not that PR head cannot move in the request window. Postflight drift therefore
leaves an uncertain/stale result, not acceptance. Grant types, CAS/digests, actor
names and check success do not prove exactly-once GitHub effects. Preserve evidence
and reconcile with authoritative remote owners; no automated Ready, Issue closure
or merge follows, including after a verified COMMENT.

## Gate B operator-only checklist (proposal; do not execute now)

1. Obtain separate explicit maintainer approval of code, independent review,
   permission model, credential controller and a disposable pilot repository/PR.
   Record the approved canonical owner/repository IDs. Gate A merging is not that
   approval. ChatGPT handoff/integration remains a separate dependent Issue.
2. Only the authorized administrator registers a private organization-owned App,
   working name `agent-platform-reviewer`. Record actual App ID/slug, organization
   ID/login, installation ID and bot numeric ID/login from authoritative metadata.
   Do not derive the bot ID from App ID or assume a `[bot]` name authenticates it.
   Restrict installation and effective token to one approved repository. Disable
   unnecessary webhooks/event subscriptions and user OAuth. Grant only Metadata
   read and Pull requests read/write; no Contents/Issues/Actions/Checks write,
   Administration, Secrets, Deployments or organization grants.
3. Key/JWT handling and short-lived installation-token minting stay in an
   independently controlled operator trust domain, not dev01 worktrees, CODEX_HOME,
   task checkpoints, models, ChatGPT or Telegram. No credentials are payload fields.
   Treat tokens as opaque variable-length secrets, never fixed-length IDs or
   receipts. Scope token permissions/repositories down, verify actual expiry and
   identity, and never substitute a user access token/PAT. No real key/token is
   generated or inspected by this implementation.
4. Independently review a real fixed-endpoint adapter and crash-safe journal:
   private owner, safe paths, atomic/fsynced intent before I/O, process serialization,
   lost-state detection, bounded transport, credential isolation and emergency
   off-switch. Validate that session metadata really belongs to the installed App;
   Gate A's typed InstallationFacts is **not** live authentication. GitHub review
   user.id/login/type proves the observed actor, not App installation/token scope
   by itself. The future transport/controller must attest that binding without
   inventing unsupported REST review-response fields or leaking credentials.
5. For one separately authorized disposable pilot, freeze exact author, App/bot,
   PR/base/main/HEAD/merge/Issue/checks, independent analysis and human body approval.
   Verify ID **and** case-insensitive login differ from author. Confirm no prior
   bot review/unknown intent; submit one COMMENT only after fresh preflight. Retain
   API result ID/state/commit/body digest and actual actor; reread exact remote
   state plus #49 reviewed-mode evidence while the Issue is still open. A COMMENT
   is not formal APPROVE, independent reasoning proof or merge authority.
6. Verify live identity attribution and permissions separately and record actual
   PASS/FAIL/UNKNOWN, not this suite's fabricated values. Simulate timeout/lost
   response and reconcile remotely before any later operator decision. Check new
   HEAD/base, CI drift, revoked/suspended installation and expired token fail closed.
   No automatic Ready/Issue closure. Those need the existing separately authorized
   independent workflow, unchanged exact SHA and green required checks.
7. Emergency shutoff: stop the trusted publisher, revoke the installation token,
   suspend/uninstall App or revoke/rotate its key through an authorized operator.
   Preserve nonsecret operation/audit evidence; do not erase UNKNOWN, auto-retry,
   signal unrelated tasks or change permissions to recover. Audit who approved
   which exact payload, credential metadata (never secret), request/outcome and
   reconciliation. Human alone merges. Rollback cannot unpublish an uncertain
   review automatically; any remote correction is a separately authorized action.

## Verification and evidence limits

`uv run pytest tests/test_review_comment.py tests/test_github_evidence.py` uses
scripted readers/writers and explicit in-memory journals, synthetic Git and fake
API results. Tests cover trusted human approval, canonical marker/body limits,
App/author/owner identity, least privilege/expiry, CI/link/thread/head drift,
postflight spoofing, idempotence, crash/timeout reconciliation, CAS contention,
redaction and denied live/unauthorized operations. No real App, token, review or
privileged service is created. Results are **VERIFIED_OFFLINE only**; actual App
principal and least-privilege enforcement, durable storage, live COMMENT transport
and independent technical analysis remain **NOT_RUN / REQUIRES_INDEPENDENT_REVIEW**.
No offline success enables a production service or Gate B. The Draft PR records
actual local and exact-HEAD CI, including unresolved dev01 baseline failures.
