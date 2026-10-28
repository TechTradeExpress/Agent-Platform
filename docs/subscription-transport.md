# ADR 003: subscription-funded execution transport

Status: **DECIDED — A (STOCK CODEX CLI) SELECTED**, 2026-10-28, Issue #24.
Issue #22 research is retained below for provenance; its C recommendation is
superseded, not an implementation option approved by the maintainer.
Runtime remains **SUBSCRIPTION_ISOLATION_BLOCKED**. This ADR authorizes neither
implementation of a replacement agent nor registration, login or inference.
PR #21 was verified merged at `fead0dc0a7efcf2160ba8453e6b563452c58e50d`;
fresh GitHub main and fetched origin/main matched that base. Existing checkouts
were preserved. [ADR 001](subscription-architecture.md) and
[ADR 002](tool-dispatch-feasibility.md) remain the security baseline.

## Binding maintainer decision (Issue #24)

Native Codex CLI is the sole intended execution engine; Agent Platform orchestrates
it and must not become a custom coding agent. ChatGPT subscription funding stays
mandatory. B (SIWC app-server) and C (custom Responses agent) are deferred and not
approved; they require a separate maintainer decision. Unresolved credential/tool
isolation is a deployment security gate, not authority to replace Codex.

The [native adapter and supervised offline dry-run](native-codex.md) implement the
next testable orchestration seam. Subscription execution remains hard-disabled;
engine selection does not approve credentials, inference or relaxed isolation.
The original comparison and proposed C milestone below are historical only.

## Original Issue #22 proposal (superseded)

Recommend **C only if the maintainer explicitly approves replacing native Codex
execution with a minimal custom agent and using subscription-funded Responses
HTTP transport**. C offers the smallest tool surface we can own and audit; its
isolation is a design obligation, not a demonstrated guarantee. No replacement
has been approved. If native Codex CLI is mandatory, retain A and its blocker;
B does not solve that blocker. If public Responses transport itself is forbidden,
neither B nor C qualifies. Do not implement a private endpoint or token proxy.

Approval must select A, B or C, accept its transport/product consequences and
confirm the intended client/deployment category. Architecture approval alone
cannot authorize real credentials or model requests. Until then, retain blocked
runtime execution and human-supervised development with independent review.

## Official evidence, checked 2026-10-28

Current official docs are not tests of pinned 0.164.0 or this account. No account
was queried. Sources and decision-relevant findings:

- [Quickstart](https://developers.openai.com/siwc/quickstart): eligible Plus/Pro
  users; all OSS partners and selected private clients; commercial limited trial.
  This repo is private. Neither MIT licensing nor private local use proves client,
  account or workspace eligibility: **UNVERIFIED**.
- [Overview](https://developers.openai.com/siwc/token-sharing-open-source):
  OSS/local-hosted flow; paid/remote offerings are directed to the interest process.
  Registrations bind user/workspace; each host needs a stable opaque host ID,
  which is not authentication proof.
- [Sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in):
  `openid profile email` plus `offline_access resource.invoke
  chatgpt.tokens.use.direct`, resource `https://api.openai.com/v1`.
  Validate state/PKCE/nonce, signed ID-token identity/issuer/audience/expiry and
  granted scopes. Identity-only sign-in or requesting scopes is insufficient.
- [Models/inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference):
  OAuth bearer requests to `POST https://api.openai.com/v1/responses` use eligible,
  consented ChatGPT plan usage. Public API transport does **not** imply separately
  billed Platform API inference. Model access is account-specific.
- [App-server](https://developers.openai.com/siwc/token-sharing-open-source/codex-app-server):
  stdio RPC, app-owned OAuth access token in child environment, no separate Codex
  login. model/list may be bundled, not entitlement proof. App refreshes token,
  restarts server and resumes saved thread. Pinned-build compatibility untested.
- [VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms):
  protected SIWC transfer is documented; host-specific attribution/revocation of
  transferred sessions is unavailable. This project authorizes **no transfer**.

**No-API-billing gate:** reject API keys, unverified grants, provider/endpoint
substitution and fallback after missing scope, ineligibility or limits. No native
auth-cache reuse or OAuth through the old broker. Docs also mention ChatGPT
credits: OAuth alone does not prove allowance-only spending. Before separately
authorized live use, the operator must verify app/plan spending controls and
reject automatic paid-credit fallback; otherwise stop.

## Exactly three alternatives

| Concern | A — stock ChatGPT Codex CLI | B — SIWC + Codex app-server | C — SIWC + custom explicit-tools agent |
| --- | --- | --- | --- |
| Product/funding | Preserves native CLI premise; supported ChatGPT subscription sign-in, no API-key mode | Retains Codex engine but changes auth/provider integration; subscription-funded public Responses transport | Changes product engine; same SIWC transport/funding, explicitly not native Codex |
| Credential owner | Trusted Codex owns native store, refresh and sessions | Trusted app owns SIWC registration/refresh; trusted app-server also receives access token | Small trusted supervisor owns SIWC registration/refresh, HTTPS client and private journal |
| Required tool boundary | Every built-in/nested operation must delegate to an OS worker or be immutably disabled; unproven at 0.164.0 | Same unresolved built-ins; dynamicTools/approval callbacks do not provide universal interception | Supervisor accepts only three explicit operations below, all executed in a separate worker; no Codex built-ins or extension discovery |
| Capability/cost | Rich native tools/session UX; least harness code, highest unresolved upstream isolation dependency | Native tools plus OAuth lifecycle, RPC adapter and restart handling; adds complexity without removing boundary gap | Smaller capability set; must build streaming, tool scheduling, durable recovery and maintain protocol/security, but finite owned tool surface |
| Session/resume | Native UUID/private history; preserve existing exact-UUID rules | Local thread ID/history; refresh requires restart + initialize + thread/resume | Own journal/session identity and context replay; cannot impersonate or adopt a native Codex UUID |
| Go/no-go | NO-GO for isolated runtime until exhaustive boundary proven | NO-GO for isolated runtime despite documented auth transport | CONDITIONAL implementation recommendation, not activation approval; eligibility and worker proof still required |

A's [official auth guide](https://learn.chatgpt.com/docs/auth) describes subscription
sign-in versus billed API keys and caching/refresh, not complete tool separation.
ADR 002's separate built-ins and unknown routes remain blockers. A/B also retain
the oversized-artifact admission blocker; no cap increase or automatic upgrade.

## Exact proposed trust boundary

**A:** trusted Codex/store → complete dispatcher → OS worker is the missing edge.
**B:** trusted SIWC owner → token-bearing app-server → the same missing edge.
Environment-token delivery, native flags and approvals do not protect tools from
proc/memory/fds or prove universal interception.

**C:** trusted supervisor → bounded typed channel → OS-confined worker.
Only supervisor owns credentials/refresh, private journal and fixed-origin HTTPS;
no redirects, proxies, model-selected URLs, task plugin loading or model-code
execution there. All task filesystem access happens in the worker. Worker sees
only credential-free runtime and approved worktree: no auth/session/control-plane
mounts, host network/IPC, parent proc/ptrace/memory or inherited auth/lock fds.
OS enforcement must cover descendants; UID/0700/env filtering alone is inadequate.
Future publisher credentials remain outside both inference and tool domains.

Minimal proposed, **unimplemented** protocol:

| Operation | Allowed payload and execution |
| --- | --- |
| read | Relative regular-file path, offset, bounded length in approved worktree |
| patch | Relative path, expected digest, bounded replacement; reject stale content |
| test | Approved test ID mapping to fixed offline argv/time/output caps; no model shell, executable, environment, install or network |

Bind call IDs to task/session, policy and turn. Deny replay, unknown tools/fields,
oversized/incomplete arguments before execution. Resolve paths race-safely inside
worker; deny symlink/hardlink escapes and special files. No MCP/plugins/subagents,
code-mode, hosted tools or jobs in MVP. Lost isolation or missing bounds means
stop, reap descendants and require human reconciliation.

## Preview limits, usage and recovery

The [preview contract](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
requires HTTP `store:false`, `stream:true`, array input and complete required
context; no `previous_response_id` or persistent conversation storage. WebSocket
continuation is connection-local. Function/custom tools require namespaces or
additional_tools items. Hosted MCP/connectors, file search, Code Interpreter,
image generation, native computer use and Responses tool_search are excluded;
local Codex MCP/shell/agents are a different surface. No audio/video input or
Files upload API. Unsupported request fields include max_output_tokens,
max_tool_calls, background, conversation and sampling controls; pin and validate
that documented allowlist before implementation. Enforce local budgets instead
of relying on unsupported server parameters. B retains local history/resume.

[Accounts/sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
requires separated account registrations and serialized rotating-token refresh.
Credentials stay in the trusted owner's protected store, outside journals/logs
and tools. Plus's five-hour total is shared across apps; Pro lacks that five-hour
limit in these docs. SIWC grants no separate app quota; policy/app limits still
apply. Link users to official Usage settings; never invent reset times.

[Errors/recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery)
distinguishes structured errors from admission bodies containing only diagnostic
text. Preserve bounded, redacted status/code/request-ID evidence, not raw secrets.
Transient failures retain credentials; confirmed revocation or terminal refresh
failure requires explicit reauthorization, without an account or billing switch.

| Trusted observed outcome | Proposed B/C handling; no runtime change here |
| --- | --- |
| 429 subscription_sharing_usage_limit_exceeded | Stop new requests; WAITING presentation only with authenticated transport provenance and reconciled prior work. App limit may apply; no inferred reset or paid fallback. |
| 503 subscription_sharing_usage_unavailable | Availability unknown; retain credentials, stop. Vendor permits bounded backoff, but this project's first MVP requires explicit operator retry. |
| 403 subscription_sharing_user_not_eligible | Reject selected user/workspace/policy; no OAuth loop or repeated inference. |
| Unsupported capability, missing grant, auth/permission failure | Stop; correct configuration or separately authorized reauthorization, never another billing path. |
| Disconnect, malformed/unknown error or incomplete output | NEEDS_HUMAN; no success claim or replay of uncertain side effects. |

Codex turn.failed alone is not a trusted quota code. Existing known failures stay
PAUSED; only direct operator hold can change presentation, never quota authority.
Unknown protocol/termination remains NEEDS_HUMAN. For C, persist tool intent and
result durably before continuing; reconcile an interrupted patch/test rather
than execute it twice. Only confirmed completion commits a turn. HTTP history
must be journaled privately, bounded and replayed explicitly. A future separate
backend/schema must bind an opaque account/client reference, policy, worktree
and context digests;
never migrate existing checkpoints or select the latest session automatically.
Account/workspace/policy change blocks resume. Preserve legitimate edits.

## Historical C milestone (not selected)

After explicit approval of **C**, build one manually invoked experimental
read → patch → fixed offline test task: real OS worker, disabled-by-default SIWC
adapter, bounded streaming/context journal and deterministic crash/cancellation
recovery. Reuse admission/host-lock/identity checks without weakening legacy
contracts. Run actual worker operations/denial canaries with local fake transport
and synthetic credentials first; this is not another inert parser. Missing
reviewed unprivileged fixtures means BLOCKED, never privileged provisioning.
Independent review must verify credential/proc/fd/network denial and recovery.
Only subsequent operator authorization may cover eligibility, OAuth and one
disposable subscription turn plus explicit journal resume.

Choosing **A/B** instead requires the upstream exhaustive dispatch/disablement
contract and independently proven worker boundary for an admissible exact build;
schedule/cost is unknown. Do not substitute C silently. Rollback preserves
journals/edits and blocked execution, never switches engine/account or deploys
the API broker. C owns protocol/security maintenance and loses native sessions;
A/B retain upstream tool-inventory/version audits.

## Validation boundary

Documentation-only change: no parser, transport, auth adapter or runtime code
added. Local validation: `uv run ruff check .` PASS; `uv run pytest` **592 passed**
(54.31s); `git diff --check` PASS. Direct `uv run agent-platform subscription`
returned **exit 13**, `launch_allowed=false`, authentication `NOT_INSPECTED` and
`LIVE_NOT_RUN`. The SHA-pinned Draft PR records final CI separately.
The existing 25 subscription tests and 110 callback-proof cases establish
synthetic denial/lineage behavior only, not SIWC eligibility or OS isolation.
Legacy runner/broker, admission, checkpoints, session UUID, host locks, isolation,
size caps and runtime GitHub-write restrictions are unchanged. No registration,
login/status/token inspection, transfer, inference, billing or host changes.
Real kernel testing NOT_RUN; account eligibility UNVERIFIED; authenticated E2E
LIVE_NOT_RUN. Research/CI PASS cannot activate runtime execution.
