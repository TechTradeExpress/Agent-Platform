# ADR 001: subscription authentication with isolated tools

Status: **SUBSCRIPTION_ISOLATION_BLOCKED**. Scope is an architecture/security
spike and non-launching diagnostic, not an enabled execution backend. ChatGPT
subscription is the only approved future inference path. There is no API-key
fallback, token extraction/forwarding, API conversion or broker deployment.

## Prerequisite and evidence

PR #16 was confirmed merged=true, merged at 2026-10-28 07:44:54 UTC. Fresh GitHub
default branch main and fetched origin/main both resolved to
`c77d32ab89c1cbb6bf8dfdbf966dd354082b4985`; ancestry of that actual merge commit was
verified before creating feature/issue-17-subscription-auth. An unmerged PR's
merge_commit_sha was not used as proof. Existing checkouts were preserved.

Pinned installed CLI evidence was collected without model turns, in a temporary
empty HOME/CODEX_HOME/XDG environment with tokens/proxies/agents omitted:

| Diagnostic | Actual result | Limit of evidence |
| --- | --- | --- |
| codex --version | 0.164.0, exit 0 | Version only |
| login --help and login status --help | Supported parsers, exit 0; device-auth present | Actual account status NOT_RUN |
| exec --help | --json, stdin, native sandbox choices | Authenticated exec NOT_RUN |
| exec resume --help | Explicit SESSION_ID/stdin, --json | Authenticated same-session resume NOT_RUN |
| exec/resume --ignore-user-config | Help states auth still uses CODEX_HOME | Does not isolate credentials |
| sandbox --help | sandbox [OPTIONS] [COMMAND]..., no linux subcommand | No generic read-isolation proof |
| app-server --help | Experimental; stdio/listener and code-mode-host options | No authenticated server started or universal tool dispatcher proven |
| Native sandbox fabricated-canary attempt | BLOCKED in the existing sandbox | No real namespace/read/write isolation PASS |

The native attempt used fixed Python code, a disposable workspace and fabricated
credential/read/write canaries, clean environment and ten-second/1 KiB bounds.
It attempted only synthetic reads/writes; no model, real secret, repository,
account or broker was involved. Failure did not trigger an unsandboxed retry.
Raw stderr/commands and identifying paths were not placed in evidence reports.

**codex login status was not run against the operator's store.** Even a nonsecret
status display can internally read authentication material. The prohibition on
real credential access takes precedence; querying an empty or synthetic store
cannot establish the real account's method/entitlement. A human can later inspect
their own status only under separately authorized testing. No login, logout,
refresh, auth.json copy/read, keyring query or authenticated inference occurred.

[Official authentication guidance](https://learn.chatgpt.com/docs/auth) describes
ChatGPT sign-in, credential caching and refresh. Device-code login is an operator
option, not an agent action here. These current docs do not prove pinned refresh
or isolation behavior. [Noninteractive documentation](https://learn.chatgpt.com/docs/non-interactive-mode)
describes exec/JSONL and explicit resume; observed help confirms parser support,
not live session compatibility. The installed candidate remains 308,139,304 bytes
(SHA-256 b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306), above
the unchanged 268,435,456-byte profile cap. It was not admitted to a runtime image.

## Assets, attackers and trust domains

The hostile model/tool side includes task prose, repo files/symlinks, commands,
patches, MCP responses/configuration, generated code and fabricated quota messages.
None can grant authorization, choose credentials/accounts/backends, widen mounts
or publish changes. Assume attempted exfiltration and persistence across turns.

- Trusted Agent Platform control plane owns admission, refs/worktree identity,
  host mutex, checkpoint/guard writer and exact session lineage. GitHub publisher
  authority is a separate future component; neither model nor tool worker gets it.
- Trusted Codex/auth domain would own subscription session, refresh authority,
  private native sessions and permitted model connection. Authentication files,
  keyring access, parent memory and descriptors must remain outside tool reach.
- Untrusted tool workers may edit only the approved disposable worktree and use
  explicitly approved offline tools. No host home, control plane, private Git
  common directory, sockets, real credentials or arbitrary host network access.
- OS/kernel, pinned Codex, supported protocol and audited tool supervisor would
  be TCB. Same UID, 0700 paths, approval prompts and model instructions are not
  isolation proofs. Vendor documentation is not a deployed security attestation.

## Compared designs

| Threat/property | A: authenticated CLI parent with native tools | B: trusted supported invocation service with external tools |
| --- | --- | --- |
| Credential ownership | Trusted Codex/store; shell must never inherit or read it | Trusted service/store; clients receive no OAuth token |
| Files/mounts | Native workspace-write is not demonstrated to deny auth-home reads | Need proven separate worker mount view, workspace-only writes and no auth/session mounts |
| Parent memory/proc | Same-UID child may target proc/fds/ptrace; Yama alone is insufficient | Separate PID/proc view, denied memory inspection and no service descriptors required |
| Environment/fds | Strip secrets/proxies/agents and close descriptors; not sufficient alone | Typed request channel only, bounded I/O; credential/lock fds never reach worker |
| Shell/exec | Must prove every spawn uses enforced worker boundary | Must prove every supported shell/unified-exec route is delegated or denied |
| Patch/read tools | In-process file operations could bypass child sandbox | All patch/read/write routes need interposition or disablement; path checks alone do not stop symlink escapes |
| MCP/plugins/subagents | Unknown or in-process tools may see trusted context | Disable discovery and nonapproved routes; unknown tools/protocol versions fail closed |
| Host networking/keyring | Native network and IPC boundaries need independent tests | Worker has no host network/session bus/credential-service sockets |
| Native sessions | Must not expose auth/store/session files to tools | Persist exact private session in trusted domain, hash/lineage outside task |
| Cancellation | Parent failure must stop all descendants and preserve guard | Bounded requests, cancellation/reaping and no queued replays after disconnect |
| Support evidence | exec/sandbox parser observed; universal safe boundary unproven | App-server exists, but no complete mediation of built-ins proven |
| Decision | Reject for unattended launch until proof | Preferred research direction only; blocked for implementation |

The [app-server documentation](https://learn.chatgpt.com/docs/app-server) describes
authentication/conversation integration and experimental dynamic tool calls.
Dynamic-tool callbacks are not evidence that **all** built-in operations use the
same boundary. The pinned help also labels app-server experimental. No app-server,
SDK, remote Code Mode host or custom proxy is asserted to be a credential-safe
production solution here. Do not invent a root service or forward OAuth through
the legacy API broker to bridge this gap.

## Intended trace and exact blocked edge

The required future flow is:

1. Operator explicitly chooses one task and approved ChatGPT account/workspace.
   Control plane acquires the existing host mutex and freshly validates admission,
   source refs, worktree and checkpoint. Model output is never authority.
2. A trusted Codex process accesses only its private approved credential store,
   authenticates directly using the supported subscription mode and records its
   exact thread.started UUID durably before continuing. API billing is forbidden.
3. Model requests a tool. **BLOCKED EDGE:** a supported, complete dispatcher must
   send *every* shell/patch/read/MCP/subagent operation to an OS-confined worker or
   reject it; nothing untrusted runs with auth/store/control-plane capabilities.
4. Worker sees approved workspace plus credential-free runtime, private proc/tmp
   and no host network. Bounded nonsecret results return over one typed channel;
   no credentials/native sessions/checkpoint/lock descriptors cross the boundary.
5. Trusted Codex continues that same session. Control plane reaps workers, verifies
   identity/ref invariants and durably records the known stop under the lock.
   Parent/protocol failure preserves recovery state as NEEDS_HUMAN.
6. Operator may explicitly resume the same UUID after fresh validation. A future
   publisher requires separate authority and independent code review; it is not
   available to runtime tools or the trusted model session.

Steps 2–5 are requirements, **not implemented or demonstrated by this spike**.
CLI authentication is supported in principle; the combined project security
boundary is not yet shown technically viable. This is not a proof of impossibility.
The human-supervised fallback is inspect/issues/prepare plus independent human
review/planning; do not hand an untrusted repo to an unrestricted host Codex or
claim that interactive approval makes credential access safe.

## Implemented boundary and offline evidence

`agent-platform subscription` reports SUBSCRIPTION_ISOLATION_BLOCKED and exits 13
without inspecting a repo/login, contacting GitHub/provider, launching Codex/tools,
reading credentials or writing checkpoints. There are no flags to enable launch,
select an API key or adopt the latest session. Existing commands remain unchanged.
The legacy API runner/broker is historical compatibility code, not a fallback for
this mode. `subscription.auth_precondition` reduces **synthetic nonsecret** adapter
evidence; even chatgpt + logged_in cannot grant launch. It is not an auth service.

Offline tests exercise API/unknown-mode rejection, missing login, the disabled
entrypoint, fabricated credential canaries never opened/tool workers never spawned,
exact UUID mismatch and known/unknown JSONL stops. These are policy/lineage tests,
**not sandboxed-worker or kernel isolation proof**. The native canary attempt is
separately BLOCKED. No quota or token result is inferred from mocks.

## Launch/resume and checkpoint plan

No runnable subscription launch argv is supplied before the blocked edge is
resolved. Supported parser requirements are fixed --json, controlled stdin and
explicit SESSION_ID for resume; no --last, ephemeral sessions, custom API provider
or unsafe sandbox flags. Authentication and every tool's OS enforcement must be
verified together, not inferred from --ignore-user-config or native flags.

Future reviewed work must require a ChatGPT auth-mode/account/workspace binding
from a supported trusted adapter, reject API/unknown/missing login, preserve the
existing lock/admission/ref and guard rules and bind both initial and resumed
session data to the same private credential domain. No tokens enter checkpoints.
A new checkpoint schema/lineage binding may be necessary; this spike does not
migrate v1/v2, change generation, adopt an API session or reset legitimate edits.
Only PAUSED can resume; exact UUID/private-session integrity must match. Changes
in auth identity, protocol, tool profile or unknown termination stop for review.

## Usage and waiting: no invented quota API

[Official usage guidance](https://learn.chatgpt.com/docs/pricing) exposes the usage
dashboard and interactive /status. Usage can be shared with ChatGPT Work, depends
on model/effort/context and may have five-hour and weekly windows depending on
plan; these are not predictable sleeps or fixed token-to-time conversions. Only
the human operator observes their official UI; no cookie scraping, hidden endpoint,
automatic login or account/credit purchase occurs. Usage/reset is UNAVAILABLE to
this prototype; there is no auto-resume signal and no automatic retry timer.

The presentation-only `stop_presentation` reuses codex.Events' exact session and
terminal validation. Its required protocol_failed input comes from the trusted
stream driver; any error/unknown value blocks even after a prior terminal event. A known turn.failed with exit 0/1 stays checkpoint PAUSED;
prose claiming quota/reset is discarded. Only a **direct operator hold** can label
that known PAUSED display WAITING_FOR_SUBSCRIPTION, without claiming an official
quota result or changing persisted phase. Missing/malformed terminal, signals,
wrong UUID or unexpected exit remain NEEDS_HUMAN even when a hold was requested.
Completion is COMPLETED, never an account-capacity/reset signal. This helper is
not wired to runtime/checkpoint writes. Future automated waiting needs a reviewed
trusted signal; the existing runtime behavior is preserved.

## Smallest safe next milestone and independent gates

A separate, no-account capability spike should generate the pinned protocol
schema offline, enumerate every tool dispatch path and demonstrate a **supported
universal external worker boundary** with fabricated auth/session/GitHub canaries.
Test reads, patches, symlinks, proc/ptrace, inherited descriptors, MCP/plugins,
subagents, network, cancellation and crash/restart on a reviewed real kernel.
Every unhandled tool must be rejected, never executed locally by the trusted
service. If 0.164.0 cannot support this, request a supported upstream interface
or independently reviewed version change; do not build a credential proxy.

Only after that proof and independent review may a human authorize actual login,
refresh/re-auth and a disposable [subscription smoke turn](subscription-smoke.md).
Also resolve the oversized artifact separately without changing caps here. Native
session persistence, account binding and restart/cancellation must pass before
production consideration. This Issue can close as a scoped architecture blocker;
a green CI or ADR approval is not deployment/live-execution authorization.
