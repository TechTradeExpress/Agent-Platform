# Subscription-authenticated Codex: validation gates

The maintainer-selected product path is Codex CLI using a ChatGPT subscription.
See [ADR 001](subscription-architecture.md) for the Issue #17 decision, threat
model, offline prototype and exact blockers. `agent-platform subscription` only
reports SUBSCRIPTION_ISOLATION_BLOCKED; it never authenticates or executes.

This document records evidence and blockers; it is **not** an authentication
implementation, approved security architecture or authorization to log in/run.
The existing API runner and reference broker are retained for compatibility,
with their security checks intact, but deploying that broker is deferred.

## Safe evidence collected for installed Codex 0.164.0

Help/version were queried with an empty temporary HOME/CODEX_HOME, a minimal
PATH/locale environment, no inherited tokens/proxies, and bounded subprocesses.
Every command exited 0. No login, login status, credential-store query, account
refresh, exec turn or resume turn was performed. No auth.json was opened/copied.

| Probe | Observed parser contract | What remains unproven |
| --- | --- | --- |
| `codex --version` | codex-cli 0.164.0 | Provider/account availability |
| `codex --no-daemon login --help` | login command; --device-auth option | Actual ChatGPT login/entitlement and re-auth |
| `codex --no-daemon exec --help` | noninteractive exec, --json JSONL, stdin prompt | Authenticated turn/event behavior |
| `codex --no-daemon exec resume --help` | explicit SESSION_ID and stdin prompt; --json | Same-session authenticated resume and edit preservation |
| exec/resume --ignore-user-config help | Auth still uses CODEX_HOME | Credential isolation from model tools |

These are parser checks, not authenticated integration tests. `--last`, auth
fallbacks and unsafe sandbox/approval flags are not adopted by Agent Platform.

The [official authentication guide](https://learn.chatgpt.com/docs/auth) describes
ChatGPT sign-in, cached file/keyring credentials and automatic token refresh.
That is current vendor guidance, not a test of pinned 0.164.0 refresh behavior.
The [noninteractive guide](https://learn.chatgpt.com/docs/non-interactive-mode)
describes exec/JSONL and continuing sessions. Neither guide demonstrates this
project's proposed credential boundary. Documentation examples for copying an
auth cache into a general-purpose container are **not accepted here**.

## Required independently reviewed boundary

A future design must keep subscription credentials and refresh authority with
a **trusted Codex process and credential store**. Model-invoked shells/tools,
untrusted worktrees, child environments/descriptors and logs must not obtain
them. No raw auth.json may be copied/mounted into a coding sandbox. A shared UID,
0700 home, environment filtering or workspace-write flag alone is not proof of
read isolation. Native sandbox flags do not by themselves demonstrate separation
between a trusted auth/session owner and its untrusted tools.

The current implementation runs Codex itself inside Bubblewrap with a credential-
free home and forces model_provider=agent_platform, requires_openai_auth=false.
The reference broker uses an API credential. Therefore simply changing a provider
flag or mounting a credential cache cannot satisfy the selected product path.
Do not forward OAuth/access/refresh tokens through the API broker or invent a
privileged credential proxy. A new trusted-process/tool-execution boundary needs
explicit scope and security review before implementation or authenticated tests.

## Follow-up acceptance matrix (all live rows NOT_RUN)

1. Pin the exact CLI artifact/version/hash and prove its supported subscription
   login method and account/workspace binding in a private operator-owned store.
   Login and account use require separate explicit operator authorization.
2. Use mocked auth/storage first to test refresh, rotation, revocation, concurrent
   refresh and re-auth failures. Unknown auth state must stop execution, without
   silently switching to API billing, another account or another session.
3. Independently audit the trusted Codex/credential-store and untrusted tool
   boundary. Negative tool attempts must fail for auth files/keyring, parent
   memory/proc, inherited descriptors, refresh authority and host credentials.
   Demonstrate OS enforcement, not health booleans or model instructions.
4. Only after review, run a separately authorized disposable subscription turn
   with JSONL and explicit same-UUID resume. Preserve legitimate edits, session
   lineage and existing lock/checkpoint invariants; test failure/reauth paths.
5. Verify safe persistence/refresh across process restarts without copying auth
   into session/checkpoint/report artifacts. Re-auth is an explicit operator step;
   never auto-login, choose --last or retry an uncertain turn.
6. Record redacted exact-SHA evidence, kernel behavior, auth/session outcomes and
   limitations separately from offline CI. Keep the PR Draft and Issue open until
   independent review passes the revised scope. Human-only merge remains intact.

Status: CLI_HELP_CONTRACT_PASS; authenticated execution, refresh/re-auth,
credential isolation and live E2E are NOT_RUN/BLOCKED. No production readiness or
privileged deployment approval follows from the diagnostic extraction.

Issue #17 rechecked pinned help (including login status, sandbox and app-server
help) and attempted only a fabricated-canary native probe. The probe was BLOCKED
inside the existing sandbox; actual login status, refresh, tool credential
isolation and live inference were not tested. See the [deferred operator smoke
checklist](subscription-smoke.md); there is no account-consuming invocation yet.
